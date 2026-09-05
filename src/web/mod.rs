pub mod gitseccomp;
pub mod gui;
pub mod handshake;
use crate::{
    auth::{BasicAuth, User, unauthorized_response},
    get_repos_base, get_users_dir,
    git::ensure_bare_repo::ensure_bare_repo,
    log_headers,
    repo_meta::RepositoryMetadataManager,
    sec::seccomp::setup_seccomp,
};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, Query},
    http::{HeaderMap, StatusCode, header},
    response::IntoResponse,
};
use handshake::handshake;
use libc::{_exit, c_int, close, dup2, execvp, exit, fork, pipe};
use std::{
    collections::HashMap,
    ffi::CString,
    io::{self, Read, Write},
    net::SocketAddr,
    os::fd::FromRawFd,
};
use tracing::{debug, info, warn};

const INVALID_REPO_PATH: &str = "Invalid repository path (expected owner/repo)";

struct RequestContext {
    req_type: &'static str,
    operation: &'static str,
    owner: String,
    repo_name: String,
    repo: String,
}

pub enum HandlerError {
    Unauthorized,
    BadRequest(&'static str),
    Forbidden(&'static str),
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> axum::response::Response {
        match self {
            Self::Unauthorized => unauthorized_response().into_response(),
            Self::BadRequest(msg) => (
                StatusCode::BAD_REQUEST,
                [(header::CONTENT_TYPE, "text/plain")],
                msg,
            )
                .into_response(),
            Self::Forbidden(msg) => (
                StatusCode::FORBIDDEN,
                [(header::CONTENT_TYPE, "text/plain")],
                msg,
            )
                .into_response(),
        }
    }
}

fn verify_auth(auth: &BasicAuth) -> Result<(), HandlerError> {
    let users_dir = get_users_dir();
    let user_opt = User::load(&auth.username, &users_dir);
    if !User::verify_password(user_opt.as_ref(), &auth.password) {
        warn!("Auth failed: invalid password for user '{}'", auth.username);
        return Err(HandlerError::Unauthorized);
    }
    Ok(())
}

fn parse_request(path: &str, params: &HashMap<String, String>) -> RequestContext {
    let repo = path
        .trim_end_matches("/info/refs")
        .trim_end_matches("/git-receive-pack")
        .trim_end_matches("/git-upload-pack");

    let req_type = if path.ends_with("/info/refs") {
        "handshake"
    } else if path.ends_with("/git-receive-pack") {
        "receive-pack"
    } else if path.ends_with("/git-upload-pack") {
        "upload-pack"
    } else {
        "other"
    };

    let operation = match req_type {
        "receive-pack" => "push",
        "upload-pack" => "fetch",
        "handshake" => match params.get("service").map(String::as_str) {
            Some("git-receive-pack") => "push",
            Some("git-upload-pack") => "fetch",
            _ => "unknown",
        },
        _ => "unknown",
    };

    let segments: Vec<&str> = repo.split('/').collect();
    let (owner, repo_name) = if segments.len() == 2 {
        (segments[0].to_string(), segments[1].to_string())
    } else {
        (String::new(), String::new())
    };

    RequestContext {
        req_type,
        operation,
        owner,
        repo_name,
        repo: repo.to_string(),
    }
}

fn check_authorization(
    addr: &SocketAddr,
    auth: &BasicAuth,
    ctx: &RequestContext,
) -> Result<(), HandlerError> {
    if ctx.owner.is_empty() || ctx.repo_name.is_empty() {
        warn!(
            %addr,
            user = %auth.username,
            repo = %ctx.repo,
            operation = %ctx.operation,
            INVALID_REPO_PATH
        );
        return Err(HandlerError::BadRequest(INVALID_REPO_PATH));
    }

    info!(
        %addr,
        user = %auth.username,
        repo = %ctx.repo,
        operation = %ctx.operation,
        "Request"
    );

    let metadata_mgr = RepositoryMetadataManager::new(get_repos_base());
    let can_read = match metadata_mgr.can_access(&ctx.owner, &ctx.repo_name, Some(&auth.username)) {
        Ok(access) => access,
        Err(e) => {
            warn!("Error checking repo access: {}", e);
            false
        }
    };

    if !can_read {
        warn!(
            %addr,
            user = %auth.username,
            owner = %ctx.owner,
            repo = %ctx.repo_name,
            "Forbidden: no access to private repository"
        );
        return Err(HandlerError::Forbidden(
            "Access denied: this repository is private",
        ));
    }

    if ctx.operation == "push" && auth.username != ctx.owner {
        warn!(
            %addr,
            user = %auth.username,
            owner = %ctx.owner,
            repo = %ctx.repo,
            "Forbidden: push access denied"
        );
        return Err(HandlerError::Forbidden(
            "Push access denied: you are not the repository owner",
        ));
    }

    Ok(())
}

fn log_request_details(
    req_type: &str,
    path: &str,
    params: &HashMap<String, String>,
    body: &Bytes,
    headers: &HeaderMap,
) {
    debug!("📨 [{}] /{} | query: {:?}", req_type, path, params);
    log_headers(headers);

    if !body.is_empty() {
        let preview_len = body.len().min(200);
        let preview = &body[..preview_len];
        debug!("   Body ({} bytes total):", body.len());
        debug!("   Hex: {:02x?}", preview);
        if let Ok(text) = std::str::from_utf8(preview) {
            debug!("   Text: {:?}", text);
        }
    }
}

async fn handle_git_pack(
    service: &str,
    _path: &str,
    repo_path: &str,
    body: Bytes,
    req_type: &str,
) -> axum::response::Response {
    let full_repo_path = get_repos_base().join(repo_path);

    if service == "receive-pack" {
        ensure_bare_repo(&full_repo_path);
    } else if !full_repo_path.is_dir() {
        warn!("upload-pack requested for nonexistent repo: {}", repo_path);
        return (
            StatusCode::NOT_FOUND,
            [(header::CONTENT_TYPE, "text/plain")],
            "Repository not found",
        )
            .into_response();
    }

    let service_owned = service.to_string();
    let full_repo_path_str = full_repo_path.to_string_lossy().to_string();
    let body_vec = body.to_vec();

    let result = tokio::task::spawn_blocking(move || unsafe {
        run_git_in_child(&service_owned, &full_repo_path_str, &body_vec)
    })
    .await
    .expect("spawn_blocking panicked");

    let (output_stdout, output_stderr) = match result {
        Ok((stdout, stderr)) => (stdout, stderr),
        Err(e) => {
            warn!("Git {} failed: {}", service, e);
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                [(header::CONTENT_TYPE, "text/plain")],
                format!("Internal server error: {e}"),
            )
                .into_response();
        }
    };

    if !output_stderr.is_empty() {
        warn!(
            "Git {} stderr: {:?}",
            service,
            String::from_utf8_lossy(&output_stderr)
        );
    }

    debug!("Git {} stdout len: {}", service, output_stdout.len());
    if !output_stdout.is_empty() {
        let preview = &output_stdout[..output_stdout.len().min(100)];
        debug!("Git {} stdout preview: {:02x?}", service, preview);
        if let Ok(text) = std::str::from_utf8(preview) {
            debug!("Git {} stdout text: {:?}", service, text);
        }
    }

    let content_type = if req_type == "receive-pack" {
        "application/x-git-receive-pack-result"
    } else {
        "application/x-git-upload-pack-result"
    };

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, content_type),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        output_stdout,
    )
        .into_response()
}

// -------------------- HTTP обработчик --------------------
pub async fn handler(
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    auth: BasicAuth,
    Path(path): Path<String>,
    Query(params): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Bytes,
) -> Result<impl IntoResponse, HandlerError> {
    debug!(%addr, "connected");

    verify_auth(&auth)?;

    let ctx = parse_request(&path, &params);

    check_authorization(&addr, &auth, &ctx)?;

    log_request_details(ctx.req_type, &path, &params, &body, &headers);

    if ctx.req_type == "handshake"
        && let Some(response) = handshake(&params, &path)
    {
        return Ok(response);
    }

    if ctx.req_type == "receive-pack" || ctx.req_type == "upload-pack" {
        let service = ctx.req_type;
        let repo_path = if ctx.req_type == "receive-pack" {
            path.strip_suffix("/git-receive-pack").unwrap()
        } else {
            path.strip_suffix("/git-upload-pack").unwrap()
        };

        return Ok(handle_git_pack(service, &path, repo_path, body, ctx.req_type).await);
    }

    Ok((StatusCode::OK, "OK").into_response())
}

unsafe fn run_git_in_child(
    service: &str,
    repo_path: &str,
    input: &[u8],
) -> io::Result<(Vec<u8>, Vec<u8>)> {
    let mut stdin_pipe = [-1i32; 2];
    let mut stdout_pipe = [-1i32; 2];
    let mut stderr_pipe = [-1i32; 2];

    if unsafe { pipe(stdin_pipe.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { pipe(stdout_pipe.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }
    if unsafe { pipe(stderr_pipe.as_mut_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }

    let pid = match unsafe { fork() } {
        -1 => return Err(io::Error::last_os_error()),
        0 => {
            // === Дочерний процесс ===
            //SPEC: НИЧЕГО НЕ ПИСАТЬ В КОНСОЛЬ, ВСЁ БУДЕТ ОТПРАВЛЕНО КЛИЕНТУ
            unsafe {
                close(stdin_pipe[1]); // оставляем только чтение
                close(stdout_pipe[0]);
                close(stderr_pipe[0]);

                dup2(stdin_pipe[0], libc::STDIN_FILENO);
                dup2(stdout_pipe[1], libc::STDOUT_FILENO);
                dup2(stderr_pipe[1], libc::STDERR_FILENO);

                close(stdin_pipe[0]);
                close(stdout_pipe[1]);
                close(stderr_pipe[1]);
            }

            // --- Место для seccomp / landlock ---
            if setup_landlock(repo_path).is_err() {
                unsafe { exit(3) };
            }
            setup_seccomp(gitseccomp::SYSCALLS);

            let git_path = CString::new("/usr/bin/git").unwrap();
            let service_c = CString::new(service).unwrap();
            let stateless = CString::new("--stateless-rpc").unwrap();
            let repo_c = CString::new(repo_path).unwrap();
            let argv: [*const libc::c_char; 5] = [
                git_path.as_ptr(),
                service_c.as_ptr(),
                stateless.as_ptr(),
                repo_c.as_ptr(),
                std::ptr::null(),
            ];

            unsafe { execvp(git_path.as_ptr(), argv.as_ptr()) };
            unsafe { _exit(1) };
        }
        pid => pid,
    };

    // === Родитель ===
    unsafe {
        close(stdin_pipe[0]);
        close(stdout_pipe[1]);
        close(stderr_pipe[1]);
    }

    // Запись тела запроса в stdin потомка
    {
        let stdin_fd = stdin_pipe[1];
        let mut stdin_file = unsafe { std::fs::File::from_raw_fd(stdin_fd) };
        stdin_file.write_all(input)?;
        stdin_file.flush()?;
        // File автоматически закроет fd при выходе из блока, что даст EOF git'у
    }

    // Параллельное чтение stdout и stderr (без дедлоков)
    let (stdout_data, stderr_data) = std::thread::scope(|s| -> io::Result<(Vec<u8>, Vec<u8>)> {
        let stdout_fd = stdout_pipe[0];
        let stderr_fd = stderr_pipe[0];

        let stdout_handle = s.spawn(move || {
            let mut f = unsafe { std::fs::File::from_raw_fd(stdout_fd) };
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            io::Result::Ok(buf)
        });
        let stderr_handle = s.spawn(move || {
            let mut f = unsafe { std::fs::File::from_raw_fd(stderr_fd) };
            let mut buf = Vec::new();
            f.read_to_end(&mut buf)?;
            io::Result::Ok(buf)
        });

        let stdout_data = stdout_handle.join().expect("stdout thread panicked")?;
        let stderr_data = stderr_handle.join().expect("stderr thread panicked")?;
        Ok((stdout_data, stderr_data))
    })?;

    // Ожидание завершения потомка
    let mut status: c_int = 0;
    if unsafe { libc::waitpid(pid, &raw mut status, 0) } == -1 {
        return Err(io::Error::last_os_error());
    }

    // Проверяем, завершился ли git успешно
    let exited_ok = libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0;
    if !exited_ok {
        let stderr_str = String::from_utf8_lossy(&stderr_data);
        return Err(io::Error::other(format!(
            "git {service} failed with status {status}: {stderr_str}"
        )));
    }

    Ok((stdout_data, stderr_data))
}

fn setup_landlock(repo_path: &str) -> Result<(), landlock::RulesetError> {
    use landlock::{
        ABI, Access, AccessFs, BitFlags, CreateRulesetError, PathBeneath, PathFd, Ruleset,
        RulesetAttr, RulesetCreatedAttr, RulesetError,
    };
    let abi = ABI::V9;
    let access_all = AccessFs::from_all(abi);

    let mut created = Ruleset::default().handle_access(access_all)?.create()?;

    // Репозиторий – обязательный путь
    let fd = PathFd::new(repo_path)
        .map_err(|_| RulesetError::CreateRuleset(CreateRulesetError::MissingHandledAccess))?;
    created = created.add_rule(PathBeneath::new(fd, access_all))?;

    // Только чтение
    let access_r: BitFlags<AccessFs> = AccessFs::ReadFile.into();
    for path in &[
        "/dev/null",
        "/proc/self/exe",
        "/etc/ld.so.cache",
        "/etc/ld.so.preload",
        "/sys/devices/system/cpu/online",
        "/proc/sys/vm/overcommit_memory",
    ] {
        if let Ok(fd) = PathFd::new(path) {
            created = created.add_rule(PathBeneath::new(fd, access_r))?;
        }
    }

    // Чтение и выполнение
    let access_read_execute = AccessFs::Execute | AccessFs::ReadFile;
    for path in &[
        "/usr/lib",
        "/usr/bin",
        "/lib64",
        "/usr/lib/git-core",
        "/usr/share/locale",
    ] {
        if let Ok(fd) = PathFd::new(path) {
            created = created.add_rule(PathBeneath::new(fd, access_read_execute))?;
        }
    }
    // Доступ к конкретным конфигурационным файлам git (только чтение)
    if let Ok(home) = std::env::var("HOME") {
        for config_file in &[".gitconfig", ".config/git/config"] {
            let path = std::path::Path::new(&home).join(config_file);
            if let Ok(fd) = PathFd::new(&path) {
                created = created.add_rule(PathBeneath::new(fd, AccessFs::ReadFile))?;
            }
        }
    }
    // Чтение и запись для /dev/null
    let access_read_write = AccessFs::ReadFile | AccessFs::WriteFile;
    if let Ok(fd) = PathFd::new("/dev/null") {
        created = created.add_rule(PathBeneath::new(fd, access_read_write))?;
    }

    let _status = created.restrict_self()?;
    Ok(())
}
