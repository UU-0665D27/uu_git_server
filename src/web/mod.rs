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
    web::gitseccomp::SYSCALLS,
};
use axum::{
    body::Bytes,
    extract::{ConnectInfo, Path, Query},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
};
use handshake::handshake;
use landlock::{ABI, Access, AccessFs, PathBeneath, Ruleset};
use std::{
    collections::HashMap,
    fs::File,
    io::{Error, Write},
    net::SocketAddr,
    os::unix::process::CommandExt,
    process::{Command, Stdio},
};
use tokio::task::spawn_blocking;
use tracing::{debug, info, warn};

// --- ОШИБКА E0599 ИСПРАВЛЕНА ЗДЕСЬ ---
use landlock::{RulesetAttr, RulesetCreatedAttr, RulesetError};

const INVALID_REPO_PATH: &str = "Invalid repository path (expected owner/repo)";

pub enum HandlerError {
    Unauthorized,
    BadRequest(&'static str),
    Forbidden(&'static str),
}

impl IntoResponse for HandlerError {
    fn into_response(self) -> Response {
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

fn check_authorization(
    addr: &SocketAddr,
    auth: &BasicAuth,
    owner: &str,
    repo_name: &str,
    is_push: bool,
) -> Result<(), HandlerError> {
    if owner.is_empty() || repo_name.is_empty() {
        warn!(%addr, user = %auth.username, INVALID_REPO_PATH);
        return Err(HandlerError::BadRequest(INVALID_REPO_PATH));
    }

    info!(%addr, user = %auth.username, repo = format!("{}/{}", owner, repo_name), "Request");

    let metadata_mgr = RepositoryMetadataManager::new(get_repos_base());
    let can_read = match metadata_mgr.can_access(owner, repo_name, Some(&auth.username)) {
        Ok(access) => access,
        Err(e) => {
            warn!("Error checking repo access: {}", e);
            false
        }
    };

    if !can_read {
        warn!(%addr, user = %auth.username, owner = %owner, repo = %repo_name, "Forbidden: no access");
        return Err(HandlerError::Forbidden(
            "Access denied: this repository is private",
        ));
    }

    if is_push && auth.username != owner {
        warn!(%addr, user = %auth.username, owner = %owner, repo = %repo_name, "Forbidden: push access denied");
        return Err(HandlerError::Forbidden(
            "Push access denied: you are not the repository owner",
        ));
    }

    Ok(())
}

// -------------------- HTTP обработчик (ВОССТАНОВЛЕН) --------------------
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

    // Простой парсинг пути
    let is_handshake = path.ends_with("/info/refs");
    let is_receive = path.ends_with("/git-receive-pack");
    let is_upload = path.ends_with("/git-upload-pack");

    let repo_path = if is_handshake {
        path.strip_suffix("/info/refs").unwrap_or(&path)
    } else if is_receive {
        path.strip_suffix("/git-receive-pack").unwrap_or(&path)
    } else if is_upload {
        path.strip_suffix("/git-upload-pack").unwrap_or(&path)
    } else {
        &path
    };

    let segments: Vec<&str> = repo_path.split('/').filter(|s| !s.is_empty()).collect();
    let (owner, repo_name) = if segments.len() >= 2 {
        (segments[segments.len() - 2], segments[segments.len() - 1])
    } else {
        ("", "")
    };

    let is_push = is_receive
        || params
            .get("service")
            .is_some_and(|s| s == "git-receive-pack");

    check_authorization(&addr, &auth, owner, repo_name, is_push)?;

    if !body.is_empty() {
        debug!("📨 Body size: {} bytes", body.len());
        log_headers(&headers);
    }

    if is_handshake && let Some(response) = handshake(&params, &path) {
        return Ok(response);
    }

    if is_receive || is_upload {
        let service = if is_receive {
            "receive-pack"
        } else {
            "upload-pack"
        };
        return Ok(handle_git_pack(service, repo_path, body).await);
    }

    Ok((StatusCode::OK, "OK").into_response())
}

// -------------------- Обработчик Git Pack (С ИСПРАВЛЕННЫМ STDIN) --------------------
pub async fn handle_git_pack(service: &str, repo_path: &str, body: Bytes) -> Response {
    let full_repo_path = get_repos_base().join(repo_path);

    if service == "receive-pack" {
        ensure_bare_repo(&full_repo_path);
    } else if !full_repo_path.is_dir() {
        warn!("upload-pack requested for nonexistent repo: {}", repo_path);
        return (StatusCode::NOT_FOUND, "Repository not found").into_response();
    }

    let full_repo_path_str = full_repo_path.to_string_lossy().to_string();
    let service_owned = service.to_string();
    let body_vec = body.to_vec(); // Теперь это используется для записи в stdin

    let result = spawn_blocking(move || {
        let mut cmd = Command::new("/usr/bin/git");
        cmd.arg(&service_owned)
            .arg("--stateless-rpc")
            .arg(&full_repo_path_str)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        unsafe {
            // 2. PRE_EXEC (дочерний процесс, ДО exec)
            cmd.pre_exec(move || {
                let repo_fd = File::open(&full_repo_path_str)
                    .map_err(|e| Error::other(format!("Failed to open repo dir: {e}")))?;
                if apply_landlock_unsafe(&repo_fd).is_err() {
                    return Err(Error::other("landlock restrict failed"));
                }
                setup_seccomp(SYSCALLS);
                Ok(())
            });
        }

        // 3. ЗАПУСК И ЗАПИСЬ В STDIN
        let mut child = cmd.spawn()?;

        if let Some(mut stdin) = child.stdin.take() {
            stdin.write_all(&body_vec)?;
        }

        child.wait_with_output()
    })
    .await
    .expect("spawn_blocking panicked");

    match result {
        Ok(output) => {
            if !output.status.success() {
                let stderr_str = String::from_utf8_lossy(&output.stderr);
                warn!(
                    "Git {} failed (status {:?}): {}",
                    service,
                    output.status.code(),
                    stderr_str
                );
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    [(header::CONTENT_TYPE, "text/plain")],
                    "Git process failed",
                )
                    .into_response();
            }

            if !output.stderr.is_empty() {
                warn!(
                    "Git {} stderr: {:?}",
                    service,
                    String::from_utf8_lossy(&output.stderr)
                );
            }

            debug!("Git {} stdout len: {}", service, output.stdout.len());

            let content_type = if service == "receive-pack" {
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
                output.stdout,
            )
                .into_response()
        }
        Err(e) => {
            warn!("Git {} execution failed: {}", service, e);
            (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error").into_response()
        }
    }
}

/// Безопасная версия применения landlock для вызова внутри `pre_exec`.
fn apply_landlock_unsafe(repo_fd: &File) -> Result<(), RulesetError> {
    let abi = ABI::from(9999);

    let access_all = AccessFs::from_all(abi);
    let access_read = AccessFs::ReadFile;
    let access_readexecute = AccessFs::ReadFile | AccessFs::Execute;
    let access_readwrite = AccessFs::ReadFile | AccessFs::WriteFile;

    let mut created = Ruleset::default().handle_access(access_all)?.create()?;

    created = created.add_rule(PathBeneath::new(repo_fd, access_all))?;

    for path in &[
        "/etc/ld.so.preload",
        "/etc/ld.so.cache",
        "/home/u_uu/.gitconfig",
        "/usr/share/locale/",
        "/sys/devices/system/cpu/online",
        "/proc/stat",
    ] {
        if let Ok(fd) = File::open(path) {
            created = created.add_rule(PathBeneath::new(fd, access_read))?;
        }
    }

    if let Ok(fd) = File::open("/dev/null") {
        created = created.add_rule(PathBeneath::new(fd, access_readwrite))?;
    }

    for path in &[
        "/usr/lib64/ld-linux-x86-64.so.2",
        "/usr/bin/git",
        "/usr/lib/",
    ] {
        if let Ok(fd) = File::open(path) {
            created = created.add_rule(PathBeneath::new(fd, access_readexecute))?;
        }
    }

    created.restrict_self()?;
    Ok(())
}
