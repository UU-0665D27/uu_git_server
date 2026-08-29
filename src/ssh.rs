use crate::{
    auth::User,
    config::Config,
    get_repos_base,
    git::{ensure_bare_repo::ensure_bare_repo, pkt_line_err},
    sec::seccomp::setup_seccomp,
};
use bytes::Bytes;
use russh::{
    Channel, ChannelId, Preferred,
    keys::{
        PrivateKey,
        key::safe_rng,
        ssh_key::{LineEnding, PublicKey},
    },
    server::{self, Auth, Msg, Server as _, Session},
};
use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpListener,
    process::{ChildStdin, Command},
    sync::Mutex,
};
use tracing::{debug, error, info, warn};

const HOST_KEY_PATH: &str = "ssh_host_ed25519_key";

fn load_or_generate_host_key() -> anyhow::Result<PrivateKey> {
    let path = Path::new(HOST_KEY_PATH);
    if path.exists() {
        let key = PrivateKey::read_openssh_file(path)?;
        info!("Loaded host key from {}", HOST_KEY_PATH);
        Ok(key)
    } else {
        let key = PrivateKey::random(&mut safe_rng(), russh::keys::Algorithm::Ed25519)
            .expect("generate host key");
        key.write_openssh_file(path, LineEnding::default())?;
        info!("Generated and saved new host key to {}", HOST_KEY_PATH);
        Ok(key)
    }
}

fn parse_git_command(cmd: &str) -> Option<(&'static str, String)> {
    let cmd = cmd.trim();
    let (service, rest) = if let Some(r) = cmd.strip_prefix("git-upload-pack") {
        ("upload-pack", r)
    } else {
        let r = cmd.strip_prefix("git-receive-pack")?;
        ("receive-pack", r)
    };

    let path = rest
        .trim()
        .trim_matches(|c| c == '\'' || c == '"')
        .trim_start_matches('/');

    let segs: Vec<&str> = path.split('/').filter(|s| !s.is_empty()).collect();
    if segs.len() != 2 || segs.iter().any(|s| *s == ".." || s.contains('\0')) {
        return None;
    }
    Some((service, format!("{}/{}", segs[0], segs[1])))
}

pub async fn run_ssh_server(config_git: Config) -> anyhow::Result<()> {
    let key = load_or_generate_host_key()?;
    let config = Arc::new(russh::server::Config {
        inactivity_timeout: Some(std::time::Duration::from_secs(3600)),
        auth_rejection_time: std::time::Duration::from_secs(3),
        auth_rejection_time_initial: Some(std::time::Duration::from_secs(0)),
        keys: vec![key],
        preferred: Preferred::default(),
        ..Default::default()
    });

    let mut sh = Server {
        id: 0,
        config: config_git,
    };
    let socket = TcpListener::bind(("::", 2222)).await?;
    info!("SSH Git server listening on {:?}", socket);
    sh.run_on_socket(config, &socket).await?;
    Ok(())
}

struct Server {
    id: usize,
    config: Config,
}

struct Handler {
    id: usize,
    user: Option<String>,
    git_stdin: Option<Arc<Mutex<Option<ChildStdin>>>>,
    config: Config,
}

impl server::Server for Server {
    type Handler = Handler;

    fn new_client(&mut self, _: Option<std::net::SocketAddr>) -> Self::Handler {
        self.id += 1;
        Handler {
            id: self.id,
            user: None,
            git_stdin: None,
            config: self.config.clone(),
        }
    }

    fn handle_session_error(&mut self, error: <Self::Handler as server::Handler>::Error) {
        error!("SSH session error: {error:#?}");
    }
}
#[allow(clippy::unused_async_trait_impl)]
impl server::Handler for Handler {
    type Error = anyhow::Error;

    async fn auth_publickey(
        &mut self,
        user: &str,
        public_key: &PublicKey,
    ) -> Result<Auth, Self::Error> {
        info!("auth_publickey user={}", user);
        self.user = Some(user.to_string());
        //SPEC: пользователь public имеет read доступ к публичным репозиториям
        if user == "public" {
            return Ok(Auth::Accept);
        }
        match User::load(user, &self.config.users_dir) {
            Some(u) if u.verify_public_key(public_key) => {
                info!("SSH auth ok for user={}", user);
                Ok(Auth::Accept)
            }
            _ => {
                warn!("SSH auth failed for user={}", user);
                Ok(Auth::Reject {
                    proceed_with_methods: None,
                    partial_success: false,
                })
            }
        }
    }

    //LLM:не удалять
    //    async fn auth_openssh_certificate(
    //        &mut self,
    //        user: &str,
    //        _certificate: &Certificate,
    //    ) -> Result<Auth, Self::Error> {
    //        info!("auth_certificate user={}", user);
    //        self.user = Some(user.to_string());
    //        Ok(Auth::Accept)
    //    }

    async fn channel_open_session(
        &mut self,
        _channel: Channel<Msg>,
        reply: server::ChannelOpenHandle,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        reply.accept().await;
        Ok(())
    }

    async fn exec_request(
        &mut self,
        channel: ChannelId,
        data: &[u8],
        session: &mut Session,
    ) -> Result<(), Self::Error> {
        let command = String::from_utf8_lossy(data);
        info!("exec_request user={:?} cmd={}", self.user, command);

        let Some((service, repo)) = parse_git_command(&command) else {
            warn!("Unknown or invalid git command: {}", command);
            session.channel_failure(channel)?;
            return Ok(());
        };

        let user = self.user.clone().unwrap_or_else(|| "anonymous".into());
        let owner = repo.split('/').next().unwrap_or("");

        // push только owner
        if service == "receive-pack" && user != owner {
            warn!("push denied: user={} owner={} repo={}", user, owner, repo);
            let handle = session.handle();
            session.channel_success(channel)?;
            let _ = session.data(
                channel,
                pkt_line_err("Push access denied: not the repository owner"),
            );
            let _ = handle.exit_status_request(channel, 1).await;
            let _ = session.eof(channel);
            let _ = session.close(channel);
            return Ok(());
        }

        let full_path: PathBuf = get_repos_base().join(&repo);

        if service == "receive-pack" {
            // push может создать репозиторий, если его ещё нет
            ensure_bare_repo(&full_path);
        } else if !full_path.is_dir() {
            warn!("upload-pack requested for nonexistent repo: {}", repo);
            let handle = session.handle();
            session.channel_success(channel)?;
            let _ = session.data(channel, pkt_line_err("Repository not found"));
            let _ = handle.exit_status_request(channel, 1).await;
            let _ = session.eof(channel);
            let _ = session.close(channel);
            return Ok(());
        }

        info!(
            "Git request: service={} repo={} path={}",
            service,
            repo,
            full_path.display()
        );

        // клиент может слать data
        session.channel_success(channel)?;

        // в exec_request:
        let mut command = Command::new("git");
        command
            .arg(service)
            .arg(&full_path)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);

        // Клонируем путь для замыкания
        let repo_path_for_child = full_path.clone();

        unsafe {
            command.pre_exec(move || {
                if setup_landlock(&repo_path_for_child).is_err() {
                    libc::exit(3);
                }
                setup_seccomp(SYSCALLS);
                Ok(())
            });
        }

        let mut child = command.spawn()?;

        let stdin = child.stdin.take().unwrap();
        let mut stdout = child.stdout.take().unwrap();
        let mut stderr = child.stderr.take().unwrap();

        let stdin_slot = Arc::new(Mutex::new(Some(stdin)));
        self.git_stdin = Some(stdin_slot.clone());

        let handle = session.handle();
        let ch = channel;

        // git stdout → SSH
        {
            let handle = handle.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 65536];
                loop {
                    match stdout.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if handle
                                .data(ch, Bytes::copy_from_slice(&buf[..n]))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Err(e) => {
                            warn!("git stdout: {e}");
                            break;
                        }
                    }
                }
            });
        }

        // git stderr → лог
        {
            let service = service.to_string();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                while let Ok(n) = stderr.read(&mut buf).await {
                    if n == 0 {
                        break;
                    }
                    warn!(
                        "git {} stderr: {}",
                        service,
                        String::from_utf8_lossy(&buf[..n])
                    );
                }
            });
        }

        // wait → exit-status + eof + close
        {
            let service = service.to_string();
            tokio::spawn(async move {
                let status = child.wait().await;
                match &status {
                    Ok(s) => debug!("git {service} exited: {s}"),
                    Err(e) => warn!("git wait: {e}"),
                }
                let code = status.ok().and_then(|s| s.code()).unwrap_or(1) as u32;
                let _ = handle.exit_status_request(ch, code).await;
                let _ = handle.eof(ch).await;
                let _ = handle.close(ch).await;
                *stdin_slot.lock().await = None;
            });
        }

        Ok(())
    }

    async fn data(
        &mut self,
        _channel: ChannelId,
        data: &[u8],
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(slot) = &self.git_stdin {
            let mut g = slot.lock().await;
            if let Some(stdin) = g.as_mut()
                && let Err(e) = stdin.write_all(data).await
            {
                warn!("git stdin write: {e}");
                *g = None;
            }
        }
        Ok(())
    }

    async fn channel_eof(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(slot) = &self.git_stdin {
            let mut g = slot.lock().await;
            if let Some(mut stdin) = g.take() {
                let _ = stdin.shutdown().await;
            }
        }
        Ok(())
    }

    async fn channel_close(
        &mut self,
        _channel: ChannelId,
        _session: &mut Session,
    ) -> Result<(), Self::Error> {
        if let Some(slot) = &self.git_stdin {
            *slot.lock().await = None;
        }
        Ok(())
    }
}

fn setup_landlock(repo_path: &PathBuf) -> Result<(), landlock::RulesetError> {
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
    let access_rx = AccessFs::Execute | AccessFs::ReadFile;
    for path in &[
        "/usr/lib",
        "/usr/bin",
        "/lib64",
        "/usr/lib/git-core",
        "/usr/share/locale",
    ] {
        if let Ok(fd) = PathFd::new(path) {
            created = created.add_rule(PathBeneath::new(fd, access_rx))?;
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
    let access_rw = AccessFs::ReadFile | AccessFs::WriteFile;
    if let Ok(fd) = PathFd::new("/dev/null") {
        created = created.add_rule(PathBeneath::new(fd, access_rw))?;
    }

    let _status = created.restrict_self()?;
    Ok(())
}

pub const SYSCALLS: &[&str] = &[
    "execve",
    "close",
    "write",
    "gettid",
    "getpid",
    "rt_sigprocmask",
    "rt_sigaction",
    "rt_sigreturn",
    "futex",
    "recvfrom",
    "newfstatat",
    "brk",
    "mmap",
    "writev",
    "exit_group",
    "openat",
    "fstat",
    "read",
    "access",
    "arch_prctl",
    "set_tid_address",
    "set_robust_list",
    "rseq",
    "getrandom",
    "mprotect",
    "prlimit64",
    "getcwd",
    "geteuid",
    "chdir",
    "getdents64",
    "uname",
    "pipe2",
    "alarm",
    "munmap",
    "fcntl",
    "madvise",
    "clone3",
    "clone",
    "mkdir",
    "exit",
    "dup2",
    "wait4",
    "rmdir",
    "unlink",
    "tgkill",
    "ioctl",
    "poll",
    "setitimer",
    "pread64",
    "fsync",
    "link",
    "rename",
    "setsid",
    "restart_syscall",
    "dup",
];
