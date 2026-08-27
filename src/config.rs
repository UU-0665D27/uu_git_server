use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::info;
// -------------------- Конфигурация --------------------
#[derive(Debug, Deserialize, Serialize, Clone)]
pub struct Config {
    #[serde(default = "default_repos_base")]
    pub(crate) repos_base: PathBuf,
    #[serde(default = "default_users_dir")]
    pub(crate) users_dir: PathBuf,
    #[serde(default = "default_host")]
    pub(crate) host: String,
    #[serde(default = "default_port")]
    pub(crate) port: u16,
    #[serde(default = "default_log_level")]
    pub(crate) log_level: String,

    #[serde(default = "default_ssh_port")]
    pub ssh_port: u16,
    #[serde(default = "default_gui_port")]
    pub gui_port: u16,
    #[serde(default = "default_sessions_db")]
    pub sessions_db: PathBuf,
}

fn default_gui_port() -> u16 {
    8081
}
fn default_sessions_db() -> PathBuf {
    PathBuf::from("./sessions.db")
}
fn default_ssh_port() -> u16 {
    2222
}
fn default_users_dir() -> PathBuf {
    // <-- Дефолтное значение
    PathBuf::from("./users")
}
fn default_repos_base() -> PathBuf {
    PathBuf::from("/tmp/git-server")
}
fn default_host() -> String {
    "127.0.0.1".to_string()
}
fn default_port() -> u16 {
    8080
}
fn default_log_level() -> String {
    "info".to_string()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            repos_base: default_repos_base(),
            users_dir: default_users_dir(), // <-- Добавлено
            host: default_host(),
            port: default_port(),
            ssh_port: 2222,
            log_level: default_log_level(),
            gui_port: default_gui_port(),
            sessions_db: default_sessions_db(),
        }
    }
}

/// Загружает конфигурацию из первого найденного файла config.toml.
/// Если ни один не найден, создаёт config.toml в текущей директории со значениями по умолчанию.
pub fn load_or_create_config() -> Config {
    let config_paths = [
        Some(PathBuf::from("config.toml")),
        Some(PathBuf::from("/etc/uu_git_server/config.toml")),
    ];

    // Поиск существующего конфига
    for path in config_paths.into_iter().flatten() {
        if path.exists() {
            match std::fs::read_to_string(&path) {
                Ok(content) => match toml::from_str(&content) {
                    Ok(cfg) => {
                        info!("Loaded config from {}", path.display());
                        return cfg;
                    }
                    Err(e) => {
                        eprintln!("Error parsing config {}: {}", path.display(), e);
                    }
                },
                Err(e) => {
                    eprintln!("Error reading config {}: {}", path.display(), e);
                }
            }
        }
    }

    // Если не нашли, создаём в текущей директории
    let default_config = Config::default();
    let toml_string = toml::to_string_pretty(&default_config).unwrap();
    let default_path = PathBuf::from("config.toml");
    if let Err(e) = std::fs::write(&default_path, toml_string) {
        eprintln!(
            "Failed to create default config at {}: {}",
            default_path.display(),
            e
        );
    } else {
        info!("Created default config at {}", default_path.display());
    }
    default_config
}
