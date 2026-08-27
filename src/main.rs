use crate::config::load_or_create_config;
use crate::web::handler;
use axum::{Router, extract::DefaultBodyLimit, http::HeaderMap, routing::any, serve};
use std::{net::SocketAddr, path::PathBuf, sync::OnceLock};
use tokio::net::TcpListener;
use tracing::{debug, error, info};
use tracing_subscriber::EnvFilter;

mod auth;
mod config;
mod git;
mod sec;
mod ssh;
mod web;

// Глобальное хранилище базовой директории
static REPOS_BASE: OnceLock<PathBuf> = OnceLock::new();
static USERS_DIR: OnceLock<PathBuf> = OnceLock::new();

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let config = load_or_create_config();

    // Настройка логирования
    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Сохраняем базовую директорию в глобальную переменную
    REPOS_BASE
        .set(config.repos_base.clone())
        .expect("REPOS_BASE already set");

    USERS_DIR
        .set(config.users_dir.clone())
        .expect("USERS_DIR already set");

    let http_config = config.clone();
    let ssh_config = config.clone();

    // HTTP сервер
    let http_handle = tokio::spawn(async move {
        if let Err(e) = run_http_server(http_config).await {
            error!("HTTP server error: {e:#}");
        }
    });

    // SSH сервер
    let ssh_handle = tokio::spawn(async move {
        if let Err(e) = ssh::run_ssh_server(ssh_config).await {
            error!("SSH server error: {e:#}");
        }
    });
    let gui_config = config.clone();
    let gui_handle = tokio::spawn(async move {
        if let Err(e) = web::gui::run_gui_server(gui_config).await {
            error!("GUI server error: {e:#}");
        }
    });
    // Ждём, пока упадёт/остановится любой из серверов
    tokio::select! {
        _ = http_handle => {
            error!("HTTP server stopped");
        }
        _ = ssh_handle => {
            error!("SSH server stopped");
        }
        _ = gui_handle => { error!("GUI server stopped"); }
    }

    Ok(())
}

async fn run_http_server(config: crate::config::Config) -> anyhow::Result<()> {
    let app = Router::new()
        .route("/{*path}", any(handler))
        .layer(DefaultBodyLimit::max(1024 * 1024 * 1024)); // 1 GiB

    let addr = format!("{}:{}", config.host, config.port);
    let listener = TcpListener::bind(&addr).await?;

    info!(
        repos_base = %config.repos_base.display(),
        addr = addr,
        users_dir = %config.users_dir.display(),
        "🌐 Git server listening",
    );

    serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    Ok(())
}

fn get_users_dir() -> PathBuf {
    USERS_DIR.get().unwrap().clone()
}

fn get_repos_base() -> PathBuf {
    REPOS_BASE.get().unwrap().clone()
}

fn log_headers(headers: &HeaderMap) {
    for (name, value) in headers {
        debug!("   {}: {:?}", name, value);
    }
}
