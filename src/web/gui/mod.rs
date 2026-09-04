pub mod repos;
pub mod session_store;
pub mod templates;

use crate::{
    auth::User,
    config::Config,
    repo_meta::{RepositoryMetadataManager, Visibility},
    web::gui::{
        session_store::SqliteSessionStore,
        templates::{RenderOr500, RepoEntry},
    },
};
use axum::{
    Form, Json, Router,
    extract::{FromRequestParts, OptionalFromRequestParts, Path as AxumPath, State},
    http::{StatusCode, request::Parts},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{delete, get, post},
};
use repos::scan_repos;
use serde::{Deserialize, Serialize};
use sqlx::SqlitePool;
use templates::{DashboardTemplate, LoginTemplate};
use tower_sessions::{Expiry, Session, SessionManagerLayer, cookie::time::Duration};

use tracing::info;

const SESSION_USER_KEY: &str = "user";

pub async fn run_gui_server(config: Config) -> anyhow::Result<()> {
    let db_url = format!("sqlite://{}?mode=rwc", config.sessions_db.display());
    let pool = SqlitePool::connect(&db_url).await?;

    let session_store = SqliteSessionStore::new(pool).await?;

    let session_layer = SessionManagerLayer::new(session_store)
        .with_secure(false) // выставить true, если GUI за TLS/HTTPS
        .with_expiry(Expiry::OnInactivity(Duration::hours(24)));

    let app = Router::new()
        .route("/", get(dashboard))
        .route("/login", get(login_form).post(login_submit))
        .route("/logout", axum::routing::post(logout))
        .route(
            "/api/repo/:owner/:repo/visibility",
            post(set_repo_visibility),
        )
        .route(
            "/api/repo/:owner/:repo/collaborators",
            post(add_collaborator),
        )
        .route(
            "/api/repo/:owner/:repo/collaborators/:username",
            delete(remove_collaborator),
        )
        .layer(session_layer)
        .with_state(config.clone());

    let addr = format!("{}:{}", config.host, config.gui_port);
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("🖥️  GUI listening on {}", addr);
    axum::serve(listener, app.into_make_service()).await?;
    Ok(())
}

/// Extractor: требует активную сессию, иначе редиректит на /login
pub struct AuthUser(pub String);

impl<S> FromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = Redirect;

    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
        let session = Session::from_request_parts(parts, state)
            .await
            .map_err(|_| Redirect::to("/login"))?;

        match session.get::<String>(SESSION_USER_KEY).await {
            Ok(Some(user)) => Ok(AuthUser(user)),
            _ => Err(Redirect::to("/login")),
        }
    }
}

/// Опциональная версия того же извлечения — используется там, где авторизация
/// не обязательна (например, дашборд доступен и анонимусам).
impl<S> OptionalFromRequestParts<S> for AuthUser
where
    S: Send + Sync,
{
    type Rejection = Redirect;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        let Ok(session) = Session::from_request_parts(parts, state).await else {
            return Ok(None);
        };

        match session.get::<String>(SESSION_USER_KEY).await {
            Ok(Some(user)) => Ok(Some(AuthUser(user))),
            _ => Ok(None),
        }
    }
}

async fn login_form(session: Session) -> Response {
    // уже залогинен — сразу на дашборд
    if session
        .get::<String>(SESSION_USER_KEY)
        .await
        .ok()
        .flatten()
        .is_some()
    {
        return Redirect::to("/").into_response();
    }
    Html(LoginTemplate { error: None }.render_or_500()).into_response()
}

#[derive(Deserialize)]
struct LoginForm {
    username: String,
    password: String,
}

async fn login_submit(
    State(config): State<Config>,
    session: Session,
    Form(form): Form<LoginForm>,
) -> Response {
    let ok = User::load(&form.username, &config.users_dir)
        .map(|u| User::verify_password(Some(&u), &form.password))
        .unwrap_or(false);

    if !ok {
        return Html(
            LoginTemplate {
                error: Some("Неверный логин или пароль".into()),
            }
            .render_or_500(),
        )
        .into_response();
    }

    if session
        .insert(SESSION_USER_KEY, form.username)
        .await
        .is_err()
    {
        return Html(
            LoginTemplate {
                error: Some("Внутренняя ошибка сессии".into()),
            }
            .render_or_500(),
        )
        .into_response();
    }

    Redirect::to("/").into_response()
}

async fn logout(session: Session) -> Redirect {
    let _ = session.delete().await;
    Redirect::to("/login")
}
async fn dashboard(State(config): State<Config>, user: Option<AuthUser>) -> Response {
    let all = scan_repos(&config.repos_base);

    let (username, own_repos, other_repos) = match user {
        Some(AuthUser(u)) => {
            let (own, other): (Vec<_>, Vec<_>) =
                all.into_iter().partition(|(owner, _)| owner == &u);
            (
                Some(u.clone()),
                build_repo_entries(own, &u, &config),
                build_repo_entries(other, "public", &config),
            )
        }
        None => (None, Vec::new(), build_repo_entries(all, "public", &config)),
    };

    Html(
        DashboardTemplate {
            user: username,
            own_repos,
            other_repos,
        }
        .render_or_500(),
    )
    .into_response()
}

/// Собирает клон-ссылки (HTTP и SSH) для списка репозиториев.
/// `ssh_user` — от чьего имени формируется SSH-ссылка: имя владельца для
/// собственных репозиториев (RW) или "public" для чужих/публичных (RO).
fn build_repo_entries(
    repos: Vec<(String, String)>,
    ssh_user: &str,
    config: &Config,
) -> Vec<RepoEntry> {
    repos
        .into_iter()
        .map(|(owner, repo)| {
            let path = format!("{owner}/{repo}");
            RepoEntry {
                http_url: format!("http://{}:{}/{path}", config.host, config.port),
                ssh_url: format!(
                    "ssh://{ssh_user}@{}:{}/{path}",
                    config.host, config.ssh_port
                ),
                path,
            }
        })
        .collect()
}

// -------------------- API обработчики --------------------

#[derive(Serialize, Deserialize)]
struct VisibilityRequest {
    visibility: String,
}

#[derive(Serialize, Deserialize)]
struct CollaboratorRequest {
    username: String,
}

#[derive(Serialize)]
struct ApiResponse {
    success: bool,
    message: String,
}

/// Установить видимость репозитория (только для владельца)
async fn set_repo_visibility(
    AuthUser(username): AuthUser,
    AxumPath((owner, repo)): AxumPath<(String, String)>,
    State(config): State<Config>,
    Json(payload): Json<VisibilityRequest>,
) -> impl IntoResponse {
    // Проверяем, что пользователь — владелец
    if username != owner {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse {
                success: false,
                message: "You are not the repository owner".to_string(),
            }),
        )
            .into_response();
    }

    // Парсим видимость
    let visibility = match Visibility::from_str(&payload.visibility) {
        Some(v) => v,
        None => {
            return (
                StatusCode::BAD_REQUEST,
                Json(ApiResponse {
                    success: false,
                    message: "Invalid visibility value. Use 'public' or 'private'".to_string(),
                }),
            )
                .into_response();
        }
    };

    let metadata_mgr = RepositoryMetadataManager::new(config.repos_base.clone());

    match metadata_mgr.set_visibility(&owner, &repo, visibility) {
        Ok(_) => (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("Repository set to {}", visibility.as_str()),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to update visibility: {}", e),
            }),
        )
            .into_response(),
    }
}

/// Добавить коллаборатора (только для владельца)
async fn add_collaborator(
    AuthUser(username): AuthUser,
    AxumPath((owner, repo)): AxumPath<(String, String)>,
    State(config): State<Config>,
    Json(payload): Json<CollaboratorRequest>,
) -> impl IntoResponse {
    // Проверяем, что пользователь — владелец
    if username != owner {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse {
                success: false,
                message: "You are not the repository owner".to_string(),
            }),
        )
            .into_response();
    }

    let metadata_mgr = RepositoryMetadataManager::new(config.repos_base.clone());

    match metadata_mgr.add_collaborator(&owner, &repo, &payload.username) {
        Ok(_) => (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("User '{}' added as collaborator", payload.username),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to add collaborator: {}", e),
            }),
        )
            .into_response(),
    }
}

/// Удалить коллаборатора (только для владельца)
async fn remove_collaborator(
    AuthUser(username): AuthUser,
    AxumPath((owner, repo, collaborator)): AxumPath<(String, String, String)>,
    State(config): State<Config>,
) -> impl IntoResponse {
    // Проверяем, что пользователь — владелец
    if username != owner {
        return (
            StatusCode::FORBIDDEN,
            Json(ApiResponse {
                success: false,
                message: "You are not the repository owner".to_string(),
            }),
        )
            .into_response();
    }

    let metadata_mgr = RepositoryMetadataManager::new(config.repos_base.clone());

    match metadata_mgr.remove_collaborator(&owner, &repo, &collaborator) {
        Ok(_) => (
            StatusCode::OK,
            Json(ApiResponse {
                success: true,
                message: format!("User '{}' removed from collaborators", collaborator),
            }),
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(ApiResponse {
                success: false,
                message: format!("Failed to remove collaborator: {}", e),
            }),
        )
            .into_response(),
    }
}
