use askama::Template;

#[derive(Template)]
#[template(path = "gui/login.html")]
pub struct LoginTemplate {
    pub error: Option<String>,
}

#[derive(Clone)]
pub struct RepoEntry {
    pub path: String,
    pub http_url: String,
    pub ssh_url: String,
}

#[derive(Template)]
#[template(path = "gui/dashboard.html")]
pub struct DashboardTemplate {
    pub user: Option<String>,
    pub own_repos: Vec<RepoEntry>,
    pub other_repos: Vec<RepoEntry>,
}

/// Небольшой хелпер, чтобы не тащить askama::Error в хендлеры axum
pub trait RenderOr500: Template {
    fn render_or_500(&self) -> String {
        self.render()
            .unwrap_or_else(|e| format!("template error: {e}"))
    }
}
impl<T: Template> RenderOr500 for T {}
