use std::path::{Path, PathBuf};

/// Возвращает список (owner, repo) для всех bare-репозиториев в repos_base.
/// Ожидается структура repos_base/<owner>/<repo> (bare git dir).
pub fn scan_repos(base: &Path) -> Vec<(String, String)> {
    let mut out = Vec::new();

    let Ok(owners) = std::fs::read_dir(base) else {
        return out;
    };

    for owner_entry in owners.flatten() {
        let owner_path: PathBuf = owner_entry.path();
        if !owner_path.is_dir() {
            continue;
        }
        let owner = owner_entry.file_name().to_string_lossy().to_string();

        let Ok(repos) = std::fs::read_dir(&owner_path) else {
            continue;
        };
        for repo_entry in repos.flatten() {
            if repo_entry.path().is_dir() {
                let repo = repo_entry.file_name().to_string_lossy().to_string();
                out.push((owner.clone(), repo));
            }
        }
    }

    out.sort();
    out
}
