use crate::git::check_bare::check_bare;
use gix::create::{Kind, Options, into};
use std::path::PathBuf;
use tracing::info;

/// Проверяет, что по указанному пути находится bare-репозиторий.
/// Если каталога нет — создаёт. Если есть, но не bare — пересоздаёт.
pub fn ensure_bare_repo(path: &PathBuf) {
    if path.exists() {
        // Проверим, что репозиторий действительно bare
        check_bare(path);
    } else {
        info!("Creating bare repo at {}", path.display());
        // gix самостоятельно создаст необходимые директории
        into(path, Kind::Bare, Options::default())
            .unwrap_or_else(|e| panic!("Failed to init bare repo at {}: {:?}", path.display(), e));
        info!("Bare repo created at {}", path.display());
    }
}
