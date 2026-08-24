use gix::create::{Kind, into};
use std::path::PathBuf;
use tracing::info;

use crate::git::check_bare::check_bare;

/// Проверяет, что по указанному пути находится bare-репозиторий.
/// Если каталога нет — создаёт. Если есть, но не bare — пересоздаёт.
pub fn ensure_bare_repo(path: &PathBuf) {
    if !path.exists() {
        info!("Creating bare repo at {}", path.display());
        // gix самостоятельно создаст необходимые директории
        into(path, Kind::Bare, Default::default())
            .unwrap_or_else(|e| panic!("Failed to init bare repo at {}: {:?}", path.display(), e));
        info!("Bare repo created at {}", path.display());
    } else {
        // Проверим, что репозиторий действительно bare
        check_bare(path);
    }
}
