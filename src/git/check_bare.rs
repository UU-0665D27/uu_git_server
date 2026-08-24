use std::path::Path;
use tracing::{debug, info, warn};

pub fn check_bare(path: &Path) {
    if gix::open(path).map(|r| r.is_bare()).unwrap_or(false) {
        debug!("repo {} is bare", path.display());
        return;
    }

    warn!("Reinitializing {} as bare repo", path.display());

    let _ = std::fs::remove_dir_all(path);
    std::fs::create_dir_all(path).unwrap();

    gix::create::into(path, gix::create::Kind::Bare, Default::default())
        .unwrap_or_else(|e| panic!("Failed to init bare repo at {}: {:?}", path.display(), e));

    info!("Bare repo created at {}", path.display());
}
