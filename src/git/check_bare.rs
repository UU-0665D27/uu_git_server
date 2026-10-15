use gix::{
    create::{Kind, Options, into},
    open,
};
use std::{
    fs::{create_dir_all, remove_dir_all},
    path::Path,
};
use tracing::{debug, info, warn};

pub fn check_bare(path: &Path) {
    if open(path).is_ok_and(|r| r.is_bare()) {
        debug!("repo {} is bare", path.display());
        return;
    }

    warn!("Reinitializing {} as bare repo", path.display());

    let _ = remove_dir_all(path);
    create_dir_all(path).unwrap();

    into(path, Kind::Bare, Options::default())
        .unwrap_or_else(|e| panic!("Failed to init bare repo at {}: {:?}", path.display(), e));

    info!("Bare repo created at {}", path.display());
}
