use crate::{get_repos_base, git::ensure_bare_repo::ensure_bare_repo};
use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use gix_packetline::blocking_io::{Writer, encode};
use std::{collections::HashMap, io::Write};
use tracing::{debug, warn};

pub fn handshake(params: &HashMap<String, String>, path: &str) -> Option<Response> {
    let service_str = params.get("service").map(String::as_str)?;

    if service_str != "git-receive-pack" && service_str != "git-upload-pack" {
        return None;
    }

    let repo_path = path.strip_suffix("/info/refs")?;
    let full_repo_path = get_repos_base().join(repo_path);

    if service_str == "git-receive-pack" {
        ensure_bare_repo(&full_repo_path);
    } else if !full_repo_path.is_dir() {
        warn!(
            "upload-pack handshake requested for nonexistent repo: {}",
            repo_path
        );
        return Some(
            (
                StatusCode::NOT_FOUND,
                [(header::CONTENT_TYPE, "text/plain")],
                "Repository not found",
            )
                .into_response(),
        );
    }

    // Упрощенная обработка ошибки через .ok()?
    let repo = gix::discover(&full_repo_path).ok()?;

    // Использование оператора ? вместо let...else (требование clippy::question_mark)
    let response_body = build_advertisement_body(&repo, service_str)?;

    debug!("Generated native gix advertisement for {}", service_str);

    Some(
        (
            StatusCode::OK,
            [
                (
                    header::CONTENT_TYPE,
                    format!("application/x-{service_str}-advertisement"),
                ),
                (
                    header::CACHE_CONTROL,
                    "no-cache, max-age=0, must-revalidate".to_string(),
                ),
            ],
            response_body,
        )
            .into_response(),
    )
}

/// Выделено в отдельную функцию для соблюдения лимита `clippy::too_many_lines` (100 строк)
/// и принципа единственной ответственности (SRP).
fn build_advertisement_body(repo: &gix::Repository, service_str: &str) -> Option<Vec<u8>> {
    let platform = repo.references().ok()?;

    let mut refs: Vec<_> = platform.all().ok()?.filter_map(Result::ok).collect();
    refs.sort_by(|a, b| a.name().as_bstr().cmp(b.name().as_bstr()));

    let mut writer = Writer::new(Vec::new());

    let service_line = format!("# service={service_str}\n");
    writer.write_all(service_line.as_bytes()).ok()?;
    encode::flush_to_write(writer.inner_mut()).ok()?;

    let caps = if service_str == "git-upload-pack" {
        "multi_ack thin-pack side-band side-band-64k ofs-delta shallow deepen-since deepen-not deepen-relative no-progress include-tag multi_ack_detailed object-format=sha1 agent=gitoxide/0.89.0"
    } else {
        "report-status delete-refs side-band-64k quiet atomic push-options object-format=sha1 agent=gitoxide/0.89.0"
    };

    let refs_len = refs.len();
    let mut first = true;

    for named_ref in refs {
        let ref_name_owned = named_ref.name().as_bstr().to_owned();

        let target_id = named_ref.into_fully_peeled_id().map_or_else(
            |_| "0000000000000000000000000000000000000000".to_string(),
            |id| id.to_string(),
        );

        let ref_name_lossy = String::from_utf8_lossy(&ref_name_owned);

        // ИСПРАВЛЕНИЕ: используем пробел ' ' вместо табуляции '\t'
        let line = if first {
            first = false;
            format!("{target_id} {ref_name_lossy}\0{caps}\n") // <-- Здесь был \t
        } else {
            format!("{target_id} {ref_name_lossy}\n") // <-- И здесь был \t
        };

        writer.write_all(line.as_bytes()).ok()?;
    }

    encode::flush_to_write(writer.inner_mut()).ok()?;

    debug!("Included {} refs in advertisement", refs_len);
    Some(writer.into_inner())
}
