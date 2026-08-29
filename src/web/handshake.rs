use crate::{get_repos_base, git::ensure_bare_repo::ensure_bare_repo};
use axum::{
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use gix_packetline::{
    PacketLineRef,
    blocking_io::{Writer, encode},
    decode,
};
use std::{collections::HashMap, io::Write, process::Command};
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

    let service_cmd = service_str.strip_prefix("git-").unwrap_or(service_str);
    let output = Command::new("git")
        .arg(service_cmd)
        .arg("--stateless-rpc")
        .arg("--advertise-refs")
        .arg(&full_repo_path)
        .output()
        .ok()?;

    debug!("Git {} stdout len: {}", service_cmd, output.stdout.len());
    if !output.stderr.is_empty() {
        debug!(
            "Git {} stderr: {:?}",
            service_cmd,
            String::from_utf8_lossy(&output.stderr)
        );
    }

    // Валидируем и парсим вывод git
    let mut remaining = output.stdout.as_slice();
    let mut line_count = 0;
    let mut first_line = true;

    while !remaining.is_empty() {
        match decode::streaming(remaining) {
            Ok(decode::Stream::Complete {
                line,
                bytes_consumed,
            }) => {
                line_count += 1;

                if let Some(data) = line.as_slice() {
                    if first_line {
                        // Первая линия: "oid ref\x00caps"
                        if let Some((ref_part, caps)) = parse_first_line(data) {
                            debug!("Head: {} | Caps: {}", ref_part, caps);
                        }
                        first_line = false;
                    } else {
                        // Остальные: просто "oid ref"
                        if let Some(text) = line.as_text() {
                            debug!("Ref: {}", text.as_bstr());
                        }
                    }
                } else if line == PacketLineRef::Flush {
                    debug!("Flush packet");
                }

                remaining = &remaining[bytes_consumed..];
            }
            Ok(decode::Stream::Incomplete { bytes_needed }) => {
                warn!("Incomplete pkt-line: need {} more bytes", bytes_needed);
                break;
            }
            Err(e) => {
                warn!("Invalid pkt-line: {}", e);
                return None;
            }
        }
    }

    debug!(
        "Validated {} pkt-lines from git {}",
        line_count, service_cmd
    );

    // Формируем ответ
    let mut writer = Writer::new(Vec::new());

    let service_line = format!("# service={service_str}\n");
    writer.write_all(service_line.as_bytes()).ok()?;
    encode::flush_to_write(writer.inner_mut()).ok()?;
    writer.inner_mut().write_all(&output.stdout).ok()?;

    let response_body = writer.into_inner();
    let response = (
        StatusCode::OK,
        [
            (
                header::CONTENT_TYPE,
                format!("application/x-{}-advertisement", service_str),
            ),
            (
                header::CACHE_CONTROL,
                "no-cache, max-age=0, must-revalidate".to_string(),
            ),
        ],
        response_body,
    )
        .into_response();

    Some(response)
}

/// Парсит первую линию: "178796ff... refs/heads/main\x00report-status..."
fn parse_first_line(data: &[u8]) -> Option<(String, String)> {
    let text = String::from_utf8_lossy(data);

    // Разделяем по NUL (\x00)
    let parts: Vec<&str> = text.split('\0').collect();

    if parts.len() >= 2 {
        let ref_part = parts[0].trim_end();
        let caps = parts[1].trim_end_matches('\n');
        Some((ref_part.to_string(), caps.to_string()))
    } else {
        // Нет capabilities (старый git?)
        Some((text.trim_end().to_string(), String::new()))
    }
}
