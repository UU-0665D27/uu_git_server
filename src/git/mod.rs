pub mod check_bare;
pub mod ensure_bare_repo;
use bytes::Bytes;
pub fn pkt_line_err(msg: &str) -> Bytes {
    let payload = format!("ERR {msg}\n");
    let len = payload.len() + 4; // +4 за сам префикс длины
    Bytes::from(format!("{len:04x}{payload}"))
}
