pub(crate) mod check_bare;
pub(crate) mod ensure_bare_repo;
use bytes::Bytes;
pub fn pkt_line_err(msg: &str) -> Bytes {
    let payload = format!("ERR {}\n", msg);
    let len = payload.len() + 4; // +4 за сам префикс длины
    Bytes::from(format!("{:04x}{}", len, payload))
}
