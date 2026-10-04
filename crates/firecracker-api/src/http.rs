use crate::Error;
use tokio::io::{AsyncRead, AsyncReadExt};
pub const MAX_RESPONSE: usize = 1_048_576;
pub const MAX_HEADER: usize = 8192;

/// Strict Content-Length framing; ambiguous framing, transfer encoding, and duplicate lengths fail.
pub async fn read_response(stream: &mut (impl AsyncRead + Unpin)) -> Result<(u16, Vec<u8>), Error> {
    let mut header = Vec::with_capacity(512);
    while !header.ends_with(b"\r\n\r\n") {
        if header.len() == MAX_HEADER {
            return Err(Error::Response);
        }
        header.push(stream.read_u8().await?);
    }
    let text = std::str::from_utf8(&header).map_err(|_| Error::Response)?;
    let mut lines = text.split("\r\n");
    let status_line = lines.next().ok_or(Error::Response)?;
    let mut status = status_line.splitn(3, ' ');
    if status.next() != Some("HTTP/1.1") {
        return Err(Error::Response);
    }
    let code = status.next().ok_or(Error::Response)?;
    if code.len() != 3 {
        return Err(Error::Response);
    }
    let code: u16 = code.parse().map_err(|_| Error::Response)?;
    if !(100..=599).contains(&code) {
        return Err(Error::Response);
    }
    let mut length = None;
    for line in lines.filter(|line| !line.is_empty()) {
        let (name, value) = line.split_once(':').ok_or(Error::Response)?;
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(Error::Response);
        }
        if name.eq_ignore_ascii_case("content-length") {
            if length.is_some() {
                return Err(Error::Response);
            }
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Error::Response);
            }
            let value: usize = value.parse().map_err(|_| Error::Response)?;
            if value > MAX_RESPONSE {
                return Err(Error::Response);
            }
            length = Some(value);
        }
    }
    let length = match (code, length) {
        (204, None | Some(0)) => 0,
        (204, Some(_)) => return Err(Error::Response),
        (_, Some(length)) => length,
        _ => return Err(Error::Response),
    };
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await?;
    Ok((code, body))
}
