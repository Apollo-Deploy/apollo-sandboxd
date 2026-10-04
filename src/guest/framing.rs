use crate::error::{Error, Result};
use guest_protocol::GuestEnvelope;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

const HEADER_BYTES: usize = 20;
const MAX_FRAME_BYTES: usize = guest_protocol::wire::MAX_FRAME_BYTES;

pub async fn write<W: AsyncWrite + Unpin>(
    writer: &mut W,
    request_id: u64,
    value: &GuestEnvelope,
) -> Result<()> {
    let (header, body) = sandboxd_protocol::codec::encode_frame_parts(request_id, value)?;
    writer.write_all(&header).await?;
    writer.write_all(&body).await?;
    writer.flush().await?;
    Ok(())
}

pub async fn read<R: AsyncRead + Unpin>(reader: &mut R) -> Result<(u64, GuestEnvelope)> {
    let mut header = [0u8; HEADER_BYTES];
    reader.read_exact(&mut header).await?;
    let parsed = sandboxd_protocol::codec::Header::decode_limited(header, MAX_FRAME_BYTES)?;
    let mut body = vec![0u8; parsed.body_len as usize];
    reader.read_exact(&mut body).await?;
    let envelope = sandboxd_protocol::codec::decode_body(&body)?;
    Ok((parsed.request_id, envelope))
}

pub fn validate(
    envelope: &GuestEnvelope,
    expected: &guest_protocol::SessionIdentity,
) -> Result<()> {
    envelope
        .validate(expected)
        .map_err(|_| Error::Config("guest envelope authentication failed"))
}
