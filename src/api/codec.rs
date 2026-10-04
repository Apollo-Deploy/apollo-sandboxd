use crate::error::Result;
use sandboxd_protocol::codec::{self, HEADER_BYTES, Header};
use serde::{Serialize, de::DeserializeOwned};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub async fn read<T: DeserializeOwned>(io: &mut (impl AsyncRead + Unpin)) -> Result<(u64, T)> {
    read_limited(io, sandboxd_protocol::MAX_FRAME_BYTES).await
}
pub async fn read_limited<T: DeserializeOwned>(
    io: &mut (impl AsyncRead + Unpin),
    limit: usize,
) -> Result<(u64, T)> {
    let mut bytes = [0; HEADER_BYTES];
    io.read_exact(&mut bytes).await?;
    let header = Header::decode_limited(bytes, limit)?;
    let mut body = vec![0; header.body_len as usize];
    io.read_exact(&mut body).await?;
    Ok((header.request_id, codec::decode_body(&body)?))
}
pub async fn write<T: Serialize>(
    io: &mut (impl AsyncWrite + Unpin),
    id: u64,
    value: &T,
) -> Result<()> {
    let (header, body) = codec::encode_frame_parts(id, value)?;
    io.write_all(&header).await?;
    io.write_all(&body).await?;
    Ok(())
}

#[cfg(test)]
#[path = "codec_tests.rs"]
mod tests;
