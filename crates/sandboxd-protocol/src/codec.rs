//! A fixed-size header is validated before any body allocation. Unknown flags fail closed.
use crate::{MAX_FRAME_BYTES, PROTOCOL_VERSION};
use serde::{Serialize, de::DeserializeOwned};
use std::io::{Cursor, Read, Write};

pub const HEADER_BYTES: usize = 20;
pub const MAGIC: [u8; 4] = *b"ASD\0";

#[derive(Debug, thiserror::Error)]
pub enum CodecError {
    #[error("invalid or unsupported frame header")]
    Header,
    #[error("frame body exceeds size limit")]
    Limit,
    #[error("invalid encoded body")]
    Body,
    #[error("frame IO failed")]
    Io(#[from] std::io::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Header {
    pub request_id: u64,
    pub body_len: u32,
}
impl Header {
    pub fn encode(self) -> Result<[u8; HEADER_BYTES], CodecError> {
        if self.body_len == 0 || self.body_len as usize > MAX_FRAME_BYTES {
            return Err(CodecError::Limit);
        }
        let mut bytes = [0; HEADER_BYTES];
        bytes[..4].copy_from_slice(&MAGIC);
        bytes[4..6].copy_from_slice(&PROTOCOL_VERSION.to_be_bytes());
        bytes[8..12].copy_from_slice(&self.body_len.to_be_bytes());
        bytes[12..20].copy_from_slice(&self.request_id.to_be_bytes());
        Ok(bytes)
    }
    pub fn decode(bytes: [u8; HEADER_BYTES]) -> Result<Self, CodecError> {
        Self::decode_limited(bytes, MAX_FRAME_BYTES)
    }
    /// Wire bounds and the caller's stricter policy are checked before allocation.
    pub fn decode_limited(bytes: [u8; HEADER_BYTES], limit: usize) -> Result<Self, CodecError> {
        if bytes[..4] != MAGIC
            || u16::from_be_bytes([bytes[4], bytes[5]]) != PROTOCOL_VERSION
            || bytes[6..8] != [0, 0]
        {
            return Err(CodecError::Header);
        }
        let len = u32::from_be_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
        if len == 0 || len as usize > MAX_FRAME_BYTES.min(limit) {
            return Err(CodecError::Limit);
        }
        let request_id =
            u64::from_be_bytes(bytes[12..20].try_into().map_err(|_| CodecError::Header)?);
        Ok(Self {
            request_id,
            body_len: len,
        })
    }
}

struct LimitedWriter(Vec<u8>);
impl Write for LimitedWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        if bytes.len() > MAX_FRAME_BYTES.saturating_sub(self.0.len()) {
            return Err(std::io::Error::other("frame size limit"));
        }
        self.0.extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

pub fn encode_body<T: Serialize>(value: &T) -> Result<Vec<u8>, CodecError> {
    let mut writer = LimitedWriter(Vec::new());
    ciborium::into_writer(value, &mut writer).map_err(|_| CodecError::Limit)?;
    Ok(writer.0)
}
pub fn decode_body<T: DeserializeOwned>(bytes: &[u8]) -> Result<T, CodecError> {
    if bytes.is_empty() || bytes.len() > MAX_FRAME_BYTES {
        return Err(CodecError::Limit);
    }
    crate::cbor::validate(bytes)?;
    let mut cursor = Cursor::new(bytes);
    let value = ciborium::de::from_reader_with_recursion_limit(&mut cursor, 32)
        .map_err(|_| CodecError::Body)?;
    if cursor.position() != bytes.len() as u64 {
        return Err(CodecError::Body);
    }
    Ok(value)
}
pub fn write_frame<T: Serialize>(mut io: impl Write, id: u64, value: &T) -> Result<(), CodecError> {
    let (header, body) = encode_frame_parts(id, value)?;
    io.write_all(&header)?;
    io.write_all(&body)?;
    Ok(())
}
pub fn read_frame<T: DeserializeOwned>(mut io: impl Read) -> Result<(u64, T), CodecError> {
    read_frame_limited(&mut io, MAX_FRAME_BYTES)
}
pub fn read_frame_limited<T: DeserializeOwned>(
    mut io: impl Read,
    limit: usize,
) -> Result<(u64, T), CodecError> {
    let mut header = [0; HEADER_BYTES];
    io.read_exact(&mut header)?;
    let header = Header::decode_limited(header, limit)?;
    let mut body = vec![0; header.body_len as usize];
    io.read_exact(&mut body)?;
    Ok((header.request_id, decode_body(&body)?))
}

pub fn encode_frame_parts<T: Serialize>(
    id: u64,
    value: &T,
) -> Result<([u8; HEADER_BYTES], Vec<u8>), CodecError> {
    let body = encode_body(value)?;
    let header = Header {
        request_id: id,
        body_len: u32::try_from(body.len()).map_err(|_| CodecError::Limit)?,
    }
    .encode()?;
    Ok((header, body))
}
