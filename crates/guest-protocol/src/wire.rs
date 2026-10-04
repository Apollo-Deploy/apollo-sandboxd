//! Guest transport framing. It deliberately reuses the bounded canonical frame
//! codec used by the host protocol so a guest cannot request an unbounded body.
use serde::{Serialize, de::DeserializeOwned};
use std::io::{Read, Write};

pub const MAX_FRAME_BYTES: usize = sandboxd_protocol::MAX_FRAME_BYTES;
pub type WireError = sandboxd_protocol::codec::CodecError;

pub fn read<T: DeserializeOwned>(reader: impl Read) -> Result<(u64, T), WireError> {
    sandboxd_protocol::codec::read_frame_limited(reader, MAX_FRAME_BYTES)
}

pub fn write<T: Serialize>(
    writer: impl Write,
    request_id: u64,
    value: &T,
) -> Result<(), WireError> {
    sandboxd_protocol::codec::write_frame(writer, request_id, value)
}
