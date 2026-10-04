use guest_protocol::{GuestEnvelope, GuestMessage, SessionIdentity};
use std::io::{Read, Write};

pub const BOOT_OPERATION: &str = "guest-boot";

pub fn read<R: Read>(reader: R) -> Result<(u64, GuestEnvelope), ProtocolError> {
    guest_protocol::wire::read(reader).map_err(ProtocolError::Frame)
}

pub fn write<W: Write>(writer: W, id: u64, envelope: &GuestEnvelope) -> Result<(), ProtocolError> {
    guest_protocol::wire::write(writer, id, envelope).map_err(ProtocolError::Frame)
}

pub fn envelope(
    identity: &SessionIdentity,
    operation: sandboxd_protocol::OperationId,
    message: GuestMessage,
) -> GuestEnvelope {
    GuestEnvelope {
        identity: identity.clone(),
        operation,
        message,
    }
}

#[derive(Debug, thiserror::Error)]
pub enum ProtocolError {
    #[error("guest frame error: {0}")]
    Frame(#[source] guest_protocol::wire::WireError),
}
