//! Receipt retirement owns cleanup acknowledgement and retry authority.
use guest_protocol::GuestMessage;
use sandboxd_protocol::OperationId;
use std::{collections::HashMap, fs::File};

pub(super) fn retire(
    state: Option<&File>,
    operations: &mut HashMap<OperationId, ([u8; 32], GuestMessage)>,
    target: &OperationId,
) -> GuestMessage {
    let Some((_, receipt)) = operations.get(target) else {
        return GuestMessage::Error {
            code: "operation receipt not found".into(),
        };
    };
    if matches!(receipt, GuestMessage::FilesystemExportReady { .. }) {
        let Some(state) = state else {
            return GuestMessage::Error {
                code: "filesystem export retirement unavailable".into(),
            };
        };
        if crate::filesystem_export::retire(state, target).is_err() {
            return GuestMessage::Error {
                code: "filesystem export retirement failed".into(),
            };
        }
    }
    operations.remove(target);
    GuestMessage::Ready
}

#[cfg(test)]
#[path = "supervisor_retirement_tests.rs"]
mod tests;
