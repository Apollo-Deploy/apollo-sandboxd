use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    UnsupportedHost,
    UnsupportedCapability,
    KvmUnavailable,
    RuntimeProfileInvalid,
    ImageNotFound,
    ImageDigestMismatch,
    ImageImportFailed,
    SandboxNotFound,
    StaleGeneration,
    OperationConflict,
    OperationOutOfOrder,
    OperationReceiptUnavailable,
    LeaseExpired,
    LeaseMismatch,
    SessionUnavailable,
    GuestHandshakeFailed,
    GuestProtocolMismatch,
    ExecNotFound,
    ExecTimeout,
    ExecFailed,
    OutputSinkFailed,
    FileTransferFailed,
    NetworkAttachmentInvalid,
    VolumeInvalid,
    SnapshotNotFound,
    SnapshotIncompatible,
    SnapshotIntegrityFailed,
    SecretSnapshotForbidden,
    ResourceLimitInvalid,
    QuotaExceeded,
    RecoveryFailed,
    InvalidRequest,
    RequestTimeout,
    Unauthorized,
    StorageFailed,
    ProtocolMismatch,
    Internal,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize, thiserror::Error)]
#[error("{code:?}: {message}")]
#[serde(deny_unknown_fields)]
pub struct ApiError {
    pub code: ErrorCode,
    /// Static/context-safe description. Never include caller secrets or raw guest data.
    pub message: String,
}
impl ApiError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
        }
    }
}
