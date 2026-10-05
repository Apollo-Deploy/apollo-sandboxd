//! Owner-scoped durable receipt metadata. Inspection never transfers descriptors.
use crate::{OperationId, Response};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OperationReceiptState {
    Pending,
    Complete,
    /// No retained receipt; the sequence is at or below the owner's watermark.
    Unavailable,
    /// No receipt and the sequence is above the owner's watermark. Not retry authority.
    Unknown,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OperationReceipt {
    pub operation: OperationId,
    pub operation_sequence: u64,
    pub accepted_sequence: u64,
    pub state: OperationReceiptState,
    /// Opaque server-normalized SHA-256, not a client's semantic request hash.
    pub request_digest: Option<String>,
    /// Saved public response metadata only, including for filesystem exports.
    pub response: Option<Box<Response>>,
}
