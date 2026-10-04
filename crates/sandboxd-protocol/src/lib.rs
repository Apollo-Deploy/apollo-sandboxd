//! Versioned local control contract. No host paths grant guest filesystem authority.
mod cbor;
pub mod checkpoint;
pub mod codec;
pub mod error;
pub mod exec;
pub mod files;
pub mod guest;
pub mod identity;
pub mod image;
pub mod request;
pub mod spec;
pub mod state;
mod validation;
pub use checkpoint::*;
pub use error::{ApiError, ErrorCode};
pub use guest::*;
pub use identity::*;
pub use image::*;
pub use request::*;
pub use spec::*;
pub use state::*;

pub const PROTOCOL_VERSION: u16 = 1;
pub const MAX_FRAME_BYTES: usize = 1_048_576;
pub const MAX_DATA_BYTES: usize = 65_536;

mod snapshot;
pub use snapshot::{SnapshotCommand, SnapshotInfo, SnapshotSecretPolicy};
