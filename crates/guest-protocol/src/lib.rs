//! Guest-originated information is advisory. No message grants host filesystem authority.
pub mod exec;
pub mod files;
pub mod handshake;
pub mod message;
pub mod status;
pub mod wire;
pub use exec::*;
pub use files::*;
pub use handshake::*;
pub use message::*;
pub use status::*;
pub const GUEST_PROTOCOL_VERSION: u16 = 1;
pub const GUEST_PORT: u32 = 1024;
