//! Bounded sandboxd-to-guest transport over Firecracker vsock UDS proxies.

mod endpoint;
mod framing;
mod transport;

pub use endpoint::GuestEndpoint;
pub use transport::{GuestConnection, GuestPeer};
