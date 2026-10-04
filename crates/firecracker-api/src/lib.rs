//! Explicit v1.17 Firecracker Unix HTTP contract. No subprocess/curl integration.
pub mod client;
pub mod devices;
pub mod http;
pub mod snapshot;
pub use client::Client;
pub use devices::*;
pub use snapshot::*;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Firecracker socket IO failed")]
    Io(#[from] std::io::Error),
    #[error("Firecracker request timed out")]
    Timeout,
    #[error("invalid or oversized Firecracker response")]
    Response,
    #[error("Firecracker rejected request with HTTP status {0}")]
    Status(u16),
    #[error("invalid Firecracker request")]
    Request,
}
