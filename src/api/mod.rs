pub(crate) mod ancillary;
pub mod client;
mod codec;
mod handlers;
#[cfg(test)]
mod handlers_tests;
mod runtime_admin;
mod runtime_authority;
mod runtime_boot;
mod runtime_checkpoint;
mod runtime_checkpoint_create;
mod runtime_checkpoint_recover;
mod runtime_cleanup;
mod runtime_control;
mod runtime_exec_identity;
#[cfg(target_os = "linux")]
mod runtime_filesystem_export;
mod runtime_guest;
mod runtime_image;
mod runtime_journal;
mod runtime_policy;
pub mod runtime_queue;
mod runtime_recover;
mod runtime_service;
mod runtime_volume;
mod runtime_watch;
pub mod runtime_worker;
mod server;
mod socket;
mod socket_namespace;
mod state_worker;
pub use server::{cleanup_owned_sessions, serve, serve_with_runtime};

pub(crate) fn socket_preflight(config: &crate::config::Daemon) -> crate::error::Result<()> {
    let parent = config.socket.parent().ok_or(crate::error::Error::Path)?;
    socket_namespace::preflight(&crate::security::path::SecureDir::open(parent)?)
}

mod runtime_snapshot;
mod runtime_snapshot_capture;
mod runtime_snapshot_cleanup;
mod runtime_snapshot_compatibility;
mod runtime_snapshot_output;
mod runtime_snapshot_recover;
mod runtime_snapshot_restore;

mod response_transport;
