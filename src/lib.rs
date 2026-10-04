//! Standalone host components. Runtime execution is never substituted with host processes.
pub mod api;
pub mod config;
mod config_execution;
pub mod doctor;
pub mod error;
pub mod exec;
pub mod guest;
pub mod image;
pub mod jailer;
pub mod network;
pub mod process;
pub mod runtime;
pub mod security;
pub mod session;
pub mod snapshot;
pub mod state;
pub mod storage;
pub(crate) mod volume_catalog;
