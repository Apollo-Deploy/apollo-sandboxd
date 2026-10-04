//! Execution output persistence.
mod bridge;
mod journal;
mod journal_replay;
mod router;
mod router_restore;
mod sink;
mod snapshot;
mod transport;

pub use bridge::ExecOutputBridge;
pub use journal::{JournalItem, JournalPage, OutputJournal};
pub use router::ExecEventRouter;
pub use sink::OutputSink;
pub use snapshot::{OutputSnapshotRecord, SnapshotOutput};

#[cfg(test)]
mod journal_tests;

#[cfg(test)]
mod transport_tests;

#[cfg(test)]
#[path = "router_snapshot_tests.rs"]
mod router_snapshot_tests;
