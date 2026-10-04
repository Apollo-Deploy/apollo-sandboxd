//! Capture-time exec journals are bound to the encrypted VM manifest.
use super::runtime_service::{LiveVm, RuntimeService};
use crate::{
    error::{Error, Result},
    exec::ExecEventRouter,
    state::{LaunchIntent, snapshot::SnapshotIntent},
};
use std::{path::PathBuf, sync::Arc};
impl RuntimeService {
    pub(super) fn session_output_root(&self, intent: &LaunchIntent) -> PathBuf {
        self.config
            .state
            .directory
            .join("output")
            .join(intent.key.sandbox.as_str())
            .join(format!(
                "g{}-s{}",
                intent.key.sandbox_generation.get(),
                intent.key.generation.get()
            ))
    }
    pub(super) async fn capture_snapshot_output(
        &self,
        vm: &Arc<LiveVm>,
        intent: &SnapshotIntent,
    ) -> Result<String> {
        let root = self.config.state.directory.join("snapshot-output");
        let router = vm.exec_router.clone();
        let state = self.state.clone();
        let saved = intent.clone();
        tokio::task::spawn_blocking(move || {
            let output =
                router.snapshot_capture(&root, saved.command.id(), 256 << 20, &mut |output| {
                    let (uid, op, output) = (saved.uid, saved.operation.clone(), output.clone());
                    state.with_store_blocking(move |store| {
                        store.snapshot_update(uid, &op, |intent| {
                            intent.record.output = Some(output);
                            Ok(())
                        })?;
                        Ok(())
                    })
                })?;
            Ok(hex::encode(output.digest))
        })
        .await
        .map_err(|_| Error::State)?
    }
    pub(super) async fn restore_snapshot_output(
        &self,
        intent: &SnapshotIntent,
        restored: &LaunchIntent,
        digest: &str,
    ) -> Result<()> {
        let output = intent.record.output.clone().ok_or(Error::State)?;
        if hex::encode(output.digest) != digest {
            return Err(Error::State);
        }
        let root = self.session_output_root(restored);
        let state = self.state.clone();
        let (uid, operation) = (intent.uid, intent.operation.clone());
        tokio::task::spawn_blocking(move || {
            ExecEventRouter::snapshot_restore_journaled(&output, &root, &mut |record| {
                let (operation, record) = (operation.clone(), record.clone());
                state.with_store_blocking(move |store| {
                    store.snapshot_update(uid, &operation, |intent| {
                        intent.restored_output = Some(record);
                        Ok(())
                    })?;
                    Ok(())
                })
            })
        })
        .await
        .map_err(|_| Error::State)?
    }
}
