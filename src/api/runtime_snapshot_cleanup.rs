//! Failed captures release only durably journaled owned artifacts.
use super::runtime_service::RuntimeService;
use crate::{
    error::{Error, Result},
    state::snapshot::SnapshotIntent,
};
impl RuntimeService {
    pub(super) async fn discard_snapshot_capture(&self, intent: &SnapshotIntent) -> Result<()> {
        let (uid, op) = (intent.uid, intent.operation.clone());
        let saved = self
            .state
            .with_store(move |store| store.snapshot_update(uid, &op, |_| Ok(())))
            .await?;
        let catalog = self.snapshots.clone().ok_or(Error::State)?;
        let checkpoints = self.checkpoints.clone();
        tokio::task::spawn_blocking(move || {
            if let Some(artifacts) = &saved.record.artifacts {
                catalog.delete(artifacts)?;
            }
            if let Some(output) = &saved.record.output {
                crate::exec::ExecEventRouter::snapshot_delete(output)?;
            }
            if let Some(stage) = &saved.checkpoint_stage {
                checkpoints.cleanup_stage(stage)?;
            }
            checkpoints.delete(&saved.record.checkpoint)
        })
        .await
        .map_err(|_| Error::State)?
    }
}
