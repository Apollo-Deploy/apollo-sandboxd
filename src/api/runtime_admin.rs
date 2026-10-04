//! Offline administrative recovery over one exact durable store.

use super::{handlers::now_ms, runtime_service::RuntimeService};
use crate::error::{Error, Result};
use sandboxd_protocol::SessionId;

impl RuntimeService {
    /// Admit and clean only the durable session selected by its globally unique ID.
    pub(super) async fn cleanup_exact_owned(&self, session_id: SessionId) -> Result<()> {
        let (uid, intent) = self
            .state
            .with_store(move |store| store.admit_admin_stop_for_session(&session_id, now_ms()?))
            .await?;
        self.cleanup_untracked(uid, &intent.key).await
    }

    /// Stop sessions discovered through the configured durable store.
    ///
    /// Every effect still passes through recovery's process, resource, artifact,
    /// and path identity checks. A failure stops the scan so a later invocation
    /// can resume from durable state without weakening ownership requirements.
    pub(super) async fn cleanup_all_owned(&self) -> Result<()> {
        let mut after = None;
        let mut inspected = 0usize;
        loop {
            let cursor = after.clone();
            let page = self
                .state
                .with_store(move |store| store.runtime_inventory(cursor.as_ref(), 256))
                .await?;
            if page.is_empty() {
                return Ok(());
            }
            for (uid, intent) in page {
                after = Some(intent.key.sandbox.clone());
                inspected = inspected.checked_add(1).ok_or(Error::State)?;
                if inspected > self.config.quotas.max_sandbox_identities as usize {
                    return Err(Error::Config(
                        "durable cleanup inventory exceeds sandbox identity quota",
                    ));
                }
                let key = intent.key.clone();
                self.state
                    .with_store(move |store| store.admit_admin_stop(uid, &key, now_ms()?))
                    .await?;
                self.cleanup_untracked(uid, &intent.key).await?;
            }
        }
    }
}
