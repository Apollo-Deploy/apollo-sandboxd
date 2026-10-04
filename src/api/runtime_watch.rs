//! One bounded host scan; no persistent thread or timer for each VM.
use super::{handlers::now_ms, runtime_service::RuntimeService};
use crate::{error::Result, state::ExpiredStop};
use sandboxd_protocol::EventKind;

impl RuntimeService {
    pub(super) async fn observed_failures(&self) -> Result<Vec<ExpiredStop>> {
        let sessions: Vec<_> = self.live.lock().await.values().cloned().collect();
        let mut stops = Vec::new();
        for vm in sessions {
            let reason = if vm.process.has_exited()? {
                Some(EventKind::VmmCrashed)
            } else if vm
                .guest
                .lock()
                .await
                .as_ref()
                .is_some_and(|guest| guest.is_closed())
            {
                Some(EventKind::GuestAgentLost)
            } else {
                None
            };
            if let Some(reason) = reason {
                let (uid, key) = (vm.owner, vm.intent.key.clone());
                match self
                    .state
                    .with_store(move |store| store.admit_runtime_loss(uid, &key, reason, now_ms()?))
                    .await
                {
                    Ok(stop) => stops.push(stop),
                    // Cleanup may have committed between observation and admission.
                    Err(error) => eprintln!("runtime failure observation rejected: {error}"),
                }
            }
        }
        Ok(stops)
    }
}
