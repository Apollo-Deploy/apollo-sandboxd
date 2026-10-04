//! One daemon-wide bounded policy scan; effects share the lifecycle scheduler.
use super::{handlers::now_ms, runtime_service::RuntimeService};
use crate::{
    error::{Error, Result},
    state::SessionKey,
};
use sandboxd_protocol::SessionControl;
use std::sync::{Arc, atomic::Ordering};

struct ScanGuard(Arc<RuntimeService>);
impl Drop for ScanGuard {
    fn drop(&mut self) {
        self.0.policy_running.store(false, Ordering::Release);
    }
}
struct EffectGuard {
    runtime: Arc<RuntimeService>,
    key: SessionKey,
}
impl Drop for EffectGuard {
    fn drop(&mut self) {
        if let Ok(mut pending) = self.runtime.policy_pending.lock()
            && pending.get(&self.key.sandbox) == Some(&self.key)
        {
            pending.remove(&self.key.sandbox);
        }
    }
}

impl RuntimeService {
    pub fn tick_policy(self: &Arc<Self>) {
        if self
            .policy_running
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let runtime = Arc::clone(self);
        tokio::spawn(async move {
            let _guard = ScanGuard(Arc::clone(&runtime));
            if let Err(error) = runtime.scan_policy().await {
                eprintln!("runtime policy scan failed: {error}");
            }
        });
    }

    async fn scan_policy(self: &Arc<Self>) -> Result<()> {
        let mut stops = self.observed_failures().await?;
        stops.extend(
            self.state
                .with_store(|store| {
                    let now = now_ms()?;
                    // Runtime intent precedes generic stopped-sandbox lease bookkeeping.
                    let stops = store.admit_expired_session_stops(now, 256)?;
                    store.expire_leases(now)?;
                    Ok(stops)
                })
                .await?,
        );
        for stop in stops {
            {
                let mut pending = self.policy_pending.lock().map_err(|_| Error::State)?;
                if pending.contains_key(&stop.key.sandbox) {
                    continue;
                }
                if pending.len() >= self.config.quotas.max_active_sandboxes as usize {
                    return Err(Error::State);
                }
                pending.insert(stop.key.sandbox.clone(), stop.key.clone());
            }
            let sandbox = stop.key.sandbox.clone();
            let guard = EffectGuard {
                runtime: Arc::clone(self),
                key: stop.key.clone(),
            };
            let effect = async move {
                let result = guard
                    .runtime
                    .apply_existing(stop.owner_uid, &stop.key, SessionControl::Stop)
                    .await;
                if let Err(error) = &result {
                    eprintln!("expiry stop effect failed: {error}");
                }
                drop(guard);
                result
            };
            // Admission failure drops the guard; the durable pending intent is scanned again.
            match self.queue.submit(sandbox, effect).await {
                Ok(receive) => drop(receive),
                Err(error) => return Err(error),
            }
        }
        Ok(())
    }
}
