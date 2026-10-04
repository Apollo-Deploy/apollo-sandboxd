//! Internal bounded recovery inventory. Caller APIs remain principal scoped.
use super::{LaunchIntent, SessionKey, Store, session};
use crate::error::{Error, Result};
use rusqlite::{TransactionBehavior, params};
use sandboxd_protocol::{
    ApiError, ErrorCode, EventKind, Response, SandboxId, SandboxState, SessionId, SessionState,
    codec,
};

impl Store {
    /// Find and admit an administrative stop for one exact durable session.
    /// The caller runs this callback on the exclusive Store owner, so lookup
    /// and admission cannot be separated by another state operation.
    pub(crate) fn admit_admin_stop_for_session(
        &mut self,
        session_id: &SessionId,
        now: u64,
    ) -> Result<(u32, LaunchIntent)> {
        let columns = session::COLUMNS
            .split(',')
            .map(|name| format!("s.{}", name.trim()))
            .collect::<Vec<_>>()
            .join(",");
        let selected = {
            let mut statement = self.connection.prepare(&format!(
                "SELECT {columns}, b.owner_uid FROM sessions s
                 LEFT JOIN sandboxes b ON s.sandbox=b.id WHERE s.session_id=?1"
            ))?;
            let mut rows = statement.query([session_id.as_str()])?;
            rows.next()?
                .map(|row| {
                    let intent = session::decode(row)?;
                    let owner_uid: Option<u32> = row.get(8)?;
                    Ok::<_, Error>((owner_uid, intent))
                })
                .transpose()?
        };
        let (owner_uid, intent) = match selected {
            None => return Err(Error::Config("requested cleanup session not found")),
            Some((None, _)) => return Err(Error::State),
            Some((Some(owner_uid), intent)) => (owner_uid, intent),
        };
        if intent.key.session != *session_id {
            return Err(Error::State);
        }
        self.admit_admin_stop(owner_uid, &intent.key, now)?;
        Ok((owner_uid, intent))
    }

    pub(crate) fn runtime_inventory(
        &self,
        after: Option<&SandboxId>,
        limit: u16,
    ) -> Result<Vec<(u32, LaunchIntent)>> {
        if limit == 0 || limit > 256 {
            return Err(Error::State);
        }
        let columns = session::COLUMNS
            .split(',')
            .map(|name| format!("s.{}", name.trim()))
            .collect::<Vec<_>>()
            .join(",");
        let mut statement =
            self.connection
                .prepare(&format!(
            "SELECT {columns}, b.owner_uid FROM sessions s JOIN sandboxes b ON s.sandbox=b.id
            WHERE s.sandbox>?1 ORDER BY s.sandbox LIMIT ?2"))?;
        let mut rows = statement.query(params![after.map_or("", SandboxId::as_str), limit])?;
        let mut result = Vec::new();
        while let Some(row) = rows.next()? {
            let intent = session::decode(row)?;
            let owner = row.get(8)?;
            result.push((owner, intent));
        }
        Ok(result)
    }

    /// A failure retains allocations until kernel cleanup has been proved.
    pub(crate) fn runtime_failed(&mut self, uid: u32, key: &SessionKey, now: u64) -> Result<()> {
        let mut intent = self.session_intent(uid, key)?;
        // Preserve an admitted cleanup intent across a secondary failure.
        // Its receipt and ownership remain valid until verified teardown.
        if intent.state == SessionState::Terminating
            && self
                .pending_session_control(uid, key)?
                .is_some_and(|pending| pending.control == sandboxd_protocol::SessionControl::Stop)
        {
            return Ok(());
        }
        if intent.state == SessionState::Failed {
            return Ok(());
        }
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let mut record = super::control_observe::current_for_update(&tx, uid, key)?;
        intent.state = SessionState::Failed;
        record.state = SandboxState::Failed;
        record.session.as_mut().ok_or(Error::State)?.state = SessionState::Failed;
        tx.execute(
            "UPDATE sessions SET record=?1 WHERE session_id=?2",
            params![codec::encode_body(&intent)?, key.session.as_str()],
        )?;
        tx.execute(
            "UPDATE sandboxes SET record=?1 WHERE id=?2",
            params![codec::encode_body(&record)?, key.sandbox.as_str()],
        )?;
        super::session_control::complete_start_receipt(
            &tx,
            uid,
            key,
            &Response::Error(ApiError::new(
                ErrorCode::RecoveryFailed,
                "session start failed before guest readiness",
            )),
        )?;
        super::events::append(&tx, uid, &record, EventKind::RecoveryFailed, now)?;
        super::events::trim(&tx, self.event_retention)?;
        tx.commit()?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::IdentityPools,
        state::{
            CleanupObservations, CleanupProof, SessionControlContext, SessionKey,
            SessionPreparation, checkpoint_tests, guest_operation_tests,
        },
    };
    use sandboxd_protocol::{Fence, Mutation, OperationId, Response, SessionControl};

    fn add_preparing_session(
        store: &mut Store,
        base: &LaunchIntent,
        sandbox_id: &str,
        now: u64,
    ) -> SessionKey {
        let spec = store
            .inspect(1000, &base.key.sandbox)
            .expect("base sandbox")
            .spec;
        let record = match store
            .mutate(
                1000,
                &OperationId::new(format!("create-{sandbox_id}")).expect("operation"),
                &Mutation::Create {
                    sandbox: SandboxId::new(sandbox_id).expect("sandbox id"),
                    expected_generation: None,
                    spec: Box::new(spec),
                    lease_seconds: 3600,
                },
                now,
            )
            .expect("create second sandbox")
        {
            Response::Sandbox(record) => *record,
            _ => panic!("sandbox creation response"),
        };
        let prepared = store
            .prepare_session(
                1000,
                &OperationId::new(format!("prepare-{sandbox_id}")).expect("operation"),
                &Fence {
                    sandbox: record.id.clone(),
                    generation: record.generation,
                    session_generation: None,
                    lease: record.lease.id,
                },
                SessionPreparation {
                    pins: &base.pins,
                    pools: &IdentityPools {
                        uid_first: 200_000,
                        uid_last: 200_001,
                        gid_first: 300_000,
                        gid_last: 300_001,
                        cid_first: 3,
                        cid_last: 4,
                    },
                    host_boot_id: "00000000-0000-4000-8000-000000000001",
                    now_ms: now + 1,
                },
            )
            .expect("prepare second session");
        prepared.intent.expect("session intent").key
    }

    #[test]
    fn exact_cleanup_admits_only_the_requested_session_in_a_shared_store() {
        let (_directory, mut store, fence) = checkpoint_tests::fixture();
        let base_record = store.inspect(1000, &fence.sandbox).expect("base sandbox");
        let base_session = base_record.session.expect("base session");
        let target_key = SessionKey {
            sandbox: base_record.id,
            sandbox_generation: base_record.generation,
            session: base_session.id,
            generation: base_session.generation,
        };
        let base_intent = store
            .session_intent(1000, &target_key)
            .expect("base intent");
        let other_key = add_preparing_session(&mut store, &base_intent, "other-sandbox", 1200);

        let (uid, admitted) = store
            .admit_admin_stop_for_session(&target_key.session, 1300)
            .expect("admit exact session");

        assert_eq!(uid, 1000);
        assert_eq!(admitted.key, target_key);
        assert_eq!(
            store
                .session_intent(1000, &target_key)
                .expect("target")
                .state,
            SessionState::Terminating
        );
        assert_eq!(
            store.session_intent(1000, &other_key).expect("other").state,
            SessionState::Preparing
        );
        assert!(
            store
                .pending_session_control(1000, &other_key)
                .expect("other pending control")
                .is_none()
        );
    }

    #[test]
    fn missing_exact_cleanup_id_fails_before_session_admission() {
        let (_directory, mut store, fence) = checkpoint_tests::fixture();
        let record = store.inspect(1000, &fence.sandbox).expect("sandbox");
        let session = record.session.expect("session");
        let key = SessionKey {
            sandbox: record.id,
            sandbox_generation: record.generation,
            session: session.id,
            generation: session.generation,
        };

        let error = store
            .admit_admin_stop_for_session(&SessionId::new("missing-session").unwrap(), 1300)
            .expect_err("unknown ID must fail closed");

        assert!(matches!(
            error,
            Error::Config("requested cleanup session not found")
        ));
        assert_eq!(
            store
                .session_intent(1000, &key)
                .expect("unchanged session")
                .state,
            SessionState::Active
        );
        assert!(
            store
                .pending_session_control(1000, &key)
                .expect("pending control")
                .is_none()
        );
    }

    #[test]
    fn failed_start_replay_returns_the_terminal_failure_receipt() {
        let (_directory, mut store, old_fence, _) = guest_operation_tests::active_store();
        let old_session = store
            .inspect(1000, &old_fence.sandbox)
            .expect("sandbox")
            .session
            .expect("old session");
        let old_key = SessionKey {
            sandbox: old_fence.sandbox.clone(),
            sandbox_generation: old_fence.generation,
            session: old_session.id,
            generation: old_session.generation,
        };
        let old_intent = store.session_intent(1000, &old_key).expect("old intent");
        let resources = store
            .inspect(1000, &old_fence.sandbox)
            .expect("sandbox")
            .spec
            .resources;
        store
            .reserve_diagnostics(1000, &old_key, &resources)
            .expect("reserve diagnostics");
        store
            .admit_admin_stop(1000, &old_key, 1_100)
            .expect("stop old session");
        assert!(
            store
                .record_session_stopped(
                    1000,
                    &old_key,
                    CleanupProof::incomplete(old_key.clone()),
                    1_100,
                )
                .is_err(),
            "incomplete cleanup must retain the disk reservation"
        );
        assert_eq!(store.diagnostic_reservations().unwrap().len(), 1);
        store
            .record_session_stopped(
                1000,
                &old_key,
                CleanupProof::new(
                    old_key.clone(),
                    CleanupObservations {
                        process_absent: true,
                        staged_jail_absent: true,
                        cgroup_absent: true,
                        jail_root_absent: true,
                        sockets_absent: true,
                        diagnostics_absent: true,
                    },
                ),
                1_101,
            )
            .expect("release old session");
        assert!(store.diagnostic_reservations().unwrap().is_empty());

        let stopped = store
            .inspect(1000, &old_fence.sandbox)
            .expect("stopped sandbox");
        let start_fence = Fence {
            sandbox: stopped.id.clone(),
            generation: stopped.generation,
            session_generation: None,
            lease: stopped.lease.id,
        };
        let operation = OperationId::new("failed-start-replay").expect("operation");
        let pins = old_intent.pins.clone();
        let pools = IdentityPools {
            uid_first: 200_000,
            uid_last: 200_001,
            gid_first: 300_000,
            gid_last: 300_001,
            cid_first: 3,
            cid_last: 4,
        };
        let admitted = store
            .begin_session_control(
                1000,
                &operation,
                &start_fence,
                SessionControl::Start,
                SessionControlContext {
                    pins: Some(&pins),
                    pools: &pools,
                    host_boot_id: &old_intent.host_boot_id,
                    now_ms: 1_200,
                },
            )
            .expect("admit new start");
        let key = admitted.key.expect("new session key");
        store
            .runtime_failed(1000, &key, 1_300)
            .expect("persist start failure");

        let replay = store
            .replay_session_control(1000, &operation, &start_fence, SessionControl::Start)
            .expect("replay lookup")
            .expect("stored receipt");
        assert!(matches!(
            replay.response,
            Response::Error(error) if error.code == sandboxd_protocol::ErrorCode::RecoveryFailed
        ));
        assert_eq!(
            store
                .session_intent(1000, &key)
                .expect("failed session")
                .state,
            SessionState::Failed
        );
    }
}
