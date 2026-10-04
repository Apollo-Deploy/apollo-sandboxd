//! Durable aggregate reservation for the two RLIMIT_FSIZE-bounded logs.
use super::{SessionKey, Store};
use crate::{
    error::{Error, Result},
    jailer::VmmResourceLimits,
};
use rusqlite::{OptionalExtension, Transaction, TransactionBehavior, params};
use sandboxd_protocol::{ApiError, ErrorCode, Resources};

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DiagnosticReservation {
    pub session_id: String,
    pub session_uid: u32,
    pub reserved_bytes: u64,
}

impl Store {
    /// Reserve serial plus jailer stderr before either diagnostic file exists.
    /// The immediate transaction makes sum-and-insert atomic across writers.
    pub(crate) fn reserve_diagnostics(
        &mut self,
        uid: u32,
        key: &SessionKey,
        resources: &Resources,
    ) -> Result<()> {
        let intent = self.session_intent(uid, key)?;
        if matches!(
            intent.state,
            sandboxd_protocol::SessionState::Preparing
                | sandboxd_protocol::SessionState::Terminated
        ) {
            return Err(Error::State);
        }
        let per_file = VmmResourceLimits::from_resources(resources)?.file_size_bytes;
        let reserved = per_file.checked_mul(2).ok_or(Error::State)?;
        let max_file_mib = self
            .quotas
            .max_memory_mib
            .max(self.quotas.max_state_disk_mib);
        let per_session_cap = u64::from(max_file_mib)
            .checked_mul(1_048_576)
            .and_then(|value| value.checked_mul(2))
            .ok_or(Error::State)?;
        if reserved > per_session_cap {
            return Err(Error::Config(
                "diagnostics reservation exceeds session quota",
            ));
        }
        let aggregate_cap = per_session_cap
            .checked_mul(u64::from(self.quotas.max_active_sandboxes))
            .ok_or(Error::State)?;
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        let session_uid: Option<u32> = tx
            .query_row(
                "SELECT uid FROM sessions WHERE session_id=?1",
                [key.session.as_str()],
                |row| row.get(0),
            )
            .optional()?;
        if session_uid != Some(intent.uid) {
            return Err(Error::State);
        }
        reserve_row(
            &tx,
            key.session.as_str(),
            intent.uid,
            reserved,
            aggregate_cap,
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn diagnostic_reservations(&self) -> Result<Vec<DiagnosticReservation>> {
        let mut statement = self.connection.prepare(
            "SELECT session_id,session_uid,reserved_bytes FROM diagnostic_reservations ORDER BY session_id",
        )?;
        let rows = statement.query_map([], |row| {
            Ok(DiagnosticReservation {
                session_id: row.get(0)?,
                session_uid: row.get(1)?,
                reserved_bytes: row.get(2)?,
            })
        })?;
        rows.collect::<rusqlite::Result<Vec<_>>>()
            .map_err(Into::into)
    }
}

fn reserve_row(
    tx: &Transaction<'_>,
    session_id: &str,
    uid: u32,
    bytes: u64,
    aggregate_cap: u64,
) -> Result<()> {
    if bytes == 0 || bytes > i64::MAX as u64 || aggregate_cap > i64::MAX as u64 {
        return Err(Error::State);
    }
    let old: Option<(u32, u64)> = tx
        .query_row(
            "SELECT session_uid,reserved_bytes FROM diagnostic_reservations WHERE session_id=?1",
            [session_id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    let used: i64 = tx.query_row(
        "SELECT COALESCE(SUM(reserved_bytes),0) FROM diagnostic_reservations",
        [],
        |row| row.get(0),
    )?;
    let used = u64::try_from(used).map_err(|_| Error::State)?;
    if used > aggregate_cap {
        return Err(Error::State);
    }
    if let Some((old_uid, old_bytes)) = old {
        return if old_uid == uid && old_bytes == bytes {
            Ok(())
        } else {
            Err(Error::State)
        };
    }
    if bytes > aggregate_cap - used {
        return Err(ApiError::new(
            ErrorCode::QuotaExceeded,
            "aggregate diagnostics capacity reached",
        )
        .into());
    }
    tx.execute(
        "INSERT INTO diagnostic_reservations(session_id,session_uid,reserved_bytes) VALUES (?1,?2,?3)",
        params![session_id, uid, i64::try_from(bytes).map_err(|_| Error::State)?],
    )?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::reserve_row;
    use rusqlite::{Connection, TransactionBehavior};

    #[test]
    fn durable_reservation_is_idempotent_and_uses_session_uid() {
        let (_directory, mut store, fence, _) = crate::state::guest_operation_tests::active_store();
        let sandbox = store.inspect(1000, &fence.sandbox).unwrap();
        let (_, intent) = store.runtime_inventory(None, 1).unwrap().pop().unwrap();
        let resources = sandbox.spec.resources;
        store
            .reserve_diagnostics(1000, &intent.key, &resources)
            .unwrap();
        store
            .reserve_diagnostics(1000, &intent.key, &resources)
            .unwrap();
        let reservations = store.diagnostic_reservations().unwrap();
        assert_eq!(reservations.len(), 1);
        assert_eq!(reservations[0].session_uid, intent.uid);
        assert_eq!(reservations[0].reserved_bytes, 512 * 1_048_576);
    }

    fn table(connection: &Connection) {
        connection
            .execute_batch(
                "CREATE TABLE diagnostic_reservations(
                    session_id TEXT PRIMARY KEY, session_uid INTEGER NOT NULL,
                    reserved_bytes INTEGER NOT NULL
                ) STRICT;",
            )
            .unwrap();
    }

    #[test]
    fn aggregate_cap_rejects_max_plus_one() {
        let mut connection = Connection::open_in_memory().unwrap();
        table(&connection);
        for id in ["one", "two", "three"] {
            let tx = connection
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            reserve_row(&tx, id, 1000, 10, 30).unwrap();
            tx.commit().unwrap();
        }
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .unwrap();
        assert!(reserve_row(&tx, "four", 1000, 10, 30).is_err());
        tx.rollback().unwrap();
        assert_eq!(
            connection
                .query_row("SELECT COUNT(*) FROM diagnostic_reservations", [], |row| {
                    row.get::<_, u32>(0)
                })
                .unwrap(),
            3
        );
    }

    #[test]
    fn concurrent_reservations_cannot_overcommit() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("reservations.sqlite3");
        let setup = Connection::open(&path).unwrap();
        table(&setup);
        drop(setup);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let workers = ["left", "right"].map(|id| {
            let path = path.clone();
            let barrier = barrier.clone();
            std::thread::spawn(move || {
                let mut connection = Connection::open(path).unwrap();
                connection
                    .busy_timeout(std::time::Duration::from_secs(2))
                    .unwrap();
                barrier.wait();
                let tx = connection
                    .transaction_with_behavior(TransactionBehavior::Immediate)
                    .unwrap();
                let result = reserve_row(&tx, id, 1000, 11, 20);
                if result.is_ok() {
                    tx.commit().unwrap();
                }
                result.is_ok()
            })
        });
        barrier.wait();
        let admitted = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .filter(|admitted| *admitted)
            .count();
        assert_eq!(admitted, 1);
        let connection = Connection::open(path).unwrap();
        assert_eq!(
            connection
                .query_row(
                    "SELECT SUM(reserved_bytes) FROM diagnostic_reservations",
                    [],
                    |row| row.get::<_, u64>(0)
                )
                .unwrap(),
            11
        );
    }
}
