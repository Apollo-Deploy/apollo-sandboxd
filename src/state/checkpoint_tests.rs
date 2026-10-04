use super::{SessionKey, Store, checkpoint::*, guest_operation_tests::active_store};
use crate::{config::CheckpointLimits, storage::DriveIdentity};
use rusqlite::params;
use sandboxd_protocol::{
    ApiError, CheckpointCommand, ErrorCode, Fence, OperationId, Response, codec,
};
use sandboxd_protocol::{CheckpointId, Mutation, SessionState};

pub(super) fn fixture() -> (tempfile::TempDir, Store, Fence) {
    let (directory, mut store, fence, _) = active_store();
    let record = store.inspect(1000, &fence.sandbox).unwrap();
    let session = record.session.unwrap();
    let key = SessionKey {
        sandbox: fence.sandbox.clone(),
        sandbox_generation: fence.generation,
        session: session.id,
        generation: session.generation,
    };
    let mut intent = store.session_intent(1000, &key).unwrap();
    intent.state = SessionState::JailerStarting;
    store
        .connection
        .execute(
            "UPDATE sessions SET record=?1 WHERE session_id=?2",
            params![codec::encode_body(&intent).unwrap(), key.session.as_str()],
        )
        .unwrap();
    let drive = store.plan_state_drive(1000, &key).unwrap();
    let owner = drive.pending_owner.unwrap();
    let identity = DriveIdentity {
        device: 1,
        inode: 1234,
        size: drive.size,
        uid: owner.uid,
        gid: owner.gid,
    };
    store.record_prepared_drive(1000, &key, identity).unwrap();
    store.record_published_drive(1000, &key, identity).unwrap();
    intent.state = SessionState::Active;
    store
        .connection
        .execute(
            "UPDATE sessions SET record=?1 WHERE session_id=?2",
            params![codec::encode_body(&intent).unwrap(), key.session.as_str()],
        )
        .unwrap();
    (directory, store, fence)
}
#[test]
fn checkpoint_admission_fences_authority_and_preserves_pending_intent_across_reopen() {
    let (directory, mut store, fence) = fixture();
    let operation = OperationId::with_sequence(1, "checkpoint").unwrap();
    let command = CheckpointCommand::Create {
        id: CheckpointId::new("cp").unwrap(),
        fence: fence.clone(),
    };
    let limits = CheckpointLimits::default();
    assert_eq!(
        store
            .admit_checkpoint(1001, &operation, 1, &command, &limits, 1002)
            .err()
            .unwrap()
            .api()
            .code,
        ErrorCode::SandboxNotFound
    );
    let mut stale = fence.clone();
    stale.generation = sandboxd_protocol::SandboxGeneration::new(2).unwrap();
    assert_eq!(
        store
            .admit_checkpoint(
                1000,
                &operation,
                1,
                &CheckpointCommand::Create {
                    id: "cp".parse().unwrap(),
                    fence: stale
                },
                &limits,
                1002
            )
            .err()
            .unwrap()
            .api()
            .code,
        ErrorCode::StaleGeneration
    );
    assert_eq!(
        store
            .admit_checkpoint(1000, &operation, 1, &command, &limits, u64::MAX)
            .err()
            .unwrap()
            .api()
            .code,
        ErrorCode::LeaseExpired
    );
    let admitted = store
        .admit_checkpoint(1000, &operation, 1, &command, &limits, 1002)
        .unwrap();
    assert!(matches!(admitted, CheckpointAdmission::Pending(_)));
    assert_eq!(
        store
            .mutate(
                1000,
                &OperationId::new("renew-during-copy").unwrap(),
                &Mutation::Renew {
                    fence: fence.clone(),
                    sequence: 1,
                    duration_seconds: 3600
                },
                1003
            )
            .err()
            .unwrap()
            .api()
            .code,
        ErrorCode::SessionUnavailable
    );
    assert_eq!(store.pending_checkpoints().unwrap().len(), 1);
    assert!(matches!(
        store
            .admit_checkpoint(1000, &operation, 1, &command, &limits, u64::MAX)
            .unwrap(),
        CheckpointAdmission::Pending(_)
    ));
    let different = CheckpointCommand::Create {
        id: "different".parse().unwrap(),
        fence,
    };
    assert_eq!(
        store
            .admit_checkpoint(1000, &operation, 1, &different, &limits, 1003)
            .err()
            .unwrap()
            .api()
            .code,
        ErrorCode::OperationConflict
    );
    drop(store);
    // The admission fixture has no real VMM; verify durable SQLite contents independently of runtime adoption.
    let reopened = rusqlite::Connection::open(directory.path().join("state.sqlite3")).unwrap();
    let bytes: Vec<u8> = reopened
        .query_row(
            "SELECT record FROM checkpoint_intents WHERE owner_uid=1000",
            [],
            |r| r.get(0),
        )
        .unwrap();
    let persisted: CheckpointIntent = codec::decode_body(&bytes).unwrap();
    assert_eq!(persisted.operation, operation);
    assert_eq!(persisted.command, command);
}
#[test]
fn checkpoint_quota_reserves_bytes_and_receipt_completion_is_replayed() {
    let (_directory, mut store, fence) = fixture();
    let operation = OperationId::with_sequence(1, "checkpoint").unwrap();
    let command = CheckpointCommand::Create {
        id: "cp".parse().unwrap(),
        fence: fence.clone(),
    };
    let limits = CheckpointLimits {
        max_count: 1,
        max_bytes_per_checkpoint: 1 << 20,
        max_total_bytes: 1 << 20,
    };
    assert_eq!(
        store
            .admit_checkpoint(1000, &operation, 1, &command, &limits, 1002)
            .err()
            .unwrap()
            .api()
            .code,
        ErrorCode::QuotaExceeded
    );
    assert_eq!(store.operation_watermark(1000).unwrap(), 0);
    let limits = CheckpointLimits::default();
    let CheckpointAdmission::Pending(intent) = store
        .admit_checkpoint(1000, &operation, 1, &command, &limits, 1002)
        .unwrap()
    else {
        panic!()
    };
    let response = Response::Error(ApiError::new(ErrorCode::RecoveryFailed, "interrupted"));
    store
        .finish_checkpoint(&intent, &response, None, None)
        .unwrap();
    assert!(store.pending_checkpoints().unwrap().is_empty());
    let CheckpointAdmission::Complete(replayed) = store
        .admit_checkpoint(1000, &operation, 1, &command, &limits, u64::MAX)
        .unwrap()
    else {
        panic!()
    };
    assert_eq!(replayed, response);
    assert_eq!(
        store
            .connection
            .query_row::<u32, _, _>("SELECT COUNT(*) FROM checkpoints", [], |r| r.get(0))
            .unwrap(),
        0
    );
}
