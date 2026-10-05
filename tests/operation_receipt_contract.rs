mod support;
use sandboxd_protocol::*;
use support::*;

#[test]
fn inspection_recovers_a_real_receipt_after_reopen_without_mutation_or_cross_owner_access() {
    // SQLite metadata proof only: create does not import an image or boot a guest.
    let dir = directory();
    let path = dir.path().canonicalize().unwrap();
    let operation = OperationId::with_sequence(1, "create").unwrap();
    let mutation = create("receipt", None);
    let mut store = open(&path, 100);
    let response = store
        .mutate_checked_sequenced(1000, &operation, &mutation, 1000, Some(1), || Ok(()))
        .unwrap();
    drop(store);
    let mut store = open(&path, 100);
    let receipt = store.inspect_operation(1000, &operation, 1).unwrap();
    assert_eq!(receipt.state, OperationReceiptState::Complete);
    assert_eq!(receipt.response.as_deref(), Some(&response));
    assert_eq!(
        receipt.request_digest.as_deref(),
        Some(hex::encode(sha2::Sha256::digest(codec::encode_body(&mutation).unwrap())).as_str())
    );
    assert_eq!(receipt.accepted_sequence, 1);
    let foreign = store.inspect_operation(2000, &operation, 1).unwrap();
    assert_eq!(foreign.state, OperationReceiptState::Unknown);
    assert_eq!(foreign.accepted_sequence, 0);
    assert!(foreign.response.is_none() && foreign.request_digest.is_none());
    let absent = OperationId::with_sequence(1, "never-used").unwrap();
    assert_eq!(
        store.inspect_operation(1000, &absent, 1).unwrap().state,
        OperationReceiptState::Unavailable
    );
    let future = OperationId::with_sequence(2, "future").unwrap();
    assert_eq!(
        store.inspect_operation(1000, &future, 2).unwrap().state,
        OperationReceiptState::Unknown
    );
    assert!(store.inspect_operation(1000, &operation, 2).is_err());
    assert_eq!(store.operation_watermark(1000).unwrap(), 1);
    assert_eq!(store.list(1000, None, 16).unwrap().len(), 1);
}
use sha2::Digest;
