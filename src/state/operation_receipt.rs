use super::Store;
use crate::error::{Error, Result};
use rusqlite::{OptionalExtension, params};
use sandboxd_protocol::{
    ApiError, ErrorCode, OperationId, OperationReceipt, OperationReceiptState, Response, codec,
};

impl Store {
    /// Read one consistent owner-scoped snapshot without admitting or replaying an effect.
    pub fn inspect_operation(
        &mut self,
        uid: u32,
        operation: &OperationId,
        sequence: u64,
    ) -> Result<OperationReceipt> {
        if !operation.matches_sequence(sequence) {
            return Err(
                ApiError::new(ErrorCode::InvalidRequest, "operation inspection sequence").into(),
            );
        }
        let tx = self.connection.transaction()?;
        let accepted_sequence: u64 = tx
            .query_row(
                "SELECT accepted_sequence FROM operation_watermarks WHERE owner_uid=?1",
                [uid],
                |row| row.get(0),
            )
            .optional()?
            .unwrap_or(0);
        let mut rows = tx.prepare(
            "SELECT request_digest,response,0 FROM operations WHERE owner_uid=?1 AND id=?2
             UNION ALL
             SELECT request_digest,response,pending FROM image_operations WHERE owner_uid=?1 AND operation_id=?2
 UNION ALL SELECT request_digest,response,pending FROM dynamic_volumes WHERE owner_uid=?1 AND operation_id=?2
 UNION ALL SELECT request_digest,response,pending FROM volume_releases WHERE owner_uid=?1 AND operation_id=?2",
        )?;
        let receipts = rows
            .query_map(params![uid, operation.as_str()], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, bool>(2)?,
                ))
            })?
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let (state, request_digest, response) = match receipts.as_slice() {
            [] => (
                if sequence <= accepted_sequence {
                    OperationReceiptState::Unavailable
                } else {
                    OperationReceiptState::Unknown
                },
                None,
                None,
            ),
            [(digest, bytes, image_pending)] => {
                if digest.len() != 32 || sequence > accepted_sequence {
                    return Err(Error::State);
                }
                let response: Response = codec::decode_body(bytes)?;
                if matches!(response, Response::OperationReceipt(_)) {
                    return Err(Error::State);
                }
                let linked: bool = tx.query_row(
                    "SELECT EXISTS(SELECT 1 FROM session_operations WHERE owner_uid=?1 AND operation_id=?2)
                     OR EXISTS(SELECT 1 FROM pending_session_controls WHERE owner_uid=?1 AND operation_id=?2)",
                    params![uid, operation.as_str()], |row| row.get(0),
                )?;
                let pending = *image_pending
                    || linked
                    || matches!(
                        response,
                        Response::GuestPending { .. }
                            | Response::ImagePending { .. }
                            | Response::SnapshotPending { .. }
                            | Response::CheckpointPending { .. }
                    );
                (
                    if pending {
                        OperationReceiptState::Pending
                    } else {
                        OperationReceiptState::Complete
                    },
                    Some(hex::encode(digest)),
                    Some(Box::new(response)),
                )
            }
            _ => return Err(Error::State),
        };
        Ok(OperationReceipt {
            operation: operation.clone(),
            operation_sequence: sequence,
            accepted_sequence,
            state,
            request_digest,
            response,
        })
    }
}
