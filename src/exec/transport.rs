//! Transport discontinuities are metadata, not invented missing output bytes.
use super::OutputJournal;
use crate::error::{Error, Result};
use rusqlite::TransactionBehavior;
impl OutputJournal {
    pub(crate) fn mark_transport_gap(&mut self) -> Result<()> {
        let tx = self
            .connection
            .transaction_with_behavior(TransactionBehavior::Immediate)?;
        tx.execute(
            "INSERT OR IGNORE INTO transport_gaps SELECT high_watermark FROM journal_meta",
            [],
        )?;
        // Retain the first known discontinuity and the most recent 63 boundaries.
        tx.execute("DELETE FROM transport_gaps WHERE after_sequence IN (SELECT after_sequence FROM transport_gaps ORDER BY after_sequence LIMIT MAX(0,(SELECT COUNT(*) FROM transport_gaps)-64) OFFSET 1)", [])?;
        tx.commit()?;
        Ok(())
    }
    pub(super) fn transport_gaps(&self, from: u64) -> Result<Vec<u64>> {
        let mut query = self.connection.prepare("SELECT after_sequence FROM transport_gaps WHERE after_sequence>=?1 ORDER BY after_sequence LIMIT 65")?;
        let values = query
            .query_map([from.saturating_sub(1)], |row| row.get(0))?
            .collect::<std::result::Result<Vec<u64>, _>>()?;
        if values.len() > 64 {
            return Err(Error::State);
        }
        Ok(values)
    }
}
