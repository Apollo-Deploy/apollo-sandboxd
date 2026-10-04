//! Bounded replay preserves output sequence and distinguishes loss from transport resets.
use super::journal::{MAX_REPLAY_BYTES, decode_record};
use super::{JournalItem, JournalPage, OutputJournal};
use crate::error::{Error, Result};
use rusqlite::params;
impl OutputJournal {
    pub fn replay(&self, from_sequence: u64, limit: u16) -> Result<JournalPage> {
        if from_sequence == 0 || limit == 0 || limit > 4096 {
            return Err(Error::Config("invalid output journal replay bounds"));
        }
        let high: u64 =
            self.connection
                .query_row("SELECT high_watermark FROM journal_meta", [], |row| {
                    row.get(0)
                })?;
        let first: Option<u64> =
            self.connection
                .query_row("SELECT MIN(sequence) FROM output_records", [], |row| {
                    row.get(0)
                })?;
        let mut items = Vec::new();
        let mut cursor = from_sequence;
        let mut bytes = 0usize;
        if let Some(first) = first {
            if cursor < first {
                items.push(JournalItem::Gap {
                    from_sequence: cursor,
                    to_sequence: first - 1,
                });
                cursor = first;
            }
        } else if cursor <= high {
            items.push(JournalItem::Gap {
                from_sequence: cursor,
                to_sequence: high,
            });
            return Ok(JournalPage {
                items,
                high_watermark: high,
                transport_gaps: self.transport_gaps(from_sequence)?,
            });
        }
        let mut statement = self.connection.prepare(
            "SELECT sequence,timestamp,stream,flags,payload,digest FROM output_records WHERE sequence>=?1 ORDER BY sequence LIMIT ?2",
        )?;
        let mut rows = statement.query(params![cursor, limit])?;
        while let Some(row) = rows.next()? {
            if items.len() >= usize::from(limit) {
                break;
            }
            let sequence: u64 = row.get(0)?;
            if sequence > cursor {
                items.push(JournalItem::Gap {
                    from_sequence: cursor,
                    to_sequence: sequence - 1,
                });
                cursor = sequence;
                if items.len() >= usize::from(limit) {
                    break;
                }
            }
            match decode_record(row, &self.exec) {
                Ok(record) if record.sequence == cursor => {
                    if bytes.saturating_add(record.payload.len()) > MAX_REPLAY_BYTES {
                        break;
                    }
                    bytes = bytes.saturating_add(record.payload.len());
                    items.push(JournalItem::Record(record));
                }
                Err(Error::State) | Ok(_) => {
                    items.push(JournalItem::Gap {
                        from_sequence: sequence,
                        to_sequence: sequence,
                    });
                }
                Err(error) => return Err(error),
            }
            cursor = sequence.checked_add(1).ok_or(Error::State)?;
        }
        Ok(JournalPage {
            items,
            high_watermark: high,
            transport_gaps: self.transport_gaps(from_sequence)?,
        })
    }
}
