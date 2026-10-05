//! Replay a journal cursor, follow live output, and report every retention gap.
use super::{exec::Calls, terminal::Input};
use apollo_sandboxd::error::{Error, Result};
use sandboxd_protocol::{exec::*, *};
use std::{io::Write, time::Duration};

pub(super) async fn follow(
    calls: &mut Calls<'_>,
    exec: ExecId,
    mut cursor: u64,
    once: bool,
    interactive: bool,
    raw: bool,
) -> Result<bool> {
    if cursor == 0 {
        return Err(Error::Config("output sequence must be positive"));
    }
    let mut input = interactive.then(|| Input::open(raw)).transpose()?;
    let mut bytes = vec![0u8; MAX_DATA_BYTES];
    let mut resize = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())?;
    if raw {
        calls
            .call(GuestCommand::ExecResizePty {
                exec: exec.clone(),
                size: Input::size()?,
            })
            .await?;
    }
    let mut reported_transport_gap = None;
    loop {
        let reply = calls
            .call(GuestCommand::ExecAttach {
                exec: exec.clone(),
                from_sequence: cursor,
                limit: 128,
            })
            .await?;
        let GuestReply::ExecOutput(page) = reply else {
            return Err(Error::State);
        };
        if page.exec != exec {
            return Err(Error::State);
        }
        for after in page.transport_gaps {
            if reported_transport_gap.is_none_or(|known| after > known) {
                eprintln!("TRANSPORT_GAP after_sequence={after}");
                reported_transport_gap = Some(after);
            }
        }
        for item in page.items {
            match item {
                ExecOutputItem::Record(record) => {
                    if record.sequence < cursor {
                        return Err(Error::State);
                    }
                    match record.stream {
                        Stream::Stdout | Stream::Terminal => {
                            std::io::stdout().write_all(&record.payload)?
                        }
                        Stream::Stderr => std::io::stderr().write_all(&record.payload)?,
                    }
                    cursor = record.sequence.checked_add(1).ok_or(Error::State)?;
                }
                ExecOutputItem::Gap {
                    from_sequence,
                    to_sequence,
                } => {
                    eprintln!("OUTPUT_GAP {from_sequence}..{to_sequence}");
                    cursor = to_sequence.checked_add(1).ok_or(Error::State)?;
                }
            }
        }
        std::io::stdout().flush()?;
        std::io::stderr().flush()?;
        if once {
            return Ok(true);
        }
        let status = status(calls, &exec).await?;
        if !status.running && cursor > status.output_high_watermark {
            return Ok(status.exit_code == Some(0) && status.signal.is_none() && !status.timed_out);
        }
        if cursor <= page.high_watermark {
            continue;
        }
        tokio::select! {
            count = async {
                match &mut input { Some(input) => input.read(&mut bytes).await,
                    None => std::future::pending().await }
            } => {
                let count = count?;
                calls.call(GuestCommand::ExecStdin { exec: exec.clone(), data: bytes[..count].to_vec(), eof: count == 0 }).await?;
                if count == 0 { input = None; }
            }
            _ = tokio::signal::ctrl_c() => {
                calls.call(GuestCommand::ExecCancel { exec: exec.clone() }).await?;
                return Ok(false);
            }
            _ = resize.recv(), if raw => {
                calls.call(GuestCommand::ExecResizePty { exec: exec.clone(), size: Input::size()? }).await?;
            }
            _ = tokio::time::sleep(Duration::from_millis(100)) => {}
        }
    }
}

async fn status(calls: &mut Calls<'_>, exec: &ExecId) -> Result<ExecSummary> {
    let mut after = None;
    loop {
        let reply = calls
            .call(GuestCommand::ExecList {
                after: after.clone(),
                limit: 256,
            })
            .await?;
        let GuestReply::ExecList { entries } = reply else {
            return Err(Error::State);
        };
        let next = entries.last().map(|entry| entry.exec.clone());
        let full = entries.len() == 256;
        if let Some(entry) = entries.into_iter().find(|entry| &entry.exec == exec) {
            return Ok(entry);
        }
        if !full || next == after {
            return Err(Error::Config("execution absent from list"));
        }
        after = next;
    }
}
