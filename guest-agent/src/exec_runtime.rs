use super::{OutputState, StdinRequest};
use guest_protocol::{GuestMessage, OutputRecord, Stream};
#[cfg(not(target_os = "linux"))]
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use sandboxd_protocol::ExecId;
use std::io::{Read, Write};
use std::process::{Child, Command};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, mpsc::SyncSender};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(target_os = "linux")]
use std::collections::HashSet;

const OUTPUT_CHUNK: usize = 64 * 1024;

pub(super) fn spawn_reader<R: Read + Send + 'static>(
    exec: ExecId,
    reader: Option<R>,
    stream: Stream,
    output: Arc<Mutex<OutputState>>,
    readers_done: Arc<AtomicUsize>,
) -> Result<(), String> {
    let Some(mut reader) = reader else {
        readers_done.fetch_add(1, Ordering::Release);
        return Ok(());
    };
    thread::Builder::new()
        .name("guest-exec-output".into())
        .spawn(move || {
            let mut buffer = vec![0; OUTPUT_CHUNK];
            loop {
                let count = match reader.read(&mut buffer) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => n,
                };
                let mut state = match output.lock() {
                    Ok(value) => value,
                    Err(_) => break,
                };
                let record = OutputRecord {
                    exec: exec.clone(),
                    stream,
                    sequence: state.sequence,
                    timestamp_unix_ms: now_ms(),
                    flags: 0,
                    payload: buffer[..count].to_vec(),
                };
                state.sequence = state.sequence.saturating_add(1);
                let message = GuestMessage::Output { record };
                let sender = match state.events.lock() {
                    Ok(value) => value.as_ref().cloned(),
                    Err(_) => break,
                };
                match sender {
                    Some(sender) if sender.send(message.clone()).is_ok() => {}
                    Some(_) => {
                        if let Ok(mut current) = state.events.lock() {
                            *current = None;
                        }
                        journal(&mut state, message);
                    }
                    None => journal(&mut state, message),
                }
            }
            readers_done.fetch_add(1, Ordering::Release);
        })
        .map(|_| ())
        .map_err(|e| format!("exec output reader failed: {e}"))
}

fn journal(state: &mut OutputState, message: GuestMessage) {
    if state.journal.len() >= 1024
        && let Some(GuestMessage::Output { record }) = state.journal.pop_front()
    {
        state.gap_from.get_or_insert(record.sequence);
    }
    state.journal.push_back(message);
}

pub(super) fn stdin_worker(
    mut writer: Box<dyn Write + Send>,
    receiver: std::sync::mpsc::Receiver<StdinRequest>,
) {
    while let Ok(request) = receiver.recv() {
        let result = writer
            .write_all(&request.data)
            .map_err(|e| format!("write failed: {e}"))
            .and_then(|()| {
                if request.eof {
                    writer.flush().map_err(|e| format!("flush failed: {e}"))
                } else {
                    Ok(())
                }
            });
        let eof = request.eof;
        let _ = request.result.send(result);
        if eof {
            break;
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn wait_for_child(
    mut child: Child,
    exec: ExecId,
    events: Arc<Mutex<Option<SyncSender<GuestMessage>>>>,
    timeout_ms: u32,
    output: Arc<Mutex<OutputState>>,
    readers_done: Arc<AtomicUsize>,
    reader_count: usize,
    alive: Arc<AtomicBool>,
    lifecycle: Arc<Mutex<()>>,
    #[cfg(target_os = "linux")] cgroup: crate::exec_cgroup::ExecCgroup,
    #[cfg(target_os = "linux")] known_children: Arc<Mutex<HashSet<Pid>>>,
) {
    let deadline = Duration::from_millis(u64::from(timeout_ms));
    let start = std::time::Instant::now();
    let mut timed_out = false;
    let status: Option<std::process::ExitStatus> = loop {
        let guard = match lifecycle.lock() {
            Ok(value) => value,
            Err(_) => break None,
        };
        match child.try_wait() {
            Ok(Some(status)) => {
                alive.store(false, Ordering::Release);
                drop(guard);
                break Some(status);
            }
            Ok(None) if start.elapsed() >= deadline => {
                timed_out = true;
                #[cfg(target_os = "linux")]
                let _ = cgroup.kill();
                #[cfg(not(target_os = "linux"))]
                let _ = killpg(Pid::from_raw(child.id() as i32), Signal::SIGKILL);
                let _ = child.wait();
                alive.store(false, Ordering::Release);
                drop(guard);
                break None;
            }
            Ok(None) => {
                drop(guard);
                thread::sleep(Duration::from_millis(10));
            }
            Err(_) => {
                alive.store(false, Ordering::Release);
                drop(guard);
                break None;
            }
        }
    };
    #[cfg(target_os = "linux")]
    let cleanup_failed = cgroup.kill_and_remove().is_err();
    #[cfg(target_os = "linux")]
    if let Ok(mut children) = known_children.lock() {
        children.remove(&Pid::from_raw(child.id() as i32));
    }
    #[cfg(target_os = "linux")]
    let (mut exit_code, mut signal) = status
        .map(|value| (value.code(), signal_from_status(&value)))
        .unwrap_or((None, None));
    #[cfg(not(target_os = "linux"))]
    let (exit_code, signal) = status
        .map(|value| (value.code(), signal_from_status(&value)))
        .unwrap_or((None, None));
    #[cfg(target_os = "linux")]
    if cleanup_failed {
        exit_code = Some(125);
        signal = None;
    }
    let reader_deadline = std::time::Instant::now() + Duration::from_secs(5);
    while readers_done.load(Ordering::Acquire) < reader_count
        && std::time::Instant::now() < reader_deadline
    {
        thread::sleep(Duration::from_millis(1));
    }
    let reader_gap = if readers_done.load(Ordering::Acquire) < reader_count
        && let Ok(mut state) = output.lock()
    {
        // A descendant may have inherited a pipe after the leader exited. Do
        // not block the control plane forever or claim a complete byte stream;
        // retain an explicit gap marker for reconnecting clients.
        let sequence = state.sequence;
        state.gap_from.get_or_insert(sequence);
        state.gap_from
    } else {
        None
    };
    if let Some(from_sequence) = reader_gap
        && let Ok(Some(sender)) = events.lock().map(|value| value.as_ref().cloned())
    {
        let _ = sender.send(GuestMessage::OutputGap {
            exec: exec.clone(),
            from_sequence,
        });
    }
    if let Ok(Some(sender)) = events.lock().map(|value| value.as_ref().cloned()) {
        let _ = sender.send(GuestMessage::ExecExit {
            exec,
            exit_code,
            signal,
            timed_out,
        });
    }
}

#[cfg(target_os = "linux")]
pub(super) fn spawn_orphan_reaper() -> Arc<Mutex<HashSet<Pid>>> {
    let known = Arc::new(Mutex::new(HashSet::new()));
    let shared = known.clone();
    let _ = thread::Builder::new()
        .name("guest-child-reaper".into())
        .spawn(move || {
            loop {
                let candidate = match nix::sys::wait::waitid(
                    nix::sys::wait::Id::All,
                    nix::sys::wait::WaitPidFlag::WEXITED
                        | nix::sys::wait::WaitPidFlag::WNOHANG
                        | nix::sys::wait::WaitPidFlag::WNOWAIT,
                ) {
                    Ok(nix::sys::wait::WaitStatus::Exited(pid, _))
                    | Ok(nix::sys::wait::WaitStatus::Signaled(pid, _, _)) => Some(pid),
                    Ok(_) => None,
                    Err(_) => None,
                };
                if let Some(pid) = candidate {
                    let owned = shared
                        .lock()
                        .map(|children| children.contains(&pid))
                        .unwrap_or(true);
                    if !owned {
                        let _ = nix::sys::wait::waitid(
                            nix::sys::wait::Id::Pid(pid),
                            nix::sys::wait::WaitPidFlag::WEXITED,
                        );
                    }
                    continue;
                }
                thread::sleep(Duration::from_millis(10));
            }
        });
    known
}

fn signal_from_status(status: &std::process::ExitStatus) -> Option<u8> {
    #[cfg(unix)]
    {
        std::os::unix::process::ExitStatusExt::signal(status).and_then(|v| u8::try_from(v).ok())
    }
    #[cfg(not(unix))]
    {
        let _ = status;
        None
    }
}
fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .ok()
        .and_then(|d| u64::try_from(d.as_millis()).ok())
        .unwrap_or(0)
}

pub(super) trait CommandIdentity {
    fn process_group(&mut self, pgid: i32) -> &mut Self;
}

#[cfg(unix)]
impl CommandIdentity for Command {
    fn process_group(&mut self, pgid: i32) -> &mut Self {
        std::os::unix::process::CommandExt::process_group(self, pgid)
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code)]
pub(super) fn configure_controlling_tty(command: &mut Command, slave_fd: std::os::fd::RawFd) {
    use std::os::unix::process::CommandExt;
    // SAFETY: this pre-exec closure only establishes a new session and assigns the
    // already-open PTY slave as controlling terminal before the guest command runs.
    unsafe {
        command.pre_exec(move || {
            nix::unistd::setsid().map_err(|_| std::io::Error::other("setsid failed"))?;
            let result = nix::libc::ioctl(slave_fd, nix::libc::TIOCSCTTY, 0);
            if result < 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
}
