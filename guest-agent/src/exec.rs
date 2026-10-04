use guest_protocol::{ExecutionSpec, GuestMessage, Stream};
#[cfg(target_os = "linux")]
use nix::{
    pty::{Winsize, openpty},
    unistd::dup,
};
use sandboxd_protocol::ExecId;
use std::collections::HashMap;
#[cfg(target_os = "linux")]
use std::collections::HashSet;
use std::collections::VecDeque;
use std::io::Write;
#[cfg(target_os = "linux")]
use std::os::fd::{AsRawFd, OwnedFd};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{
    Arc, Mutex,
    mpsc::{SyncSender, sync_channel},
};
use std::thread;

const MAX_EXECUTIONS: usize = 256;

pub struct Manager {
    pub(crate) processes: HashMap<ExecId, Process>,
    pub(crate) completed: HashMap<ExecId, GuestMessage>,
    events: Arc<Mutex<Option<SyncSender<GuestMessage>>>>,
    #[cfg(target_os = "linux")]
    known_children: Arc<Mutex<HashSet<nix::unistd::Pid>>>,
}

pub(crate) struct Process {
    pub(crate) pid: u32,
    pub(crate) alive: Arc<AtomicBool>,
    lifecycle: Arc<Mutex<()>>,
    output: Arc<Mutex<OutputState>>,
    stdin: Option<SyncSender<StdinRequest>>,
    pub(crate) detached: bool,
    #[cfg(target_os = "linux")]
    pty: Option<OwnedFd>,
}

struct StdinRequest {
    data: Vec<u8>,
    eof: bool,
    result: SyncSender<Result<(), String>>,
}

struct OutputState {
    exec: ExecId,
    sequence: u64,
    events: Arc<Mutex<Option<SyncSender<GuestMessage>>>>,
    journal: VecDeque<GuestMessage>,
    gap_from: Option<u64>,
}

impl Manager {
    pub fn new(events: SyncSender<GuestMessage>) -> Self {
        Self {
            processes: HashMap::new(),
            completed: HashMap::new(),
            events: Arc::new(Mutex::new(Some(events))),
            #[cfg(target_os = "linux")]
            known_children: spawn_orphan_reaper(),
        }
    }

    pub fn disconnect_events(&mut self) {
        if let Ok(mut current) = self.events.lock() {
            *current = None;
        }
    }

    pub fn set_events(&mut self, events: SyncSender<GuestMessage>) {
        if let Ok(mut current) = self.events.lock() {
            *current = Some(events.clone());
        }
        for process in self.processes.values() {
            if let Ok(mut output) = process.output.lock() {
                if let Some(gap) = output.gap_from {
                    match events.try_send(GuestMessage::OutputGap {
                        exec: output.exec.clone(),
                        from_sequence: gap,
                    }) {
                        Ok(()) => output.gap_from = None,
                        Err(std::sync::mpsc::TrySendError::Full(_)) => break,
                        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => break,
                    }
                }
                while let Some(message) = output.journal.pop_front() {
                    match events.try_send(message.clone()) {
                        Ok(()) => {}
                        Err(std::sync::mpsc::TrySendError::Full(_)) => {
                            output.journal.push_front(message);
                            break;
                        }
                        Err(std::sync::mpsc::TrySendError::Disconnected(_)) => {
                            output.journal.push_front(message);
                            break;
                        }
                    }
                }
            }
        }
    }

    #[allow(unused_variables)]
    pub fn start(&mut self, spec: ExecutionSpec) -> Result<(), String> {
        spec.validate().map_err(str::to_owned)?;
        if self.processes.contains_key(&spec.id) || self.completed.contains_key(&spec.id) {
            return Err("exec ID already exists".into());
        }
        if self.processes.len() >= MAX_EXECUTIONS {
            return Err("exec limit reached".into());
        }
        if self.completed.len() >= MAX_EXECUTIONS {
            return Err("completed exec receipt capacity exhausted".into());
        }
        let mut command = Command::new(&spec.argv[0]);
        command
            .args(&spec.argv[1..])
            .current_dir(&spec.cwd)
            .uid(spec.uid)
            .gid(spec.gid);
        if spec.pty.is_none() {
            command.process_group(0);
        }
        command.env_clear();
        command.envs(&spec.environment);
        for (key, value) in &spec.secret_environment {
            command.env(key, &value.0);
        }
        #[cfg(target_os = "linux")]
        let pty = spec
            .pty
            .map(|size| {
                openpty(
                    Some(&Winsize {
                        ws_row: size.rows,
                        ws_col: size.columns,
                        ws_xpixel: 0,
                        ws_ypixel: 0,
                    }),
                    None,
                )
            })
            .transpose()
            .map_err(|e| format!("PTY allocation failed: {e}"))?;
        #[cfg(not(target_os = "linux"))]
        let pty: Option<()> = None;
        if let Some(pair) = pty.as_ref() {
            #[cfg(target_os = "linux")]
            {
                command.stdin(Stdio::from(std::fs::File::from(
                    dup(&pair.slave).map_err(|e| format!("PTY setup failed: {e}"))?,
                )));
                command.stdout(Stdio::from(std::fs::File::from(
                    dup(&pair.slave).map_err(|e| format!("PTY setup failed: {e}"))?,
                )));
                command.stderr(Stdio::from(std::fs::File::from(
                    dup(&pair.slave).map_err(|e| format!("PTY setup failed: {e}"))?,
                )));
                configure_controlling_tty(&mut command, pair.slave.as_raw_fd());
            }
        } else {
            command.stdin(if matches!(spec.stdin, guest_protocol::StdinMode::Stream) {
                Stdio::piped()
            } else {
                Stdio::null()
            });
            command.stdout(Stdio::piped()).stderr(Stdio::piped());
        }
        let mut child = command
            .spawn()
            .map_err(|e| format!("exec spawn failed: {e}"))?;
        let pid = child.id();
        #[cfg(target_os = "linux")]
        if let Ok(mut children) = self.known_children.lock() {
            children.insert(nix::unistd::Pid::from_raw(pid as i32));
        }
        #[cfg(target_os = "linux")]
        let (stdin, pty_reader, pty_control) = if let Some(pair) = pty {
            let input = std::fs::File::from(
                dup(&pair.master).map_err(|e| format!("PTY setup failed: {e}"))?,
            );
            let reader = std::fs::File::from(
                dup(&pair.master).map_err(|e| format!("PTY setup failed: {e}"))?,
            );
            (
                Some(Box::new(input) as Box<dyn Write + Send>),
                Some(reader),
                Some(pair.master),
            )
        } else {
            (
                child
                    .stdin
                    .take()
                    .map(|value| Box::new(value) as Box<dyn Write + Send>),
                None::<std::fs::File>,
                None,
            )
        };
        #[cfg(not(target_os = "linux"))]
        let (stdin, pty_reader, pty_control) = (
            child
                .stdin
                .take()
                .map(|value| Box::new(value) as Box<dyn Write + Send>),
            None::<std::fs::File>,
            None::<()>,
        );
        let output = Arc::new(Mutex::new(OutputState {
            exec: spec.id.clone(),
            sequence: 1,
            events: self.events.clone(),
            journal: VecDeque::new(),
            gap_from: None,
        }));
        let readers_done = Arc::new(AtomicUsize::new(0));
        let reader_count = if pty_reader.is_some() { 1 } else { 2 };
        if pty_reader.is_some() {
            spawn_reader(
                spec.id.clone(),
                pty_reader,
                Stream::Terminal,
                output.clone(),
                readers_done.clone(),
            )
            .inspect_err(|_| {
                let _ = child.kill();
                let _ = child.wait();
            })?;
        } else {
            spawn_reader(
                spec.id.clone(),
                child.stdout.take(),
                Stream::Stdout,
                output.clone(),
                readers_done.clone(),
            )
            .inspect_err(|_| {
                let _ = child.kill();
                let _ = child.wait();
            })?;
            spawn_reader(
                spec.id.clone(),
                child.stderr.take(),
                Stream::Stderr,
                output.clone(),
                readers_done.clone(),
            )
            .inspect_err(|_| {
                let _ = child.kill();
                let _ = child.wait();
            })?;
        }
        let stdin = match stdin {
            Some(writer) => {
                let (requests, receiver) = sync_channel(8);
                thread::Builder::new()
                    .name("guest-exec-stdin".into())
                    .spawn(move || stdin_worker(writer, receiver))
                    .map_err(|e| {
                        let _ = child.kill();
                        let _ = child.wait();
                        format!("exec stdin worker failed: {e}")
                    })?;
                Some(requests)
            }
            None => None,
        };
        let events = self.events.clone();
        let exec = spec.id.clone();
        let timed_out = spec.timeout_ms;
        let alive = Arc::new(AtomicBool::new(true));
        let waiter_alive = alive.clone();
        let lifecycle = Arc::new(Mutex::new(()));
        let waiter_lifecycle = lifecycle.clone();
        let waiter_output = output.clone();
        #[cfg(target_os = "linux")]
        let waiter_children = self.known_children.clone();
        let child_slot = Arc::new(Mutex::new(Some(child)));
        let waiter_child = child_slot.clone();
        let waiter = thread::Builder::new()
            .name("guest-exec-wait".into())
            .spawn(move || {
                let child = waiter_child.lock().ok().and_then(|mut slot| slot.take());
                if let Some(child) = child {
                    wait_for_child(
                        child,
                        exec,
                        events,
                        timed_out,
                        waiter_output,
                        readers_done,
                        reader_count,
                        waiter_alive,
                        waiter_lifecycle,
                        #[cfg(target_os = "linux")]
                        waiter_children,
                    );
                }
            });
        if let Err(error) = waiter {
            if let Ok(mut slot) = child_slot.lock()
                && let Some(mut child) = slot.take()
            {
                let _ = child.kill();
                let _ = child.wait();
            }
            return Err(format!("exec waiter failed: {error}"));
        }
        self.processes.insert(
            spec.id,
            Process {
                pid,
                alive,
                lifecycle,
                output,
                stdin,
                detached: spec.detached,
                #[cfg(target_os = "linux")]
                pty: pty_control,
            },
        );
        Ok(())
    }
}

#[path = "exec_control.rs"]
mod exec_control;
#[path = "exec_runtime.rs"]
mod exec_runtime;
#[path = "exec_state.rs"]
mod exec_state;
#[cfg(target_os = "linux")]
use exec_runtime::configure_controlling_tty;
#[cfg(target_os = "linux")]
use exec_runtime::spawn_orphan_reaper;
use exec_runtime::{CommandIdentity, spawn_reader, stdin_worker, wait_for_child};

#[cfg(test)]
#[path = "exec_tests.rs"]
mod exec_tests;
