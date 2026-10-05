use super::{Manager, StdinRequest};
use nix::sys::signal::{Signal, killpg};
use nix::unistd::Pid;
use sandboxd_protocol::ExecId;
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
use std::sync::atomic::Ordering;
use std::sync::mpsc::sync_channel;
use std::time::Duration;

impl Manager {
    pub fn stdin(&self, exec: &ExecId, data: &[u8], eof: bool) -> Result<(), String> {
        let process = self
            .processes
            .get(exec)
            .ok_or_else(|| "exec not found".to_owned())?;
        if !process.alive.load(Ordering::Acquire) {
            return Err("exec already exited".into());
        }
        let sender = process
            .stdin
            .as_ref()
            .ok_or_else(|| "stdin is closed".to_owned())?;
        let (result_tx, result_rx) = sync_channel(1);
        sender
            .send(StdinRequest {
                data: data.to_vec(),
                eof,
                result: result_tx,
            })
            .map_err(|_| "stdin worker stopped".to_owned())?;
        result_rx
            .recv_timeout(Duration::from_secs(2))
            .map_err(|_| "exec stdin timed out".to_owned())?
            .map_err(|e| format!("exec stdin failed: {e}"))
    }

    pub fn signal(&self, exec: &ExecId, value: u8) -> Result<(), String> {
        let process = self
            .processes
            .get(exec)
            .ok_or_else(|| "exec not found".to_owned())?;
        let signal = Signal::try_from(i32::from(value)).map_err(|_| "invalid signal")?;
        let _guard = process
            .lifecycle
            .lock()
            .map_err(|_| "lifecycle lock poisoned")?;
        if !process.alive.load(Ordering::Acquire) {
            return Err("exec already exited".into());
        }
        killpg(
            Pid::from_raw(i32::try_from(process.pid).map_err(|_| "pid out of range")?),
            signal,
        )
        .map_err(|e| format!("exec signal failed: {e}"))
    }

    pub fn cancel(&self, exec: &ExecId) -> Result<(), String> {
        let process = self
            .processes
            .get(exec)
            .ok_or_else(|| "exec not found".to_owned())?;
        let _guard = process
            .lifecycle
            .lock()
            .map_err(|_| "lifecycle lock poisoned")?;
        if !process.alive.load(Ordering::Acquire) {
            return Err("exec already exited".into());
        }
        #[cfg(target_os = "linux")]
        {
            process
                .cgroup
                .kill()
                .map_err(|e| format!("exec cancellation failed: {e}"))
        }
        #[cfg(not(target_os = "linux"))]
        {
            killpg(
                Pid::from_raw(i32::try_from(process.pid).map_err(|_| "pid out of range")?),
                Signal::SIGTERM,
            )
            .map_err(|e| format!("exec cancel failed: {e}"))
        }
    }

    #[allow(unsafe_code)]
    pub fn resize(&self, exec: &ExecId, size: guest_protocol::TerminalSize) -> Result<(), String> {
        #[cfg(target_os = "linux")]
        {
            let process = self
                .processes
                .get(exec)
                .ok_or_else(|| "exec not found".to_owned())?;
            let _guard = process
                .lifecycle
                .lock()
                .map_err(|_| "lifecycle lock poisoned")?;
            if !process.alive.load(Ordering::Acquire) {
                return Err("exec already exited".into());
            }
            let fd = process
                .pty
                .as_ref()
                .ok_or_else(|| "exec is not a PTY".to_owned())?
                .as_raw_fd();
            let window = nix::libc::winsize {
                ws_row: size.rows,
                ws_col: size.columns,
                ws_xpixel: 0,
                ws_ypixel: 0,
            };
            // SAFETY: fd is an owned PTY descriptor and window points to a valid winsize value.
            let result = unsafe { nix::libc::ioctl(fd, nix::libc::TIOCSWINSZ, &window) };
            if result < 0 {
                return Err(std::io::Error::last_os_error().to_string());
            }
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (exec, size);
            Err("PTY resize requires Linux".into())
        }
    }
}
