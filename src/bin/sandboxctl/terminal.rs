//! Scoped terminal state; no permanently blocked stdin thread at CLI shutdown.
use apollo_sandboxd::error::{Error, Result};
use nix::sys::termios::{self, SetArg, Termios};
use rustix::fs::{FileType, OFlags};
use std::{fs::File, io::Read, os::fd::OwnedFd};
use tokio::io::unix::AsyncFd;

pub(super) struct Input {
    fd: Option<AsyncFd<OwnedFd>>,
    regular: Option<File>,
    original_flags: OFlags,
    terminal: Option<Termios>,
}
impl Input {
    pub fn size() -> Result<sandboxd_protocol::exec::TerminalSize> {
        let size = rustix::termios::tcgetwinsize(std::io::stdin())?;
        let size = sandboxd_protocol::exec::TerminalSize {
            rows: size.ws_row,
            columns: size.ws_col,
        };
        if size.rows == 0 || size.columns == 0 || size.rows > 4096 || size.columns > 4096 {
            return Err(Error::Config("invalid terminal window size"));
        }
        Ok(size)
    }
    pub fn open(raw: bool) -> Result<Self> {
        let stdin = std::io::stdin();
        let fd = rustix::io::dup(&stdin)?;
        let original_flags = rustix::fs::fcntl_getfl(&fd)?;
        let terminal = if raw {
            let saved = termios::tcgetattr(&fd)
                .map_err(|_| Error::Config("PTY interaction needs terminal stdin"))?;
            Some(saved)
        } else {
            None
        };
        let regular =
            FileType::from_raw_mode(rustix::fs::fstat(&fd)?.st_mode) == FileType::RegularFile;
        let mut input = Self {
            fd: None,
            regular: None,
            original_flags,
            terminal,
        };
        if regular {
            input.regular = Some(File::from(fd));
        } else {
            rustix::fs::fcntl_setfl(&fd, original_flags | OFlags::NONBLOCK)?;
            match AsyncFd::new(fd) {
                Ok(fd) => input.fd = Some(fd),
                Err(error) => {
                    let _ = rustix::fs::fcntl_setfl(&stdin, original_flags);
                    return Err(error.into());
                }
            }
        }
        if let Some(saved) = &input.terminal {
            let mut raw = saved.clone();
            termios::cfmakeraw(&mut raw);
            termios::tcsetattr(&stdin, SetArg::TCSANOW, &raw)
                .map_err(|_| Error::Config("terminal mode update failed"))?;
        }
        Ok(input)
    }
    pub async fn read(&mut self, bytes: &mut [u8]) -> Result<usize> {
        if let Some(file) = &mut self.regular {
            return Ok(file.read(bytes)?);
        }
        let fd = self.fd.as_ref().ok_or(Error::State)?;
        loop {
            let mut ready = fd.readable().await?;
            match ready.try_io(|fd| {
                rustix::io::read(fd.get_ref(), &mut *bytes).map_err(std::io::Error::from)
            }) {
                Ok(result) => return Ok(result?),
                Err(_) => continue,
            }
        }
    }
}
impl Drop for Input {
    fn drop(&mut self) {
        let stdin = std::io::stdin();
        let _ = rustix::fs::fcntl_setfl(&stdin, self.original_flags);
        if let Some(saved) = &self.terminal {
            let _ = termios::tcsetattr(&stdin, SetArg::TCSANOW, saved);
        }
    }
}
