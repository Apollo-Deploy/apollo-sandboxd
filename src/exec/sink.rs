use crate::error::{Error, Result};
use guest_protocol::OutputPolicy;
use rustix::{
    fs::{self, FileType, OFlags, fcntl_getfl, fcntl_setfl},
    io,
};
use std::os::fd::{AsFd, OwnedFd};

pub struct OutputSink {
    fd: OwnedFd,
    policy: OutputPolicy,
}

#[cfg(test)]
mod tests {
    use super::*;
    use rustix::{
        fs::{self, Mode, OFlags},
        io::dup,
    };
    use std::io::{Seek, SeekFrom};
    use tempfile::NamedTempFile;

    #[test]
    fn writable_pipe_preserves_binary_bytes() {
        let file = NamedTempFile::new().expect("file");
        let writer = file.as_file();
        let read_fd = dup(writer).expect("dup");
        let write_fd =
            fs::open(file.path(), OFlags::RDWR | OFlags::CLOEXEC, Mode::empty()).expect("open");
        let sink = OutputSink::new(write_fd, OutputPolicy::Required).expect("sink");
        let bytes = [0, 255, 10, 0];
        assert_eq!(sink.write(&bytes).expect("write"), bytes.len());
        let mut received = [0; 4];
        let mut reader = std::fs::File::from(read_fd);
        reader.seek(SeekFrom::Start(0)).expect("seek");
        std::io::Read::read_exact(&mut reader, &mut received).expect("read");
        assert_eq!(received, bytes);
    }

    #[test]
    fn read_end_is_rejected() {
        let file = NamedTempFile::new().expect("file");
        let read_fd =
            fs::open(file.path(), OFlags::RDONLY | OFlags::CLOEXEC, Mode::empty()).expect("open");
        assert!(OutputSink::new(read_fd, OutputPolicy::Required).is_err());
    }
}
impl OutputSink {
    pub fn new(fd: OwnedFd, policy: OutputPolicy) -> Result<Self> {
        if matches!(policy, OutputPolicy::Disabled) {
            return Ok(Self { fd, policy });
        }
        let stat = fs::fstat(&fd)?;
        if !matches!(
            FileType::from_raw_mode(stat.st_mode),
            FileType::RegularFile | FileType::Fifo | FileType::Socket
        ) {
            return Err(Error::Path);
        }
        let flags = fcntl_getfl(&fd)?;
        if flags.bits() & 0x3 == 0 {
            return Err(Error::Path);
        }
        fcntl_setfl(&fd, flags | OFlags::NONBLOCK)?;
        Ok(Self { fd, policy })
    }
    pub fn policy(&self) -> OutputPolicy {
        self.policy
    }
    pub fn write(&self, bytes: &[u8]) -> Result<usize> {
        if matches!(self.policy, OutputPolicy::Disabled) || bytes.is_empty() {
            return Ok(0);
        }
        let mut written = 0;
        while written < bytes.len() {
            match io::write(&self.fd, &bytes[written..]) {
                Ok(0) => return Err(Error::Config("output sink closed")),
                Ok(n) => written += n,
                Err(rustix::io::Errno::AGAIN) => {
                    return Err(Error::Config("output sink backpressure"));
                }
                Err(e) => return Err(Error::Kernel(e)),
            }
        }
        Ok(written)
    }
    pub fn as_fd(&self) -> impl AsFd + '_ {
        &self.fd
    }
}
