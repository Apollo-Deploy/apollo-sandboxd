//! One-request Unix transport with optional SCM_RIGHTS output sinks.
use crate::error::{Error, Result};
use nix::sys::socket::{ControlMessage, ControlMessageOwned, MsgFlags, recvmsg, sendmsg};
use sandboxd_protocol::{GuestCommand, Request, codec, exec::OutputPolicy};
use std::io::{IoSlice, IoSliceMut};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

const MAX_FDS: usize = 2;
// Linux SCM_MAX_FD is 253; allocating that bounded control space means a
// valid SCM_RIGHTS message cannot be truncated before we adopt its FDs.
const RECV_FD_CAP: usize = 253;
const REQUEST_LIMIT: usize = 131_072;

pub fn validate_fd_count(request: &Request, count: usize) -> Result<()> {
    if count > MAX_FDS {
        return Err(Error::Path);
    }
    let exec_start = matches!(request, Request::Guest { command, .. }
        if matches!(command.as_ref(), GuestCommand::ExecStart { .. }));
    if let Request::Volume { command, .. } = request {
        let expected = usize::from(matches!(
            command.as_ref(),
            sandboxd_protocol::VolumeCommand::Import { .. }
        ));
        return if count == expected {
            Ok(())
        } else {
            Err(Error::Path)
        };
    }
    if !exec_start && count != 0 {
        return Err(Error::Path);
    }
    if let Request::Guest { command, .. } = request
        && let GuestCommand::ExecStart { spec } = command.as_ref()
        && matches!(spec.output_policy, OutputPolicy::Required)
        && count != 2
    {
        return Err(Error::Path);
    }
    Ok(())
}

#[cfg(test)]
#[allow(unsafe_code)]
pub fn recv_request_blocking(
    stream: &std::os::unix::net::UnixStream,
) -> Result<(u64, Request, Vec<OwnedFd>)> {
    use std::io::Read;
    let mut first = vec![0u8; 8192];
    let mut control = nix::cmsg_space!([RawFd; RECV_FD_CAP]);
    let mut iov = [IoSliceMut::new(&mut first)];
    #[cfg(target_os = "linux")]
    let flags = MsgFlags::MSG_CMSG_CLOEXEC;
    #[cfg(not(target_os = "linux"))]
    let flags = MsgFlags::empty();
    let (received, truncated, fds) = {
        let message = recvmsg::<()>(stream.as_raw_fd(), &mut iov, Some(&mut control), flags)
            .map_err(|_| Error::State)?;
        if message.bytes == 0 {
            return Err(Error::State);
        }
        // Adopt every descriptor before validating count/truncation. OwnedFd
        // closes all received rights if any later validation rejects the frame.
        let mut raw_fds = Vec::new();
        for item in message.cmsgs().map_err(|_| Error::State)? {
            if let ControlMessageOwned::ScmRights(values) = item {
                raw_fds.extend(values);
            }
        }
        // Adopt all kernel-installed descriptors before any fallible flag
        // operation. A later CLOEXEC failure must not leak the remainder.
        let fds = raw_fds
            .into_iter()
            .map(|raw| unsafe { OwnedFd::from_raw_fd(raw) })
            .collect::<Vec<_>>();
        for fd in &fds {
            rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::CLOEXEC).map_err(|_| Error::Path)?;
        }
        (
            message.bytes,
            message.flags.contains(MsgFlags::MSG_CTRUNC),
            fds,
        )
    };
    drop(iov);
    if truncated || fds.len() > MAX_FDS {
        return Err(Error::Path);
    }
    let mut bytes = first[..received].to_vec();
    let mut reader = stream;
    if bytes.len() < codec::HEADER_BYTES {
        let old_len = bytes.len();
        bytes.resize(codec::HEADER_BYTES, 0);
        reader
            .read_exact(&mut bytes[old_len..])
            .map_err(|_| Error::State)?;
    }
    let mut header = [0u8; codec::HEADER_BYTES];
    header.copy_from_slice(&bytes[..codec::HEADER_BYTES]);
    let parsed = codec::Header::decode_limited(header, REQUEST_LIMIT).map_err(|_| Error::State)?;
    let total = codec::HEADER_BYTES
        .checked_add(parsed.body_len as usize)
        .ok_or(Error::Path)?;
    if total > REQUEST_LIMIT + codec::HEADER_BYTES {
        return Err(Error::Path);
    }
    if bytes.len() < total {
        let old_len = bytes.len();
        bytes.resize(total, 0);
        reader
            .read_exact(&mut bytes[old_len..])
            .map_err(|_| Error::State)?;
    }
    if bytes.len() != total {
        return Err(Error::State);
    }
    let request =
        codec::decode_body(&bytes[codec::HEADER_BYTES..total]).map_err(|_| Error::State)?;
    Ok((parsed.request_id, request, fds))
}

pub async fn recv_request(
    stream: &mut tokio::net::UnixStream,
) -> Result<(u64, Request, Vec<OwnedFd>)> {
    recv_frame(stream).await
}

#[allow(unsafe_code)]
/// Receives one bounded request without blocking a Tokio worker. SCM_RIGHTS
/// must accompany the first bytes; the remainder is ordinary stream data.
pub(super) async fn recv_frame<T: serde::de::DeserializeOwned>(
    stream: &mut tokio::net::UnixStream,
) -> Result<(u64, T, Vec<OwnedFd>)> {
    use std::io;
    use tokio::io::AsyncReadExt;
    use tokio::io::Interest;
    let mut first = vec![0u8; 8192];
    let mut control = nix::cmsg_space!([RawFd; RECV_FD_CAP]);
    let (received, truncated, fds) = loop {
        stream.readable().await.map_err(|_| Error::State)?;
        let mut iov = [IoSliceMut::new(&mut first)];
        let result = stream.try_io(Interest::READABLE, || {
            #[cfg(target_os = "linux")]
            let flags = MsgFlags::MSG_CMSG_CLOEXEC;
            #[cfg(not(target_os = "linux"))]
            let flags = MsgFlags::empty();
            recvmsg::<()>(stream.as_raw_fd(), &mut iov, Some(&mut control), flags)
                .map_err(|error| io::Error::from_raw_os_error(error as i32))
        });
        match result {
            Ok(message) => {
                if message.bytes == 0 {
                    return Err(Error::State);
                }
                let received = message.bytes;
                let truncated = message.flags.contains(MsgFlags::MSG_CTRUNC);
                // The enlarged bounded control area lets normal over-limit
                // requests (up to RECV_FD_CAP) be adopted and closed safely.
                let mut raw_fds = Vec::new();
                for item in message.cmsgs().map_err(|_| Error::Path)? {
                    if let ControlMessageOwned::ScmRights(values) = item {
                        raw_fds.extend(values);
                    }
                }
                let fds = raw_fds
                    .into_iter()
                    .map(|raw| unsafe { OwnedFd::from_raw_fd(raw) })
                    .collect::<Vec<_>>();
                for fd in &fds {
                    rustix::io::fcntl_setfd(fd, rustix::io::FdFlags::CLOEXEC)
                        .map_err(|_| Error::Path)?;
                }
                break (received, truncated, fds);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => return Err(Error::State),
        }
    };
    if truncated || fds.len() > MAX_FDS {
        return Err(Error::Path);
    }
    let mut bytes = first[..received].to_vec();
    if bytes.len() < codec::HEADER_BYTES {
        let old_len = bytes.len();
        bytes.resize(codec::HEADER_BYTES, 0);
        stream
            .read_exact(&mut bytes[old_len..])
            .await
            .map_err(|_| Error::State)?;
    }
    let mut header = [0u8; codec::HEADER_BYTES];
    header.copy_from_slice(&bytes[..codec::HEADER_BYTES]);
    let parsed = codec::Header::decode_limited(header, REQUEST_LIMIT).map_err(|_| Error::State)?;
    let total = codec::HEADER_BYTES
        .checked_add(parsed.body_len as usize)
        .ok_or(Error::Path)?;
    if total > REQUEST_LIMIT + codec::HEADER_BYTES {
        return Err(Error::Path);
    }
    if bytes.len() < total {
        let old_len = bytes.len();
        bytes.resize(total, 0);
        stream
            .read_exact(&mut bytes[old_len..])
            .await
            .map_err(|_| Error::State)?;
    }
    if bytes.len() != total {
        return Err(Error::State);
    }
    let request =
        codec::decode_body(&bytes[codec::HEADER_BYTES..total]).map_err(|_| Error::State)?;
    Ok((parsed.request_id, request, fds))
}

pub fn send_request(
    stream: &std::os::unix::net::UnixStream,
    id: u64,
    request: &Request,
    fds: &[RawFd],
) -> Result<()> {
    use std::io::Write;
    if fds.len() > MAX_FDS {
        return Err(Error::Path);
    }
    let (header, body) = codec::encode_frame_parts(id, request).map_err(|_| Error::State)?;
    let total = header.len() + body.len();
    let iov = [IoSlice::new(&header), IoSlice::new(&body)];
    let controls = if fds.is_empty() {
        Vec::new()
    } else {
        vec![ControlMessage::ScmRights(fds)]
    };
    let sent = sendmsg::<()>(stream.as_raw_fd(), &iov, &controls, MsgFlags::empty(), None)
        .map_err(|_| Error::State)?;
    if sent > total {
        return Err(Error::State);
    }
    // SCM_RIGHTS must be sent only once. Complete a short stream write with
    // plain bytes; repeating sendmsg would duplicate the descriptors.
    if sent < total {
        let mut remainder = Vec::with_capacity(total - sent);
        remainder.extend_from_slice(&header);
        remainder.extend_from_slice(&body);
        stream
            .try_clone()
            .map_err(|_| Error::State)?
            .write_all(&remainder[sent..])
            .map_err(|_| Error::State)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::fd::AsRawFd;

    #[test]
    fn round_trips_two_real_rights_descriptors() {
        let (left, right) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        let first = tempfile::tempfile().expect("first sink");
        let second = tempfile::tempfile().expect("second sink");
        send_request(
            &left,
            7,
            &Request::Capabilities,
            &[first.as_raw_fd(), second.as_raw_fd()],
        )
        .expect("sendmsg");
        let (id, request, fds) = recv_request_blocking(&right).expect("recvmsg");
        assert_eq!(id, 7);
        assert_eq!(request, Request::Capabilities);
        assert_eq!(fds.len(), 2);
        for fd in fds {
            let stat = rustix::fs::fstat(&fd).expect("received fd stat");
            assert_eq!(
                rustix::fs::FileType::from_raw_mode(stat.st_mode),
                rustix::fs::FileType::RegularFile
            );
        }
    }

    #[test]
    fn accepts_fragmented_stream_frame() {
        use std::io::Write;
        let (left, right) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        let (header, body) =
            codec::encode_frame_parts(9, &Request::Capabilities).expect("encode frame");
        let mut frame = header.to_vec();
        frame.extend_from_slice(&body);
        let split = codec::HEADER_BYTES.min(frame.len());
        let mut writer = left;
        writer.write_all(&frame[..split]).expect("header fragment");
        writer.write_all(&frame[split..]).expect("body fragment");
        let (id, request, fds) = recv_request_blocking(&right).expect("fragmented frame");
        assert_eq!(id, 9);
        assert_eq!(request, Request::Capabilities);
        assert!(fds.is_empty());
    }

    #[test]
    fn accepts_delayed_fragment_without_coalescing() {
        use std::io::Write;
        use std::time::Duration;
        let (mut left, right) = std::os::unix::net::UnixStream::pair().expect("socket pair");
        right
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("read timeout");
        let (header, body) =
            codec::encode_frame_parts(10, &Request::Capabilities).expect("encode frame");
        let sender = std::thread::spawn(move || {
            left.write_all(&header[..1]).expect("first byte");
            std::thread::sleep(Duration::from_millis(25));
            left.write_all(&header[1..]).expect("header remainder");
            left.write_all(&body).expect("body");
        });
        let (id, request, fds) = recv_request_blocking(&right).expect("delayed frame");
        sender.join().expect("sender");
        assert_eq!(id, 10);
        assert_eq!(request, Request::Capabilities);
        assert!(fds.is_empty());
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn async_receiver_rejects_three_rights_without_fd_leak() {
        use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
        use std::io::IoSlice;
        use std::os::fd::AsRawFd;
        let (left, mut right) = tokio::net::UnixStream::pair().expect("socket pair");
        let sender = left.into_std().expect("sender std");
        let files = (0..3)
            .map(|_| tempfile::tempfile().expect("sink"))
            .collect::<Vec<_>>();
        let rights = files.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
        let iov = [IoSlice::new(b"x")];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &iov,
            &[ControlMessage::ScmRights(&rights)],
            MsgFlags::empty(),
            None,
        )
        .expect("send rights");
        drop(sender);
        assert!(recv_request(&mut right).await.is_err());
        assert_only_original_rights(&files);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn async_receiver_rejects_max_rights_without_fd_leak() {
        use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
        use std::io::IoSlice;
        use std::os::fd::AsRawFd;
        let (left, mut right) = tokio::net::UnixStream::pair().expect("socket pair");
        let sender = left.into_std().expect("sender std");
        let files = (0..253)
            .map(|_| tempfile::tempfile().expect("sink"))
            .collect::<Vec<_>>();
        let rights = files.iter().map(AsRawFd::as_raw_fd).collect::<Vec<_>>();
        let iov = [IoSlice::new(b"x")];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &iov,
            &[ControlMessage::ScmRights(&rights)],
            MsgFlags::empty(),
            None,
        )
        .expect("send max rights");
        drop(sender);
        assert!(recv_request(&mut right).await.is_err());
        assert_only_original_rights(&files);
    }

    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn async_receiver_closes_rights_when_frame_ends_early() {
        use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
        use std::io::IoSlice;
        use std::os::fd::AsRawFd;
        let (left, mut right) = tokio::net::UnixStream::pair().expect("socket pair");
        let sender = left.into_std().expect("sender std");
        let file = tempfile::tempfile().expect("sink");
        let iov = [IoSlice::new(b"x")];
        sendmsg::<()>(
            sender.as_raw_fd(),
            &iov,
            &[ControlMessage::ScmRights(&[file.as_raw_fd()])],
            MsgFlags::empty(),
            None,
        )
        .expect("send rights");
        drop(sender);
        assert!(recv_request(&mut right).await.is_err());
        assert_only_original_rights(std::slice::from_ref(&file));
    }

    #[tokio::test]
    async fn async_receiver_handles_delayed_fragment() {
        use tokio::io::AsyncWriteExt;
        use tokio::time::{Duration, sleep};
        let (mut left, mut right) = tokio::net::UnixStream::pair().expect("socket pair");
        let (header, body) =
            codec::encode_frame_parts(11, &Request::Capabilities).expect("encode frame");
        let sender = tokio::spawn(async move {
            left.write_all(&header[..1]).await.expect("first byte");
            sleep(Duration::from_millis(25)).await;
            left.write_all(&header[1..])
                .await
                .expect("header remainder");
            left.write_all(&body).await.expect("body");
        });
        let (id, request, fds) = recv_request(&mut right).await.expect("async frame");
        sender.await.expect("sender");
        assert_eq!(id, 11);
        assert_eq!(request, Request::Capabilities);
        assert!(fds.is_empty());
    }

    #[cfg(target_os = "linux")]
    fn assert_only_original_rights(files: &[std::fs::File]) {
        use std::collections::BTreeMap;
        use std::os::unix::fs::MetadataExt;
        // Process-wide counts race with other tests and include the receiving
        // socket. These originals stay alive to prevent inode reuse instead.
        let mut counts = BTreeMap::new();
        for file in files {
            let meta = file.metadata().expect("sink identity");
            assert!(counts.insert((meta.dev(), meta.ino()), 0usize).is_none());
        }
        for entry in std::fs::read_dir("/proc/self/fd").expect("fd directory") {
            let path = entry.expect("fd entry").path();
            if let Ok(meta) = std::fs::metadata(path) {
                if let Some(count) = counts.get_mut(&(meta.dev(), meta.ino())) {
                    *count += 1;
                }
            }
        }
        assert!(
            counts.values().all(|count| *count == 1),
            "SCM_RIGHTS leak: {counts:?}"
        );
    }

    #[test]
    fn descriptors_are_forbidden_on_non_exec_requests() {
        assert!(validate_fd_count(&Request::Capabilities, 1).is_err());
        assert!(validate_fd_count(&Request::Capabilities, 3).is_err());
    }
}
