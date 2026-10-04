use crate::config::Security;
use sandboxd_protocol::{ApiError, ErrorCode};

#[derive(Clone, Copy, Debug)]
pub struct Peer {
    pub uid: u32,
    pub gid: u32,
    pub pid: u32,
}
impl Peer {
    pub fn authorize(self, policy: &Security) -> Result<Self, ApiError> {
        let daemon_uid = rustix::process::geteuid().as_raw();
        let uid_ok = policy.allowed_uids.is_empty() || policy.allowed_uids.contains(&self.uid);
        let gid_ok = policy.allowed_gids.is_empty() || policy.allowed_gids.contains(&self.gid);
        let pid_ok = policy.allowed_pids.is_empty() || policy.allowed_pids.contains(&self.pid);
        if (policy.allowed_uids.is_empty() && policy.allowed_gids.is_empty())
            || (daemon_uid != 0 && self.uid == daemon_uid)
            || !uid_ok
            || !gid_ok
            || !pid_ok
        {
            return Err(ApiError::new(
                ErrorCode::Unauthorized,
                "peer credentials rejected",
            ));
        }
        Ok(self)
    }
    #[cfg(target_os = "linux")]
    pub fn from_stream(stream: &tokio::net::UnixStream) -> crate::error::Result<Self> {
        let cred = rustix::net::sockopt::socket_peercred(stream)?;
        let pid = u32::try_from(cred.pid.as_raw_nonzero().get())
            .map_err(|_| crate::error::Error::Path)?;
        Ok(Self {
            uid: cred.uid.as_raw(),
            gid: cred.gid.as_raw(),
            pid,
        })
    }
    #[cfg(not(target_os = "linux"))]
    pub fn from_stream(_: &tokio::net::UnixStream) -> crate::error::Result<Self> {
        Err(ApiError::new(ErrorCode::UnsupportedHost, "SO_PEERCRED requires Linux").into())
    }
}
