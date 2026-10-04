use crate::{Error, devices::*, http, snapshot::*};
use serde::{Serialize, de::DeserializeOwned};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{io::AsyncWriteExt, net::UnixStream, time::timeout};

#[derive(Clone, Debug)]
pub struct Client {
    socket: PathBuf,
    deadline: Duration,
    peer_pid: Option<u32>,
}
impl Client {
    pub fn new(socket: impl AsRef<Path>, deadline: Duration) -> Result<Self, Error> {
        if !socket.as_ref().is_absolute()
            || deadline.is_zero()
            || deadline > Duration::from_secs(300)
        {
            return Err(Error::Request);
        }
        Ok(Self {
            socket: socket.as_ref().into(),
            deadline,
            peer_pid: None,
        })
    }
    /// Every request authenticates the Unix socket's actual process peer.
    pub fn with_peer(mut self, pid: u32) -> Result<Self, Error> {
        if !cfg!(target_os = "linux") || pid == 0 || pid > i32::MAX as u32 {
            return Err(Error::Request);
        }
        self.peer_pid = Some(pid);
        Ok(self)
    }
    async fn request<T: Serialize>(
        &self,
        method: &str,
        path: &str,
        value: Option<&T>,
    ) -> Result<Vec<u8>, Error> {
        let body = match value {
            Some(value) => serde_json::to_vec(value).map_err(|_| Error::Request)?,
            None => Vec::new(),
        };
        if body.len() > http::MAX_RESPONSE {
            return Err(Error::Request);
        }
        timeout(self.deadline, async {
            let mut stream = UnixStream::connect(&self.socket).await?;
            #[cfg(target_os="linux")]
            if self.peer_pid.is_some_and(|expected| stream.peer_cred()
                .ok().and_then(|peer| peer.pid()).and_then(|pid| u32::try_from(pid).ok()) != Some(expected)) {
                return Err(Error::Response);
            }
            let header = format!("{method} {path} HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n", body.len());
            stream.write_all(header.as_bytes()).await?;
            stream.write_all(&body).await?;
            let (code, response) = http::read_response(&mut stream).await?;
            if !(200..=299).contains(&code) { return Err(Error::Status(code)); }
            Ok(response)
        }).await.map_err(|_| Error::Timeout)?
    }
    async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, Error> {
        let bytes = self.request::<()>("GET", path, None).await?;
        serde_json::from_slice(&bytes).map_err(|_| Error::Response)
    }
    pub async fn version(&self) -> Result<Version, Error> {
        self.get("/version").await
    }
    pub async fn instance_info(&self) -> Result<InstanceInfo, Error> {
        self.get("/").await
    }
    pub async fn machine(&self, value: &MachineConfiguration) -> Result<(), Error> {
        if value.vcpu_count == 0
            || value.vcpu_count > 32
            || value.mem_size_mib == 0
            || (value.smt && value.vcpu_count != 1 && !value.vcpu_count.is_multiple_of(2))
        {
            return Err(Error::Request);
        }
        self.request("PUT", "/machine-config", Some(value))
            .await
            .map(|_| ())
    }
    pub async fn boot_source(&self, value: &BootSource) -> Result<(), Error> {
        self.request("PUT", "/boot-source", Some(value))
            .await
            .map(|_| ())
    }
    pub async fn serial(&self, value: &SerialDevice) -> Result<(), Error> {
        self.request("PUT", "/serial", Some(value))
            .await
            .map(|_| ())
    }
    pub async fn drive(&self, value: &Drive) -> Result<(), Error> {
        if !valid_id(&value.drive_id) {
            return Err(Error::Request);
        }
        self.request("PUT", &format!("/drives/{}", value.drive_id), Some(value))
            .await
            .map(|_| ())
    }
    pub async fn network(&self, value: &NetworkInterface) -> Result<(), Error> {
        if !valid_id(&value.iface_id) {
            return Err(Error::Request);
        }
        self.request(
            "PUT",
            &format!("/network-interfaces/{}", value.iface_id),
            Some(value),
        )
        .await
        .map(|_| ())
    }
    pub async fn vsock(&self, value: &Vsock) -> Result<(), Error> {
        if value.guest_cid < 3 || value.guest_cid == u32::MAX {
            return Err(Error::Request);
        }
        self.request("PUT", "/vsock", Some(value)).await.map(|_| ())
    }
    pub async fn balloon(&self, value: &Balloon) -> Result<(), Error> {
        self.request("PUT", "/balloon", Some(value))
            .await
            .map(|_| ())
    }
    pub async fn entropy(&self, value: &Entropy) -> Result<(), Error> {
        self.request("PUT", "/entropy", Some(value))
            .await
            .map(|_| ())
    }
    pub async fn logger(&self, value: &Logger) -> Result<(), Error> {
        self.request("PUT", "/logger", Some(value))
            .await
            .map(|_| ())
    }
    pub async fn metrics(&self, value: &Metrics) -> Result<(), Error> {
        self.request("PUT", "/metrics", Some(value))
            .await
            .map(|_| ())
    }
    pub async fn mmds_config(&self, value: &MmdsConfig) -> Result<(), Error> {
        self.request("PUT", "/mmds/config", Some(value))
            .await
            .map(|_| ())
    }
    pub async fn start(&self) -> Result<(), Error> {
        #[derive(Serialize)]
        struct Action {
            action_type: &'static str,
        }
        self.request(
            "PUT",
            "/actions",
            Some(&Action {
                action_type: "InstanceStart",
            }),
        )
        .await
        .map(|_| ())
    }
    pub async fn pause(&self) -> Result<(), Error> {
        self.vm_state("Paused").await
    }
    pub async fn resume(&self) -> Result<(), Error> {
        self.vm_state("Resumed").await
    }
    async fn vm_state(&self, state: &str) -> Result<(), Error> {
        #[derive(Serialize)]
        struct State<'a> {
            state: &'a str,
        }
        self.request("PATCH", "/vm", Some(&State { state }))
            .await
            .map(|_| ())
    }
    pub async fn snapshot_create(&self, value: &SnapshotCreate) -> Result<(), Error> {
        if !value.sync_snapshot_files {
            return Err(Error::Request);
        }
        self.request("PUT", "/snapshot/create", Some(value))
            .await
            .map(|_| ())
    }
    pub async fn snapshot_load(&self, value: &SnapshotLoad) -> Result<(), Error> {
        if value.enable_diff_snapshots {
            return Err(Error::Request);
        }
        self.request("PUT", "/snapshot/load", Some(value))
            .await
            .map(|_| ())
    }
}
