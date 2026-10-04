//! Bounded VMM boot and authenticated guest readiness.
use super::{LaunchInputs, LaunchJournal, LaunchResult, launch};
use crate::{
    error::{Error, Result},
    guest::{GuestConnection, GuestEndpoint},
    process::ProcessIdentity,
};
use guest_protocol::SessionIdentity;
use sandboxd_protocol::OperationId;
use std::time::{Duration, Instant};
use tokio::time::sleep;

/// Durable transitions required after the VMM process is captured.
pub trait BootJournal: LaunchJournal {
    fn record_vmm_booting(&mut self, process: &ProcessIdentity) -> Result<()>;
    fn record_guest_handshake(&mut self, process: &ProcessIdentity) -> Result<()>;
    fn record_guest_ready(
        &mut self,
        process: &ProcessIdentity,
        identity: &SessionIdentity,
    ) -> Result<()>;
}

pub struct BootInputs<'a> {
    pub launch: LaunchInputs<'a>,
    pub expected_guest: SessionIdentity,
    pub handshake_operation: OperationId,
    pub restore_identity: Option<SessionIdentity>,
}

pub struct BootResult {
    pub launch: LaunchResult,
    pub guest: GuestConnection,
}

/// Launches through the mandatory jailer path, then waits for a pinned
/// endpoint and a complete identity-authenticated guest READY handshake.
pub async fn boot(input: BootInputs<'_>, journal: &mut dyn BootJournal) -> Result<BootResult> {
    input
        .expected_guest
        .authenticate(&super::arguments::identity(input.launch.intent))
        .map_err(|_| Error::Config("guest identity differs from durable session intent"))?;
    let deadline = Instant::now() + input.launch.timeout;
    #[cfg(target_os = "linux")]
    let (guest_uid, guest_gid) = (input.launch.intent.uid, input.launch.intent.gid);
    let restoring = input.restore_identity.is_some();
    let network = input.launch.network.clone();
    let volumes = input.launch.volumes.clone();
    let launched = launch(input.launch, journal).await?;
    if let Err(error) = journal.record_vmm_booting(&launched.process) {
        return stop_on_error(&launched.process, Err(error)).await;
    }
    #[cfg(target_os = "linux")]
    let endpoint = stop_on_error(
        &launched.process,
        wait_endpoint(&launched, guest_uid, guest_gid, deadline).await,
    )
    .await?;
    #[cfg(not(target_os = "linux"))]
    let endpoint =
        stop_on_error(&launched.process, wait_endpoint(&launched, deadline).await).await?;
    if let Err(error) = journal.record_guest_handshake(&launched.process) {
        return stop_on_error(&launched.process, Err(error)).await;
    }
    let guest = if let Some(old) = input.restore_identity {
        let quarantine = stop_on_error(
            &launched.process,
            connect_guest(
                &endpoint,
                &launched.process,
                old.clone(),
                OperationId::new("restore-quarantine").map_err(|_| Error::State)?,
                deadline,
            )
            .await,
        )
        .await?;
        quarantine
            .rebind_with_process_timeout(
                &endpoint,
                old,
                input.expected_guest.clone(),
                input.handshake_operation,
                remaining(deadline)?,
                &launched.process,
            )
            .await
    } else {
        connect_guest(
            &endpoint,
            &launched.process,
            input.expected_guest.clone(),
            input.handshake_operation,
            deadline,
        )
        .await
    };
    let guest = stop_on_error(&launched.process, guest).await?;
    if restoring {
        let reply = stop_on_error(
            &launched.process,
            guest
                .request(
                    OperationId::new("restore-thaw").map_err(|_| Error::State)?,
                    guest_protocol::GuestMessage::FilesystemUnquiesce,
                )
                .await,
        )
        .await?;
        if !matches!(reply.message, guest_protocol::GuestMessage::Ready) {
            return stop_on_error(&launched.process, Err(Error::State)).await;
        }
        for name in ["snapshot-freeze", "restore-thaw"] {
            let operation = OperationId::new(name).map_err(|_| Error::State)?;
            stop_on_error(
                &launched.process,
                guest
                    .request(
                        OperationId::new(format!("retire-{name}")).map_err(|_| Error::State)?,
                        guest_protocol::GuestMessage::RetireOperation { operation },
                    )
                    .await,
            )
            .await?;
        }
    }
    if !restoring && !volumes.is_empty() {
        let config = volumes
            .iter()
            .enumerate()
            .map(|(index, volume)| {
                Ok(guest_protocol::GuestVolumeConfig {
                    device_index: u8::try_from(index).map_err(|_| Error::State)?,
                    mount_point: volume.guest_mount_point.clone(),
                    filesystem: volume.filesystem.clone(),
                    read_only: volume.read_only,
                })
            })
            .collect::<Result<Vec<_>>>()?;
        let operation = OperationId::new("volumes-config")
            .map_err(|_| Error::Config("volume configuration operation ID invalid"))?;
        let reply = stop_on_error(
            &launched.process,
            guest
                .request(
                    operation,
                    guest_protocol::GuestMessage::ConfigureVolumes { volumes: config },
                )
                .await
                .map_err(|_| Error::Config("guest volume configuration failed")),
        )
        .await?;
        if !matches!(reply.message, guest_protocol::GuestMessage::Ready) {
            return stop_on_error(
                &launched.process,
                Err(Error::Config("guest volume configuration rejected")),
            )
            .await;
        }
    }
    if let sandboxd_protocol::NetworkMode::ExternalAttachment(attachment) = &network {
        let config = crate::network::guest_config(attachment).map_err(Error::Config)?;
        let operation = OperationId::new("network-config")
            .map_err(|_| Error::Config("network operation ID invalid"))?;
        let reply = stop_on_error(
            &launched.process,
            guest
                .request(
                    operation,
                    guest_protocol::GuestMessage::ConfigureNetwork { config },
                )
                .await
                .map_err(|_| Error::Config("guest network configuration failed")),
        )
        .await?;
        if !matches!(reply.message, guest_protocol::GuestMessage::Ready) {
            return stop_on_error(
                &launched.process,
                Err(Error::Config("guest network configuration rejected")),
            )
            .await;
        }
    }
    if let Err(error) = journal.record_guest_ready(&launched.process, &input.expected_guest) {
        return stop_on_error(&launched.process, Err(error)).await;
    }
    Ok(BootResult {
        launch: launched,
        guest,
    })
}

#[cfg(target_os = "linux")]
async fn wait_endpoint(
    launched: &LaunchResult,
    uid: u32,
    gid: u32,
    deadline: Instant,
) -> Result<GuestEndpoint> {
    loop {
        #[cfg(target_os = "linux")]
        let observed = GuestEndpoint::observed_for_session(
            &launched.vsock_socket,
            &launched.manifest,
            uid,
            gid,
        );
        #[cfg(not(target_os = "linux"))]
        let observed = GuestEndpoint::observed(&launched.vsock_socket);
        match observed {
            Ok(endpoint) => return Ok(endpoint),
            Err(_) if Instant::now() < deadline => sleep(Duration::from_millis(10)).await,
            Err(_) => return Err(Error::Config("guest vsock endpoint readiness timeout")),
        }
    }
}

#[cfg(not(target_os = "linux"))]
async fn wait_endpoint(launched: &LaunchResult, deadline: Instant) -> Result<GuestEndpoint> {
    loop {
        match GuestEndpoint::observed(&launched.vsock_socket) {
            Ok(endpoint) => return Ok(endpoint),
            Err(_) if Instant::now() < deadline => sleep(Duration::from_millis(10)).await,
            Err(_) => return Err(Error::Config("guest vsock endpoint readiness timeout")),
        }
    }
}

async fn connect_guest(
    endpoint: &GuestEndpoint,
    process: &ProcessIdentity,
    expected: SessionIdentity,
    operation: OperationId,
    deadline: Instant,
) -> Result<GuestConnection> {
    GuestConnection::connect_with_process_timeout(
        endpoint,
        expected,
        operation,
        remaining(deadline)?,
        process,
    )
    .await
}

fn remaining(deadline: Instant) -> Result<Duration> {
    deadline
        .checked_duration_since(Instant::now())
        .ok_or(Error::Config("guest boot deadline exceeded"))
}

async fn stop_on_error<T>(process: &ProcessIdentity, result: Result<T>) -> Result<T> {
    match result {
        Ok(value) => Ok(value),
        Err(error) => {
            super::cleanup::terminate_and_wait(process).await?;
            Err(error)
        }
    }
}
