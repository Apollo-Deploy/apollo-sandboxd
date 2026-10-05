use crate::{config::Config, doctor, error::Result, security::peer::Peer, state::Store};
use sandboxd_protocol::*;
use std::time::{SystemTime, UNIX_EPOCH};

pub fn now_ms() -> Result<u64> {
    let elapsed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| crate::error::Error::State)?;
    u64::try_from(elapsed.as_millis()).map_err(|_| crate::error::Error::State)
}
pub fn dispatch(
    store: &mut Store,
    config: &Config,
    peer: Peer,
    request: Request,
) -> Result<Response> {
    if let Some(response) = stateless(config, &request) {
        return Ok(response);
    }
    match request {
        Request::SnapshotInspect { id } => {
            Ok(Response::Snapshot(store.inspect_snapshot(peer.uid, &id)?))
        }
        Request::SnapshotList {
            sandbox,
            after,
            limit,
        } => Ok(Response::Snapshots(store.list_snapshots(
            peer.uid,
            &sandbox,
            after.as_ref(),
            limit,
        )?)),
        Request::Inspect { sandbox } => Ok(Response::Sandbox(Box::new(
            store.inspect(peer.uid, &sandbox)?,
        ))),
        Request::List { after, limit } => Ok(Response::Sandboxes(store.list(
            peer.uid,
            after.as_ref(),
            limit,
        )?)),
        Request::Events {
            from_sequence,
            limit,
        } => Ok(Response::Events(store.events(
            peer.uid,
            from_sequence,
            limit,
        )?)),
        Request::OperationInspect {
            operation,
            operation_sequence,
        } => Ok(Response::OperationReceipt(Box::new(
            store.inspect_operation(peer.uid, &operation, operation_sequence)?,
        ))),
        Request::OperationWatermark => Ok(Response::OperationWatermark {
            accepted_sequence: store.operation_watermark(peer.uid)?,
        }),
        Request::Mutate {
            operation,
            operation_sequence,
            mutation,
        } => store.mutate_checked_sequenced(
            peer.uid,
            &operation,
            &mutation,
            now_ms()?,
            Some(operation_sequence),
            || {
                if let Mutation::Create { spec, .. } = mutation.as_ref() {
                    let runtime = config.runtimes.iter().any(|r| {
                        r.name == spec.runtime_profile && r.architecture == spec.architecture
                    });
                    let kernel = config.kernels.iter().any(|k| {
                        k.name == spec.kernel_profile && k.architecture == spec.architecture
                    });
                    if !runtime || !kernel {
                        return Err(ApiError::new(
                            ErrorCode::RuntimeProfileInvalid,
                            "sandbox catalog selection not allowed",
                        )
                        .into());
                    }
                }
                Ok(())
            },
        ),
        Request::Guest { .. } => Err(ApiError::new(
            ErrorCode::UnsupportedCapability,
            "verified runtime service is unavailable",
        )
        .into()),
        _ => Err(crate::error::Error::State),
    }
}

/// These responses describe the administrative API and never wait for SQLite.
pub fn stateless(config: &Config, request: &Request) -> Option<Response> {
    match request {
        Request::Capabilities => Some(Response::Capabilities(Capabilities {
            protocol_version: PROTOCOL_VERSION,
            architecture: if std::env::consts::ARCH == "x86_64" {
                Architecture::X86_64
            } else {
                Architecture::Aarch64
            },
            kvm_available: doctor::kvm_available(),
            runtime_profiles: config.runtimes.iter().map(|p| p.name.clone()).collect(),
            supported: [
                "durable_identity_metadata",
                "generation_fencing",
                "operation_receipts",
                "finite_lease_metadata",
                "bounded_events",
            ]
            .iter()
            .map(|s| (*s).into())
            .collect(),
            qualification: "APOLLO_SANDBOXD_PRODUCTION_PARTIAL".into(),
        })),
        Request::Health => Some(Response::Health(Health {
            daemon: "ADMINISTRATIVE_ONLY".into(),
            storage: "OPEN".into(),
            runtime: "EXECUTION_UNAVAILABLE".into(),
            guest: "NOT_IMPLEMENTED".into(),
        })),
        Request::RuntimeList => Some(Response::RuntimeList(
            config.runtimes.iter().map(|p| p.name.clone()).collect(),
        )),
        _ => None,
    }
}
