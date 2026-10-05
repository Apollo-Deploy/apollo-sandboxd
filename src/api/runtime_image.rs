//! Prepared image API dispatch kept separate from VM lifecycle code.
use super::runtime_service::RuntimeService;
use crate::security::peer::Peer;
use crate::{
    error::{Error, Result},
    state::PreparedImageRecord,
};
use sandboxd_protocol::{
    ApiError, Architecture, ErrorCode, ImageCommand, ImageDigest, ImageInfo, Request, Response,
};
use tokio::time::Instant;

#[cfg(target_os = "linux")]
async fn import_prepared(
    runtime: &std::sync::Arc<RuntimeService>,
    owner_uid: u32,
    operation: &sandboxd_protocol::OperationId,
    prepared_artifact_id: String,
    manifest_digest: String,
    lease_id: String,
    architecture: Architecture,
) -> Result<ImageInfo> {
    let runtime = std::sync::Arc::clone(runtime);
    let operation = operation.clone();
    tokio::task::spawn_blocking(move || {
        import_prepared_sync(
            &runtime,
            owner_uid,
            &operation,
            &prepared_artifact_id,
            &manifest_digest,
            &lease_id,
            architecture,
        )
    })
    .await
    .map_err(|_| Error::State)?
}

#[cfg(not(target_os = "linux"))]
async fn import_prepared(
    _: &std::sync::Arc<RuntimeService>,
    _: u32,
    _: &sandboxd_protocol::OperationId,
    _: String,
    _: String,
    _: String,
    _: Architecture,
) -> Result<ImageInfo> {
    Err(Error::Config("Artifactd prepared imports require Linux"))
}

#[cfg(target_os = "linux")]
fn import_prepared_sync(
    runtime: &RuntimeService,
    owner_uid: u32,
    operation: &sandboxd_protocol::OperationId,
    prepared_artifact_id: &str,
    manifest_digest: &str,
    lease_id: &str,
    architecture: Architecture,
) -> Result<ImageInfo> {
    use artifactd_protocol::{
        Action, ArtifactDigest, BlobDigest, LeaseId, ManifestDigest, Platform, PreparedArtifactId,
    };
    use std::io::Read;

    let settings = runtime.authority.artifactd_settings()?;
    let endpoint = &settings;
    let platform_arch = match architecture {
        Architecture::X86_64 => "amd64",
        Architecture::Aarch64 => "arm64",
    };
    if platform_arch != crate::image::host_oci_architecture() {
        return Err(Error::Config(
            "prepared image architecture differs from host",
        ));
    }
    let artifact_id =
        PreparedArtifactId::try_from(prepared_artifact_id.to_owned()).map_err(|_| Error::Path)?;
    let manifest: ArtifactDigest = manifest_digest.parse().map_err(|_| Error::Path)?;
    let lease: LeaseId = lease_id.to_owned().try_into().map_err(|_| Error::Path)?;
    let platform = Platform {
        os: "linux".into(),
        architecture: platform_arch.into(),
        variant: None,
    };
    let mut handoff = runtime.state.with_store_blocking({
        let operation = operation.clone();
        move |store| store.artifactd_image_handoff(owner_uid, &operation)
    })?;
    if handoff.is_none() {
        // Token allocation has no content effect. Persist every exact token and
        // the producer-issued lease before Resolve, OPEN_BLOB, OPEN_PREPARED,
        // or release can affect externally visible state.
        let fresh = crate::state::ArtifactdImageHandoff {
            prepared_artifact_id: prepared_artifact_id.to_owned(),
            manifest_digest: manifest_digest.to_owned(),
            lease_id: lease_id.to_owned(),
            architecture: platform_arch.to_owned(),
            resolve_operation: crate::image::artifactd::allocate(
                &endpoint.socket,
                endpoint.server_uid,
            )?,
            open_config_operation: crate::image::artifactd::allocate(
                &endpoint.socket,
                endpoint.server_uid,
            )?,
            open_prepared_operation: crate::image::artifactd::allocate(
                &endpoint.socket,
                endpoint.server_uid,
            )?,
            release_operation: crate::image::artifactd::allocate(
                &endpoint.socket,
                endpoint.server_uid,
            )?,
            phase: 0,
            layers: 0,
            config_json: None,
        };
        handoff = Some(runtime.state.with_store_blocking({
            let operation = operation.clone();
            move |store| store.create_artifactd_image_handoff(owner_uid, &operation, &fresh)
        })?);
    }
    let mut handoff = handoff.ok_or(Error::State)?;
    if handoff.prepared_artifact_id != prepared_artifact_id
        || handoff.manifest_digest != manifest_digest
        || handoff.lease_id != lease_id
        || handoff.architecture != platform_arch
    {
        return Err(Error::State);
    }

    if handoff.phase == 0 {
        let resolve_id =
            artifactd_protocol::OperationId::try_from(handoff.resolve_operation.clone())
                .map_err(|_| Error::State)?;
        let (resolved, _) = crate::image::artifactd::call(
            &endpoint.socket,
            endpoint.server_uid,
            resolve_id.as_str(),
            Action::Resolve {
                digest: manifest.clone(),
                platform: platform.clone(),
            },
            None,
        )?;
        if resolved
            .get("verified")
            .and_then(serde_json::Value::as_bool)
            != Some(true)
            || crate::image::artifactd::value_string(&resolved, "manifest_digest")?
                != manifest_digest
            || resolved
                .get("platform")
                .and_then(|value| value.get("architecture"))
                .and_then(serde_json::Value::as_str)
                != Some(platform_arch)
        {
            return Err(Error::Artifact(
                "Artifactd resolve facts do not match request",
            ));
        }
        let layers = resolved
            .get("layer_digests")
            .and_then(serde_json::Value::as_array)
            .ok_or(Error::State)?;
        if layers.is_empty() || layers.len() > 256 {
            return Err(Error::Path);
        }
        let config = resolved.get("config").ok_or(Error::State)?;
        let config_digest: BlobDigest = crate::image::artifactd::value_string(config, "digest")?
            .parse()
            .map_err(|_| Error::State)?;
        let config_size = crate::image::artifactd::value_u64(config, "size")?;
        if config_size == 0 || config_size > 65_536 {
            return Err(Error::Path);
        }
        let config_operation =
            artifactd_protocol::OperationId::try_from(handoff.open_config_operation.clone())
                .map_err(|_| Error::State)?;
        let (_, descriptor) = crate::image::artifactd::call(
            &endpoint.socket,
            endpoint.server_uid,
            config_operation.as_str(),
            Action::OpenBlob {
                digest: config_digest,
                lease: lease.clone(),
            },
            None,
        )?;
        let mut config_file = crate::image::artifactd::prepared_fd(descriptor)?;
        let stat = rustix::fs::fstat(&config_file)?;
        if rustix::fs::FileType::from_raw_mode(stat.st_mode) != rustix::fs::FileType::RegularFile
            || stat.st_uid != endpoint.server_uid
            || stat.st_size < 0
            || stat.st_size as u64 != config_size
            || stat.st_mode & 0o222 != 0
            || rustix::fs::fcntl_getfl(&config_file)? & rustix::fs::OFlags::ACCMODE
                != rustix::fs::OFlags::RDONLY
        {
            return Err(Error::Path);
        }
        let mut bytes = Vec::with_capacity(config_size as usize);
        config_file.take(config_size + 1).read_to_end(&mut bytes)?;
        if bytes.len() as u64 != config_size {
            return Err(Error::State);
        }
        let parsed: crate::image::ImageConfig = serde_json::from_slice(&bytes)
            .map_err(|_| Error::Artifact("OCI image configuration is invalid"))?;
        if parsed.architecture.as_deref() != Some(platform_arch)
            || parsed.os.as_deref() != Some("linux")
            || parsed.rootfs.kind.as_deref() != Some("layers")
            || parsed.rootfs.diff_ids.len() != layers.len()
        {
            return Err(Error::Artifact(
                "OCI config platform or layer count mismatch",
            ));
        }
        let config_json = serde_json::to_vec(&parsed).map_err(|_| Error::State)?;
        if config_json.len() > 65_536 {
            return Err(Error::Path);
        }
        handoff.phase = 1;
        handoff.layers = layers.len() as u32;
        handoff.config_json = Some(config_json);
        runtime.state.with_store_blocking({
            let operation = operation.clone();
            let handoff = handoff.clone();
            move |store| store.update_artifactd_image_handoff(owner_uid, &operation, &handoff)
        })?;
    }

    if handoff.phase < 2 {
        let destination = settings.prepared_root.join(
            manifest_digest
                .strip_prefix("sha256:")
                .ok_or(Error::State)?,
        );
        let size = u64::from(settings.prepared_size_mib) * 1_048_576;
        let formatter_sha256 = runtime.authority.execution.formatter_sha256.clone();
        let expected_config = handoff.config_json.clone().ok_or(Error::State)?;
        let existing = runtime.state.with_store_blocking({
            let digest = manifest_digest.to_owned();
            move |store| store.prepared_image(&digest)
        })?;
        if let Some(record) = existing {
            if record.architecture != platform_arch
                || record.rootfs_path != destination.to_string_lossy()
                || record.rootfs_size != size
                || record.formatter_sha256 != formatter_sha256
                || record.layers != handoff.layers
                || record.config_json.as_deref() != Some(expected_config.as_slice())
            {
                return Err(Error::State);
            }
            if record.published {
                let verified = crate::runtime::verify(&destination, &record.rootfs_sha256, false)?;
                if verified.size != record.rootfs_size
                    || verified.device != record.rootfs_device
                    || verified.inode != record.rootfs_inode
                {
                    return Err(Error::State);
                }
            } else if destination.exists() {
                let verified = crate::runtime::verify(&destination, &record.rootfs_sha256, false)?;
                if verified.size != record.rootfs_size
                    || verified.device != record.rootfs_device
                    || verified.inode != record.rootfs_inode
                {
                    return Err(Error::State);
                }
                runtime.state.with_store_blocking({
                    let digest = manifest_digest.to_owned();
                    move |store| store.publish_prepared_image(&digest)
                })?;
            } else {
                runtime.state.with_store_blocking({
                    let digest = manifest_digest.to_owned();
                    move |store| store.retire_unpublished_image(&digest)
                })?;
                prepare_from_artifactd_fd(
                    runtime,
                    &destination,
                    size,
                    &formatter_sha256,
                    &handoff,
                    &endpoint.socket,
                    endpoint.server_uid,
                    &artifact_id,
                    &manifest,
                    &lease,
                )?;
            }
        } else {
            prepare_from_artifactd_fd(
                runtime,
                &destination,
                size,
                &formatter_sha256,
                &handoff,
                &endpoint.socket,
                endpoint.server_uid,
                &artifact_id,
                &manifest,
                &lease,
            )?;
        }
        runtime
            .state
            .with_store_blocking({
                let digest = manifest_digest.to_owned();
                move |store| store.publish_prepared_image(&digest)
            })
            .or_else(|error| {
                // Existing published rows make publication idempotent.
                if runtime
                    .state
                    .with_store_blocking({
                        let digest = manifest_digest.to_owned();
                        move |store| store.prepared_image(&digest)
                    })?
                    .is_some_and(|record| record.published)
                {
                    Ok(())
                } else {
                    Err(error)
                }
            })?;
        handoff.phase = 2;
        runtime.state.with_store_blocking({
            let operation = operation.clone();
            let handoff = handoff.clone();
            move |store| store.update_artifactd_image_handoff(owner_uid, &operation, &handoff)
        })?;
    }

    if handoff.phase == 2 {
        let release_operation =
            artifactd_protocol::OperationId::try_from(handoff.release_operation.clone())
                .map_err(|_| Error::State)?;
        let (released, _) = crate::image::artifactd::call(
            &endpoint.socket,
            endpoint.server_uid,
            release_operation.as_str(),
            Action::LeaseRelease { id: lease },
            None,
        )?;
        if crate::image::artifactd::value_string(&released, "lease_id")? != lease_id {
            return Err(Error::State);
        }
        handoff.phase = 3;
        runtime.state.with_store_blocking({
            let operation = operation.clone();
            let handoff = handoff.clone();
            move |store| store.update_artifactd_image_handoff(owner_uid, &operation, &handoff)
        })?;
    }
    let record = runtime
        .state
        .with_store_blocking({
            let digest = manifest_digest.to_owned();
            move |store| store.prepared_image(&digest)
        })?
        .ok_or(Error::State)?;
    if !record.published {
        return Err(Error::State);
    }
    runtime.authority.register_prepared_image(&record)?;
    record_info(record)
}

impl RuntimeService {
    pub(super) async fn image_request(
        self: &std::sync::Arc<Self>,
        peer: Peer,
        request: Request,
        deadline: Instant,
    ) -> Result<Response> {
        match request {
            Request::ImageInspect { digest } => {
                let digest_value = digest.as_str().to_owned();
                let record = self
                    .state
                    .with_store_blocking(move |store| store.prepared_image(&digest_value))?
                    .ok_or_else(|| {
                        ApiError::new(ErrorCode::ImageNotFound, "prepared image is absent")
                    })?;
                Ok(Response::Image(record_info(record)?))
            }
            Request::ImageList { after, limit } => {
                let cursor = after.map(|value| value.as_str().to_owned());
                let records = self.state.with_store_blocking(move |store| {
                    store.list_prepared_images(cursor.as_deref(), limit)
                })?;
                Ok(Response::Images(
                    records
                        .into_iter()
                        .map(record_info)
                        .collect::<Result<Vec<_>>>()?,
                ))
            }
            Request::Image {
                operation,
                operation_sequence,
                command,
            } => {
                command.validate().map_err(|_| Error::Path)?;
                let operation_for_admit = operation.clone();
                let command_for_admit = (*command).clone();
                let (request_digest, replay) = self.state.with_store_blocking(move |store| {
                    store.admit_image_operation(
                        peer.uid,
                        &operation_for_admit,
                        operation_sequence,
                        &command_for_admit,
                    )
                })?;
                if let Some(response) = replay {
                    return Ok(response);
                }
                let runtime = std::sync::Arc::clone(self);
                let pending_operation = operation.clone();
                // Artifactd may be temporarily unavailable after the public
                // operation has been admitted. Keep its durable receipt
                // pending on failure so the same request can resume from its
                // exact saved tokens and lease after a retry or restart.
                let (reply, response) = tokio::sync::oneshot::channel();
                // Queue ownership survives a disconnected or timed-out caller;
                // the operation receipt is completed only after the image is prepared.
                let queued = self
                    .queue
                    .submit(
                        sandboxd_protocol::SandboxId::new("prepared-image-handoff")
                            .map_err(|_| Error::State)?,
                        async move {
                            let effect: Result<Response> = async {
                                if Instant::now() >= deadline {
                                    return Err(crate::api::state_worker::deadline_error());
                                }
                                let ImageCommand::ImportPrepared {
                                    prepared_artifact_id,
                                    manifest_digest,
                                    lease_id,
                                    architecture,
                                } = *command;
                                let response = Response::Image(
                                    import_prepared(
                                        &runtime,
                                        peer.uid,
                                        &operation,
                                        prepared_artifact_id,
                                        manifest_digest,
                                        lease_id,
                                        architecture,
                                    )
                                    .await?,
                                );
                                Ok(response)
                            }
                            .await;
                            let response = match effect {
                                Ok(response) => response,
                                Err(error) => Response::Error(error.api()),
                            };
                            if !matches!(&response, Response::Error(_)) {
                                let operation_for_complete = operation.clone();
                                let response_for_complete = response.clone();
                                runtime.state.with_store_blocking(move |store| {
                                    store.complete_image_operation(
                                        peer.uid,
                                        &operation_for_complete,
                                        request_digest,
                                        &response_for_complete,
                                    )
                                })?;
                            }
                            let _ = reply.send(response);
                            Ok(())
                        },
                    )
                    .await?;
                drop(queued);
                match tokio::time::timeout_at(deadline, response).await {
                    Ok(Ok(Response::Error(error))) => Err(error.into()),
                    Ok(Ok(response)) => Ok(response),
                    Ok(Err(_)) => Err(Error::State),
                    Err(_) => Ok(Response::ImagePending {
                        operation: pending_operation,
                    }),
                }
            }
            _ => Err(Error::State),
        }
    }
}

fn record_info(record: PreparedImageRecord) -> Result<ImageInfo> {
    Ok(ImageInfo {
        digest: ImageDigest::new(record.digest).map_err(|_| Error::State)?,
        architecture: match record.architecture.as_str() {
            "amd64" => Architecture::X86_64,
            "arm64" => Architecture::Aarch64,
            _ => return Err(Error::State),
        },
        rootfs_sha256: record.rootfs_sha256,
        bytes: record.rootfs_size,
        layers: record.layers,
    })
}

#[cfg(target_os = "linux")]
#[allow(clippy::too_many_arguments)]
fn prepare_from_artifactd_fd(
    runtime: &RuntimeService,
    destination: &std::path::Path,
    size: u64,
    formatter_sha256: &str,
    handoff: &crate::state::ArtifactdImageHandoff,
    socket: &std::path::Path,
    server_uid: u32,
    artifact_id: &artifactd_protocol::PreparedArtifactId,
    manifest: &artifactd_protocol::ArtifactDigest,
    lease: &artifactd_protocol::LeaseId,
) -> Result<()> {
    let open_operation =
        artifactd_protocol::OperationId::try_from(handoff.open_prepared_operation.clone())
            .map_err(|_| Error::State)?;
    let (opened, descriptor) = crate::image::artifactd::call(
        socket,
        server_uid,
        open_operation.as_str(),
        artifactd_protocol::Action::OpenPrepared {
            id: artifact_id.clone(),
            lease: lease.clone(),
        },
        None,
    )?;
    if crate::image::artifactd::value_string(&opened, "prepared_artifact_id")?
        != artifact_id.as_str()
    {
        return Err(Error::State);
    }
    let prepared_rootfs = crate::image::artifactd::prepared_fd(descriptor)?;
    let mut formatter = runtime.authority.image_formatter()?;
    let architecture = handoff.architecture.clone();
    let digest = manifest.to_string();
    let rootfs_path = destination.to_string_lossy().into_owned();
    let layers = handoff.layers;
    let config_json = handoff.config_json.clone();
    let formatter_sha256 = formatter_sha256.to_owned();
    let state = runtime.state.clone();
    crate::image::build_read_only_ext4_from_fd(
        &mut formatter,
        &prepared_rootfs,
        server_uid,
        destination,
        size,
        &mut |prepared| {
            let record = PreparedImageRecord {
                digest: digest.clone(),
                architecture: architecture.clone(),
                rootfs_path: rootfs_path.clone(),
                rootfs_sha256: prepared.sha256.clone(),
                rootfs_size: prepared.bytes,
                rootfs_device: prepared.device,
                rootfs_inode: prepared.inode,
                formatter_sha256: formatter_sha256.clone(),
                created_at: crate::api::handlers::now_ms()?,
                layers,
                config_json: config_json.clone(),
                published: false,
            };
            state.with_store_blocking(move |store| store.record_prepared_image(&record))?;
            Ok(())
        },
    )?;
    Ok(())
}
