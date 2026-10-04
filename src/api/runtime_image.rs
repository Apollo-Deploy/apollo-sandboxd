//! OCI image API dispatch kept separate from VM lifecycle code.
use super::runtime_service::RuntimeService;
use crate::security::peer::Peer;
use crate::{
    error::{Error, Result},
    image::{ImageReference, RegistryAuth},
    state::PreparedImageRecord,
};
use sandboxd_protocol::{
    ApiError, Architecture, ErrorCode, ImageCommand, ImageDigest, ImageInfo, Request, Response,
};
use tokio::time::Instant;

impl RuntimeService {
    pub(super) async fn image_request(
        &self,
        peer: Peer,
        request: Request,
        deadline: Instant,
    ) -> Result<Response> {
        let service = self.images.clone().ok_or_else(|| {
            ApiError::new(
                ErrorCode::UnsupportedCapability,
                "OCI image service is unavailable",
            )
        })?;
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
                let resolved_before = self.state.with_store_blocking({
                    let operation = operation.clone();
                    move |store| store.image_operation_resolution(peer.uid, &operation)
                })?;
                let effect: Result<Response> = async {
                    if Instant::now() >= deadline {
                        return Err(crate::api::state_worker::deadline_error());
                    }
                    let result = match *command {
                        ImageCommand::ImportLayout { relative_layout } => {
                            let service = service.clone();
                            tokio::task::spawn_blocking(move || {
                                service.import_layout(relative_layout.as_ref())
                            })
                            .await
                            .map_err(|_| Error::State)??
                        }
                        ImageCommand::Pull {
                            reference,
                            username,
                            password,
                        } => {
                            let parsed =
                                ImageReference::parse(&reference).map_err(|_| Error::Path)?;
                            let auth = match (username, password) {
                                (Some(username), Some(password)) => Some(RegistryAuth {
                                    username,
                                    password: password.0.clone(),
                                }),
                                _ => None,
                            };
                            let registry = crate::image::RegistryClient::new(
                                auth,
                                self.authority
                                    .execution
                                    .oci
                                    .as_ref()
                                    .ok_or(Error::Config("OCI settings unavailable"))?
                                    .max_blob_bytes,
                            )
                            .map_err(|_| Error::State)?;
                            let resolved = if let Some(resolved) = resolved_before {
                                resolved
                            } else {
                                let (resolved, _, _) = registry
                                    .resolve_manifest_with_bytes(&parsed)
                                    .await
                                    .map_err(|_| Error::State)?;
                                self.state.with_store_blocking({
                                    let operation = operation.clone();
                                    let resolved = resolved.clone();
                                    move |store| {
                                        store.record_image_resolution(
                                            peer.uid, &operation, &resolved,
                                        )
                                    }
                                })?;
                                resolved
                            };
                            let pinned = ImageReference {
                                registry: parsed.registry.clone(),
                                repository: parsed.repository.clone(),
                                reference: resolved,
                            };
                            service
                                .pull(&pinned, &registry)
                                .await
                                .map_err(|_| Error::State)?
                        }
                    };
                    Ok(Response::Image(prepare_import(self, result).await?))
                }
                .await;
                let response = match effect {
                    Ok(response) => response,
                    Err(error) => Response::Error(error.api()),
                };
                let operation_for_complete = operation.clone();
                let response_for_complete = response.clone();
                self.state.with_store_blocking(move |store| {
                    store.complete_image_operation(
                        peer.uid,
                        &operation_for_complete,
                        request_digest,
                        &response_for_complete,
                    )
                })?;
                match response {
                    Response::Error(error) => Err(error.into()),
                    response => Ok(response),
                }
            }
            _ => Err(Error::State),
        }
    }
}

fn record_info(record: PreparedImageRecord) -> Result<ImageInfo> {
    Ok(ImageInfo {
        digest: ImageDigest::new(record.digest).map_err(|_| Error::State)?,
        architecture: if record.architecture == "amd64" {
            Architecture::X86_64
        } else {
            Architecture::Aarch64
        },
        rootfs_sha256: record.rootfs_sha256,
        bytes: record.rootfs_size,
        layers: record.layers,
    })
}

async fn prepare_import(
    runtime: &RuntimeService,
    import: crate::image::ImageImport,
) -> Result<ImageInfo> {
    let settings = runtime.authority.oci_settings()?;
    let mut formatter = runtime.authority.oci_formatter()?;
    let state = runtime.state.clone();
    let digest = import.digest.clone();
    let source = import.rootfs.clone();
    let destination = settings
        .prepared_root
        .join(digest.strip_prefix("sha256:").ok_or(Error::State)?);
    let size = u64::from(settings.prepared_size_mib) * 1_048_576;
    let formatter_sha256 = settings.formatter_sha256.clone();
    let layers = import.manifest.layers.len() as u32;
    let config_json = import
        .config
        .as_ref()
        .map(serde_json::to_vec)
        .transpose()
        .map_err(|_| Error::State)?;
    if layers > 256
        || config_json
            .as_ref()
            .is_some_and(|bytes| bytes.len() > 65_536)
    {
        return Err(Error::Path);
    }
    let digest_for_worker = digest.clone();
    let architecture = "amd64".to_owned();
    let result = tokio::task::spawn_blocking(move || {
        crate::security::path::SecureDir::open(&settings.prepared_root)?;
        let stale = state.with_store_blocking({
            let digest = digest_for_worker.clone();
            move |store| store.prepared_image(&digest)
        })?;
        if let Some(stale) = stale
            && !stale.published
            && !std::path::Path::new(&stale.rootfs_path).exists()
        {
            state.with_store_blocking({
                let digest = digest_for_worker.clone();
                move |store| store.retire_unpublished_image(&digest)
            })?;
        }
        let artifact = crate::image::build_read_only_ext4(
            &mut formatter,
            &source,
            &destination,
            size,
            &mut |prepared| {
                let record = PreparedImageRecord {
                    digest: digest_for_worker.clone(),
                    architecture: architecture.clone(),
                    rootfs_path: destination.to_string_lossy().into_owned(),
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
        Ok::<_, Error>(artifact)
    })
    .await
    .map_err(|_| Error::State)??;
    runtime.state.with_store_blocking({
        let digest = digest.clone();
        move |store| store.publish_prepared_image(&digest)
    })?;
    let record = runtime
        .state
        .with_store_blocking({
            let digest = digest.clone();
            move |store| store.prepared_image(&digest)
        })?
        .ok_or(Error::State)?;
    runtime.authority.register_prepared_image(&record)?;
    Ok(ImageInfo {
        digest: ImageDigest::new(digest).map_err(|_| Error::State)?,
        architecture: Architecture::X86_64,
        rootfs_sha256: result.sha256,
        bytes: result.size,
        layers,
    })
}
