use super::model::{ImageManifest, ImageReference, OciDescriptor, OciIndex, host_oci_architecture};
use futures_util::StreamExt;
use reqwest::{Client, StatusCode, Url, header};
use sha2::{Digest, Sha256};
use std::path::Path;
use zeroize::Zeroize;

#[path = "registry_blob.rs"]
mod blob;

#[derive(Clone)]
pub struct RegistryAuth {
    pub username: String,
    pub password: String,
}

impl std::fmt::Debug for RegistryAuth {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistryAuth")
            .field("username", &self.username)
            .field("password", &"[REDACTED]")
            .finish()
    }
}

impl Drop for RegistryAuth {
    fn drop(&mut self) {
        self.username.zeroize();
        self.password.zeroize();
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RegistryError {
    #[error("invalid registry response")]
    Response,
    #[error("registry request failed")]
    Request(#[from] reqwest::Error),
    #[error("registry returned status {0}")]
    Status(StatusCode),
    #[error("registry digest mismatch")]
    Digest,
    #[error("registry object exceeds configured limit")]
    Limit,
    #[error("registry JSON failed")]
    Json(#[from] serde_json::Error),
    #[error("registry file failed")]
    Io(#[from] std::io::Error),
    #[error("registry authentication challenge invalid")]
    Auth,
}

#[derive(Clone)]
pub struct RegistryClient {
    http: Client,
    auth: Option<RegistryAuth>,
    max_object_bytes: u64,
}

impl RegistryClient {
    pub fn new(auth: Option<RegistryAuth>, max_object_bytes: u64) -> Result<Self, RegistryError> {
        if !(1 << 10..=1 << 40).contains(&max_object_bytes) {
            return Err(RegistryError::Limit);
        }
        let http = Client::builder()
            .user_agent("apollo-sandboxd/oci")
            // Registry redirects are not part of the trusted image endpoint.
            // Follow-up requests would otherwise leak repository credentials.
            .redirect(reqwest::redirect::Policy::none())
            .connect_timeout(std::time::Duration::from_secs(10))
            .timeout(std::time::Duration::from_secs(300))
            .build()?;
        Ok(Self {
            http,
            auth,
            max_object_bytes,
        })
    }

    pub async fn resolve_manifest(
        &self,
        reference: &ImageReference,
    ) -> Result<(String, ImageManifest), RegistryError> {
        let (digest, manifest, _) = self.resolve_manifest_with_bytes(reference).await?;
        Ok((digest, manifest))
    }

    pub(crate) async fn resolve_manifest_with_bytes(
        &self,
        reference: &ImageReference,
    ) -> Result<(String, ImageManifest, Vec<u8>), RegistryError> {
        let url = format!(
            "https://{}/v2/{}/manifests/{}",
            reference.registry, reference.repository, reference.reference
        );
        let response = self
            .authenticated(&url, Some("application/vnd.oci.image.index.v1+json, application/vnd.oci.image.manifest.v1+json, application/vnd.docker.distribution.manifest.list.v2+json, application/vnd.docker.distribution.manifest.v2+json"))
            .await?;
        let response = checked(response).await?;
        let bytes = bounded_bytes(
            response,
            self.max_object_bytes.min(super::model::MAX_METADATA_BYTES),
        )
        .await?;
        let digest = format!("sha256:{:x}", Sha256::digest(&bytes));
        let requested_digest = reference.reference.strip_prefix("sha256:");
        if let Some(expected) = requested_digest {
            if expected.len() != 64 || format!("{:x}", Sha256::digest(&bytes)) != expected {
                return Err(RegistryError::Digest);
            }
        }
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        if value.get("manifests").is_some() {
            let index: OciIndex = serde_json::from_value(value)?;
            let descriptor = index
                .manifests
                .into_iter()
                .find(|d| {
                    d.platform.as_ref().is_some_and(|p| {
                        p.os == "linux" && p.architecture == host_oci_architecture()
                    })
                })
                .ok_or(RegistryError::Response)?;
            let manifest_url = format!(
                "https://{}/v2/{}/manifests/{}",
                reference.registry, reference.repository, descriptor.digest
            );
            let response = self.authenticated(&manifest_url, None).await?;
            let body = bounded_bytes(
                response,
                self.max_object_bytes.min(super::model::MAX_METADATA_BYTES),
            )
            .await?;
            if descriptor.size != body.len() as u64
                || format!("sha256:{:x}", Sha256::digest(&body)) != descriptor.digest
            {
                return Err(RegistryError::Digest);
            }
            let digest = format!("sha256:{:x}", Sha256::digest(&body));
            return Ok((digest, serde_json::from_slice(&body)?, body));
        }
        Ok((digest, serde_json::from_value(value)?, bytes))
    }

    pub async fn download_blob(
        &self,
        reference: &ImageReference,
        descriptor: &OciDescriptor,
        destination: &Path,
    ) -> Result<(), RegistryError> {
        let digest = descriptor
            .digest
            .strip_prefix("sha256:")
            .ok_or(RegistryError::Response)?;
        if descriptor.size > self.max_object_bytes
            || digest.len() != 64
            || !digest
                .bytes()
                .all(|c| c.is_ascii_digit() || matches!(c, b'a'..=b'f'))
        {
            return Err(RegistryError::Limit);
        }
        let url = format!(
            "https://{}/v2/{}/blobs/{}",
            reference.registry, reference.repository, descriptor.digest
        );
        let response = self.authenticated(&url, None).await?;
        blob::download(response, destination, descriptor, self.max_object_bytes).await
    }

    fn request(&self, url: &str) -> reqwest::RequestBuilder {
        let request = self.http.get(url);
        match &self.auth {
            Some(auth) => request.basic_auth(&auth.username, Some(&auth.password)),
            None => request,
        }
    }

    async fn authenticated(
        &self,
        url: &str,
        accept: Option<&str>,
    ) -> Result<reqwest::Response, RegistryError> {
        let mut request = self.request(url);
        if let Some(value) = accept {
            request = request.header(header::ACCEPT, value);
        }
        let response = request.send().await?;
        if response.status() != StatusCode::UNAUTHORIZED {
            return checked(response).await;
        }
        let challenge = response
            .headers()
            .get(header::WWW_AUTHENTICATE)
            .and_then(|value| value.to_str().ok())
            .and_then(parse_bearer_challenge)
            .ok_or(RegistryError::Auth)?;
        let realm = Url::parse(&challenge.realm).map_err(|_| RegistryError::Auth)?;
        if realm.scheme() != "https" || realm.host_str().is_none() {
            return Err(RegistryError::Auth);
        }
        let realm_host = realm.host_str().map(str::to_owned);
        let mut token_request = self.http.get(realm).query(&[
            ("service", challenge.service.as_deref().unwrap_or("")),
            ("scope", challenge.scope.as_deref().unwrap_or("")),
        ]);
        // Do not send repository credentials to an unrelated token service.
        if let Some(auth) = &self.auth {
            let registry_host = Url::parse(url)
                .ok()
                .and_then(|value| value.host_str().map(str::to_owned));
            if registry_host.as_deref() == realm_host.as_deref() {
                token_request = token_request.basic_auth(&auth.username, Some(&auth.password));
            }
        }
        let token_response = checked(token_request.send().await?).await?;
        let token_bytes = bounded_bytes(token_response, self.max_object_bytes.min(1 << 20)).await?;
        let token: TokenResponse =
            serde_json::from_slice(&token_bytes).map_err(|_| RegistryError::Auth)?;
        let token = token
            .token
            .or(token.access_token)
            .filter(|value| !value.is_empty())
            .ok_or(RegistryError::Auth)?;
        let mut retry = self.http.get(url).bearer_auth(token);
        if let Some(value) = accept {
            retry = retry.header(header::ACCEPT, value);
        }
        checked(retry.send().await?).await
    }
}

#[derive(Debug, serde::Deserialize)]
struct TokenResponse {
    token: Option<String>,
    access_token: Option<String>,
}

#[derive(Debug)]
struct BearerChallenge {
    realm: String,
    service: Option<String>,
    scope: Option<String>,
}

fn parse_bearer_challenge(value: &str) -> Option<BearerChallenge> {
    let mut parts = value.splitn(2, ' ');
    if !parts.next()?.eq_ignore_ascii_case("bearer") {
        return None;
    }
    let mut values = std::collections::HashMap::new();
    for item in parts.next()?.split(',') {
        let (key, raw) = item.trim().split_once('=')?;
        let value = raw.trim().strip_prefix('"')?.strip_suffix('"')?;
        if value.contains('"') || value.contains('\n') || value.contains('\r') {
            return None;
        }
        values.insert(key.to_ascii_lowercase(), value.to_owned());
    }
    Some(BearerChallenge {
        realm: values.remove("realm")?,
        service: values.remove("service"),
        scope: values.remove("scope"),
    })
}

async fn checked(response: reqwest::Response) -> Result<reqwest::Response, RegistryError> {
    if response.status() == StatusCode::UNAUTHORIZED || !response.status().is_success() {
        return Err(RegistryError::Status(response.status()));
    }
    Ok(response)
}

async fn bounded_bytes(response: reqwest::Response, max: u64) -> Result<Vec<u8>, RegistryError> {
    if response.content_length().is_some_and(|size| size > max) {
        return Err(RegistryError::Limit);
    }
    let mut out = Vec::new();
    let mut stream = response.bytes_stream();
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if out
            .len()
            .checked_add(chunk.len())
            .is_none_or(|size| size as u64 > max)
        {
            return Err(RegistryError::Limit);
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}
