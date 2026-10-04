//! Bounded registry streaming into a pinned anonymous content inode.
use super::{OciDescriptor, RegistryError};
use crate::image::{content::verify_file, content_publish::Publication};
use futures_util::StreamExt;
use sha2::{Digest, Sha256};
use std::path::Path;
use tokio::io::AsyncWriteExt;

pub(super) async fn download(
    response: reqwest::Response,
    destination: &Path,
    descriptor: &OciDescriptor,
    max: u64,
) -> Result<(), RegistryError> {
    if response
        .content_length()
        .is_some_and(|size| size != descriptor.size)
    {
        return Err(RegistryError::Digest);
    }
    let path = destination.to_owned();
    let publication = tokio::task::spawn_blocking(move || Publication::create(&path))
        .await
        .map_err(|_| RegistryError::Response)??;
    let mut file = tokio::fs::File::from_std(publication.file.try_clone()?);
    let mut stream = response.bytes_stream();
    let mut hash = Sha256::new();
    let mut size = 0u64;
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        size = size
            .checked_add(chunk.len() as u64)
            .ok_or(RegistryError::Limit)?;
        if size > descriptor.size || size > max {
            return Err(RegistryError::Limit);
        }
        hash.update(&chunk);
        file.write_all(&chunk).await?;
    }
    // Flush Tokio's pending write before hashing or publishing the shared FD.
    file.flush().await?;
    drop(file);
    if size != descriptor.size || format!("sha256:{:x}", hash.finalize()) != descriptor.digest {
        return Err(RegistryError::Digest);
    }
    let digest = descriptor.digest.clone();
    let expected = descriptor.size;
    tokio::task::spawn_blocking(move || {
        // NOREPLACE may race with another importer. Verify the opened winner;
        // an existing filename never makes corrupt or foreign bytes trusted.
        verify_file(publication.publish()?, &digest, expected)
    })
    .await
    .map_err(|_| RegistryError::Response)??;
    Ok(())
}
