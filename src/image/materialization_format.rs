use std::io;

use super::Identity;

pub(super) fn digest_value(digest: &str) -> io::Result<&str> {
    let value = digest
        .strip_prefix("sha256:")
        .ok_or_else(|| invalid("unsupported OCI digest"))?;
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid("invalid OCI digest"));
    }
    Ok(value)
}

pub(super) fn invalid(error: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error)
}

pub(super) fn intent_bytes(nonce: &str, digest: &str) -> String {
    format!("APOLLO-OCI-INTENT-1\n{nonce}\n{digest}\n")
}

pub(super) fn parse_intent(bytes: &[u8]) -> io::Result<(String, String)> {
    let value = std::str::from_utf8(bytes).map_err(|_| invalid("OCI intent encoding"))?;
    let mut lines = value.lines();
    if lines.next() != Some("APOLLO-OCI-INTENT-1") {
        return Err(invalid("OCI intent version"));
    }
    let nonce = lines.next().ok_or_else(|| invalid("OCI intent nonce"))?;
    let digest = lines.next().ok_or_else(|| invalid("OCI intent digest"))?;
    if lines.next().is_some()
        || nonce.len() != 32
        || !nonce
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(invalid("OCI intent fields"));
    }
    digest_value(digest)?;
    if value != intent_bytes(nonce, digest) {
        return Err(invalid("OCI intent format"));
    }
    Ok((nonce.to_owned(), digest.to_owned()))
}

pub(super) fn identity_bytes(digest: &str, identity: Identity) -> String {
    format!(
        "APOLLO-OCI-PREPARED-1\n{digest}\n{}\n{}\n",
        identity.device, identity.inode
    )
}

pub(super) fn parse_identity(bytes: &[u8], digest: &str) -> io::Result<Identity> {
    let value = std::str::from_utf8(bytes).map_err(|_| invalid("OCI prepared marker encoding"))?;
    let mut lines = value.lines();
    if lines.next() != Some("APOLLO-OCI-PREPARED-1") || lines.next() != Some(digest) {
        return Err(invalid("OCI prepared marker digest"));
    }
    let device = parse_number(lines.next())?;
    let inode = parse_number(lines.next())?;
    if lines.next().is_some() {
        return Err(invalid("OCI prepared marker fields"));
    }
    let identity = Identity { device, inode };
    if value != identity_bytes(digest, identity) {
        return Err(invalid("OCI prepared marker format"));
    }
    Ok(identity)
}

pub(super) fn commit_bytes(digest: &str, identity: Identity) -> String {
    format!(
        "APOLLO-OCI-COMMIT-1\n{digest}\n{}\n{}\n",
        identity.device, identity.inode
    )
}

pub(super) fn parse_commit(bytes: &[u8], digest: &str) -> io::Result<Identity> {
    let value = std::str::from_utf8(bytes).map_err(|_| invalid("OCI commit marker encoding"))?;
    let mut lines = value.lines();
    if lines.next() != Some("APOLLO-OCI-COMMIT-1") || lines.next() != Some(digest) {
        return Err(invalid("OCI commit marker digest"));
    }
    let device = parse_number(lines.next())?;
    let inode = parse_number(lines.next())?;
    if lines.next().is_some() {
        return Err(invalid("OCI commit marker fields"));
    }
    let identity = Identity { device, inode };
    if value != commit_bytes(digest, identity) {
        return Err(invalid("OCI commit marker format"));
    }
    Ok(identity)
}

pub(super) fn valid_transaction_name(name: &str) -> bool {
    name.strip_prefix(".txn-").is_some_and(|nonce| {
        nonce.len() == 32
            && nonce
                .bytes()
                .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    })
}

fn parse_number(value: Option<&str>) -> io::Result<u64> {
    value
        .ok_or_else(|| invalid("OCI identity field"))?
        .parse()
        .map_err(|_| invalid("OCI identity number"))
}
