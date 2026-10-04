use serde::{Deserialize, Deserializer, Serialize};
use std::{fmt, str::FromStr};

#[derive(Debug, thiserror::Error)]
#[error("identity must be 1..64 ASCII letters, digits, dash or underscore")]
pub struct InvalidIdentity;

fn valid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

macro_rules! identity {
    ($($name:ident),+ $(,)?) => {$(
        #[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);
        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, InvalidIdentity> {
                let value = value.into();
                if valid(&value) { Ok(Self(value)) } else { Err(InvalidIdentity) }
            }
            pub fn as_str(&self) -> &str { &self.0 }

        }
        impl fmt::Display for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { self.0.fmt(f) }
        }
        impl FromStr for $name {
            type Err = InvalidIdentity;
            fn from_str(value: &str) -> Result<Self, Self::Err> { Self::new(value) }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Self::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
            }
        }
    )+};
}
identity!(
    SandboxId,
    SessionId,
    OperationId,
    LeaseId,
    ExecId,
    SnapshotId,
    VolumeId,
    CheckpointId
);

impl OperationId {
    /// Construct the sequence-bound wire form used by public mutations.
    pub fn with_sequence(sequence: u64, opaque: impl AsRef<str>) -> Result<Self, InvalidIdentity> {
        if sequence == 0 || sequence > i64::MAX as u64 {
            return Err(InvalidIdentity);
        }
        Self::new(format!("op-{sequence}-{}", opaque.as_ref()))
    }

    pub fn sequence(&self) -> Option<u64> {
        let rest = self.0.strip_prefix("op-")?;
        let (sequence, opaque) = rest.split_once('-')?;
        if opaque.is_empty()
            || !opaque
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        {
            return None;
        }
        sequence
            .parse()
            .ok()
            .filter(|value: &u64| *value > 0 && *value <= i64::MAX as u64)
    }

    pub fn matches_sequence(&self, sequence: u64) -> bool {
        self.sequence() == Some(sequence)
    }
}

macro_rules! generation {
    ($name:ident) => {
        #[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(u64);
        impl $name {
            pub fn new(value: u64) -> Result<Self, &'static str> {
                if value == 0 || value > i64::MAX as u64 {
                    Err("generation out of range")
                } else {
                    Ok(Self(value))
                }
            }
            pub const fn get(self) -> u64 {
                self.0
            }
            pub fn next(self) -> Result<Self, &'static str> {
                Self::new(self.0.checked_add(1).ok_or("generation exhausted")?)
            }
        }
        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
                Self::new(u64::deserialize(d)?).map_err(serde::de::Error::custom)
            }
        }
    };
}
generation!(SandboxGeneration);
generation!(SessionGeneration);

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ImageDigest(String);
impl ImageDigest {
    pub fn new(value: impl Into<String>) -> Result<Self, &'static str> {
        let value = value.into();
        let hash = value
            .strip_prefix("sha256:")
            .ok_or("digest requires sha256 prefix")?;
        if hash.len() != 64
            || !hash
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("digest requires 64 lower-case hex digits");
        }
        Ok(Self(value))
    }
    pub fn as_str(&self) -> &str {
        &self.0
    }
}
impl<'de> Deserialize<'de> for ImageDigest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        Self::new(String::deserialize(d)?).map_err(serde::de::Error::custom)
    }
}
