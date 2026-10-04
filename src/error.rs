use sandboxd_protocol::{ApiError, ErrorCode};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("filesystem IO failed")]
    Io(#[from] std::io::Error),
    #[error("kernel operation failed")]
    Kernel(#[from] rustix::io::Errno),
    #[error("durable state operation failed")]
    Store(#[from] rusqlite::Error),
    #[error("configuration rejected: {0}")]
    Config(&'static str),
    #[error("trusted artifact rejected: {0}")]
    Artifact(&'static str),
    #[error("path ownership/type/permissions rejected")]
    Path,
    #[error("durable state could not be decoded")]
    State,
    #[error("daemon instance already owns state or socket")]
    Locked,
    #[error("control protocol failed")]
    Codec(#[from] sandboxd_protocol::codec::CodecError),
    #[error("{0}")]
    Api(#[from] ApiError),
}
impl Error {
    pub fn api(&self) -> ApiError {
        match self {
            Self::Api(error) => error.clone(),
            Self::Artifact(_) => ApiError::new(
                ErrorCode::RuntimeProfileInvalid,
                "trusted runtime artifact rejected",
            ),
            Self::Store(_) | Self::State | Self::Io(_) | Self::Kernel(_) => {
                ApiError::new(ErrorCode::StorageFailed, "durable operation failed")
            }
            _ => ApiError::new(ErrorCode::InvalidRequest, "request rejected"),
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
