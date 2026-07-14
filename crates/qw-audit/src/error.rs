use thiserror::Error;

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),

    #[error("serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("crypto error: {0}")]
    Crypto(#[from] qw_crypto::CryptoError),

    #[error("chain integrity violation: {0}")]
    ChainViolation(String),

    #[error("signature verification failed at entry {0}")]
    SignatureInvalid(u64),

    #[error("logger channel closed")]
    ChannelClosed,
}
