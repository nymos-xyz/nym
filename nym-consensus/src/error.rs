use thiserror::Error;

pub type ConsensusResult<T> = std::result::Result<T, ConsensusError>;

#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("Invalid block: {0}")]
    InvalidBlock(String),

    #[error("Invalid proof of work: {0}")]
    InvalidProofOfWork(String),

    #[error("Invalid proof of stake: {0}")]
    InvalidProofOfStake(String),

    #[error("Difficulty adjustment error: {0}")]
    DifficultyError(String),

    #[error("Validator error: {0}")]
    ValidatorError(String),

    #[error("Mining error: {0}")]
    MiningError(String),

    #[error("Stake management error: {0}")]
    StakeError(String),

    #[error("Network synchronization error: {0}")]
    SyncError(String),

    #[error("Consensus protocol error: {0}")]
    ProtocolError(String),

    #[error("Cryptographic error: {0}")]
    CryptoError(String),

    #[error("Storage error: {0}")]
    StorageError(String),

    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("Network error: {0}")]
    NetworkError(String),

    #[error("Configuration error: {0}")]
    ConfigError(String),

    #[error("Internal error: {0}")]
    Internal(String),
}