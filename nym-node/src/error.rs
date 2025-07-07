use thiserror::Error;

#[derive(Error, Debug)]
pub enum NodeError {
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Network error: {0}")]
    Network(#[from] nym_network::error::NetworkError),
    
    #[error("Storage error: {0}")]
    Storage(#[from] nym_storage::error::StorageError),
    
    #[error("Consensus error: {0}")]
    Consensus(#[from] nym_consensus::error::ConsensusError),
    
    #[error("Crypto error: {0}")]
    Crypto(#[from] nym_crypto::error::CryptoError),
    
    #[error("Compute error: {0}")]
    Compute(#[from] nym_compute::error::ComputeError),
    
    #[error("Economics error: {0}")]
    Economics(#[from] nym_economics::error::EconomicsError),
    
    #[error("QuID error: {0}")]
    QuID(#[from] quid_core::error::QuIDError),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(String),
    
    #[error("Node not initialized")]
    NotInitialized,
    
    #[error("Node already running")]
    AlreadyRunning,
    
    #[error("Invalid genesis block")]
    InvalidGenesis,
    
    #[error("Synchronization failed: {0}")]
    SyncFailed(String),
    
    #[error("RPC error: {0}")]
    Rpc(String),
    
    #[error("State error: {0}")]
    State(String),
    
    #[error("Other error: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, NodeError>;

impl From<serde_json::Error> for NodeError {
    fn from(e: serde_json::Error) -> Self {
        NodeError::Serialization(e.to_string())
    }
}

impl From<bincode::Error> for NodeError {
    fn from(e: bincode::Error) -> Self {
        NodeError::Serialization(e.to_string())
    }
}

impl From<toml::de::Error> for NodeError {
    fn from(e: toml::de::Error) -> Self {
        NodeError::Config(e.to_string())
    }
}

impl From<toml::ser::Error> for NodeError {
    fn from(e: toml::ser::Error) -> Self {
        NodeError::Config(e.to_string())
    }
}