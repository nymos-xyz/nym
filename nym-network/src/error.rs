//! Network error types

use thiserror::Error;
use nym_crypto::CryptoError;
use nym_core::CoreError;

/// Errors that can occur during network operations
#[derive(Error, Debug)]
pub enum NetworkError {
    #[error("Connection failed: {reason}")]
    ConnectionFailed { reason: String },
    
    #[error("Peer error: {reason}")]
    PeerError { reason: String },
    
    #[error("Protocol error: {reason}")]
    ProtocolError { reason: String },
    
    #[error("Handshake failed: {reason}")]
    HandshakeFailed { reason: String },
    
    #[error("Discovery failed: {reason}")]
    DiscoveryFailed { reason: String },
    
    #[error("Routing failed: {reason}")]
    RoutingFailed { reason: String },
    
    #[error("Synchronization failed: {reason}")]
    SyncFailed { reason: String },
    
    #[error("Message error: {reason}")]
    MessageError { reason: String },
    
    #[error("Authentication failed: {reason}")]
    AuthenticationFailed { reason: String },
    
    #[error("Node error: {reason}")]
    NodeError { reason: String },
    
    #[error("Timeout: {reason}")]
    Timeout { reason: String },
    
    #[error("Network configuration error: {reason}")]
    ConfigError { reason: String },
    
    #[error("Serialization error: {reason}")]
    Serialization { reason: String },
    
    #[error("Crypto error: {0}")]
    Crypto(#[from] CryptoError),
    
    #[error("Core error: {0}")]
    Core(#[from] CoreError),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    // #[error("LibP2P error: {0}")]
    // LibP2P(#[from] libp2p::swarm::SwarmError),
}

/// Result type for network operations
pub type NetworkResult<T> = Result<T, NetworkError>;