//! Network error types

use thiserror::Error;
use nym_crypto::CryptoError;
use nym_core::CoreError;

/// Errors that can occur during network operations
#[derive(Error, Debug, Clone)]
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
    
    #[error("Bootstrap error: {reason}")]
    BootstrapError { reason: String },
    
    #[error("Subscription error: {reason}")]
    SubscriptionError { reason: String },
    
    #[error("Publish error: {reason}")]
    PublishError { reason: String },
    
    #[error("Crypto error: {reason}")]
    Crypto { reason: String },
    
    #[error("Core error: {reason}")]
    Core { reason: String },
    
    #[error("IO error: {reason}")]
    Io { reason: String },
}

/// Result type for network operations
pub type NetworkResult<T> = Result<T, NetworkError>;