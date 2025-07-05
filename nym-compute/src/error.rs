//! Error handling for the Nym Compute platform

use thiserror::Error;

/// Result type for compute operations
pub type ComputeResult<T> = Result<T, ComputeError>;

/// Comprehensive error types for the compute platform
#[derive(Error, Debug, Clone)]
pub enum ComputeError {
    /// Authentication and authorization errors
    #[error("Authentication failed: {0}")]
    AuthenticationFailed(String),
    
    #[error("Authorization denied: {0}")]
    AuthorizationDenied(String),
    
    #[error("Invalid QuID identity: {0}")]
    InvalidQuIDIdentity(String),
    
    /// Resource management errors
    #[error("Resource not found: {0}")]
    ResourceNotFound(String),
    
    #[error("Insufficient resources: {0}")]
    InsufficientResources(String),
    
    #[error("Resource allocation failed: {0}")]
    ResourceAllocationFailed(String),
    
    #[error("Resource specification invalid: {0}")]
    InvalidResourceSpec(String),
    
    /// Job execution errors
    #[error("Job execution failed: {0}")]
    JobExecutionFailed(String),
    
    #[error("Job not found: {0}")]
    JobNotFound(String),
    
    #[error("Job timeout: {0}")]
    JobTimeout(String),
    
    #[error("Job validation failed: {0}")]
    JobValidationFailed(String),
    
    #[error("Execution environment error: {0}")]
    ExecutionEnvironmentError(String),
    
    /// Privacy and cryptographic errors
    #[error("Zero-knowledge proof generation failed: {0}")]
    ZkProofGenerationFailed(String),
    
    #[error("Zero-knowledge proof verification failed: {0}")]
    ZkProofVerificationFailed(String),
    
    #[error("Privacy constraint violation: {0}")]
    PrivacyConstraintViolation(String),
    
    #[error("Cryptographic operation failed: {0}")]
    CryptographicError(String),
    
    /// Network and communication errors
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Node not reachable: {0}")]
    NodeNotReachable(String),
    
    #[error("Communication protocol error: {0}")]
    ProtocolError(String),
    
    #[error("Peer discovery failed: {0}")]
    PeerDiscoveryFailed(String),
    
    /// Blockchain and transaction errors
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
    
    #[error("Insufficient balance: {0}")]
    InsufficientBalance(String),
    
    #[error("Block validation failed: {0}")]
    BlockValidationFailed(String),
    
    #[error("Chain synchronization error: {0}")]
    ChainSyncError(String),
    
    /// Storage errors
    #[error("Storage error: {0}")]
    StorageError(String),
    
    #[error("Data corruption: {0}")]
    DataCorruption(String),
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    /// Configuration and setup errors
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Invalid parameter: {0}")]
    InvalidParameter(String),
    
    #[error("Missing dependency: {0}")]
    MissingDependency(String),
    
    /// Economic and incentive errors
    #[error("Payment required: {0}")]
    PaymentRequired(String),
    
    #[error("Insufficient stake: {0}")]
    InsufficientStake(String),
    
    #[error("Reputation too low: {0}")]
    ReputationTooLow(String),
    
    #[error("Economic validation failed: {0}")]
    EconomicValidationFailed(String),
    
    /// Internal system errors
    #[error("Internal error: {0}")]
    InternalError(String),
    
    #[error("Timeout: {0}")]
    Timeout(String),
    
    #[error("Capacity exceeded: {0}")]
    CapacityExceeded(String),
    
    #[error("Service unavailable: {0}")]
    ServiceUnavailable(String),
}

impl ComputeError {
    /// Check if error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            ComputeError::NetworkError(_) => true,
            ComputeError::NodeNotReachable(_) => true,
            ComputeError::Timeout(_) => true,
            ComputeError::ServiceUnavailable(_) => true,
            ComputeError::ChainSyncError(_) => true,
            ComputeError::PeerDiscoveryFailed(_) => true,
            _ => false,
        }
    }
    
    /// Check if error is authentication-related
    pub fn is_auth_error(&self) -> bool {
        matches!(
            self,
            ComputeError::AuthenticationFailed(_)
                | ComputeError::AuthorizationDenied(_)
                | ComputeError::InvalidQuIDIdentity(_)
        )
    }
    
    /// Check if error is resource-related
    pub fn is_resource_error(&self) -> bool {
        matches!(
            self,
            ComputeError::ResourceNotFound(_)
                | ComputeError::InsufficientResources(_)
                | ComputeError::ResourceAllocationFailed(_)
                | ComputeError::InvalidResourceSpec(_)
        )
    }
    
    /// Check if error is privacy-related
    pub fn is_privacy_error(&self) -> bool {
        matches!(
            self,
            ComputeError::ZkProofGenerationFailed(_)
                | ComputeError::ZkProofVerificationFailed(_)
                | ComputeError::PrivacyConstraintViolation(_)
                | ComputeError::CryptographicError(_)
        )
    }
    
    /// Get error category for logging and metrics
    pub fn category(&self) -> &'static str {
        match self {
            ComputeError::AuthenticationFailed(_)
            | ComputeError::AuthorizationDenied(_)
            | ComputeError::InvalidQuIDIdentity(_) => "auth",
            
            ComputeError::ResourceNotFound(_)
            | ComputeError::InsufficientResources(_)
            | ComputeError::ResourceAllocationFailed(_)
            | ComputeError::InvalidResourceSpec(_) => "resource",
            
            ComputeError::JobExecutionFailed(_)
            | ComputeError::JobNotFound(_)
            | ComputeError::JobTimeout(_)
            | ComputeError::JobValidationFailed(_)
            | ComputeError::ExecutionEnvironmentError(_) => "execution",
            
            ComputeError::ZkProofGenerationFailed(_)
            | ComputeError::ZkProofVerificationFailed(_)
            | ComputeError::PrivacyConstraintViolation(_)
            | ComputeError::CryptographicError(_) => "privacy",
            
            ComputeError::NetworkError(_)
            | ComputeError::NodeNotReachable(_)
            | ComputeError::ProtocolError(_)
            | ComputeError::PeerDiscoveryFailed(_) => "network",
            
            ComputeError::TransactionFailed(_)
            | ComputeError::InsufficientBalance(_)
            | ComputeError::BlockValidationFailed(_)
            | ComputeError::ChainSyncError(_) => "blockchain",
            
            ComputeError::StorageError(_)
            | ComputeError::DataCorruption(_)
            | ComputeError::SerializationError(_) => "storage",
            
            ComputeError::ConfigurationError(_)
            | ComputeError::InvalidParameter(_)
            | ComputeError::MissingDependency(_) => "config",
            
            ComputeError::PaymentRequired(_)
            | ComputeError::InsufficientStake(_)
            | ComputeError::ReputationTooLow(_)
            | ComputeError::EconomicValidationFailed(_) => "economic",
            
            ComputeError::InternalError(_)
            | ComputeError::Timeout(_)
            | ComputeError::CapacityExceeded(_)
            | ComputeError::ServiceUnavailable(_) => "system",
        }
    }
}

// Convert from common error types
impl From<std::io::Error> for ComputeError {
    fn from(err: std::io::Error) -> Self {
        ComputeError::InternalError(err.to_string())
    }
}

impl From<serde_json::Error> for ComputeError {
    fn from(err: serde_json::Error) -> Self {
        ComputeError::SerializationError(err.to_string())
    }
}

impl From<tokio::time::error::Elapsed> for ComputeError {
    fn from(err: tokio::time::error::Elapsed) -> Self {
        ComputeError::Timeout(err.to_string())
    }
}

impl From<nym_core::error::NymError> for ComputeError {
    fn from(err: nym_core::error::NymError) -> Self {
        match err {
            nym_core::error::NymError::AuthenticationFailed(msg) => {
                ComputeError::AuthenticationFailed(msg)
            }
            nym_core::error::NymError::InsufficientBalance(msg) => {
                ComputeError::InsufficientBalance(msg)
            }
            nym_core::error::NymError::TransactionFailed(msg) => {
                ComputeError::TransactionFailed(msg)
            }
            _ => ComputeError::InternalError(err.to_string()),
        }
    }
}

impl From<nym_crypto::error::CryptoError> for ComputeError {
    fn from(err: nym_crypto::error::CryptoError) -> Self {
        ComputeError::CryptographicError(err.to_string())
    }
}

impl From<nym_network::error::NetworkError> for ComputeError {
    fn from(err: nym_network::error::NetworkError) -> Self {
        ComputeError::NetworkError(err.to_string())
    }
}

impl From<nym_storage::error::StorageError> for ComputeError {
    fn from(err: nym_storage::error::StorageError) -> Self {
        ComputeError::StorageError(err.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_error_categorization() {
        let auth_error = ComputeError::AuthenticationFailed("test".to_string());
        assert!(auth_error.is_auth_error());
        assert_eq!(auth_error.category(), "auth");

        let resource_error = ComputeError::InsufficientResources("test".to_string());
        assert!(resource_error.is_resource_error());
        assert_eq!(resource_error.category(), "resource");

        let privacy_error = ComputeError::ZkProofGenerationFailed("test".to_string());
        assert!(privacy_error.is_privacy_error());
        assert_eq!(privacy_error.category(), "privacy");
    }

    #[test]
    fn test_error_recoverability() {
        let recoverable = ComputeError::NetworkError("test".to_string());
        assert!(recoverable.is_recoverable());

        let non_recoverable = ComputeError::AuthenticationFailed("test".to_string());
        assert!(!non_recoverable.is_recoverable());
    }
}