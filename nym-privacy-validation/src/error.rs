//! Privacy validation error types

use thiserror::Error;

/// Privacy validation error types
#[derive(Debug, Error)]
pub enum PrivacyValidationError {
    /// Zero-knowledge proof analysis error
    #[error("Zero-knowledge proof analysis failed: {0}")]
    ZKProofAnalysis(String),
    
    /// Anonymity analysis error
    #[error("Anonymity analysis failed: {0}")]
    AnonymityAnalysis(String),
    
    /// Privacy leak detection error
    #[error("Privacy leak detection failed: {0}")]
    PrivacyLeakDetection(String),
    
    /// Cryptographic assumption validation error
    #[error("Cryptographic assumption validation failed: {0}")]
    CryptoAssumptionValidation(String),
    
    /// Transaction graph analysis error
    #[error("Transaction graph analysis failed: {0}")]
    TransactionGraphAnalysis(String),
    
    /// Metadata privacy analysis error
    #[error("Metadata privacy analysis failed: {0}")]
    MetadataPrivacyAnalysis(String),
    
    /// Differential privacy analysis error
    #[error("Differential privacy analysis failed: {0}")]
    DifferentialPrivacyAnalysis(String),
    
    /// Statistical analysis error
    #[error("Statistical analysis failed: {0}")]
    StatisticalAnalysis(String),
    
    /// Graph analysis error
    #[error("Graph analysis failed: {0}")]
    GraphAnalysis(String),
    
    /// Mathematical computation error
    #[error("Mathematical computation failed: {0}")]
    MathematicalComputation(String),
    
    /// Data access error
    #[error("Data access failed: {0}")]
    DataAccess(String),
    
    /// Configuration error
    #[error("Configuration error: {0}")]
    Configuration(String),
    
    /// I/O error
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
    
    /// Serialization error
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    /// Generic error
    #[error("Privacy validation error: {0}")]
    Generic(String),
}

/// Result type for privacy validation operations
pub type Result<T> = std::result::Result<T, PrivacyValidationError>;