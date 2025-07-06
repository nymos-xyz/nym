//! Privacy module error types

use std::fmt;

/// Privacy operation errors
#[derive(Debug, Clone)]
pub enum PrivacyError {
    /// Operation not found
    NotFound(String),
    /// Invalid input
    InvalidInput(String),
    /// Cryptographic error
    CryptographicError(String),
    /// Authorization failed
    AuthorizationFailed(String),
    /// Insufficient authorization signatures
    InsufficientAuthorization(String),
    /// Authorization expired
    Expired(String),
    /// Operation too early
    TooEarly(String),
    /// Operation disabled
    OperationDisabled(String),
    /// Insufficient data for operation
    InsufficientData(String),
    /// Compliance check failed
    ComplianceFailed(String),
    /// Generic error with message
    Other(String),
}

impl fmt::Display for PrivacyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivacyError::NotFound(msg) => write!(f, "Not found: {}", msg),
            PrivacyError::InvalidInput(msg) => write!(f, "Invalid input: {}", msg),
            PrivacyError::CryptographicError(msg) => write!(f, "Cryptographic error: {}", msg),
            PrivacyError::AuthorizationFailed(msg) => write!(f, "Authorization failed: {}", msg),
            PrivacyError::InsufficientAuthorization(msg) => write!(f, "Insufficient authorization: {}", msg),
            PrivacyError::Expired(msg) => write!(f, "Expired: {}", msg),
            PrivacyError::TooEarly(msg) => write!(f, "Too early: {}", msg),
            PrivacyError::OperationDisabled(msg) => write!(f, "Operation disabled: {}", msg),
            PrivacyError::InsufficientData(msg) => write!(f, "Insufficient data: {}", msg),
            PrivacyError::ComplianceFailed(msg) => write!(f, "Compliance failed: {}", msg),
            PrivacyError::Other(msg) => write!(f, "Error: {}", msg),
        }
    }
}

impl std::error::Error for PrivacyError {}

/// Result type for privacy operations
pub type PrivacyResult<T> = Result<T, PrivacyError>;