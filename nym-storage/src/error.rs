//! Storage error types

use thiserror::Error;
use nym_crypto::CryptoError;
use nym_core::CoreError;

/// Errors that can occur during storage operations
#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {reason}")]
    DatabaseError { reason: String },
    
    #[error("Encryption error: {0}")]
    Encryption(#[from] CryptoError),
    
    #[error("Core error: {0}")]
    Core(#[from] CoreError),
    
    #[error("Serialization error: {reason}")]
    Serialization { reason: String },
    
    #[error("Compression error: {reason}")]
    Compression { reason: String },
    
    #[error("Key not found: {key}")]
    KeyNotFound { key: String },
    
    #[error("Invalid data format: {reason}")]
    InvalidData { reason: String },
    
    #[error("Storage corruption detected: {reason}")]
    Corruption { reason: String },
    
    #[error("Backup operation failed: {reason}")]
    BackupFailed { reason: String },
    
    #[error("Recovery operation failed: {reason}")]
    RecoveryFailed { reason: String },
    
    #[error("Index operation failed: {reason}")]
    IndexError { reason: String },
    
    #[error("Access denied: {reason}")]
    AccessDenied { reason: String },
    
    #[error("Storage capacity exceeded")]
    CapacityExceeded,
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}