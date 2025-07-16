//! Error types for cryptographic operations

use thiserror::Error;

/// Errors that can occur during cryptographic operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },
    
    #[error("Invalid signature format")]
    InvalidSignature,
    
    #[error("Signature verification failed")]
    SignatureVerificationFailed,
    
    #[error("Invalid hash format")]
    InvalidHash,
    
    #[error("Key derivation failed: {reason}")]
    KeyDerivationFailed { reason: String },
    
    #[error("Invalid commitment")]
    InvalidCommitment,
    
    #[error("Invalid stealth address format")]
    InvalidStealthAddress,
    
    #[error("zk-STARK proof generation failed: {reason}")]
    ProofGenerationFailed { reason: String },
    
    #[error("zk-STARK proof verification failed")]
    ProofVerificationFailed,
    
    #[error("Insufficient randomness")]
    InsufficientRandomness,
    
    #[error("Cryptographic operation failed: {reason}")]
    OperationFailed { reason: String },
    
    #[error("Invalid threshold")]
    InvalidThreshold,
    
    #[error("Insufficient shares for recovery")]
    InsufficientShares,
    
    #[error("Invalid balance: inputs != outputs")]
    InvalidBalance,
    
    #[error("Audit key not found")]
    AuditKeyNotFound,
    
    #[error("Insufficient permissions")]
    InsufficientPermissions,
    
    #[error("Audit key expired")]
    AuditKeyExpired,
    
    #[error("Decryption failed")]
    DecryptionFailed,
}