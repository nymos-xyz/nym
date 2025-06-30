//! Error types for Nym core operations

use thiserror::Error;
use nym_crypto::CryptoError;

/// Errors that can occur in Nym core operations
#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CoreError {
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] CryptoError),
    
    #[error("Invalid account ID: {id}")]
    InvalidAccountId { id: String },
    
    #[error("Account not found: {id}")]
    AccountNotFound { id: String },
    
    #[error("Insufficient balance: required {required}, available {available}")]
    InsufficientBalance { required: u64, available: u64 },
    
    #[error("Invalid transaction: {reason}")]
    InvalidTransaction { reason: String },
    
    #[error("Transaction verification failed")]
    TransactionVerificationFailed,
    
    #[error("Invalid chain state: {reason}")]
    InvalidChainState { reason: String },
    
    #[error("QuID authentication failed: {reason}")]
    QuIDAuthenticationFailed { reason: String },
    
    #[error("Privacy proof verification failed")]
    PrivacyProofFailed,
    
    #[error("Stealth address generation failed")]
    StealthAddressFailed,
    
    #[error("Balance encryption/decryption failed")]
    BalanceOperationFailed,
    
    #[error("Serialization error: {reason}")]
    SerializationError { reason: String },
    
    #[error("Storage operation failed: {reason}")]
    StorageError { reason: String },
}