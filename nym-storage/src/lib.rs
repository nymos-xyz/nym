//! Nym Storage - Encrypted storage layer with privacy-preserving indices
//! 
//! This module provides secure storage for Nym cryptocurrency data:
//! - Encrypted transaction storage
//! - Account chain persistence  
//! - Privacy-preserving indices
//! - Backup and recovery mechanisms
//! - QuID-integrated recovery system

pub mod error;
pub mod encrypted_store;
pub mod chain_store;
pub mod account_store;
pub mod index;
pub mod backup;
pub mod quid_recovery;

pub use error::StorageError;
pub use encrypted_store::{EncryptedStore, EncryptionConfig};
pub use chain_store::{ChainStore, BlockStore};
pub use account_store::{AccountStore, TransactionStore, QuIDTransactionStore, QuIDEncryptedTransaction};
pub use index::{PrivacyIndex, StealthAddressIndex};
pub use backup::{BackupManager, BackupConfig};
pub use quid_recovery::{QuIDRecoveryManager, QuIDRecoveryConfig};

/// Result type for storage operations
pub type StorageResult<T> = Result<T, StorageError>;