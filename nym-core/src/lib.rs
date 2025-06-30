//! Nym Core - Account chains and QuID-based authentication
//! 
//! This module implements the core data structures for Nym cryptocurrency:
//! - Individual account chains for each user
//! - QuID-based identity and authentication
//! - Private transactions with stealth addresses
//! - Encrypted balance management

pub mod error;
pub mod identity;
pub mod account;
pub mod transaction;
pub mod chain;
pub mod balance;

pub use error::CoreError;
pub use identity::{NymIdentity, QuIDAuth};
pub use account::{Account, AccountChain};
pub use transaction::{Transaction, TransactionType, PrivateTransaction, TransactionId};
pub use chain::{ChainState, Block};
pub use balance::{EncryptedBalance, BalanceProof, BalanceManager};

/// Result type for core operations
pub type CoreResult<T> = Result<T, CoreError>;