//! Nym Privacy - Privacy-preserving transaction and compliance framework
//! 
//! This module provides:
//! - Optional public transaction mechanisms
//! - Cryptographic commitment reveal systems
//! - Regulatory compliance features
//! - Audit trail generation

pub mod error;
pub mod public_transactions;
pub mod transaction_anonymity;
pub mod confidential_transactions;

pub use error::{PrivacyError, PrivacyResult};
pub use public_transactions::{
    PublicTransactionManager, PublicTransactionConfig, RevealAuthorization,
    RevealScope, SelectiveReveal, PublicTransaction, AuditEntry, ComplianceStatus
};
pub use transaction_anonymity::{
    MixCoordinator, TransactionMix, AnonymousTransaction, DecoyTransaction,
    TimingData, MixConfig, TimingGuard, GraphObfuscator
};
pub use confidential_transactions::{
    ConfidentialTransaction, AmountCommitment, RangeProof, BalanceProof,
    HomomorphicOps, BalanceVerifier, AuditSystem, AuditKey, AuditReport
};