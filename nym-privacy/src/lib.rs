//! Nym Privacy - Privacy-preserving transaction and compliance framework
//! 
//! This module provides:
//! - Optional public transaction mechanisms
//! - Cryptographic commitment reveal systems
//! - Regulatory compliance features
//! - Audit trail generation

pub mod error;
pub mod public_transactions;

pub use error::{PrivacyError, PrivacyResult};
pub use public_transactions::{
    PublicTransactionManager, PublicTransactionConfig, RevealAuthorization,
    RevealScope, SelectiveReveal, PublicTransaction, AuditEntry, ComplianceStatus
};