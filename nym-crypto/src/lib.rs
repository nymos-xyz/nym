//! Quantum-resistant cryptographic primitives for Nym cryptocurrency
//! 
//! This module implements the core cryptographic operations required for Nym:
//! - ML-DSA signatures (placeholder implementation using SHAKE256)
//! - SHAKE256 hash function
//! - Quantum-resistant key derivation
//! - zk-STARK foundations
//! - Privacy primitives (stealth addresses, commitments)

pub mod error;
pub mod hash;
pub mod signature;
pub mod key_derivation;
pub mod commitment;
pub mod stealth;
pub mod zkstark;

use serde::{Serialize, Deserialize};

pub use error::CryptoError;
pub use hash::{Hash256, Hasher, hash_multiple, hash_variable_length};
pub use signature::{SecretKey, PublicKey, Signature, KeyPair};
pub use key_derivation::derive_key;
pub use commitment::{Commitment, CommitmentOpening, commit};
pub use stealth::{StealthAddress, ViewKey, SpendKey, generate_stealth_address};

/// Security levels aligned with NIST post-quantum standards
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// 128-bit quantum security (Level 1)
    Level1,
    /// 192-bit quantum security (Level 3)  
    Level3,
    /// 256-bit quantum security (Level 5)
    Level5,
}

impl SecurityLevel {
    /// Get the byte length for this security level
    pub fn byte_length(self) -> usize {
        match self {
            SecurityLevel::Level1 => 32,  // 256 bits
            SecurityLevel::Level3 => 48,  // 384 bits  
            SecurityLevel::Level5 => 64,  // 512 bits
        }
    }
}

/// Result type for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_security_levels() {
        assert_eq!(SecurityLevel::Level1.byte_length(), 32);
        assert_eq!(SecurityLevel::Level3.byte_length(), 48);
        assert_eq!(SecurityLevel::Level5.byte_length(), 64);
    }
}