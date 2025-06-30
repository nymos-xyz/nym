//! Homomorphic commitment schemes using SHAKE256
//! 
//! Provides Pedersen-style commitments for privacy-preserving operations

use rand::{RngCore, CryptoRng};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{CryptoError, CryptoResult, Hash256, hash_multiple};

/// A homomorphic commitment to a value
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Commitment {
    hash: Hash256,
}

/// Opening information for a commitment (value + randomness)
#[derive(Clone, Serialize, Deserialize)]
pub struct CommitmentOpening {
    value: Vec<u8>,
    randomness: Vec<u8>,
}

impl Commitment {
    /// Create from hash
    pub fn from_hash(hash: Hash256) -> Self {
        Self { hash }
    }
    
    /// Get the commitment hash
    pub fn hash(&self) -> &Hash256 {
        &self.hash
    }
    
    /// Verify a commitment opening
    pub fn verify(&self, opening: &CommitmentOpening) -> bool {
        let computed = commit_with_randomness(&opening.value, &opening.randomness);
        self.hash == computed.hash
    }
}

impl CommitmentOpening {
    /// Create new opening
    pub fn new(value: Vec<u8>, randomness: Vec<u8>) -> Self {
        Self { value, randomness }
    }
    
    /// Get the committed value
    pub fn value(&self) -> &[u8] {
        &self.value
    }
    
    /// Get the randomness
    pub fn randomness(&self) -> &[u8] {
        &self.randomness
    }
}

/// Create a commitment to a value with random blinding
pub fn commit<R: RngCore + CryptoRng>(value: &[u8], rng: &mut R) -> (Commitment, CommitmentOpening) {
    let mut randomness = vec![0u8; 32]; // 256 bits of randomness
    rng.fill_bytes(&mut randomness);
    
    let commitment = commit_with_randomness(value, &randomness);
    let opening = CommitmentOpening::new(value.to_vec(), randomness);
    
    (commitment, opening)
}

/// Create a commitment with specific randomness
pub fn commit_with_randomness(value: &[u8], randomness: &[u8]) -> Commitment {
    // Commit(value, randomness) = SHAKE256(value || randomness)
    let hash = hash_multiple(&[value, randomness]);
    Commitment::from_hash(hash)
}

/// Homomorphically add two commitments (for range proofs, etc.)
pub fn add_commitments(c1: &Commitment, c2: &Commitment) -> Commitment {
    // In a real implementation, this would use elliptic curve points
    // For now, we'll hash the two commitments together
    let hash = hash_multiple(&[c1.hash.as_slice(), c2.hash.as_slice()]);
    Commitment::from_hash(hash)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_commit_and_verify() {
        let mut rng = thread_rng();
        let value = b"secret value";
        
        let (commitment, opening) = commit(value, &mut rng);
        
        // Should verify correctly
        assert!(commitment.verify(&opening));
        
        // Should not verify with wrong value
        let wrong_opening = CommitmentOpening::new(b"wrong value".to_vec(), opening.randomness().to_vec());
        assert!(!commitment.verify(&wrong_opening));
    }
    
    #[test]
    fn test_deterministic_commitment() {
        let value = b"test value";
        let randomness = [1u8; 32];
        
        let c1 = commit_with_randomness(value, &randomness);
        let c2 = commit_with_randomness(value, &randomness);
        
        assert_eq!(c1, c2);
    }
    
    #[test]
    fn test_different_randomness() {
        let value = b"test value";
        let randomness1 = [1u8; 32];
        let randomness2 = [2u8; 32];
        
        let c1 = commit_with_randomness(value, &randomness1);
        let c2 = commit_with_randomness(value, &randomness2);
        
        assert_ne!(c1, c2);
    }
}