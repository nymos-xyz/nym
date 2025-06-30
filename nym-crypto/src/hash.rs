//! SHAKE256 hash function implementation for quantum resistance

use sha3::{Shake256, digest::{Update, ExtendableOutput, XofReader}};
use serde::{Serialize, Deserialize};
use zeroize::Zeroize;
use std::fmt;

use crate::{CryptoError, CryptoResult, SecurityLevel};

/// Fixed-size hash output (32 bytes for 256-bit security)
#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, Zeroize)]
pub struct Hash256([u8; 32]);

impl Hash256 {
    /// Create a new hash from bytes
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    
    /// Get the hash as bytes
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    
    /// Get the hash as a slice
    pub fn as_slice(&self) -> &[u8] {
        &self.0
    }
    
    /// Convert to hex string for display
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0)
    }
    
    /// Create from hex string
    pub fn from_hex(hex_str: &str) -> CryptoResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|_| CryptoError::InvalidHash)?;
        
        if bytes.len() != 32 {
            return Err(CryptoError::InvalidKeyLength { 
                expected: 32, 
                actual: bytes.len() 
            });
        }
        
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        Ok(Self(array))
    }
}

impl fmt::Debug for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Hash256({})", self.to_hex())
    }
}

impl fmt::Display for Hash256 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.to_hex())
    }
}

/// SHAKE256-based hasher for quantum resistance
pub struct Hasher {
    hasher: Shake256,
}

impl Hasher {
    /// Create a new hasher
    pub fn new() -> Self {
        Self {
            hasher: Shake256::default(),
        }
    }
    
    /// Update the hasher with data
    pub fn update(&mut self, data: &[u8]) -> &mut Self {
        self.hasher.update(data);
        self
    }
    
    /// Finalize and extract fixed-size hash
    pub fn finalize(self) -> Hash256 {
        let mut output = [0u8; 32];
        self.hasher.finalize_xof().read(&mut output);
        Hash256(output)
    }
    
    /// Finalize and extract variable-length hash
    pub fn finalize_variable(self, length: usize) -> Vec<u8> {
        let mut output = vec![0u8; length];
        self.hasher.finalize_xof().read(&mut output);
        output
    }
}

impl Default for Hasher {
    fn default() -> Self {
        Self::new()
    }
}

/// Convenience function to hash data once
pub fn hash(data: &[u8]) -> Hash256 {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize()
}

/// Hash multiple pieces of data together
pub fn hash_multiple(data_pieces: &[&[u8]]) -> Hash256 {
    let mut hasher = Hasher::new();
    for piece in data_pieces {
        hasher.update(piece);
    }
    hasher.finalize()
}

/// Create a hash with specific output length for key derivation
pub fn hash_variable_length(data: &[u8], length: usize) -> Vec<u8> {
    let mut hasher = Hasher::new();
    hasher.update(data);
    hasher.finalize_variable(length)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hash_basic() {
        let data = b"test data";
        let hash1 = hash(data);
        let hash2 = hash(data);
        
        // Same input should produce same hash
        assert_eq!(hash1, hash2);
        
        // Different input should produce different hash
        let hash3 = hash(b"different data");
        assert_ne!(hash1, hash3);
    }
    
    #[test]
    fn test_hash_hex_conversion() {
        let data = b"test";
        let hash = hash(data);
        let hex = hash.to_hex();
        let recovered = Hash256::from_hex(&hex).unwrap();
        assert_eq!(hash, recovered);
    }
    
    #[test]
    fn test_hasher_incremental() {
        let mut hasher1 = Hasher::new();
        hasher1.update(b"hello").update(b"world");
        let hash1 = hasher1.finalize();
        
        let hash2 = hash(b"helloworld");
        
        assert_eq!(hash1, hash2);
    }
    
    #[test]
    fn test_variable_length_hash() {
        let data = b"test data";
        let hash32 = hash_variable_length(data, 32);
        let hash64 = hash_variable_length(data, 64);
        
        assert_eq!(hash32.len(), 32);
        assert_eq!(hash64.len(), 64);
        assert_ne!(hash32, hash64[..32]);
    }
    
    #[test]
    fn test_hash_multiple() {
        let pieces = [b"hello".as_slice(), b"world".as_slice()];
        let hash1 = hash_multiple(&pieces);
        let hash2 = hash(b"helloworld");
        
        assert_eq!(hash1, hash2);
    }
}