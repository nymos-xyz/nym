//! Stealth address generation for enhanced privacy
//! 
//! Provides one-time addresses for each transaction to prevent address reuse

use rand::{RngCore, CryptoRng};
use serde::{Serialize, Deserialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::{
    CryptoError, CryptoResult, Hash256, hash_multiple,
    key_derivation::derive_key, SecurityLevel
};

/// A stealth address for receiving anonymous payments
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StealthAddress {
    address: Hash256,
    ephemeral_pubkey: Vec<u8>,
}

/// View key for detecting stealth address payments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ViewKey {
    key: Vec<u8>,
    security_level: SecurityLevel,
}

/// Spend key for spending from stealth addresses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendKey {
    key: Vec<u8>,
    security_level: SecurityLevel,
}

impl StealthAddress {
    /// Create a new stealth address
    pub fn new(address: Hash256, ephemeral_pubkey: Vec<u8>) -> Self {
        Self {
            address,
            ephemeral_pubkey,
        }
    }
    
    /// Get the address hash
    pub fn address(&self) -> &Hash256 {
        &self.address
    }
    
    /// Get the ephemeral public key
    pub fn ephemeral_pubkey(&self) -> &[u8] {
        &self.ephemeral_pubkey
    }
    
    /// Convert to hex string for display
    pub fn to_hex(&self) -> String {
        format!("{}:{}", 
            self.address.to_hex(), 
            hex::encode(&self.ephemeral_pubkey)
        )
    }
    
    /// Create from hex string
    pub fn from_hex(hex_str: &str) -> CryptoResult<Self> {
        let parts: Vec<&str> = hex_str.split(':').collect();
        if parts.len() != 2 {
            return Err(CryptoError::InvalidStealthAddress);
        }
        
        let address = Hash256::from_hex(parts[0])?;
        let ephemeral_pubkey = hex::decode(parts[1])
            .map_err(|_| CryptoError::InvalidStealthAddress)?;
        
        Ok(Self::new(address, ephemeral_pubkey))
    }
}

impl ViewKey {
    /// Create a new view key
    pub fn new(key: Vec<u8>, security_level: SecurityLevel) -> Self {
        Self { key, security_level }
    }
    
    /// Generate a new view key
    pub fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
        security_level: SecurityLevel
    ) -> Self {
        let mut key = vec![0u8; security_level.byte_length()];
        rng.fill_bytes(&mut key);
        Self::new(key, security_level)
    }
    
    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
    
    /// Get security level
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }
    
    /// Check if a stealth address belongs to this view key
    pub fn can_detect(&self, stealth_addr: &StealthAddress, spend_key: &SpendKey) -> bool {
        // Reconstruct the shared secret
        let shared_secret = derive_shared_secret(&self.key, stealth_addr.ephemeral_pubkey());
        
        // Derive the expected address
        let expected_addr = derive_stealth_address_from_secret(&shared_secret, spend_key.as_bytes());
        
        expected_addr.address() == stealth_addr.address()
    }
}

impl SpendKey {
    /// Create a new spend key
    pub fn new(key: Vec<u8>, security_level: SecurityLevel) -> Self {
        Self { key, security_level }
    }
    
    /// Generate a new spend key
    pub fn generate<R: RngCore + CryptoRng>(
        rng: &mut R,
        security_level: SecurityLevel
    ) -> Self {
        let mut key = vec![0u8; security_level.byte_length()];
        rng.fill_bytes(&mut key);
        Self::new(key, security_level)
    }
    
    /// Get the key bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.key
    }
    
    /// Get security level
    pub fn security_level(&self) -> SecurityLevel {
        self.security_level
    }
}

/// Generate a stealth address for a recipient
pub fn generate_stealth_address<R: RngCore + CryptoRng>(
    view_key: &ViewKey,
    spend_key: &SpendKey,
    rng: &mut R
) -> CryptoResult<StealthAddress> {
    if view_key.security_level() != spend_key.security_level() {
        return Err(CryptoError::OperationFailed {
            reason: "View key and spend key security levels must match".to_string()
        });
    }
    
    // Generate ephemeral key pair
    let mut ephemeral_secret = vec![0u8; view_key.security_level().byte_length()];
    rng.fill_bytes(&mut ephemeral_secret);
    
    // Derive ephemeral public key (placeholder - in real implementation would use ECC)
    let ephemeral_pubkey = derive_key(&ephemeral_secret, b"ephemeral_pubkey", view_key.security_level());
    
    // Derive shared secret
    let shared_secret = derive_shared_secret(&ephemeral_secret, view_key.as_bytes());
    
    // Generate stealth address
    let stealth_addr = derive_stealth_address_from_secret(&shared_secret, spend_key.as_bytes());
    
    Ok(StealthAddress::new(stealth_addr.address, ephemeral_pubkey))
}

/// Generate a stealth address with specific transaction ID for deterministic generation
pub fn generate_stealth_address_deterministic(
    view_key: &ViewKey,
    spend_key: &SpendKey,
    transaction_id: &[u8]
) -> CryptoResult<StealthAddress> {
    if view_key.security_level() != spend_key.security_level() {
        return Err(CryptoError::OperationFailed {
            reason: "View key and spend key security levels must match".to_string()
        });
    }
    
    // Derive ephemeral secret from transaction ID
    let ephemeral_secret = derive_key(transaction_id, b"ephemeral_secret", view_key.security_level());
    
    // Derive ephemeral public key
    let ephemeral_pubkey = derive_key(&ephemeral_secret, b"ephemeral_pubkey", view_key.security_level());
    
    // Derive shared secret
    let shared_secret = derive_shared_secret(&ephemeral_secret, view_key.as_bytes());
    
    // Generate stealth address
    let stealth_addr = derive_stealth_address_from_secret(&shared_secret, spend_key.as_bytes());
    
    Ok(StealthAddress::new(stealth_addr.address, ephemeral_pubkey))
}

/// Derive shared secret from two keys (Diffie-Hellman style)
fn derive_shared_secret(key1: &[u8], key2: &[u8]) -> Vec<u8> {
    // Placeholder implementation using hash
    // Real implementation would use elliptic curve DH
    hash_multiple(&[key1, key2]).as_slice().to_vec()
}

/// Derive stealth address from shared secret and spend key
fn derive_stealth_address_from_secret(shared_secret: &[u8], spend_key: &[u8]) -> StealthAddress {
    let address_hash = hash_multiple(&[shared_secret, spend_key]);
    StealthAddress::new(address_hash, vec![]) // Empty ephemeral key for internal use
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_stealth_address_generation() {
        let mut rng = thread_rng();
        let security_level = SecurityLevel::Level1;
        
        let view_key = ViewKey::generate(&mut rng, security_level);
        let spend_key = SpendKey::generate(&mut rng, security_level);
        
        let stealth_addr = generate_stealth_address(&view_key, &spend_key, &mut rng).unwrap();
        
        // Should be able to detect with view key
        assert!(view_key.can_detect(&stealth_addr, &spend_key));
    }
    
    #[test]
    fn test_deterministic_stealth_address() {
        let mut rng = thread_rng();
        let security_level = SecurityLevel::Level1;
        
        let view_key = ViewKey::generate(&mut rng, security_level);
        let spend_key = SpendKey::generate(&mut rng, security_level);
        let tx_id = b"transaction123";
        
        let addr1 = generate_stealth_address_deterministic(&view_key, &spend_key, tx_id).unwrap();
        let addr2 = generate_stealth_address_deterministic(&view_key, &spend_key, tx_id).unwrap();
        
        assert_eq!(addr1, addr2);
        assert!(view_key.can_detect(&addr1, &spend_key));
    }
    
    #[test]
    fn test_different_keys_different_addresses() {
        let mut rng = thread_rng();
        let security_level = SecurityLevel::Level1;
        
        let view_key1 = ViewKey::generate(&mut rng, security_level);
        let spend_key1 = SpendKey::generate(&mut rng, security_level);
        let view_key2 = ViewKey::generate(&mut rng, security_level);
        let spend_key2 = SpendKey::generate(&mut rng, security_level);
        
        let addr1 = generate_stealth_address(&view_key1, &spend_key1, &mut rng).unwrap();
        let addr2 = generate_stealth_address(&view_key2, &spend_key2, &mut rng).unwrap();
        
        assert_ne!(addr1, addr2);
        assert!(!view_key1.can_detect(&addr2, &spend_key1));
        assert!(!view_key2.can_detect(&addr1, &spend_key2));
    }
    
    #[test]
    fn test_hex_conversion() {
        let mut rng = thread_rng();
        let security_level = SecurityLevel::Level1;
        
        let view_key = ViewKey::generate(&mut rng, security_level);
        let spend_key = SpendKey::generate(&mut rng, security_level);
        
        let addr = generate_stealth_address(&view_key, &spend_key, &mut rng).unwrap();
        let hex = addr.to_hex();
        let recovered = StealthAddress::from_hex(&hex).unwrap();
        
        assert_eq!(addr, recovered);
    }
}