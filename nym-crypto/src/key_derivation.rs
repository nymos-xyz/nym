//! Quantum-resistant key derivation functions using SHAKE256

use crate::{CryptoError, CryptoResult, SecurityLevel, hash_variable_length};

/// Derive a key of specified length from a master key and additional info
pub fn derive_key(
    master_key: &[u8],
    info: &[u8],
    security_level: SecurityLevel,
) -> Vec<u8> {
    let output_length = security_level.byte_length();
    
    // Use SHAKE256 for key derivation (similar to HKDF but quantum-resistant)
    let mut input = Vec::new();
    input.extend_from_slice(master_key);
    input.extend_from_slice(info);
    
    hash_variable_length(&input, output_length)
}

/// Derive multiple keys from a master key
pub fn derive_multiple_keys(
    master_key: &[u8],
    contexts: &[&[u8]],
    security_level: SecurityLevel,
) -> Vec<Vec<u8>> {
    contexts.iter()
        .map(|context| derive_key(master_key, context, security_level))
        .collect()
}

/// Key derivation with salt for additional security
pub fn derive_key_with_salt(
    master_key: &[u8],
    salt: &[u8],
    info: &[u8],
    security_level: SecurityLevel,
) -> Vec<u8> {
    let output_length = security_level.byte_length();
    
    let mut input = Vec::new();
    input.extend_from_slice(salt);
    input.extend_from_slice(master_key);
    input.extend_from_slice(info);
    
    hash_variable_length(&input, output_length)
}

/// Hierarchical key derivation for creating key trees
pub struct HierarchicalKeyDerivation {
    master_key: Vec<u8>,
    security_level: SecurityLevel,
}

impl HierarchicalKeyDerivation {
    /// Create a new hierarchical key derivation context
    pub fn new(master_key: Vec<u8>, security_level: SecurityLevel) -> Self {
        Self {
            master_key,
            security_level,
        }
    }
    
    /// Derive a child key at a specific path
    pub fn derive_child(&self, path: &[u32]) -> Vec<u8> {
        let mut current_key = self.master_key.clone();
        
        for &index in path {
            let index_bytes = index.to_be_bytes();
            current_key = derive_key(&current_key, &index_bytes, self.security_level);
        }
        
        current_key
    }
    
    /// Derive a child key with string path (for human-readable derivation)
    pub fn derive_child_string(&self, path: &str) -> Vec<u8> {
        derive_key(&self.master_key, path.as_bytes(), self.security_level)
    }
}

/// Specialized key derivation for different purposes
pub mod specialized {
    use super::*;
    
    /// Derive a signing key
    pub fn derive_signing_key(
        master_key: &[u8],
        purpose: &str,
        security_level: SecurityLevel,
    ) -> Vec<u8> {
        let info = format!("nym-signing-{}", purpose);
        derive_key(master_key, info.as_bytes(), security_level)
    }
    
    /// Derive an encryption key
    pub fn derive_encryption_key(
        master_key: &[u8],
        purpose: &str,
        security_level: SecurityLevel,
    ) -> Vec<u8> {
        let info = format!("nym-encryption-{}", purpose);
        derive_key(master_key, info.as_bytes(), security_level)
    }
    
    /// Derive a key for stealth addresses
    pub fn derive_stealth_key(
        master_key: &[u8],
        transaction_id: &[u8],
        security_level: SecurityLevel,
    ) -> Vec<u8> {
        let mut info = b"nym-stealth-".to_vec();
        info.extend_from_slice(transaction_id);
        derive_key(master_key, &info, security_level)
    }
    
    /// Derive a view key for privacy coins
    pub fn derive_view_key(
        master_key: &[u8],
        account_index: u32,
        security_level: SecurityLevel,
    ) -> Vec<u8> {
        let info = format!("nym-view-{}", account_index);
        derive_key(master_key, info.as_bytes(), security_level)
    }
    
    /// Derive a spend key for privacy coins
    pub fn derive_spend_key(
        master_key: &[u8],
        account_index: u32,
        security_level: SecurityLevel,
    ) -> Vec<u8> {
        let info = format!("nym-spend-{}", account_index);
        derive_key(master_key, info.as_bytes(), security_level)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{thread_rng, RngCore};

    #[test]
    fn test_basic_key_derivation() {
        let mut rng = thread_rng();
        let mut master_key = [0u8; 32];
        rng.fill_bytes(&mut master_key);
        
        let info = b"test-purpose";
        let derived1 = derive_key(&master_key, info, SecurityLevel::Level1);
        let derived2 = derive_key(&master_key, info, SecurityLevel::Level1);
        
        // Same inputs should produce same output
        assert_eq!(derived1, derived2);
        assert_eq!(derived1.len(), SecurityLevel::Level1.byte_length());
        
        // Different info should produce different output
        let derived3 = derive_key(&master_key, b"different-purpose", SecurityLevel::Level1);
        assert_ne!(derived1, derived3);
    }
    
    #[test]
    fn test_different_security_levels() {
        let master_key = [0u8; 32];
        let info = b"test";
        
        let level1 = derive_key(&master_key, info, SecurityLevel::Level1);
        let level3 = derive_key(&master_key, info, SecurityLevel::Level3);
        let level5 = derive_key(&master_key, info, SecurityLevel::Level5);
        
        assert_eq!(level1.len(), 32);
        assert_eq!(level3.len(), 48);
        assert_eq!(level5.len(), 64);
        
        // Should all be different
        assert_ne!(level1, level3[..32]);
        assert_ne!(level1, level5[..32]);
        assert_ne!(level3, level5[..48]);
    }
    
    #[test]
    fn test_hierarchical_derivation() {
        let master_key = vec![0u8; 32];
        let hkd = HierarchicalKeyDerivation::new(master_key, SecurityLevel::Level1);
        
        let path1 = [0, 1, 2];
        let path2 = [0, 1, 3];
        
        let key1 = hkd.derive_child(&path1);
        let key2 = hkd.derive_child(&path2);
        
        assert_ne!(key1, key2);
        assert_eq!(key1.len(), SecurityLevel::Level1.byte_length());
    }
    
    #[test]
    fn test_string_path_derivation() {
        let master_key = vec![0u8; 32];
        let hkd = HierarchicalKeyDerivation::new(master_key, SecurityLevel::Level1);
        
        let key1 = hkd.derive_child_string("account/0/signing");
        let key2 = hkd.derive_child_string("account/0/encryption");
        let key3 = hkd.derive_child_string("account/1/signing");
        
        // All should be different
        assert_ne!(key1, key2);
        assert_ne!(key1, key3);
        assert_ne!(key2, key3);
    }
    
    #[test]
    fn test_specialized_derivations() {
        let master_key = [0u8; 32];
        
        let signing = specialized::derive_signing_key(&master_key, "transactions", SecurityLevel::Level1);
        let encryption = specialized::derive_encryption_key(&master_key, "storage", SecurityLevel::Level1);
        let stealth = specialized::derive_stealth_key(&master_key, b"tx123", SecurityLevel::Level1);
        let view = specialized::derive_view_key(&master_key, 0, SecurityLevel::Level1);
        let spend = specialized::derive_spend_key(&master_key, 0, SecurityLevel::Level1);
        
        // All should be different
        let keys = [&signing, &encryption, &stealth, &view, &spend];
        for (i, key1) in keys.iter().enumerate() {
            for (j, key2) in keys.iter().enumerate() {
                if i != j {
                    assert_ne!(key1, key2);
                }
            }
        }
    }
    
    #[test]
    fn test_salt_derivation() {
        let master_key = [0u8; 32];
        let salt1 = b"salt1";
        let salt2 = b"salt2";
        let info = b"test";
        
        let key1 = derive_key_with_salt(&master_key, salt1, info, SecurityLevel::Level1);
        let key2 = derive_key_with_salt(&master_key, salt2, info, SecurityLevel::Level1);
        let key3 = derive_key_with_salt(&master_key, salt1, info, SecurityLevel::Level1);
        
        // Same salt should produce same key
        assert_eq!(key1, key3);
        
        // Different salt should produce different key
        assert_ne!(key1, key2);
    }
}