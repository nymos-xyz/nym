//! Privacy-preserving indices for efficient data lookup

use std::collections::{HashMap, BTreeSet};
use serde::{Serialize, Deserialize};
use nym_crypto::{Hash256, hash};
use crate::{EncryptedStore, StorageError, StorageResult};

/// Privacy-preserving index for sensitive data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyIndex {
    /// Encrypted index entries
    entries: HashMap<Hash256, Vec<u8>>,
    /// Bloom filter for membership testing
    bloom_filter: BloomFilter,
    /// Salt for key derivation
    salt: Vec<u8>,
}

/// Stealth address index for transaction lookup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StealthAddressIndex {
    /// Mapping from view key hash to encrypted stealth addresses
    view_key_index: HashMap<Hash256, Vec<EncryptedStealthEntry>>,
    /// Height-based index for pruning
    height_index: BTreeSet<(u64, Hash256)>,
    /// Index configuration
    config: IndexConfig,
}

/// Configuration for privacy indices
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexConfig {
    /// Maximum entries before rebalancing
    pub max_entries: usize,
    /// Bloom filter size
    pub bloom_size: usize,
    /// Hash function count for bloom filter
    pub bloom_hashes: usize,
    /// Encryption enabled
    pub encrypted: bool,
}

/// Encrypted stealth address entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedStealthEntry {
    /// Encrypted stealth address
    encrypted_address: Vec<u8>,
    /// Block height
    height: u64,
    /// Additional metadata
    metadata: Vec<u8>,
}

/// Simple bloom filter for membership testing
#[derive(Debug, Clone, Serialize, Deserialize)]
struct BloomFilter {
    bits: Vec<bool>,
    hash_count: usize,
    size: usize,
}

/// Index manager for all privacy-preserving indices
pub struct IndexManager {
    store: EncryptedStore,
    privacy_indices: HashMap<String, PrivacyIndex>,
    stealth_indices: HashMap<String, StealthAddressIndex>,
    config: IndexConfig,
}

impl Default for IndexConfig {
    fn default() -> Self {
        Self {
            max_entries: 10000,
            bloom_size: 1024 * 8, // 8KB
            bloom_hashes: 3,
            encrypted: true,
        }
    }
}

impl BloomFilter {
    /// Create a new bloom filter
    fn new(size: usize, hash_count: usize) -> Self {
        Self {
            bits: vec![false; size * 8], // size in bytes, convert to bits
            hash_count,
            size,
        }
    }
    
    /// Add an item to the bloom filter
    fn add(&mut self, item: &[u8]) {
        for i in 0..self.hash_count {
            let mut hasher_input = item.to_vec();
            hasher_input.push(i as u8);
            let hash_value = hash(&hasher_input);
            let index = self.hash_to_index(&hash_value);
            self.bits[index] = true;
        }
    }
    
    /// Check if an item might be in the filter
    fn contains(&self, item: &[u8]) -> bool {
        for i in 0..self.hash_count {
            let mut hasher_input = item.to_vec();
            hasher_input.push(i as u8);
            let hash_value = hash(&hasher_input);
            let index = self.hash_to_index(&hash_value);
            if !self.bits[index] {
                return false;
            }
        }
        true
    }
    
    /// Convert hash to bit index
    fn hash_to_index(&self, hash_value: &Hash256) -> usize {
        let bytes = hash_value.as_bytes();
        let mut index = 0usize;
        for (i, &byte) in bytes.iter().take(4).enumerate() {
            index |= (byte as usize) << (i * 8);
        }
        index % self.bits.len()
    }
}

impl PrivacyIndex {
    /// Create a new privacy index
    pub fn new(config: IndexConfig) -> Self {
        let bloom_filter = BloomFilter::new(config.bloom_size, config.bloom_hashes);
        let salt = b"privacy-index-salt".to_vec(); // In production, use random salt
        
        Self {
            entries: HashMap::new(),
            bloom_filter,
            salt,
        }
    }
    
    /// Add an entry to the index
    pub fn add_entry(&mut self, key: &[u8], value: &[u8]) -> StorageResult<()> {
        let entry_hash = self.derive_key(key);
        
        // Add to bloom filter
        self.bloom_filter.add(key);
        
        // Encrypt value if configured
        let encrypted_value = if true { // Always encrypt for now
            self.encrypt_value(value)?
        } else {
            value.to_vec()
        };
        
        self.entries.insert(entry_hash, encrypted_value);
        Ok(())
    }
    
    /// Get an entry from the index
    pub fn get_entry(&self, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        // Quick bloom filter check
        if !self.bloom_filter.contains(key) {
            return Ok(None);
        }
        
        let entry_hash = self.derive_key(key);
        
        if let Some(encrypted_value) = self.entries.get(&entry_hash) {
            let decrypted_value = self.decrypt_value(encrypted_value)?;
            Ok(Some(decrypted_value))
        } else {
            Ok(None)
        }
    }
    
    /// Check if a key exists (privacy-preserving)
    pub fn contains_key(&self, key: &[u8]) -> bool {
        self.bloom_filter.contains(key)
    }
    
    /// Derive a privacy-preserving key
    fn derive_key(&self, key: &[u8]) -> Hash256 {
        let mut input = self.salt.clone();
        input.extend_from_slice(key);
        hash(&input)
    }
    
    /// Encrypt a value (placeholder implementation)
    fn encrypt_value(&self, value: &[u8]) -> StorageResult<Vec<u8>> {
        // Simple XOR encryption with derived key (placeholder)
        let key = hash(&self.salt);
        let key_bytes = key.as_bytes();
        
        let mut encrypted = Vec::new();
        for (i, &byte) in value.iter().enumerate() {
            let key_byte = key_bytes[i % key_bytes.len()];
            encrypted.push(byte ^ key_byte);
        }
        
        Ok(encrypted)
    }
    
    /// Decrypt a value (placeholder implementation)
    fn decrypt_value(&self, encrypted_value: &[u8]) -> StorageResult<Vec<u8>> {
        // Simple XOR decryption with derived key (placeholder)
        let key = hash(&self.salt);
        let key_bytes = key.as_bytes();
        
        let mut decrypted = Vec::new();
        for (i, &byte) in encrypted_value.iter().enumerate() {
            let key_byte = key_bytes[i % key_bytes.len()];
            decrypted.push(byte ^ key_byte);
        }
        
        Ok(decrypted)
    }
    
    /// Get index statistics
    pub fn get_stats(&self) -> IndexStats {
        IndexStats {
            entry_count: self.entries.len(),
            bloom_filter_size: self.bloom_filter.bits.len(),
            estimated_false_positive_rate: self.calculate_false_positive_rate(),
        }
    }
    
    /// Calculate estimated false positive rate
    fn calculate_false_positive_rate(&self) -> f64 {
        let m = self.bloom_filter.bits.len() as f64;
        let k = self.bloom_filter.hash_count as f64;
        let n = self.entries.len() as f64;
        
        if n == 0.0 {
            return 0.0;
        }
        
        // Standard bloom filter false positive rate calculation
        (1.0 - (-k * n / m).exp()).powf(k)
    }
}

impl StealthAddressIndex {
    /// Create a new stealth address index
    pub fn new(config: IndexConfig) -> Self {
        Self {
            view_key_index: HashMap::new(),
            height_index: BTreeSet::new(),
            config,
        }
    }
    
    /// Add a stealth address to the index
    pub fn add_stealth_address(&mut self, view_key: &Hash256, stealth_address: &Hash256, height: u64, metadata: &[u8]) -> StorageResult<()> {
        let view_key_hash = hash(&[view_key.as_bytes(), b"stealth-index"].concat());
        
        // Encrypt stealth address
        let encrypted_address = self.encrypt_stealth_address(stealth_address)?;
        
        let entry = EncryptedStealthEntry {
            encrypted_address,
            height,
            metadata: metadata.to_vec(),
        };
        
        self.view_key_index
            .entry(view_key_hash)
            .or_insert_with(Vec::new)
            .push(entry);
        
        self.height_index.insert((height, *stealth_address));
        
        Ok(())
    }
    
    /// Find stealth addresses for a view key
    pub fn find_stealth_addresses(&self, view_key: &Hash256, height_range: Option<(u64, u64)>) -> StorageResult<Vec<(Hash256, u64, Vec<u8>)>> {
        let view_key_hash = hash(&[view_key.as_bytes(), b"stealth-index"].concat());
        
        let mut results = Vec::new();
        
        if let Some(entries) = self.view_key_index.get(&view_key_hash) {
            for entry in entries {
                // Check height range if specified
                if let Some((start, end)) = height_range {
                    if entry.height < start || entry.height > end {
                        continue;
                    }
                }
                
                // Decrypt stealth address
                let stealth_address = self.decrypt_stealth_address(&entry.encrypted_address)?;
                results.push((stealth_address, entry.height, entry.metadata.clone()));
            }
        }
        
        Ok(results)
    }
    
    /// Prune old entries by height
    pub fn prune_by_height(&mut self, min_height: u64) -> StorageResult<usize> {
        let mut pruned_count = 0;
        
        // Remove from height index
        let to_remove: Vec<_> = self.height_index
            .iter()
            .filter(|(height, _)| *height < min_height)
            .cloned()
            .collect();
        
        for item in to_remove {
            self.height_index.remove(&item);
            pruned_count += 1;
        }
        
        // Remove from view key index
        for entries in self.view_key_index.values_mut() {
            entries.retain(|entry| entry.height >= min_height);
        }
        
        // Remove empty entries
        self.view_key_index.retain(|_, entries| !entries.is_empty());
        
        Ok(pruned_count)
    }
    
    /// Encrypt stealth address (placeholder)
    fn encrypt_stealth_address(&self, address: &Hash256) -> StorageResult<Vec<u8>> {
        // Simple encryption for now
        let key = hash(b"stealth-encryption-key");
        let key_bytes = key.as_bytes();
        let address_bytes = address.as_bytes();
        
        let mut encrypted = Vec::new();
        for (i, &byte) in address_bytes.iter().enumerate() {
            let key_byte = key_bytes[i % key_bytes.len()];
            encrypted.push(byte ^ key_byte);
        }
        
        Ok(encrypted)
    }
    
    /// Decrypt stealth address (placeholder)
    fn decrypt_stealth_address(&self, encrypted: &[u8]) -> StorageResult<Hash256> {
        // Simple decryption for now
        let key = hash(b"stealth-encryption-key");
        let key_bytes = key.as_bytes();
        
        let mut decrypted = [0u8; 32];
        for (i, &byte) in encrypted.iter().take(32).enumerate() {
            let key_byte = key_bytes[i % key_bytes.len()];
            decrypted[i] = byte ^ key_byte;
        }
        
        Ok(Hash256::from(decrypted))
    }
}

impl IndexManager {
    /// Create a new index manager
    pub fn new(store: EncryptedStore, config: IndexConfig) -> Self {
        Self {
            store,
            privacy_indices: HashMap::new(),
            stealth_indices: HashMap::new(),
            config,
        }
    }
    
    /// Get or create a privacy index
    pub fn get_privacy_index(&mut self, index_name: &str) -> &mut PrivacyIndex {
        self.privacy_indices
            .entry(index_name.to_string())
            .or_insert_with(|| PrivacyIndex::new(self.config.clone()))
    }
    
    /// Get or create a stealth address index
    pub fn get_stealth_index(&mut self, index_name: &str) -> &mut StealthAddressIndex {
        self.stealth_indices
            .entry(index_name.to_string())
            .or_insert_with(|| StealthAddressIndex::new(self.config.clone()))
    }
    
    /// Persist all indices to storage
    pub fn persist_indices(&self) -> StorageResult<()> {
        // Persist privacy indices
        for (name, index) in &self.privacy_indices {
            let key = format!("privacy_index:{}", name);
            let data = bincode::serialize(index)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?;
            self.store.put("indices", key.as_bytes(), &data)?;
        }
        
        // Persist stealth indices
        for (name, index) in &self.stealth_indices {
            let key = format!("stealth_index:{}", name);
            let data = bincode::serialize(index)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?;
            self.store.put("indices", key.as_bytes(), &data)?;
        }
        
        Ok(())
    }
    
    /// Load indices from storage
    pub fn load_indices(&mut self) -> StorageResult<()> {
        for (key, value) in self.store.iterate("indices")? {
            if let Ok(key_str) = String::from_utf8(key) {
                if key_str.starts_with("privacy_index:") {
                    let index_name = key_str.strip_prefix("privacy_index:").unwrap();
                    if let Ok(index) = bincode::deserialize::<PrivacyIndex>(&value) {
                        self.privacy_indices.insert(index_name.to_string(), index);
                    }
                } else if key_str.starts_with("stealth_index:") {
                    let index_name = key_str.strip_prefix("stealth_index:").unwrap();
                    if let Ok(index) = bincode::deserialize::<StealthAddressIndex>(&value) {
                        self.stealth_indices.insert(index_name.to_string(), index);
                    }
                }
            }
        }
        
        Ok(())
    }
    
    /// Get statistics for all indices
    pub fn get_all_stats(&self) -> HashMap<String, IndexStats> {
        let mut stats = HashMap::new();
        
        for (name, index) in &self.privacy_indices {
            stats.insert(format!("privacy:{}", name), index.get_stats());
        }
        
        for (name, _index) in &self.stealth_indices {
            stats.insert(format!("stealth:{}", name), IndexStats {
                entry_count: 0, // Would implement proper stats for stealth indices
                bloom_filter_size: 0,
                estimated_false_positive_rate: 0.0,
            });
        }
        
        stats
    }
}

/// Index statistics
#[derive(Debug, Clone)]
pub struct IndexStats {
    pub entry_count: usize,
    pub bloom_filter_size: usize,
    pub estimated_false_positive_rate: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use nym_crypto::SecurityLevel;
    use crate::EncryptionConfig;
    
    #[test]
    fn test_privacy_index() {
        let config = IndexConfig::default();
        let mut index = PrivacyIndex::new(config);
        
        // Add some entries
        let key1 = b"test_key_1";
        let value1 = b"test_value_1";
        index.add_entry(key1, value1).unwrap();
        
        // Test retrieval
        let retrieved = index.get_entry(key1).unwrap().unwrap();
        assert_eq!(retrieved, value1);
        
        // Test non-existent key
        let non_existent = index.get_entry(b"non_existent").unwrap();
        assert!(non_existent.is_none());
        
        // Test bloom filter
        assert!(index.contains_key(key1));
    }
    
    #[test]
    fn test_stealth_address_index() {
        let config = IndexConfig::default();
        let mut index = StealthAddressIndex::new(config);
        
        let view_key = Hash256::from([1u8; 32]);
        let stealth_addr = Hash256::from([2u8; 32]);
        let metadata = b"test_metadata";
        
        // Add stealth address
        index.add_stealth_address(&view_key, &stealth_addr, 100, metadata).unwrap();
        
        // Find stealth addresses
        let results = index.find_stealth_addresses(&view_key, None).unwrap();
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].0, stealth_addr);
        assert_eq!(results[0].1, 100);
        assert_eq!(results[0].2, metadata);
    }
    
    #[test]
    fn test_bloom_filter() {
        let mut bloom = BloomFilter::new(1024, 3);
        
        let item1 = b"test_item_1";
        let item2 = b"test_item_2";
        
        // Add item1
        bloom.add(item1);
        
        // Check membership
        assert!(bloom.contains(item1));
        
        // item2 should likely not be in the filter
        // (though false positives are possible)
        let contains_item2 = bloom.contains(item2);
        println!("Contains item2 (may be false positive): {}", contains_item2);
    }
    
    #[test]
    fn test_index_manager() {
        let temp_dir = TempDir::new().unwrap();
        let encryption_config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path(), encryption_config).unwrap();
        
        let config = IndexConfig::default();
        let mut manager = IndexManager::new(store, config);
        
        // Get privacy index and add entry
        let index = manager.get_privacy_index("test_index");
        index.add_entry(b"test_key", b"test_value").unwrap();
        
        // Persist indices
        manager.persist_indices().unwrap();
        
        // Get stats
        let stats = manager.get_all_stats();
        assert!(stats.contains_key("privacy:test_index"));
    }
}