//! Encrypted storage backend using RocksDB

use std::path::{Path, PathBuf};
use std::collections::HashMap;
use rocksdb::{DB, Options, WriteBatch, ReadOptions, WriteOptions};
use serde::{Serialize, Deserialize};
use nym_crypto::{Hash256, SecurityLevel, derive_key, hash};
use crate::{StorageError, StorageResult};

/// Configuration for encrypted storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    /// Security level for encryption
    pub security_level: SecurityLevel,
    /// Master encryption key (derived from QuID)
    pub master_key: Vec<u8>,
    /// Salt for key derivation
    pub salt: Vec<u8>,
    /// Compression enabled
    pub compression: bool,
}

/// Encrypted storage backend
pub struct EncryptedStore {
    /// RocksDB instance
    db: DB,
    /// Encryption configuration
    config: EncryptionConfig,
    /// Column family mappings
    column_families: HashMap<String, String>,
}

/// Encrypted data entry
#[derive(Debug, Clone, Serialize, Deserialize)]
struct EncryptedEntry {
    /// Encrypted data
    data: Vec<u8>,
    /// Initialization vector
    iv: Vec<u8>,
    /// Data hash for integrity
    hash: Hash256,
    /// Compression flag
    compressed: bool,
}

impl EncryptionConfig {
    /// Create a new encryption config
    pub fn new(master_key: Vec<u8>, security_level: SecurityLevel) -> Self {
        let salt = b"nym-storage-salt".to_vec(); // In production, use random salt
        Self {
            security_level,
            master_key,
            salt,
            compression: true,
        }
    }
    
    /// Derive an encryption key for a specific purpose
    pub fn derive_key(&self, purpose: &str) -> Vec<u8> {
        let mut input = self.salt.clone();
        input.extend_from_slice(purpose.as_bytes());
        derive_key(&self.master_key, &input, self.security_level)
    }
}

impl EncryptedStore {
    /// Create a new encrypted store
    pub fn new<P: AsRef<Path>>(path: P, config: EncryptionConfig) -> StorageResult<Self> {
        let mut opts = Options::default();
        opts.create_if_missing(true);
        opts.set_compression_type(rocksdb::DBCompressionType::Lz4);
        
        // Create column families for different data types
        let cf_names = vec!["blocks", "transactions", "accounts", "indices", "metadata"];
        
        let db = DB::open_cf(&opts, &path, &cf_names)
            .map_err(|e| StorageError::DatabaseError { 
                reason: e.to_string() 
            })?;
        
        let mut column_families = HashMap::new();
        for cf_name in cf_names {
            column_families.insert(cf_name.to_string(), cf_name.to_string());
        }
        
        Ok(Self {
            db,
            config,
            column_families,
        })
    }
    
    /// Open an existing encrypted store
    pub fn open<P: AsRef<Path>>(path: P, config: EncryptionConfig) -> StorageResult<Self> {
        Self::new(path, config)
    }
    
    /// Store encrypted data
    pub fn put(&self, cf: &str, key: &[u8], value: &[u8]) -> StorageResult<()> {
        let encrypted_entry = self.encrypt_data(value)?;
        let serialized = bincode::serialize(&encrypted_entry)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        let cf_handle = self.db.cf_handle(cf)
            .ok_or_else(|| StorageError::DatabaseError { 
                reason: format!("Column family {} not found", cf) 
            })?;
        
        self.db.put_cf(cf_handle, key, serialized)
            .map_err(|e| StorageError::DatabaseError { 
                reason: e.to_string() 
            })
    }
    
    /// Retrieve and decrypt data
    pub fn get(&self, cf: &str, key: &[u8]) -> StorageResult<Option<Vec<u8>>> {
        let cf_handle = self.db.cf_handle(cf)
            .ok_or_else(|| StorageError::DatabaseError { 
                reason: format!("Column family {} not found", cf) 
            })?;
        
        let data = self.db.get_cf(cf_handle, key)
            .map_err(|e| StorageError::DatabaseError { 
                reason: e.to_string() 
            })?;
        
        match data {
            Some(encrypted_data) => {
                let encrypted_entry: EncryptedEntry = bincode::deserialize(&encrypted_data)
                    .map_err(|e| StorageError::Serialization { 
                        reason: e.to_string() 
                    })?;
                
                let decrypted = self.decrypt_data(&encrypted_entry)?;
                Ok(Some(decrypted))
            }
            None => Ok(None),
        }
    }
    
    /// Delete data
    pub fn delete(&self, cf: &str, key: &[u8]) -> StorageResult<()> {
        let cf_handle = self.db.cf_handle(cf)
            .ok_or_else(|| StorageError::DatabaseError { 
                reason: format!("Column family {} not found", cf) 
            })?;
        
        self.db.delete_cf(cf_handle, key)
            .map_err(|e| StorageError::DatabaseError { 
                reason: e.to_string() 
            })
    }
    
    /// Batch write operations
    pub fn batch_write(&self, operations: Vec<BatchOperation>) -> StorageResult<()> {
        let mut batch = WriteBatch::default();
        
        for op in operations {
            match op {
                BatchOperation::Put { cf, key, value } => {
                    let encrypted_entry = self.encrypt_data(&value)?;
                    let serialized = bincode::serialize(&encrypted_entry)
                        .map_err(|e| StorageError::Serialization { 
                            reason: e.to_string() 
                        })?;
                    
                    let cf_handle = self.db.cf_handle(&cf)
                        .ok_or_else(|| StorageError::DatabaseError { 
                            reason: format!("Column family {} not found", cf) 
                        })?;
                    
                    batch.put_cf(cf_handle, key, serialized);
                }
                BatchOperation::Delete { cf, key } => {
                    let cf_handle = self.db.cf_handle(&cf)
                        .ok_or_else(|| StorageError::DatabaseError { 
                            reason: format!("Column family {} not found", cf) 
                        })?;
                    
                    batch.delete_cf(cf_handle, key);
                }
            }
        }
        
        self.db.write(batch)
            .map_err(|e| StorageError::DatabaseError { 
                reason: e.to_string() 
            })
    }
    
    /// Iterate over keys in a column family
    pub fn iterate(&self, cf: &str) -> StorageResult<Vec<(Vec<u8>, Vec<u8>)>> {
        let cf_handle = self.db.cf_handle(cf)
            .ok_or_else(|| StorageError::DatabaseError { 
                reason: format!("Column family {} not found", cf) 
            })?;
        
        let iter = self.db.iterator_cf(cf_handle, rocksdb::IteratorMode::Start);
        let mut results = Vec::new();
        
        for item in iter {
            let (key, encrypted_data) = item
                .map_err(|e| StorageError::DatabaseError { 
                    reason: e.to_string() 
                })?;
            
            let encrypted_entry: EncryptedEntry = bincode::deserialize(&encrypted_data)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?;
            
            let decrypted = self.decrypt_data(&encrypted_entry)?;
            results.push((key.to_vec(), decrypted));
        }
        
        Ok(results)
    }
    
    /// Get storage statistics
    pub fn get_stats(&self) -> StorageResult<StorageStats> {
        let mut stats = StorageStats::default();
        
        for cf_name in self.column_families.keys() {
            if let Some(cf_handle) = self.db.cf_handle(cf_name) {
                let iter = self.db.iterator_cf(cf_handle, rocksdb::IteratorMode::Start);
                let mut cf_size = 0u64;
                let mut cf_count = 0u64;
                
                for item in iter {
                    if let Ok((key, value)) = item {
                        cf_size += key.len() as u64 + value.len() as u64;
                        cf_count += 1;
                    }
                }
                
                stats.column_families.insert(cf_name.clone(), ColumnFamilyStats {
                    entry_count: cf_count,
                    total_size: cf_size,
                });
                
                stats.total_entries += cf_count;
                stats.total_size += cf_size;
            }
        }
        
        Ok(stats)
    }
    
    /// Compact the database
    pub fn compact(&self) -> StorageResult<()> {
        self.db.compact_range::<&[u8], &[u8]>(None, None);
        Ok(())
    }
    
    /// Encrypt data
    fn encrypt_data(&self, data: &[u8]) -> StorageResult<EncryptedEntry> {
        let mut processed_data = data.to_vec();
        let mut compressed = false;
        
        // Compress if enabled and beneficial
        if self.config.compression && data.len() > 1024 {
            match lz4::compress(&data, None, false) {
                Ok(compressed_data) if compressed_data.len() < data.len() => {
                    processed_data = compressed_data;
                    compressed = true;
                }
                _ => {} // Keep original data if compression fails or doesn't help
            }
        }
        
        // Calculate hash for integrity
        let hash = hash(&processed_data);
        
        // Simple encryption using XOR with derived key (placeholder)
        // In production, use AES-GCM or similar
        let encryption_key = self.config.derive_key("data-encryption");
        let iv = b"nym-storage-iv00".to_vec(); // In production, use random IV
        
        let mut encrypted_data = Vec::new();
        for (i, &byte) in processed_data.iter().enumerate() {
            let key_byte = encryption_key[i % encryption_key.len()];
            let iv_byte = iv[i % iv.len()];
            encrypted_data.push(byte ^ key_byte ^ iv_byte);
        }
        
        Ok(EncryptedEntry {
            data: encrypted_data,
            iv,
            hash,
            compressed,
        })
    }
    
    /// Decrypt data
    fn decrypt_data(&self, entry: &EncryptedEntry) -> StorageResult<Vec<u8>> {
        // Decrypt using XOR with derived key (placeholder)
        let encryption_key = self.config.derive_key("data-encryption");
        
        let mut decrypted_data = Vec::new();
        for (i, &byte) in entry.data.iter().enumerate() {
            let key_byte = encryption_key[i % encryption_key.len()];
            let iv_byte = entry.iv[i % entry.iv.len()];
            decrypted_data.push(byte ^ key_byte ^ iv_byte);
        }
        
        // Verify integrity
        let computed_hash = hash(&decrypted_data);
        if computed_hash != entry.hash {
            return Err(StorageError::Corruption { 
                reason: "Data integrity check failed".to_string() 
            });
        }
        
        // Decompress if needed
        if entry.compressed {
            match lz4::decompress(&decrypted_data, None) {
                Ok(decompressed) => Ok(decompressed),
                Err(e) => Err(StorageError::Compression { 
                    reason: e.to_string() 
                })
            }
        } else {
            Ok(decrypted_data)
        }
    }
}

/// Batch operation for bulk writes
#[derive(Debug, Clone)]
pub enum BatchOperation {
    Put { cf: String, key: Vec<u8>, value: Vec<u8> },
    Delete { cf: String, key: Vec<u8> },
}

/// Storage statistics
#[derive(Debug, Default)]
pub struct StorageStats {
    pub total_entries: u64,
    pub total_size: u64,
    pub column_families: HashMap<String, ColumnFamilyStats>,
}

/// Column family statistics
#[derive(Debug)]
pub struct ColumnFamilyStats {
    pub entry_count: u64,
    pub total_size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use nym_crypto::SecurityLevel;

    #[test]
    fn test_encrypted_store_basic() {
        let temp_dir = TempDir::new().unwrap();
        let config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
        
        let store = EncryptedStore::new(temp_dir.path(), config).unwrap();
        
        // Test put and get
        let key = b"test_key";
        let value = b"test_value_with_some_data";
        
        store.put("metadata", key, value).unwrap();
        let retrieved = store.get("metadata", key).unwrap().unwrap();
        
        assert_eq!(retrieved, value);
    }
    
    #[test]
    fn test_encrypted_store_compression() {
        let temp_dir = TempDir::new().unwrap();
        let config = EncryptionConfig::new(vec![2u8; 32], SecurityLevel::Level1);
        
        let store = EncryptedStore::new(temp_dir.path(), config).unwrap();
        
        // Test with large data that should be compressed
        let large_data = vec![42u8; 2048];
        let key = b"large_key";
        
        store.put("metadata", key, &large_data).unwrap();
        let retrieved = store.get("metadata", key).unwrap().unwrap();
        
        assert_eq!(retrieved, large_data);
    }
    
    #[test]
    fn test_batch_operations() {
        let temp_dir = TempDir::new().unwrap();
        let config = EncryptionConfig::new(vec![3u8; 32], SecurityLevel::Level1);
        
        let store = EncryptedStore::new(temp_dir.path(), config).unwrap();
        
        let operations = vec![
            BatchOperation::Put {
                cf: "metadata".to_string(),
                key: b"key1".to_vec(),
                value: b"value1".to_vec(),
            },
            BatchOperation::Put {
                cf: "metadata".to_string(),
                key: b"key2".to_vec(),
                value: b"value2".to_vec(),
            },
        ];
        
        store.batch_write(operations).unwrap();
        
        assert_eq!(store.get("metadata", b"key1").unwrap().unwrap(), b"value1");
        assert_eq!(store.get("metadata", b"key2").unwrap().unwrap(), b"value2");
    }
    
    #[test]
    fn test_storage_stats() {
        let temp_dir = TempDir::new().unwrap();
        let config = EncryptionConfig::new(vec![4u8; 32], SecurityLevel::Level1);
        
        let store = EncryptedStore::new(temp_dir.path(), config).unwrap();
        
        // Add some data
        store.put("metadata", b"key1", b"value1").unwrap();
        store.put("blocks", b"key2", b"value2").unwrap();
        
        let stats = store.get_stats().unwrap();
        assert!(stats.total_entries >= 2);
        assert!(stats.total_size > 0);
    }
}