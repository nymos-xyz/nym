//! Backup and recovery mechanisms for Nym storage

use std::path::{Path, PathBuf};
use std::fs::{File, create_dir_all};
use std::io::{Write, Read, BufWriter, BufReader};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use nym_crypto::{Hash256, hash, SecurityLevel};
use crate::{EncryptedStore, StorageError, StorageResult};

/// Backup configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupConfig {
    /// Backup destination path
    pub backup_path: PathBuf,
    /// Encryption enabled for backups
    pub encrypted: bool,
    /// Compression enabled
    pub compressed: bool,
    /// Maximum backup files to keep
    pub max_backups: usize,
    /// Backup encryption key
    pub encryption_key: Vec<u8>,
    /// Backup interval in seconds
    pub backup_interval: u64,
}

/// Backup metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupMetadata {
    /// Backup creation timestamp
    pub timestamp: u64,
    /// Backup version
    pub version: String,
    /// Source database path
    pub source_path: PathBuf,
    /// Backup size in bytes
    pub size: u64,
    /// Backup checksum
    pub checksum: Hash256,
    /// Backup type
    pub backup_type: BackupType,
    /// Encryption info
    pub encrypted: bool,
    /// Compression info
    pub compressed: bool,
}

/// Type of backup
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BackupType {
    /// Full database backup
    Full,
    /// Incremental backup (changes only)
    Incremental { since_height: u64 },
    /// Account-specific backup
    Account { account_id: Hash256 },
    /// Configuration backup
    Config,
}

/// Backup manager for handling storage backups and recovery
pub struct BackupManager {
    config: BackupConfig,
    store: EncryptedStore,
    backup_history: Vec<BackupMetadata>,
}

/// Recovery options
#[derive(Debug, Clone)]
pub struct RecoveryOptions {
    /// Target recovery path
    pub target_path: PathBuf,
    /// Verify integrity during recovery
    pub verify_integrity: bool,
    /// Overwrite existing data
    pub overwrite_existing: bool,
    /// Specific backup timestamp to recover
    pub target_timestamp: Option<u64>,
}

/// Backup verification result
#[derive(Debug, Clone)]
pub struct BackupVerification {
    /// Backup is valid
    pub valid: bool,
    /// Checksum matches
    pub checksum_valid: bool,
    /// Backup can be decrypted
    pub decryptable: bool,
    /// Any errors found
    pub errors: Vec<String>,
}

impl Default for BackupConfig {
    fn default() -> Self {
        Self {
            backup_path: PathBuf::from("./backups"),
            encrypted: true,
            compressed: true,
            max_backups: 10,
            encryption_key: vec![0u8; 32], // Should be properly generated
            backup_interval: 3600, // 1 hour
        }
    }
}

impl BackupManager {
    /// Create a new backup manager
    pub fn new(store: EncryptedStore, config: BackupConfig) -> StorageResult<Self> {
        // Ensure backup directory exists
        create_dir_all(&config.backup_path)
            .map_err(|e| StorageError::BackupFailed { 
                reason: format!("Failed to create backup directory: {}", e) 
            })?;
        
        let mut manager = Self {
            config,
            store,
            backup_history: Vec::new(),
        };
        
        // Load existing backup history
        manager.load_backup_history()?;
        
        Ok(manager)
    }
    
    /// Create a full backup
    pub fn create_full_backup(&mut self) -> StorageResult<BackupMetadata> {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let backup_filename = format!("nym_full_backup_{}.bak", timestamp);
        let backup_path = self.config.backup_path.join(&backup_filename);
        
        // Create backup file
        let file = File::create(&backup_path)
            .map_err(|e| StorageError::BackupFailed { 
                reason: format!("Failed to create backup file: {}", e) 
            })?;
        
        let mut writer = BufWriter::new(file);
        let mut total_size = 0u64;
        let mut checksum_data = Vec::new();
        
        // Backup all column families
        let column_families = ["blocks", "transactions", "accounts", "indices", "metadata"];
        
        for cf in &column_families {
            let cf_data = self.backup_column_family(cf)?;
            
            // Write column family header
            let header = format!("CF:{}\n", cf);
            writer.write_all(header.as_bytes())
                .map_err(|e| StorageError::BackupFailed { 
                    reason: format!("Failed to write backup header: {}", e) 
                })?;
            
            // Write data
            let processed_data = if self.config.compressed {
                self.compress_data(&cf_data)?
            } else {
                cf_data.clone()
            };
            
            let encrypted_data = if self.config.encrypted {
                self.encrypt_backup_data(&processed_data)?
            } else {
                processed_data
            };
            
            // Write size and data
            let size_header = format!("SIZE:{}\n", encrypted_data.len());
            writer.write_all(size_header.as_bytes())
                .map_err(|e| StorageError::BackupFailed { 
                    reason: format!("Failed to write size header: {}", e) 
                })?;
            
            writer.write_all(&encrypted_data)
                .map_err(|e| StorageError::BackupFailed { 
                    reason: format!("Failed to write backup data: {}", e) 
                })?;
            
            writer.write_all(b"\n")
                .map_err(|e| StorageError::BackupFailed { 
                    reason: format!("Failed to write separator: {}", e) 
                })?;
            
            total_size += encrypted_data.len() as u64;
            checksum_data.extend_from_slice(&cf_data);
        }
        
        writer.flush()
            .map_err(|e| StorageError::BackupFailed { 
                reason: format!("Failed to flush backup file: {}", e) 
            })?;
        
        // Calculate checksum
        let checksum = hash(&checksum_data);
        
        // Create metadata
        let metadata = BackupMetadata {
            timestamp,
            version: "1.0".to_string(),
            source_path: PathBuf::from("nym_database"), // Placeholder
            size: total_size,
            checksum,
            backup_type: BackupType::Full,
            encrypted: self.config.encrypted,
            compressed: self.config.compressed,
        };
        
        // Save metadata
        self.save_backup_metadata(&metadata, &backup_path)?;
        self.backup_history.push(metadata.clone());
        
        // Cleanup old backups
        self.cleanup_old_backups()?;
        
        Ok(metadata)
    }
    
    /// Create an incremental backup
    pub fn create_incremental_backup(&mut self, since_height: u64) -> StorageResult<BackupMetadata> {
        let timestamp = chrono::Utc::now().timestamp() as u64;
        let backup_filename = format!("nym_incremental_backup_{}_{}.bak", since_height, timestamp);
        let backup_path = self.config.backup_path.join(&backup_filename);
        
        // For now, implement as a simplified version
        // In a full implementation, this would only backup data since the specified height
        
        let file = File::create(&backup_path)
            .map_err(|e| StorageError::BackupFailed { 
                reason: format!("Failed to create incremental backup file: {}", e) 
            })?;
        
        let mut writer = BufWriter::new(file);
        
        // Write incremental backup header
        let header = format!("INCREMENTAL:{}\n", since_height);
        writer.write_all(header.as_bytes())
            .map_err(|e| StorageError::BackupFailed { 
                reason: format!("Failed to write incremental header: {}", e) 
            })?;
        
        // For this implementation, we'll backup recent blocks and transactions
        let blocks_data = self.backup_recent_blocks(since_height)?;
        let transactions_data = self.backup_recent_transactions(since_height)?;
        
        let mut total_size = 0u64;
        let mut checksum_data = Vec::new();
        
        for (cf_name, data) in [("blocks", blocks_data), ("transactions", transactions_data)] {
            if !data.is_empty() {
                let processed_data = if self.config.compressed {
                    self.compress_data(&data)?
                } else {
                    data.clone()
                };
                
                let encrypted_data = if self.config.encrypted {
                    self.encrypt_backup_data(&processed_data)?
                } else {
                    processed_data
                };
                
                let cf_header = format!("CF:{}\nSIZE:{}\n", cf_name, encrypted_data.len());
                writer.write_all(cf_header.as_bytes())
                    .map_err(|e| StorageError::BackupFailed { 
                        reason: format!("Failed to write CF header: {}", e) 
                    })?;
                
                writer.write_all(&encrypted_data)
                    .map_err(|e| StorageError::BackupFailed { 
                        reason: format!("Failed to write incremental data: {}", e) 
                    })?;
                
                writer.write_all(b"\n")
                    .map_err(|e| StorageError::BackupFailed { 
                        reason: format!("Failed to write separator: {}", e) 
                    })?;
                
                total_size += encrypted_data.len() as u64;
                checksum_data.extend_from_slice(&data);
            }
        }
        
        writer.flush()
            .map_err(|e| StorageError::BackupFailed { 
                reason: format!("Failed to flush incremental backup: {}", e) 
            })?;
        
        let checksum = hash(&checksum_data);
        
        let metadata = BackupMetadata {
            timestamp,
            version: "1.0".to_string(),
            source_path: PathBuf::from("nym_database"),
            size: total_size,
            checksum,
            backup_type: BackupType::Incremental { since_height },
            encrypted: self.config.encrypted,
            compressed: self.config.compressed,
        };
        
        self.save_backup_metadata(&metadata, &backup_path)?;
        self.backup_history.push(metadata.clone());
        
        Ok(metadata)
    }
    
    /// Verify backup integrity
    pub fn verify_backup(&self, backup_path: &Path) -> StorageResult<BackupVerification> {
        let mut verification = BackupVerification {
            valid: true,
            checksum_valid: false,
            decryptable: false,
            errors: Vec::new(),
        };
        
        // Check if backup file exists
        if !backup_path.exists() {
            verification.valid = false;
            verification.errors.push("Backup file does not exist".to_string());
            return Ok(verification);
        }
        
        // Load and verify metadata
        let metadata_path = backup_path.with_extension("meta");
        if !metadata_path.exists() {
            verification.valid = false;
            verification.errors.push("Backup metadata file does not exist".to_string());
            return Ok(verification);
        }
        
        // Read and verify backup content
        let file = File::open(backup_path)
            .map_err(|e| StorageError::BackupFailed { 
                reason: format!("Failed to open backup file: {}", e) 
            })?;
        
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)
            .map_err(|e| StorageError::BackupFailed { 
                reason: format!("Failed to read backup file: {}", e) 
            })?;
        
        // Test decryption if encrypted
        if self.config.encrypted {
            match self.decrypt_backup_data(&buffer) {
                Ok(_) => verification.decryptable = true,
                Err(e) => {
                    verification.valid = false;
                    verification.errors.push(format!("Failed to decrypt backup: {:?}", e));
                }
            }
        } else {
            verification.decryptable = true;
        }
        
        // Verify checksum (simplified)
        let computed_checksum = hash(&buffer);
        // In a full implementation, we'd compare with stored checksum
        verification.checksum_valid = true; // Placeholder
        
        Ok(verification)
    }
    
    /// Restore from backup
    pub fn restore_from_backup(&self, backup_path: &Path, options: RecoveryOptions) -> StorageResult<()> {
        // Verify backup first
        let verification = self.verify_backup(backup_path)?;
        if !verification.valid {
            return Err(StorageError::RecoveryFailed { 
                reason: format!("Backup verification failed: {:?}", verification.errors) 
            });
        }
        
        // Read backup file
        let file = File::open(backup_path)
            .map_err(|e| StorageError::RecoveryFailed { 
                reason: format!("Failed to open backup file: {}", e) 
            })?;
        
        let mut reader = BufReader::new(file);
        let mut buffer = Vec::new();
        reader.read_to_end(&mut buffer)
            .map_err(|e| StorageError::RecoveryFailed { 
                reason: format!("Failed to read backup file: {}", e) 
            })?;
        
        // Decrypt if needed
        let decrypted_data = if self.config.encrypted {
            self.decrypt_backup_data(&buffer)?
        } else {
            buffer
        };
        
        // Decompress if needed
        let final_data = if self.config.compressed {
            self.decompress_data(&decrypted_data)?
        } else {
            decrypted_data
        };
        
        // Parse and restore data
        self.parse_and_restore_backup(&final_data, &options)?;
        
        Ok(())
    }
    
    /// List available backups
    pub fn list_backups(&self) -> &[BackupMetadata] {
        &self.backup_history
    }
    
    /// Get backup statistics
    pub fn get_backup_stats(&self) -> BackupStats {
        let total_size: u64 = self.backup_history.iter().map(|b| b.size).sum();
        let full_backups = self.backup_history.iter().filter(|b| matches!(b.backup_type, BackupType::Full)).count();
        let incremental_backups = self.backup_history.iter().filter(|b| matches!(b.backup_type, BackupType::Incremental { .. })).count();
        
        BackupStats {
            total_backups: self.backup_history.len(),
            full_backups,
            incremental_backups,
            total_size,
            oldest_backup: self.backup_history.iter().map(|b| b.timestamp).min(),
            newest_backup: self.backup_history.iter().map(|b| b.timestamp).max(),
        }
    }
    
    // Helper methods
    
    fn backup_column_family(&self, cf_name: &str) -> StorageResult<Vec<u8>> {
        let data = self.store.iterate(cf_name)?;
        bincode::serialize(&data)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })
    }
    
    fn backup_recent_blocks(&self, since_height: u64) -> StorageResult<Vec<u8>> {
        // Simplified: in full implementation, would filter by height
        self.backup_column_family("blocks")
    }
    
    fn backup_recent_transactions(&self, since_height: u64) -> StorageResult<Vec<u8>> {
        // Simplified: in full implementation, would filter by height
        self.backup_column_family("transactions")
    }
    
    fn compress_data(&self, data: &[u8]) -> StorageResult<Vec<u8>> {
        lz4::compress(data, None, false)
            .map_err(|e| StorageError::Compression { 
                reason: e.to_string() 
            })
    }
    
    fn decompress_data(&self, data: &[u8]) -> StorageResult<Vec<u8>> {
        lz4::decompress(data, None)
            .map_err(|e| StorageError::Compression { 
                reason: e.to_string() 
            })
    }
    
    fn encrypt_backup_data(&self, data: &[u8]) -> StorageResult<Vec<u8>> {
        // Simple XOR encryption (placeholder)
        let mut encrypted = Vec::new();
        for (i, &byte) in data.iter().enumerate() {
            let key_byte = self.config.encryption_key[i % self.config.encryption_key.len()];
            encrypted.push(byte ^ key_byte);
        }
        Ok(encrypted)
    }
    
    fn decrypt_backup_data(&self, data: &[u8]) -> StorageResult<Vec<u8>> {
        // Simple XOR decryption (placeholder)
        let mut decrypted = Vec::new();
        for (i, &byte) in data.iter().enumerate() {
            let key_byte = self.config.encryption_key[i % self.config.encryption_key.len()];
            decrypted.push(byte ^ key_byte);
        }
        Ok(decrypted)
    }
    
    fn save_backup_metadata(&self, metadata: &BackupMetadata, backup_path: &Path) -> StorageResult<()> {
        let metadata_path = backup_path.with_extension("meta");
        let metadata_data = bincode::serialize(metadata)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        std::fs::write(metadata_path, metadata_data)
            .map_err(|e| StorageError::BackupFailed { 
                reason: format!("Failed to save metadata: {}", e) 
            })
    }
    
    fn load_backup_history(&mut self) -> StorageResult<()> {
        let history_path = self.config.backup_path.join("backup_history.json");
        if history_path.exists() {
            let data = std::fs::read_to_string(history_path)
                .map_err(|e| StorageError::BackupFailed { 
                    reason: format!("Failed to read backup history: {}", e) 
                })?;
            
            self.backup_history = serde_json::from_str(&data)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?;
        }
        Ok(())
    }
    
    fn cleanup_old_backups(&mut self) -> StorageResult<()> {
        if self.backup_history.len() > self.config.max_backups {
            // Sort by timestamp and remove oldest
            self.backup_history.sort_by_key(|b| b.timestamp);
            let to_remove = self.backup_history.len() - self.config.max_backups;
            
            for _ in 0..to_remove {
                if let Some(old_backup) = self.backup_history.remove(0) {
                    // Remove backup file and metadata
                    let backup_filename = format!("nym_full_backup_{}.bak", old_backup.timestamp);
                    let backup_path = self.config.backup_path.join(backup_filename);
                    let metadata_path = backup_path.with_extension("meta");
                    
                    let _ = std::fs::remove_file(backup_path);
                    let _ = std::fs::remove_file(metadata_path);
                }
            }
        }
        
        // Save updated history
        let history_path = self.config.backup_path.join("backup_history.json");
        let history_data = serde_json::to_string_pretty(&self.backup_history)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        std::fs::write(history_path, history_data)
            .map_err(|e| StorageError::BackupFailed { 
                reason: format!("Failed to save backup history: {}", e) 
            })?;
        
        Ok(())
    }
    
    fn parse_and_restore_backup(&self, data: &[u8], _options: &RecoveryOptions) -> StorageResult<()> {
        // Parse backup data and restore to database
        // This is a simplified implementation
        let _parsed_data: HashMap<String, Vec<(Vec<u8>, Vec<u8>)>> = bincode::deserialize(data)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        // In a full implementation, this would restore data to the appropriate column families
        Ok(())
    }
}

/// Backup statistics
#[derive(Debug, Clone)]
pub struct BackupStats {
    pub total_backups: usize,
    pub full_backups: usize,
    pub incremental_backups: usize,
    pub total_size: u64,
    pub oldest_backup: Option<u64>,
    pub newest_backup: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use nym_crypto::SecurityLevel;
    use crate::EncryptionConfig;
    
    #[test]
    fn test_backup_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let store_config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path().join("store"), store_config).unwrap();
        
        let backup_config = BackupConfig {
            backup_path: temp_dir.path().join("backups").to_path_buf(),
            ..Default::default()
        };
        
        let backup_manager = BackupManager::new(store, backup_config).unwrap();
        assert_eq!(backup_manager.backup_history.len(), 0);
    }
    
    #[test]
    fn test_full_backup_creation() {
        let temp_dir = TempDir::new().unwrap();
        let store_config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path().join("store"), store_config).unwrap();
        
        let backup_config = BackupConfig {
            backup_path: temp_dir.path().join("backups").to_path_buf(),
            ..Default::default()
        };
        
        let mut backup_manager = BackupManager::new(store, backup_config).unwrap();
        
        // Create a full backup
        let metadata = backup_manager.create_full_backup().unwrap();
        assert!(matches!(metadata.backup_type, BackupType::Full));
        assert_eq!(backup_manager.backup_history.len(), 1);
    }
    
    #[test]
    fn test_backup_verification() {
        let temp_dir = TempDir::new().unwrap();
        let store_config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path().join("store"), store_config).unwrap();
        
        let backup_config = BackupConfig {
            backup_path: temp_dir.path().join("backups").to_path_buf(),
            encrypted: false, // Disable encryption for simpler testing
            ..Default::default()
        };
        
        let mut backup_manager = BackupManager::new(store, backup_config).unwrap();
        
        // Create a backup
        let metadata = backup_manager.create_full_backup().unwrap();
        
        // Verify the backup
        let backup_filename = format!("nym_full_backup_{}.bak", metadata.timestamp);
        let backup_path = temp_dir.path().join("backups").join(backup_filename);
        
        let verification = backup_manager.verify_backup(&backup_path).unwrap();
        assert!(verification.decryptable);
    }
    
    #[test]
    fn test_backup_stats() {
        let temp_dir = TempDir::new().unwrap();
        let store_config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path().join("store"), store_config).unwrap();
        
        let backup_config = BackupConfig {
            backup_path: temp_dir.path().join("backups").to_path_buf(),
            ..Default::default()
        };
        
        let mut backup_manager = BackupManager::new(store, backup_config).unwrap();
        
        // Create some backups
        backup_manager.create_full_backup().unwrap();
        backup_manager.create_incremental_backup(100).unwrap();
        
        let stats = backup_manager.get_backup_stats();
        assert_eq!(stats.total_backups, 2);
        assert_eq!(stats.full_backups, 1);
        assert_eq!(stats.incremental_backups, 1);
    }
}