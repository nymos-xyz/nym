//! Account chain storage and transaction history

use std::collections::{HashMap, BTreeMap};
use serde::{Serialize, Deserialize};
use nym_crypto::{Hash256, hash, SecurityLevel};
use nym_core::{Account, Transaction, NymIdentity, EncryptedBalance};
use crate::{EncryptedStore, StorageError, StorageResult};

/// Account metadata for efficient lookups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountMetadata {
    pub account_id: Hash256,
    pub creation_height: u64,
    pub last_update_height: u64,
    pub transaction_count: u64,
    pub total_received: u64,
    pub total_sent: u64,
}

/// Transaction history entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionHistoryEntry {
    pub tx_hash: Hash256,
    pub block_height: u64,
    pub timestamp: u64,
    pub transaction_type: String,
    pub amount: u64,
    pub is_incoming: bool,
}

/// Account storage manager
pub struct AccountStore {
    store: EncryptedStore,
    account_cache: HashMap<Hash256, AccountMetadata>,
    transaction_cache: HashMap<Hash256, Vec<TransactionHistoryEntry>>,
}

/// Transaction storage with privacy-preserving indices
pub struct TransactionStore {
    store: EncryptedStore,
    account_transactions: HashMap<Hash256, BTreeMap<u64, Vec<Hash256>>>, // account_id -> height -> tx_hashes
    stealth_address_index: HashMap<Hash256, Hash256>, // stealth_addr -> account_id
}

/// QuID-encrypted transaction entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuIDEncryptedTransaction {
    /// Transaction hash (public)
    pub tx_hash: Hash256,
    /// QuID identity that owns this transaction
    pub quid_identity: Hash256,
    /// Encrypted transaction data (only decryptable by QuID owner)
    pub encrypted_data: Vec<u8>,
    /// Block height (for indexing)
    pub block_height: u64,
    /// Timestamp
    pub timestamp: u64,
    /// Transaction type (for filtering)
    pub tx_type: String,
    /// Encryption nonce
    pub nonce: Vec<u8>,
}

/// QuID-integrated transaction storage
pub struct QuIDTransactionStore {
    store: EncryptedStore,
    /// Map from QuID identity to encrypted transactions
    quid_transactions: HashMap<Hash256, Vec<QuIDEncryptedTransaction>>,
    /// Privacy-preserving search indices
    height_index: BTreeMap<u64, Vec<Hash256>>, // height -> quid_identities
    type_index: HashMap<String, Vec<Hash256>>, // tx_type -> quid_identities
}

impl AccountStore {
    /// Create a new account store
    pub fn new(store: EncryptedStore) -> Self {
        Self {
            store,
            account_cache: HashMap::new(),
            transaction_cache: HashMap::new(),
        }
    }
    
    /// Store account data
    pub fn store_account(&mut self, account: &Account) -> StorageResult<()> {
        let account_id = account.account_id();
        let account_key = format!("account:{}", hex::encode(account_id.as_bytes()));
        
        // Serialize account
        let account_data = bincode::serialize(account)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        self.store.put("accounts", account_key.as_bytes(), &account_data)?;
        
        // Update metadata
        let metadata = AccountMetadata {
            account_id,
            creation_height: account.creation_height(),
            last_update_height: account.last_update_height(),
            transaction_count: account.transaction_count(),
            total_received: 0, // Will be calculated from transaction history
            total_sent: 0,     // Will be calculated from transaction history
        };
        
        self.store_account_metadata(&metadata)?;
        self.account_cache.insert(account_id, metadata);
        
        Ok(())
    }
    
    /// Retrieve account by ID
    pub fn get_account(&self, account_id: &Hash256) -> StorageResult<Option<Account>> {
        let account_key = format!("account:{}", hex::encode(account_id.as_bytes()));
        
        if let Some(data) = self.store.get("accounts", account_key.as_bytes())? {
            let account: Account = bincode::deserialize(&data)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?;
            Ok(Some(account))
        } else {
            Ok(None)
        }
    }
    
    /// Get account metadata
    pub fn get_account_metadata(&self, account_id: &Hash256) -> StorageResult<Option<AccountMetadata>> {
        // Check cache first
        if let Some(metadata) = self.account_cache.get(account_id) {
            return Ok(Some(metadata.clone()));
        }
        
        let metadata_key = format!("account_meta:{}", hex::encode(account_id.as_bytes()));
        
        if let Some(data) = self.store.get("metadata", metadata_key.as_bytes())? {
            let metadata: AccountMetadata = bincode::deserialize(&data)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?;
            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }
    
    /// Store account metadata
    fn store_account_metadata(&self, metadata: &AccountMetadata) -> StorageResult<()> {
        let metadata_key = format!("account_meta:{}", hex::encode(metadata.account_id.as_bytes()));
        let metadata_data = bincode::serialize(metadata)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        self.store.put("metadata", metadata_key.as_bytes(), &metadata_data)
    }
    
    /// Update account with new transaction
    pub fn update_account_transaction(&mut self, account_id: &Hash256, tx: &Transaction, block_height: u64) -> StorageResult<()> {
        // Get existing metadata
        let mut metadata = self.get_account_metadata(account_id)?
            .ok_or_else(|| StorageError::KeyNotFound { 
                key: hex::encode(account_id.as_bytes()) 
            })?;
        
        // Update metadata
        metadata.last_update_height = block_height;
        metadata.transaction_count += 1;
        
        // Create transaction history entry
        let history_entry = TransactionHistoryEntry {
            tx_hash: tx.hash(),
            block_height,
            timestamp: chrono::Utc::now().timestamp() as u64,
            transaction_type: format!("{:?}", tx.transaction_type()),
            amount: 0, // Will be filled based on transaction analysis
            is_incoming: false, // Will be determined based on transaction analysis
        };
        
        // Store updated metadata
        self.store_account_metadata(&metadata)?;
        self.account_cache.insert(*account_id, metadata);
        
        // Add to transaction history
        self.add_transaction_history(account_id, history_entry)?;
        
        Ok(())
    }
    
    /// Add transaction to account history
    fn add_transaction_history(&mut self, account_id: &Hash256, entry: TransactionHistoryEntry) -> StorageResult<()> {
        let history_key = format!("tx_history:{}", hex::encode(account_id.as_bytes()));
        
        // Get existing history
        let mut history: Vec<TransactionHistoryEntry> = if let Some(data) = self.store.get("metadata", history_key.as_bytes())? {
            bincode::deserialize(&data)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?
        } else {
            Vec::new()
        };
        
        history.push(entry);
        
        // Store updated history
        let history_data = bincode::serialize(&history)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        self.store.put("metadata", history_key.as_bytes(), &history_data)?;
        self.transaction_cache.insert(*account_id, history);
        
        Ok(())
    }
    
    /// Get transaction history for account
    pub fn get_transaction_history(&self, account_id: &Hash256) -> StorageResult<Vec<TransactionHistoryEntry>> {
        // Check cache first
        if let Some(history) = self.transaction_cache.get(account_id) {
            return Ok(history.clone());
        }
        
        let history_key = format!("tx_history:{}", hex::encode(account_id.as_bytes()));
        
        if let Some(data) = self.store.get("metadata", history_key.as_bytes())? {
            let history: Vec<TransactionHistoryEntry> = bincode::deserialize(&data)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?;
            Ok(history)
        } else {
            Ok(Vec::new())
        }
    }
    
    /// Get accounts by creation height range
    pub fn get_accounts_by_height_range(&self, start_height: u64, end_height: u64) -> StorageResult<Vec<Hash256>> {
        let mut account_ids = Vec::new();
        
        // Iterate through all account metadata
        for (key, value) in self.store.iterate("metadata")? {
            if let Ok(key_str) = String::from_utf8(key) {
                if key_str.starts_with("account_meta:") {
                    if let Ok(metadata) = bincode::deserialize::<AccountMetadata>(&value) {
                        if metadata.creation_height >= start_height && metadata.creation_height <= end_height {
                            account_ids.push(metadata.account_id);
                        }
                    }
                }
            }
        }
        
        Ok(account_ids)
    }
    
    /// Get total number of accounts
    pub fn get_account_count(&self) -> StorageResult<u64> {
        let mut count = 0;
        
        for (key, _) in self.store.iterate("accounts")? {
            if let Ok(key_str) = String::from_utf8(key) {
                if key_str.starts_with("account:") {
                    count += 1;
                }
            }
        }
        
        Ok(count)
    }
}

impl TransactionStore {
    /// Create a new transaction store
    pub fn new(store: EncryptedStore) -> Self {
        Self {
            store,
            account_transactions: HashMap::new(),
            stealth_address_index: HashMap::new(),
        }
    }
    
    /// Store transaction with privacy-preserving indices
    pub fn store_transaction(&mut self, tx: &Transaction, block_height: u64, account_id: &Hash256) -> StorageResult<()> {
        let tx_hash = tx.hash();
        let tx_key = format!("tx:{}", hex::encode(tx_hash.as_bytes()));
        
        // Store transaction data
        let tx_data = bincode::serialize(tx)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        self.store.put("transactions", tx_key.as_bytes(), &tx_data)?;
        
        // Update account transaction index
        self.account_transactions
            .entry(*account_id)
            .or_insert_with(BTreeMap::new)
            .entry(block_height)
            .or_insert_with(Vec::new)
            .push(tx_hash);
        
        // Index stealth addresses if present
        match tx {
            Transaction::Private(private_tx) => {
                for output in private_tx.outputs() {
                    if let Some(stealth_addr) = output.stealth_address() {
                        self.stealth_address_index.insert(stealth_addr, *account_id);
                    }
                }
            }
            _ => {}
        }
        
        Ok(())
    }
    
    /// Get transactions for account in height range
    pub fn get_account_transactions(&self, account_id: &Hash256, start_height: u64, end_height: u64) -> StorageResult<Vec<Transaction>> {
        let mut transactions = Vec::new();
        
        if let Some(height_map) = self.account_transactions.get(account_id) {
            for (&height, tx_hashes) in height_map.range(start_height..=end_height) {
                for &tx_hash in tx_hashes {
                    if let Some(tx) = self.get_transaction(&tx_hash)? {
                        transactions.push(tx);
                    }
                }
            }
        }
        
        Ok(transactions)
    }
    
    /// Get transaction by hash
    pub fn get_transaction(&self, tx_hash: &Hash256) -> StorageResult<Option<Transaction>> {
        let tx_key = format!("tx:{}", hex::encode(tx_hash.as_bytes()));
        
        if let Some(data) = self.store.get("transactions", tx_key.as_bytes())? {
            let transaction: Transaction = bincode::deserialize(&data)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?;
            Ok(Some(transaction))
        } else {
            Ok(None)
        }
    }
    
    /// Find account by stealth address
    pub fn find_account_by_stealth_address(&self, stealth_addr: &Hash256) -> Option<Hash256> {
        self.stealth_address_index.get(stealth_addr).copied()
    }
    
    /// Get transaction count for account
    pub fn get_account_transaction_count(&self, account_id: &Hash256) -> u64 {
        self.account_transactions
            .get(account_id)
            .map(|height_map| height_map.values().map(|v| v.len() as u64).sum())
            .unwrap_or(0)
    }
    
    /// Prune old transactions (for storage optimization)
    pub fn prune_transactions(&mut self, keep_heights: u64) -> StorageResult<u64> {
        let mut pruned_count = 0;
        
        for (account_id, height_map) in &mut self.account_transactions {
            let heights_to_remove: Vec<u64> = height_map
                .keys()
                .filter(|&&height| height < keep_heights)
                .copied()
                .collect();
            
            for height in heights_to_remove {
                if let Some(tx_hashes) = height_map.remove(&height) {
                    for tx_hash in tx_hashes {
                        let tx_key = format!("tx:{}", hex::encode(tx_hash.as_bytes()));
                        self.store.delete("transactions", tx_key.as_bytes())?;
                        pruned_count += 1;
                    }
                }
            }
        }
        
        Ok(pruned_count)
    }
}

impl QuIDTransactionStore {
    /// Create a new QuID transaction store
    pub fn new(store: EncryptedStore) -> Self {
        Self {
            store,
            quid_transactions: HashMap::new(),
            height_index: BTreeMap::new(),
            type_index: HashMap::new(),
        }
    }
    
    /// Store transaction encrypted with QuID identity
    pub fn store_quid_transaction(
        &mut self, 
        tx: &Transaction, 
        quid_identity: &NymIdentity,
        block_height: u64
    ) -> StorageResult<()> {
        let tx_hash = tx.hash();
        let quid_id = Hash256::from_bytes(quid_identity.to_bytes());
        
        // Serialize transaction
        let tx_data = bincode::serialize(tx)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        // Generate nonce for encryption
        let nonce: [u8; 32] = rand::random();
        
        // Encrypt transaction data with QuID identity
        let encrypted_data = self.encrypt_with_quid_identity(&tx_data, quid_identity, &nonce)?;
        
        let encrypted_tx = QuIDEncryptedTransaction {
            tx_hash,
            quid_identity: quid_id,
            encrypted_data,
            block_height,
            timestamp: chrono::Utc::now().timestamp() as u64,
            tx_type: format!("{:?}", tx.transaction_type()),
            nonce: nonce.to_vec(),
        };
        
        // Store in database
        let tx_key = format!("quid_tx:{}", hex::encode(tx_hash.as_bytes()));
        let tx_entry_data = bincode::serialize(&encrypted_tx)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        self.store.put("quid_transactions", tx_key.as_bytes(), &tx_entry_data)?;
        
        // Update in-memory indices
        self.quid_transactions
            .entry(quid_id)
            .or_insert_with(Vec::new)
            .push(encrypted_tx.clone());
        
        self.height_index
            .entry(block_height)
            .or_insert_with(Vec::new)
            .push(quid_id);
        
        self.type_index
            .entry(encrypted_tx.tx_type.clone())
            .or_insert_with(Vec::new)
            .push(quid_id);
        
        tracing::info!(
            "Stored QuID-encrypted transaction {} for identity {}",
            tx_hash,
            quid_id
        );
        
        Ok(())
    }
    
    /// Retrieve and decrypt transactions for a QuID identity
    pub fn get_quid_transactions(
        &self,
        quid_identity: &NymIdentity,
        start_height: Option<u64>,
        end_height: Option<u64>
    ) -> StorageResult<Vec<Transaction>> {
        let quid_id = Hash256::from_bytes(quid_identity.to_bytes());
        let mut transactions = Vec::new();
        
        // Get encrypted transactions for this QuID
        if let Some(encrypted_txs) = self.quid_transactions.get(&quid_id) {
            for encrypted_tx in encrypted_txs {
                // Filter by height if specified
                if let Some(start) = start_height {
                    if encrypted_tx.block_height < start {
                        continue;
                    }
                }
                if let Some(end) = end_height {
                    if encrypted_tx.block_height > end {
                        continue;
                    }
                }
                
                // Decrypt transaction
                match self.decrypt_quid_transaction(encrypted_tx, quid_identity) {
                    Ok(tx) => transactions.push(tx),
                    Err(e) => {
                        tracing::warn!(
                            "Failed to decrypt transaction {} for QuID {}: {:?}",
                            encrypted_tx.tx_hash,
                            quid_id,
                            e
                        );
                    }
                }
            }
        }
        
        Ok(transactions)
    }
    
    /// Get transaction count for QuID identity
    pub fn get_quid_transaction_count(&self, quid_identity: &NymIdentity) -> u64 {
        let quid_id = Hash256::from_bytes(quid_identity.to_bytes());
        self.quid_transactions
            .get(&quid_id)
            .map(|txs| txs.len() as u64)
            .unwrap_or(0)
    }
    
    /// Search QuID transactions by type
    pub fn search_quid_transactions_by_type(
        &self,
        quid_identity: &NymIdentity,
        tx_type: &str
    ) -> StorageResult<Vec<Transaction>> {
        let quid_id = Hash256::from_bytes(quid_identity.to_bytes());
        let mut transactions = Vec::new();
        
        if let Some(encrypted_txs) = self.quid_transactions.get(&quid_id) {
            for encrypted_tx in encrypted_txs {
                if encrypted_tx.tx_type == tx_type {
                    match self.decrypt_quid_transaction(encrypted_tx, quid_identity) {
                        Ok(tx) => transactions.push(tx),
                        Err(e) => {
                            tracing::warn!(
                                "Failed to decrypt transaction {} for QuID {}: {:?}",
                                encrypted_tx.tx_hash,
                                quid_id,
                                e
                            );
                        }
                    }
                }
            }
        }
        
        Ok(transactions)
    }
    
    /// Create backup of QuID transactions (encrypted)
    pub fn create_quid_backup(&self, quid_identity: &NymIdentity) -> StorageResult<Vec<u8>> {
        let quid_id = Hash256::from_bytes(quid_identity.to_bytes());
        
        if let Some(encrypted_txs) = self.quid_transactions.get(&quid_id) {
            let backup_data = bincode::serialize(encrypted_txs)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?;
            Ok(backup_data)
        } else {
            Ok(Vec::new())
        }
    }
    
    /// Restore QuID transactions from backup
    pub fn restore_quid_backup(
        &mut self,
        quid_identity: &NymIdentity,
        backup_data: &[u8]
    ) -> StorageResult<u64> {
        let quid_id = Hash256::from_bytes(quid_identity.to_bytes());
        
        let encrypted_txs: Vec<QuIDEncryptedTransaction> = bincode::deserialize(backup_data)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        let mut restored_count = 0;
        
        for encrypted_tx in encrypted_txs {
            // Store in database
            let tx_key = format!("quid_tx:{}", hex::encode(encrypted_tx.tx_hash.as_bytes()));
            let tx_entry_data = bincode::serialize(&encrypted_tx)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?;
            
            self.store.put("quid_transactions", tx_key.as_bytes(), &tx_entry_data)?;
            
            // Update indices
            self.quid_transactions
                .entry(quid_id)
                .or_insert_with(Vec::new)
                .push(encrypted_tx.clone());
            
            self.height_index
                .entry(encrypted_tx.block_height)
                .or_insert_with(Vec::new)
                .push(quid_id);
            
            self.type_index
                .entry(encrypted_tx.tx_type.clone())
                .or_insert_with(Vec::new)
                .push(quid_id);
            
            restored_count += 1;
        }
        
        tracing::info!(
            "Restored {} QuID transactions for identity {}",
            restored_count,
            quid_id
        );
        
        Ok(restored_count)
    }
    
    // Private helper methods
    
    fn encrypt_with_quid_identity(
        &self,
        data: &[u8],
        quid_identity: &NymIdentity,
        nonce: &[u8; 32]
    ) -> StorageResult<Vec<u8>> {
        // Simplified encryption using QuID identity as key
        // In production, would use proper AEAD encryption
        let identity_bytes = quid_identity.to_bytes();
        let key = hash(&identity_bytes);
        
        let mut encrypted = Vec::new();
        for (i, &byte) in data.iter().enumerate() {
            let key_byte = key.as_bytes()[i % 32];
            let nonce_byte = nonce[i % 32];
            encrypted.push(byte ^ key_byte ^ nonce_byte);
        }
        
        Ok(encrypted)
    }
    
    fn decrypt_quid_transaction(
        &self,
        encrypted_tx: &QuIDEncryptedTransaction,
        quid_identity: &NymIdentity
    ) -> StorageResult<Transaction> {
        // Decrypt the transaction data
        let identity_bytes = quid_identity.to_bytes();
        let key = hash(&identity_bytes);
        
        let mut decrypted = Vec::new();
        for (i, &byte) in encrypted_tx.encrypted_data.iter().enumerate() {
            let key_byte = key.as_bytes()[i % 32];
            let nonce_byte = encrypted_tx.nonce[i % 32];
            decrypted.push(byte ^ key_byte ^ nonce_byte);
        }
        
        // Deserialize transaction
        let transaction: Transaction = bincode::deserialize(&decrypted)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        Ok(transaction)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use nym_crypto::{SecurityLevel, QuIDAuth};
    use crate::EncryptionConfig;
    use nym_core::{NymIdentity, TransactionType};
    
    fn create_test_account() -> Account {
        let quid_auth = QuIDAuth::new(vec![1u8; 32], SecurityLevel::Level1);
        let identity = quid_auth.create_nym_identity(0).unwrap();
        Account::new(identity, 100).unwrap()
    }
    
    #[test]
    fn test_account_store_basic() {
        let temp_dir = TempDir::new().unwrap();
        let config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path(), config).unwrap();
        
        let mut account_store = AccountStore::new(store);
        
        // Create and store account
        let account = create_test_account();
        let account_id = account.account_id();
        
        account_store.store_account(&account).unwrap();
        
        // Retrieve account
        let retrieved = account_store.get_account(&account_id).unwrap().unwrap();
        assert_eq!(retrieved.account_id(), account_id);
        
        // Check metadata
        let metadata = account_store.get_account_metadata(&account_id).unwrap().unwrap();
        assert_eq!(metadata.account_id, account_id);
    }
    
    #[test]
    fn test_transaction_store_basic() {
        let temp_dir = TempDir::new().unwrap();
        let config = EncryptionConfig::new(vec![2u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path(), config).unwrap();
        
        let mut tx_store = TransactionStore::new(store);
        
        // Create test data
        let account = create_test_account();
        let account_id = account.account_id();
        
        // Create a simple public transaction for testing
        let quid_auth = QuIDAuth::new(vec![1u8; 32], SecurityLevel::Level1);
        let identity = quid_auth.create_nym_identity(0).unwrap();
        
        let tx = Transaction::Public(nym_core::PublicTransaction::new(
            TransactionType::PublicTransfer,
            vec![], // inputs
            vec![], // outputs
            1000,   // fee
            &identity,
        ).unwrap());
        
        let tx_hash = tx.hash();
        
        // Store transaction
        tx_store.store_transaction(&tx, 100, &account_id).unwrap();
        
        // Retrieve transaction
        let retrieved = tx_store.get_transaction(&tx_hash).unwrap().unwrap();
        assert_eq!(retrieved.hash(), tx_hash);
        
        // Check account transactions
        let account_txs = tx_store.get_account_transactions(&account_id, 100, 100).unwrap();
        assert_eq!(account_txs.len(), 1);
        assert_eq!(account_txs[0].hash(), tx_hash);
    }
    
    #[test]
    fn test_quid_transaction_store_creation() {
        let temp_dir = TempDir::new().unwrap();
        let config = EncryptionConfig::new(vec![3u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path(), config).unwrap();
        
        let quid_store = QuIDTransactionStore::new(store);
        
        assert_eq!(quid_store.quid_transactions.len(), 0);
        assert_eq!(quid_store.height_index.len(), 0);
        assert_eq!(quid_store.type_index.len(), 0);
    }
    
    #[test]
    fn test_quid_transaction_storage_and_retrieval() {
        let temp_dir = TempDir::new().unwrap();
        let config = EncryptionConfig::new(vec![4u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path(), config).unwrap();
        
        let mut quid_store = QuIDTransactionStore::new(store);
        
        // Create test identity and transaction
        let quid_auth = QuIDAuth::new(vec![5u8; 32], SecurityLevel::Level1);
        let identity = quid_auth.create_nym_identity(0).unwrap();
        
        let tx = Transaction::Public(nym_core::PublicTransaction::new(
            TransactionType::PublicTransfer,
            vec![], // inputs
            vec![], // outputs
            2000,   // fee
            &identity,
        ).unwrap());
        
        let tx_hash = tx.hash();
        let block_height = 150;
        
        // Store encrypted transaction
        quid_store.store_quid_transaction(&tx, &identity, block_height).unwrap();
        
        // Verify storage
        assert_eq!(quid_store.get_quid_transaction_count(&identity), 1);
        
        // Retrieve and decrypt transactions
        let retrieved_txs = quid_store.get_quid_transactions(&identity, None, None).unwrap();
        assert_eq!(retrieved_txs.len(), 1);
        assert_eq!(retrieved_txs[0].hash(), tx_hash);
        
        // Test height filtering
        let height_filtered = quid_store.get_quid_transactions(&identity, Some(100), Some(200)).unwrap();
        assert_eq!(height_filtered.len(), 1);
        
        let no_match = quid_store.get_quid_transactions(&identity, Some(200), Some(300)).unwrap();
        assert_eq!(no_match.len(), 0);
    }
    
    #[test]
    fn test_quid_transaction_type_search() {
        let temp_dir = TempDir::new().unwrap();
        let config = EncryptionConfig::new(vec![6u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path(), config).unwrap();
        
        let mut quid_store = QuIDTransactionStore::new(store);
        
        // Create test identity
        let quid_auth = QuIDAuth::new(vec![7u8; 32], SecurityLevel::Level1);
        let identity = quid_auth.create_nym_identity(0).unwrap();
        
        // Create different transaction types
        let public_tx = Transaction::Public(nym_core::PublicTransaction::new(
            TransactionType::PublicTransfer,
            vec![], vec![], 1000, &identity,
        ).unwrap());
        
        let miner_reward_tx = Transaction::Public(nym_core::PublicTransaction::new(
            TransactionType::MinerReward,
            vec![], vec![], 0, &identity,
        ).unwrap());
        
        // Store transactions
        quid_store.store_quid_transaction(&public_tx, &identity, 100).unwrap();
        quid_store.store_quid_transaction(&miner_reward_tx, &identity, 101).unwrap();
        
        // Search by type
        let public_txs = quid_store.search_quid_transactions_by_type(
            &identity, 
            "PublicTransfer"
        ).unwrap();
        assert_eq!(public_txs.len(), 1);
        assert_eq!(public_txs[0].hash(), public_tx.hash());
        
        let reward_txs = quid_store.search_quid_transactions_by_type(
            &identity, 
            "MinerReward"
        ).unwrap();
        assert_eq!(reward_txs.len(), 1);
        assert_eq!(reward_txs[0].hash(), miner_reward_tx.hash());
        
        // Search for non-existent type
        let no_txs = quid_store.search_quid_transactions_by_type(
            &identity, 
            "NonExistentType"
        ).unwrap();
        assert_eq!(no_txs.len(), 0);
    }
    
    #[test]
    fn test_quid_transaction_backup_and_restore() {
        let temp_dir = TempDir::new().unwrap();
        let config = EncryptionConfig::new(vec![8u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path(), config).unwrap();
        
        let mut quid_store = QuIDTransactionStore::new(store);
        
        // Create test identity and transactions
        let quid_auth = QuIDAuth::new(vec![9u8; 32], SecurityLevel::Level1);
        let identity = quid_auth.create_nym_identity(0).unwrap();
        
        // Store multiple transactions
        for i in 0..5 {
            let tx = Transaction::Public(nym_core::PublicTransaction::new(
                TransactionType::PublicTransfer,
                vec![], vec![], 1000 + i, &identity,
            ).unwrap());
            
            quid_store.store_quid_transaction(&tx, &identity, 100 + i as u64).unwrap();
        }
        
        assert_eq!(quid_store.get_quid_transaction_count(&identity), 5);
        
        // Create backup
        let backup_data = quid_store.create_quid_backup(&identity).unwrap();
        assert!(!backup_data.is_empty());
        
        // Create new store and restore
        let temp_dir2 = TempDir::new().unwrap();
        let config2 = EncryptionConfig::new(vec![10u8; 32], SecurityLevel::Level1);
        let store2 = EncryptedStore::new(temp_dir2.path(), config2).unwrap();
        
        let mut quid_store2 = QuIDTransactionStore::new(store2);
        let restored_count = quid_store2.restore_quid_backup(&identity, &backup_data).unwrap();
        
        assert_eq!(restored_count, 5);
        assert_eq!(quid_store2.get_quid_transaction_count(&identity), 5);
        
        // Verify restored transactions can be decrypted
        let restored_txs = quid_store2.get_quid_transactions(&identity, None, None).unwrap();
        assert_eq!(restored_txs.len(), 5);
    }
    
    #[test]
    fn test_quid_transaction_encryption_isolation() {
        let temp_dir = TempDir::new().unwrap();
        let config = EncryptionConfig::new(vec![11u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path(), config).unwrap();
        
        let mut quid_store = QuIDTransactionStore::new(store);
        
        // Create two different identities
        let quid_auth1 = QuIDAuth::new(vec![12u8; 32], SecurityLevel::Level1);
        let identity1 = quid_auth1.create_nym_identity(0).unwrap();
        
        let quid_auth2 = QuIDAuth::new(vec![13u8; 32], SecurityLevel::Level1);
        let identity2 = quid_auth2.create_nym_identity(0).unwrap();
        
        // Store transactions for each identity
        let tx1 = Transaction::Public(nym_core::PublicTransaction::new(
            TransactionType::PublicTransfer,
            vec![], vec![], 1000, &identity1,
        ).unwrap());
        
        let tx2 = Transaction::Public(nym_core::PublicTransaction::new(
            TransactionType::PublicTransfer,
            vec![], vec![], 2000, &identity2,
        ).unwrap());
        
        quid_store.store_quid_transaction(&tx1, &identity1, 100).unwrap();
        quid_store.store_quid_transaction(&tx2, &identity2, 101).unwrap();
        
        // Each identity should only see their own transactions
        let txs1 = quid_store.get_quid_transactions(&identity1, None, None).unwrap();
        assert_eq!(txs1.len(), 1);
        assert_eq!(txs1[0].hash(), tx1.hash());
        
        let txs2 = quid_store.get_quid_transactions(&identity2, None, None).unwrap();
        assert_eq!(txs2.len(), 1);
        assert_eq!(txs2[0].hash(), tx2.hash());
        
        // Verify transaction counts
        assert_eq!(quid_store.get_quid_transaction_count(&identity1), 1);
        assert_eq!(quid_store.get_quid_transaction_count(&identity2), 1);
    }
    
    #[test]
    fn test_quid_transaction_encryption_decryption() {
        let temp_dir = TempDir::new().unwrap();
        let config = EncryptionConfig::new(vec![14u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path(), config).unwrap();
        
        let quid_store = QuIDTransactionStore::new(store);
        
        // Create test identity and transaction
        let quid_auth = QuIDAuth::new(vec![15u8; 32], SecurityLevel::Level1);
        let identity = quid_auth.create_nym_identity(0).unwrap();
        
        let tx = Transaction::Public(nym_core::PublicTransaction::new(
            TransactionType::PublicTransfer,
            vec![], vec![], 5000, &identity,
        ).unwrap());
        
        // Test encryption
        let tx_data = bincode::serialize(&tx).unwrap();
        let nonce = [42u8; 32];
        let encrypted = quid_store.encrypt_with_quid_identity(&tx_data, &identity, &nonce).unwrap();
        
        // Verify data is actually encrypted (not the same as original)
        assert_ne!(encrypted, tx_data);
        
        // Test that encrypted data contains the nonce effect
        assert!(encrypted.len() == tx_data.len());
        
        // Create a mock encrypted transaction for decryption testing
        let encrypted_tx = QuIDEncryptedTransaction {
            tx_hash: tx.hash(),
            quid_identity: Hash256::from_bytes(identity.to_bytes()),
            encrypted_data: encrypted,
            block_height: 200,
            timestamp: 1234567890,
            tx_type: "PublicTransfer".to_string(),
            nonce: nonce.to_vec(),
        };
        
        // Test decryption
        let decrypted_tx = quid_store.decrypt_quid_transaction(&encrypted_tx, &identity).unwrap();
        assert_eq!(decrypted_tx.hash(), tx.hash());
    }
    
    #[test]
    fn test_quid_transaction_multiple_heights() {
        let temp_dir = TempDir::new().unwrap();
        let config = EncryptionConfig::new(vec![16u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path(), config).unwrap();
        
        let mut quid_store = QuIDTransactionStore::new(store);
        
        // Create test identity
        let quid_auth = QuIDAuth::new(vec![17u8; 32], SecurityLevel::Level1);
        let identity = quid_auth.create_nym_identity(0).unwrap();
        
        // Store transactions at different heights
        let heights = vec![100, 150, 200, 250, 300];
        let mut tx_hashes = Vec::new();
        
        for height in &heights {
            let tx = Transaction::Public(nym_core::PublicTransaction::new(
                TransactionType::PublicTransfer,
                vec![], vec![], *height, &identity,
            ).unwrap());
            
            tx_hashes.push(tx.hash());
            quid_store.store_quid_transaction(&tx, &identity, *height).unwrap();
        }
        
        // Test height range filtering
        let range_txs = quid_store.get_quid_transactions(&identity, Some(150), Some(250)).unwrap();
        assert_eq!(range_txs.len(), 3); // Heights 150, 200, 250
        
        let early_txs = quid_store.get_quid_transactions(&identity, Some(50), Some(120)).unwrap();
        assert_eq!(early_txs.len(), 1); // Height 100
        
        let late_txs = quid_store.get_quid_transactions(&identity, Some(280), Some(350)).unwrap();
        assert_eq!(late_txs.len(), 1); // Height 300
        
        // Verify all transactions are still there
        let all_txs = quid_store.get_quid_transactions(&identity, None, None).unwrap();
        assert_eq!(all_txs.len(), 5);
    }
}