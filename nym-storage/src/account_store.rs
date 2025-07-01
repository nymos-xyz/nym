//! Account chain storage and transaction history

use std::collections::{HashMap, BTreeMap};
use serde::{Serialize, Deserialize};
use nym_crypto::{Hash256, hash};
use nym_core::{Account, Transaction, NymIdentity, EncryptedBalance};
use crate::{EncryptedStore, StorageError, StorageResult, BatchOperation};

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
}