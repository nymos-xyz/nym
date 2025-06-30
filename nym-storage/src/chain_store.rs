//! Blockchain data persistence

use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use nym_crypto::{Hash256, hash};
use nym_core::{Block, Transaction, BlockHeader, Proof};
use crate::{EncryptedStore, StorageError, StorageResult, BatchOperation};

/// Block metadata for efficient lookups
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockMetadata {
    pub height: u64,
    pub hash: Hash256,
    pub parent_hash: Hash256,
    pub timestamp: u64,
    pub transaction_count: usize,
    pub size: usize,
}

/// Chain statistics
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ChainStats {
    pub tip_height: u64,
    pub tip_hash: Hash256,
    pub total_transactions: u64,
    pub total_blocks: u64,
    pub chain_work: u64,
}

/// Blockchain storage manager
pub struct ChainStore {
    store: EncryptedStore,
    cache: HashMap<Hash256, BlockMetadata>,
    stats: ChainStats,
}

/// Block storage with transaction indices
pub struct BlockStore {
    store: EncryptedStore,
    block_height_index: HashMap<u64, Hash256>,
    transaction_index: HashMap<Hash256, (Hash256, usize)>, // tx_hash -> (block_hash, index)
}

impl ChainStore {
    /// Create a new chain store
    pub fn new(store: EncryptedStore) -> StorageResult<Self> {
        let mut chain_store = Self {
            store,
            cache: HashMap::new(),
            stats: ChainStats::default(),
        };
        
        // Load existing stats
        chain_store.load_stats()?;
        Ok(chain_store)
    }
    
    /// Store a new block
    pub fn store_block(&mut self, block: &Block) -> StorageResult<()> {
        let block_hash = block.hash();
        let block_key = format!("block:{}", hex::encode(block_hash.as_bytes()));
        
        // Serialize block
        let block_data = bincode::serialize(block)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        // Create metadata
        let metadata = BlockMetadata {
            height: block.header().height(),
            hash: block_hash,
            parent_hash: block.header().parent_hash(),
            timestamp: block.header().timestamp(),
            transaction_count: block.transactions().len(),
            size: block_data.len(),
        };
        
        let metadata_key = format!("block_meta:{}", hex::encode(block_hash.as_bytes()));
        let metadata_data = bincode::serialize(&metadata)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        // Height index
        let height_key = format!("height:{}", block.header().height());
        let height_data = bincode::serialize(&block_hash)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        // Batch write
        let operations = vec![
            BatchOperation::Put {
                cf: "blocks".to_string(),
                key: block_key.as_bytes().to_vec(),
                value: block_data,
            },
            BatchOperation::Put {
                cf: "metadata".to_string(),
                key: metadata_key.as_bytes().to_vec(),
                value: metadata_data,
            },
            BatchOperation::Put {
                cf: "indices".to_string(),
                key: height_key.as_bytes().to_vec(),
                value: height_data,
            },
        ];
        
        self.store.batch_write(operations)?;
        
        // Update cache and stats
        self.cache.insert(block_hash, metadata.clone());
        self.update_stats(&metadata)?;
        
        Ok(())
    }
    
    /// Retrieve a block by hash
    pub fn get_block(&self, block_hash: &Hash256) -> StorageResult<Option<Block>> {
        let block_key = format!("block:{}", hex::encode(block_hash.as_bytes()));
        
        if let Some(data) = self.store.get("blocks", block_key.as_bytes())? {
            let block: Block = bincode::deserialize(&data)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?;
            Ok(Some(block))
        } else {
            Ok(None)
        }
    }
    
    /// Retrieve a block by height
    pub fn get_block_by_height(&self, height: u64) -> StorageResult<Option<Block>> {
        let height_key = format!("height:{}", height);
        
        if let Some(hash_data) = self.store.get("indices", height_key.as_bytes())? {
            let block_hash: Hash256 = bincode::deserialize(&hash_data)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?;
            self.get_block(&block_hash)
        } else {
            Ok(None)
        }
    }
    
    /// Get block metadata
    pub fn get_block_metadata(&self, block_hash: &Hash256) -> StorageResult<Option<BlockMetadata>> {
        // Check cache first
        if let Some(metadata) = self.cache.get(block_hash) {
            return Ok(Some(metadata.clone()));
        }
        
        let metadata_key = format!("block_meta:{}", hex::encode(block_hash.as_bytes()));
        
        if let Some(data) = self.store.get("metadata", metadata_key.as_bytes())? {
            let metadata: BlockMetadata = bincode::deserialize(&data)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?;
            Ok(Some(metadata))
        } else {
            Ok(None)
        }
    }
    
    /// Get chain tip (latest block)
    pub fn get_chain_tip(&self) -> StorageResult<Option<Block>> {
        if self.stats.tip_height == 0 {
            return Ok(None);
        }
        
        self.get_block(&self.stats.tip_hash)
    }
    
    /// Get chain statistics
    pub fn get_stats(&self) -> &ChainStats {
        &self.stats
    }
    
    /// Load chain statistics from storage
    fn load_stats(&mut self) -> StorageResult<()> {
        if let Some(data) = self.store.get("metadata", b"chain_stats")? {
            self.stats = bincode::deserialize(&data)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?;
        }
        Ok(())
    }
    
    /// Update chain statistics
    fn update_stats(&mut self, metadata: &BlockMetadata) -> StorageResult<()> {
        if metadata.height > self.stats.tip_height {
            self.stats.tip_height = metadata.height;
            self.stats.tip_hash = metadata.hash;
        }
        
        self.stats.total_blocks += 1;
        self.stats.total_transactions += metadata.transaction_count as u64;
        self.stats.chain_work += 1; // Simplified work calculation
        
        // Persist stats
        let stats_data = bincode::serialize(&self.stats)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        self.store.put("metadata", b"chain_stats", &stats_data)?;
        
        Ok(())
    }
    
    /// Prune old blocks (for storage optimization)
    pub fn prune_blocks(&mut self, keep_blocks: u64) -> StorageResult<u64> {
        if self.stats.tip_height <= keep_blocks {
            return Ok(0);
        }
        
        let prune_height = self.stats.tip_height - keep_blocks;
        let mut pruned_count = 0;
        
        for height in 0..=prune_height {
            if let Some(block) = self.get_block_by_height(height)? {
                let block_hash = block.hash();
                
                // Remove block and metadata
                let block_key = format!("block:{}", hex::encode(block_hash.as_bytes()));
                let metadata_key = format!("block_meta:{}", hex::encode(block_hash.as_bytes()));
                let height_key = format!("height:{}", height);
                
                let operations = vec![
                    BatchOperation::Delete {
                        cf: "blocks".to_string(),
                        key: block_key.as_bytes().to_vec(),
                    },
                    BatchOperation::Delete {
                        cf: "metadata".to_string(),
                        key: metadata_key.as_bytes().to_vec(),
                    },
                    BatchOperation::Delete {
                        cf: "indices".to_string(),
                        key: height_key.as_bytes().to_vec(),
                    },
                ];
                
                self.store.batch_write(operations)?;
                self.cache.remove(&block_hash);
                pruned_count += 1;
            }
        }
        
        Ok(pruned_count)
    }
}

impl BlockStore {
    /// Create a new block store
    pub fn new(store: EncryptedStore) -> Self {
        Self {
            store,
            block_height_index: HashMap::new(),
            transaction_index: HashMap::new(),
        }
    }
    
    /// Store a block with transaction indices
    pub fn store_block_with_transactions(&mut self, block: &Block) -> StorageResult<()> {
        let block_hash = block.hash();
        let height = block.header().height();
        
        // Store the block
        let block_key = format!("block:{}", hex::encode(block_hash.as_bytes()));
        let block_data = bincode::serialize(block)
            .map_err(|e| StorageError::Serialization { 
                reason: e.to_string() 
            })?;
        
        self.store.put("blocks", block_key.as_bytes(), &block_data)?;
        
        // Update height index
        self.block_height_index.insert(height, block_hash);
        
        // Index transactions
        for (index, transaction) in block.transactions().iter().enumerate() {
            let tx_hash = transaction.hash();
            self.transaction_index.insert(tx_hash, (block_hash, index));
            
            // Store transaction separately for quick access
            let tx_key = format!("tx:{}", hex::encode(tx_hash.as_bytes()));
            let tx_data = bincode::serialize(transaction)
                .map_err(|e| StorageError::Serialization { 
                    reason: e.to_string() 
                })?;
            
            self.store.put("transactions", tx_key.as_bytes(), &tx_data)?;
        }
        
        Ok(())
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
    
    /// Get transaction location (block hash and index)
    pub fn get_transaction_location(&self, tx_hash: &Hash256) -> Option<(Hash256, usize)> {
        self.transaction_index.get(tx_hash).copied()
    }
    
    /// Check if transaction exists
    pub fn has_transaction(&self, tx_hash: &Hash256) -> bool {
        self.transaction_index.contains_key(tx_hash)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use nym_crypto::{SecurityLevel};
    use crate::EncryptionConfig;
    use nym_core::{BlockHeader, Transaction, TransactionType};
    
    fn create_test_block(height: u64, parent_hash: Hash256) -> Block {
        let header = BlockHeader::new(
            height,
            parent_hash,
            Hash256::default(),
            chrono::Utc::now().timestamp() as u64,
            Hash256::default(),
            vec![], // merkle_path
        );
        
        let transactions = vec![];
        Block::new(header, transactions, Proof::default())
    }
    
    #[test]
    fn test_chain_store_basic() {
        let temp_dir = TempDir::new().unwrap();
        let config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path(), config).unwrap();
        
        let mut chain_store = ChainStore::new(store).unwrap();
        
        // Create and store a test block
        let block = create_test_block(1, Hash256::default());
        let block_hash = block.hash();
        
        chain_store.store_block(&block).unwrap();
        
        // Retrieve by hash
        let retrieved = chain_store.get_block(&block_hash).unwrap().unwrap();
        assert_eq!(retrieved.hash(), block_hash);
        
        // Retrieve by height
        let retrieved_by_height = chain_store.get_block_by_height(1).unwrap().unwrap();
        assert_eq!(retrieved_by_height.hash(), block_hash);
        
        // Check stats
        let stats = chain_store.get_stats();
        assert_eq!(stats.tip_height, 1);
        assert_eq!(stats.total_blocks, 1);
    }
    
    #[test]
    fn test_block_store_transactions() {
        let temp_dir = TempDir::new().unwrap();
        let config = EncryptionConfig::new(vec![2u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path(), config).unwrap();
        
        let mut block_store = BlockStore::new(store);
        
        // Create a test block with transactions
        let block = create_test_block(1, Hash256::default());
        
        block_store.store_block_with_transactions(&block).unwrap();
        
        // Test transaction lookup
        for transaction in block.transactions() {
            let tx_hash = transaction.hash();
            assert!(block_store.has_transaction(&tx_hash));
            
            let retrieved_tx = block_store.get_transaction(&tx_hash).unwrap().unwrap();
            assert_eq!(retrieved_tx.hash(), tx_hash);
        }
    }
}