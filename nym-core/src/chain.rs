//! Chain state management and block structures

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use nym_crypto::Hash256;
use crate::{CoreError, CoreResult, TransactionId, Account};

/// Block in the Nym blockchain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    /// Block height
    height: u64,
    /// Previous block hash
    previous_hash: Hash256,
    /// Merkle root of transactions
    merkle_root: Hash256,
    /// Block timestamp
    timestamp: DateTime<Utc>,
    /// List of transaction IDs in this block
    transaction_ids: Vec<TransactionId>,
    /// Block hash
    hash: Hash256,
    /// Miner/Validator information
    producer: Hash256,
    /// Block size in bytes
    size: u64,
}

/// Overall chain state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    /// Current block height
    current_height: u64,
    /// Hash of the latest block
    latest_block_hash: Hash256,
    /// Total number of transactions
    total_transactions: u64,
    /// Active account count
    active_accounts: u64,
    /// Last update timestamp
    last_updated: DateTime<Utc>,
    /// Network statistics
    network_stats: NetworkStats,
}

/// Network statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStats {
    /// Average block time in seconds
    avg_block_time: f64,
    /// Average transactions per block
    avg_tx_per_block: f64,
    /// Total value transferred (in smallest unit)
    total_value_transferred: u128,
    /// Active validator count
    active_validators: u32,
    /// Active miner count
    active_miners: u32,
}

impl Block {
    /// Create a new block
    pub fn new(
        height: u64,
        previous_hash: Hash256,
        transaction_ids: Vec<TransactionId>,
        producer: Hash256,
    ) -> CoreResult<Self> {
        let timestamp = Utc::now();
        
        // Calculate merkle root of transactions
        let merkle_root = Self::calculate_merkle_root(&transaction_ids)?;
        
        // Calculate block hash
        let hash = Self::calculate_block_hash(
            height,
            &previous_hash,
            &merkle_root,
            &timestamp,
            &producer,
        )?;
        
        // Estimate block size (placeholder)
        let size = (transaction_ids.len() * 64) as u64; // Rough estimate
        
        Ok(Self {
            height,
            previous_hash,
            merkle_root,
            timestamp,
            transaction_ids,
            hash,
            producer,
            size,
        })
    }
    
    /// Get block height
    pub fn height(&self) -> u64 {
        self.height
    }
    
    /// Get block hash
    pub fn hash(&self) -> &Hash256 {
        &self.hash
    }
    
    /// Get previous block hash
    pub fn previous_hash(&self) -> &Hash256 {
        &self.previous_hash
    }
    
    /// Get transaction IDs
    pub fn transaction_ids(&self) -> &[TransactionId] {
        &self.transaction_ids
    }
    
    /// Get timestamp
    pub fn timestamp(&self) -> &DateTime<Utc> {
        &self.timestamp
    }
    
    /// Get producer (miner/validator)
    pub fn producer(&self) -> &Hash256 {
        &self.producer
    }
    
    /// Get block size
    pub fn size(&self) -> u64 {
        self.size
    }
    
    /// Verify block integrity
    pub fn verify(&self) -> CoreResult<bool> {
        // Verify merkle root
        let computed_merkle = Self::calculate_merkle_root(&self.transaction_ids)?;
        if computed_merkle != self.merkle_root {
            return Ok(false);
        }
        
        // Verify block hash
        let computed_hash = Self::calculate_block_hash(
            self.height,
            &self.previous_hash,
            &self.merkle_root,
            &self.timestamp,
            &self.producer,
        )?;
        
        Ok(computed_hash == self.hash)
    }
    
    /// Calculate merkle root of transaction IDs
    fn calculate_merkle_root(transaction_ids: &[TransactionId]) -> CoreResult<Hash256> {
        if transaction_ids.is_empty() {
            // Empty block merkle root
            return Ok(Hash256::from_bytes([0u8; 32]));
        }
        
        if transaction_ids.len() == 1 {
            return Ok(transaction_ids[0]);
        }
        
        // Simple merkle tree implementation
        let mut current_level: Vec<Hash256> = transaction_ids.to_vec();
        
        while current_level.len() > 1 {
            let mut next_level = Vec::new();
            
            for chunk in current_level.chunks(2) {
                let left = &chunk[0];
                let right = chunk.get(1).unwrap_or(left); // Duplicate if odd number
                
                let combined = nym_crypto::hash::hash_multiple(&[
                    left.as_slice(),
                    right.as_slice(),
                ]);
                next_level.push(combined);
            }
            
            current_level = next_level;
        }
        
        Ok(current_level[0])
    }
    
    /// Calculate block hash
    fn calculate_block_hash(
        height: u64,
        previous_hash: &Hash256,
        merkle_root: &Hash256,
        timestamp: &DateTime<Utc>,
        producer: &Hash256,
    ) -> CoreResult<Hash256> {
        let mut data = Vec::new();
        
        data.extend_from_slice(&height.to_le_bytes());
        data.extend_from_slice(previous_hash.as_slice());
        data.extend_from_slice(merkle_root.as_slice());
        data.extend_from_slice(&timestamp.timestamp().to_le_bytes());
        data.extend_from_slice(producer.as_slice());
        
        Ok(nym_crypto::hash::hash(&data))
    }
}

impl ChainState {
    /// Create a new chain state (genesis)
    pub fn new() -> Self {
        Self {
            current_height: 0,
            latest_block_hash: Hash256::from_bytes([0u8; 32]),
            total_transactions: 0,
            active_accounts: 0,
            last_updated: Utc::now(),
            network_stats: NetworkStats {
                avg_block_time: 60.0, // 1 minute target
                avg_tx_per_block: 0.0,
                total_value_transferred: 0,
                active_validators: 0,
                active_miners: 0,
            },
        }
    }
    
    /// Update state with a new block
    pub fn update_with_block(&mut self, block: &Block) -> CoreResult<()> {
        // Verify block height is sequential
        if block.height() != self.current_height + 1 {
            return Err(CoreError::InvalidChainState {
                reason: format!(
                    "Invalid block height: expected {}, got {}",
                    self.current_height + 1,
                    block.height()
                ),
            });
        }
        
        // Verify previous hash matches
        if block.previous_hash() != &self.latest_block_hash {
            return Err(CoreError::InvalidChainState {
                reason: "Previous hash mismatch".to_string(),
            });
        }
        
        // Update state
        self.current_height = block.height();
        self.latest_block_hash = *block.hash();
        self.total_transactions += block.transaction_ids().len() as u64;
        self.last_updated = Utc::now();
        
        // Update network statistics
        self.update_network_stats(block)?;
        
        Ok(())
    }
    
    /// Get current height
    pub fn current_height(&self) -> u64 {
        self.current_height
    }
    
    /// Get latest block hash
    pub fn latest_block_hash(&self) -> &Hash256 {
        &self.latest_block_hash
    }
    
    /// Get total transactions
    pub fn total_transactions(&self) -> u64 {
        self.total_transactions
    }
    
    /// Get network statistics
    pub fn network_stats(&self) -> &NetworkStats {
        &self.network_stats
    }
    
    /// Update network statistics with new block
    fn update_network_stats(&mut self, _block: &Block) -> CoreResult<()> {
        // Update average transactions per block
        if self.current_height > 0 {
            let total_tx = self.total_transactions as f64;
            let blocks = self.current_height as f64;
            self.network_stats.avg_tx_per_block = total_tx / blocks;
        }
        
        // Update average block time (placeholder - would need historical data)
        // This would be calculated from actual block timestamps in real implementation
        
        Ok(())
    }
}

impl Default for ChainState {
    fn default() -> Self {
        Self::new()
    }
}

/// Chain manager for handling blockchain state
pub struct ChainManager {
    /// Current chain state
    state: ChainState,
    /// Block storage (in real implementation, this would be a database)
    blocks: HashMap<u64, Block>,
    /// Block hash to height mapping
    hash_to_height: HashMap<Hash256, u64>,
}

impl ChainManager {
    /// Create a new chain manager
    pub fn new() -> Self {
        Self {
            state: ChainState::new(),
            blocks: HashMap::new(),
            hash_to_height: HashMap::new(),
        }
    }
    
    /// Add a new block to the chain
    pub fn add_block(&mut self, block: Block) -> CoreResult<()> {
        // Verify block
        if !block.verify()? {
            return Err(CoreError::InvalidChainState {
                reason: "Block verification failed".to_string(),
            });
        }
        
        // Update state
        self.state.update_with_block(&block)?;
        
        // Store block
        let height = block.height();
        let hash = block.hash().clone();
        self.blocks.insert(height, block);
        self.hash_to_height.insert(hash, height);
        
        Ok(())
    }
    
    /// Get block by height
    pub fn get_block_by_height(&self, height: u64) -> Option<&Block> {
        self.blocks.get(&height)
    }
    
    /// Get block by hash
    pub fn get_block_by_hash(&self, hash: &Hash256) -> Option<&Block> {
        self.hash_to_height.get(hash)
            .and_then(|height| self.blocks.get(height))
    }
    
    /// Get current chain state
    pub fn state(&self) -> &ChainState {
        &self.state
    }
    
    /// Get latest block
    pub fn latest_block(&self) -> Option<&Block> {
        self.get_block_by_height(self.state.current_height())
    }
    
    /// Get blocks in range
    pub fn get_blocks_range(&self, from: u64, to: u64) -> Vec<&Block> {
        (from..=to.min(self.state.current_height()))
            .filter_map(|height| self.blocks.get(&height))
            .collect()
    }
    
    /// Verify chain integrity
    pub fn verify_chain(&self) -> CoreResult<bool> {
        if self.blocks.is_empty() {
            return Ok(true);
        }
        
        // Check each block
        for height in 0..=self.state.current_height() {
            if let Some(block) = self.blocks.get(&height) {
                if !block.verify()? {
                    return Ok(false);
                }
                
                // Check sequential linking
                if height > 0 {
                    if let Some(prev_block) = self.blocks.get(&(height - 1)) {
                        if block.previous_hash() != prev_block.hash() {
                            return Ok(false);
                        }
                    } else {
                        return Ok(false);
                    }
                }
            } else {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
}

impl Default for ChainManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_block_creation() {
        let previous_hash = Hash256::from_bytes([1u8; 32]);
        let producer = Hash256::from_bytes([2u8; 32]);
        let tx_ids = vec![
            Hash256::from_bytes([3u8; 32]),
            Hash256::from_bytes([4u8; 32]),
        ];
        
        let block = Block::new(1, previous_hash, tx_ids, producer).unwrap();
        
        assert_eq!(block.height(), 1);
        assert_eq!(block.previous_hash(), &previous_hash);
        assert_eq!(block.transaction_ids().len(), 2);
        assert!(block.verify().unwrap());
    }
    
    #[test]
    fn test_chain_state() {
        let mut state = ChainState::new();
        assert_eq!(state.current_height(), 0);
        
        let block = Block::new(
            1,
            state.latest_block_hash().clone(),
            vec![Hash256::from_bytes([1u8; 32])],
            Hash256::from_bytes([2u8; 32]),
        ).unwrap();
        
        state.update_with_block(&block).unwrap();
        assert_eq!(state.current_height(), 1);
        assert_eq!(state.total_transactions(), 1);
    }
    
    #[test]
    fn test_chain_manager() {
        let mut manager = ChainManager::new();
        
        let block1 = Block::new(
            1,
            Hash256::from_bytes([0u8; 32]), // Genesis previous hash
            vec![Hash256::from_bytes([1u8; 32])],
            Hash256::from_bytes([2u8; 32]),
        ).unwrap();
        
        let block1_hash = *block1.hash();
        manager.add_block(block1).unwrap();
        
        let block2 = Block::new(
            2,
            block1_hash,
            vec![Hash256::from_bytes([3u8; 32])],
            Hash256::from_bytes([4u8; 32]),
        ).unwrap();
        
        manager.add_block(block2).unwrap();
        
        assert_eq!(manager.state().current_height(), 2);
        assert!(manager.verify_chain().unwrap());
        
        let blocks = manager.get_blocks_range(1, 2);
        assert_eq!(blocks.len(), 2);
    }
    
    #[test]
    fn test_merkle_root() {
        let tx_ids = vec![
            Hash256::from_bytes([1u8; 32]),
            Hash256::from_bytes([2u8; 32]),
            Hash256::from_bytes([3u8; 32]),
        ];
        
        let merkle_root = Block::calculate_merkle_root(&tx_ids).unwrap();
        
        // Same inputs should produce same root
        let merkle_root2 = Block::calculate_merkle_root(&tx_ids).unwrap();
        assert_eq!(merkle_root, merkle_root2);
        
        // Different inputs should produce different root
        let tx_ids2 = vec![Hash256::from_bytes([4u8; 32])];
        let merkle_root3 = Block::calculate_merkle_root(&tx_ids2).unwrap();
        assert_ne!(merkle_root, merkle_root3);
    }
}