use crate::{
    error::{ConsensusError, ConsensusResult},
    types::Block,
};
use nym_crypto::Hash256;

use std::time::Duration;
use serde::{Deserialize, Serialize};
use tracing::{info, debug};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DifficultyTarget {
    target: [u8; 32],
    compact: u64,
}

impl DifficultyTarget {
    pub fn new(compact: u64) -> Self {
        let target = Self::compact_to_target(compact);
        Self { target, compact }
    }

    pub fn from_compact(compact: u64) -> Self {
        Self::new(compact)
    }

    pub fn as_compact(&self) -> u64 {
        self.compact
    }

    pub fn meets_target(&self, hash: &Hash256) -> bool {
        let hash_bytes = hash.as_bytes();
        
        // Compare hash with target (hash must be <= target)
        for i in 0..32 {
            match hash_bytes[i].cmp(&self.target[i]) {
                std::cmp::Ordering::Less => return true,
                std::cmp::Ordering::Greater => return false,
                std::cmp::Ordering::Equal => continue,
            }
        }
        
        true // Equal case
    }

    pub fn difficulty(&self) -> f64 {
        // Calculate difficulty as max_target / current_target
        let max_target = 0xFFFFFFFFFFFFFFFFu64;
        max_target as f64 / self.compact as f64
    }

    fn compact_to_target(compact: u64) -> [u8; 32] {
        let mut target = [0u8; 32];
        
        // Extract exponent and mantissa from compact representation
        let exponent = (compact >> 24) as u8;
        let mantissa = compact & 0xFFFFFF;
        
        if exponent <= 3 {
            let mantissa_bytes = mantissa.to_be_bytes();
            let offset = 3 - exponent as usize;
            if offset < 32 {
                target[28 + offset..32].copy_from_slice(&mantissa_bytes[5..8]);
            }
        } else if exponent < 32 {
            let mantissa_bytes = mantissa.to_be_bytes();
            let offset = 32 - exponent as usize;
            if offset >= 3 {
                target[offset - 3..offset].copy_from_slice(&mantissa_bytes[5..8]);
            }
        }
        
        target
    }
}

pub struct DifficultyAdjustment {
    target_block_time: Duration,
    adjustment_period: u64,
    max_adjustment_factor: f64,
    min_adjustment_factor: f64,
}

impl DifficultyAdjustment {
    pub fn new(target_block_time: Duration, adjustment_period: u64) -> Self {
        Self {
            target_block_time,
            adjustment_period,
            max_adjustment_factor: 4.0,  // Max 4x difficulty increase
            min_adjustment_factor: 0.25, // Max 4x difficulty decrease
        }
    }

    pub fn calculate_new_difficulty(&self, recent_blocks: &[Block]) -> ConsensusResult<DifficultyTarget> {
        if recent_blocks.len() < self.adjustment_period as usize {
            return Err(ConsensusError::DifficultyError(
                "Insufficient blocks for difficulty adjustment".to_string()
            ));
        }

        let blocks_to_analyze = &recent_blocks[recent_blocks.len() - self.adjustment_period as usize..];
        
        // Calculate actual time taken for the period
        let first_block = &blocks_to_analyze[0];
        let last_block = &blocks_to_analyze[blocks_to_analyze.len() - 1];
        
        let actual_time = last_block.header.timestamp
            .signed_duration_since(first_block.header.timestamp)
            .to_std()
            .map_err(|_| ConsensusError::DifficultyError("Invalid timestamp range".to_string()))?;

        // Calculate expected time
        let expected_time = self.target_block_time * (self.adjustment_period as u32 - 1);

        // Calculate adjustment factor
        let time_factor = actual_time.as_secs_f64() / expected_time.as_secs_f64();
        
        // Clamp adjustment factor to prevent extreme changes
        let clamped_factor = time_factor
            .max(self.min_adjustment_factor)
            .min(self.max_adjustment_factor);

        // Get current difficulty from the last block
        let current_difficulty = if let Some(pow_proof) = &last_block.consensus_data.pow_proof {
            pow_proof.difficulty
        } else {
            return Err(ConsensusError::DifficultyError(
                "No PoW proof found in recent block".to_string()
            ));
        };

        // Calculate new difficulty (inverse relationship: faster time = higher difficulty)
        let new_difficulty = ((current_difficulty as f64) / clamped_factor) as u64;
        let new_difficulty = new_difficulty.max(1000).min(u64::MAX / 256);

        debug!(
            "Difficulty adjustment: blocks={}, actual_time={:?}, expected_time={:?}, factor={:.2}, old_diff={}, new_diff={}",
            self.adjustment_period, actual_time, expected_time, clamped_factor, current_difficulty, new_difficulty
        );

        Ok(DifficultyTarget::new(new_difficulty))
    }

    pub fn estimate_next_adjustment(
        &self,
        recent_blocks: &[Block],
        current_time: chrono::DateTime<chrono::Utc>,
    ) -> ConsensusResult<(f64, Duration)> {
        if recent_blocks.is_empty() {
            return Err(ConsensusError::DifficultyError(
                "No recent blocks provided".to_string()
            ));
        }

        let blocks_since_adjustment = recent_blocks.len() as u64 % self.adjustment_period;
        let blocks_remaining = self.adjustment_period - blocks_since_adjustment;

        if blocks_since_adjustment == 0 {
            return Ok((1.0, Duration::from_secs(0))); // Just adjusted
        }

        // Estimate current pace
        let first_block = &recent_blocks[0];
        let actual_time_so_far = current_time
            .signed_duration_since(first_block.header.timestamp)
            .to_std()
            .map_err(|_| ConsensusError::DifficultyError("Invalid timestamp range".to_string()))?;

        let expected_time_so_far = self.target_block_time * blocks_since_adjustment as u32;
        let current_pace_factor = actual_time_so_far.as_secs_f64() / expected_time_so_far.as_secs_f64();

        // Estimate time until next adjustment
        let estimated_time_per_block = actual_time_so_far.as_secs_f64() / blocks_since_adjustment as f64;
        let estimated_time_remaining = Duration::from_secs_f64(
            estimated_time_per_block * blocks_remaining as f64
        );

        Ok((current_pace_factor, estimated_time_remaining))
    }

    pub fn get_target_block_time(&self) -> Duration {
        self.target_block_time
    }

    pub fn get_adjustment_period(&self) -> u64 {
        self.adjustment_period
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nym_core::{NymIdentity, Transaction};
    use crate::types::{ConsensusData, ProofOfWorkData};
    use chrono::Utc;

    fn create_test_block(height: u64, timestamp: chrono::DateTime<chrono::Utc>, difficulty: u64) -> Block {
        let consensus_data = ConsensusData {
            pow_proof: Some(ProofOfWorkData {
                algorithm: "test".to_string(),
                work_hash: Hash256::default(),
                difficulty,
                mining_time: 1000,
                miner_identity: NymIdentity::default(),
            }),
            pos_proof: None,
            validator_votes: Vec::new(),
            finality_signatures: Vec::new(),
        };

        let mut block = Block::new(height, Hash256::default(), Vec::new(), consensus_data);
        block.header.timestamp = timestamp;
        block
    }

    #[test]
    fn test_difficulty_target_meets_target() {
        let target = DifficultyTarget::new(0x1d00ffff);
        
        // Create a hash that should meet the target
        let easy_hash = Hash256::from_hex("00000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
        assert!(target.meets_target(&easy_hash));
        
        // Create a hash that shouldn't meet the target
        let hard_hash = Hash256::from_hex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff").unwrap();
        assert!(!target.meets_target(&hard_hash));
    }

    #[test]
    fn test_difficulty_adjustment_faster_blocks() {
        let adjuster = DifficultyAdjustment::new(Duration::from_secs(120), 10);
        
        let start_time = Utc::now();
        let mut blocks = Vec::new();
        
        // Create blocks that are mined too fast (60 seconds instead of 120)
        for i in 0..10 {
            let timestamp = start_time + chrono::Duration::seconds(60 * i);
            blocks.push(create_test_block(i as u64, timestamp, 1000));
        }
        
        let new_target = adjuster.calculate_new_difficulty(&blocks).unwrap();
        
        // Difficulty should increase (blocks were too fast)
        assert!(new_target.as_compact() > 1000);
    }

    #[test]
    fn test_difficulty_adjustment_slower_blocks() {
        let adjuster = DifficultyAdjustment::new(Duration::from_secs(120), 10);
        
        let start_time = Utc::now();
        let mut blocks = Vec::new();
        
        // Create blocks that are mined too slow (240 seconds instead of 120)
        for i in 0..10 {
            let timestamp = start_time + chrono::Duration::seconds(240 * i);
            blocks.push(create_test_block(i as u64, timestamp, 1000));
        }
        
        let new_target = adjuster.calculate_new_difficulty(&blocks).unwrap();
        
        // Difficulty should decrease (blocks were too slow)
        assert!(new_target.as_compact() < 1000);
    }
}