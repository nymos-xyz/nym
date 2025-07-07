use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use crate::error::Result;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeState {
    pub status: NodeStatus,
    pub started_at: Option<DateTime<Utc>>,
    pub block_height: u64,
    pub last_block_hash: Option<String>,
    pub last_block_time: Option<DateTime<Utc>>,
    pub peer_count: usize,
    pub syncing: bool,
    pub sync_progress: f64,
    pub validator_status: ValidatorStatus,
    pub mining_status: MiningStatus,
    pub compute_jobs_active: usize,
    pub compute_jobs_completed: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum NodeStatus {
    Stopped,
    Starting,
    Running,
    Syncing,
    Stopping,
    Error(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorStatus {
    pub is_validator: bool,
    pub staked_amount: u64,
    pub delegation_amount: u64,
    pub blocks_validated: u64,
    pub last_validation_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningStatus {
    pub is_mining: bool,
    pub hash_rate: f64,
    pub blocks_mined: u64,
    pub last_block_mined: Option<DateTime<Utc>>,
    pub current_difficulty: u64,
}

impl Default for NodeState {
    fn default() -> Self {
        Self {
            status: NodeStatus::Stopped,
            started_at: None,
            block_height: 0,
            last_block_hash: None,
            last_block_time: None,
            peer_count: 0,
            syncing: false,
            sync_progress: 0.0,
            validator_status: ValidatorStatus {
                is_validator: false,
                staked_amount: 0,
                delegation_amount: 0,
                blocks_validated: 0,
                last_validation_time: None,
            },
            mining_status: MiningStatus {
                is_mining: false,
                hash_rate: 0.0,
                blocks_mined: 0,
                last_block_mined: None,
                current_difficulty: 0,
            },
            compute_jobs_active: 0,
            compute_jobs_completed: 0,
        }
    }
}

pub struct StateManager {
    state: Arc<RwLock<NodeState>>,
}

impl StateManager {
    pub fn new() -> Self {
        Self {
            state: Arc::new(RwLock::new(NodeState::default())),
        }
    }
    
    pub async fn get_state(&self) -> NodeState {
        self.state.read().await.clone()
    }
    
    pub async fn update_status(&self, status: NodeStatus) -> Result<()> {
        let mut state = self.state.write().await;
        state.status = status;
        
        if matches!(state.status, NodeStatus::Running) && state.started_at.is_none() {
            state.started_at = Some(Utc::now());
        }
        
        Ok(())
    }
    
    pub async fn update_block_info(&self, height: u64, hash: String) -> Result<()> {
        let mut state = self.state.write().await;
        state.block_height = height;
        state.last_block_hash = Some(hash);
        state.last_block_time = Some(Utc::now());
        Ok(())
    }
    
    pub async fn update_sync_progress(&self, syncing: bool, progress: f64) -> Result<()> {
        let mut state = self.state.write().await;
        state.syncing = syncing;
        state.sync_progress = progress.clamp(0.0, 100.0);
        Ok(())
    }
    
    pub async fn update_peer_count(&self, count: usize) -> Result<()> {
        let mut state = self.state.write().await;
        state.peer_count = count;
        Ok(())
    }
    
    pub async fn update_validator_status(&self, is_validator: bool, staked: u64) -> Result<()> {
        let mut state = self.state.write().await;
        state.validator_status.is_validator = is_validator;
        state.validator_status.staked_amount = staked;
        
        if is_validator {
            state.validator_status.last_validation_time = Some(Utc::now());
        }
        
        Ok(())
    }
    
    pub async fn update_mining_status(&self, is_mining: bool, hash_rate: f64) -> Result<()> {
        let mut state = self.state.write().await;
        state.mining_status.is_mining = is_mining;
        state.mining_status.hash_rate = hash_rate;
        Ok(())
    }
    
    pub async fn increment_compute_jobs(&self, active_delta: i32, completed_delta: u64) -> Result<()> {
        let mut state = self.state.write().await;
        state.compute_jobs_active = (state.compute_jobs_active as i32 + active_delta).max(0) as usize;
        state.compute_jobs_completed += completed_delta;
        Ok(())
    }
    
    pub async fn get_summary(&self) -> String {
        let state = self.state.read().await;
        format!(
            "Node Status: {:?}\nBlock Height: {}\nPeers: {}\nSync: {}% complete\nValidator: {}\nMining: {}\nCompute Jobs: {} active, {} completed",
            state.status,
            state.block_height,
            state.peer_count,
            state.sync_progress,
            state.validator_status.is_validator,
            state.mining_status.is_mining,
            state.compute_jobs_active,
            state.compute_jobs_completed
        )
    }
}

impl Default for StateManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_state_manager() {
        let manager = StateManager::new();
        
        // Test initial state
        let state = manager.get_state().await;
        assert_eq!(state.status, NodeStatus::Stopped);
        assert_eq!(state.block_height, 0);
        
        // Test status update
        manager.update_status(NodeStatus::Running).await.unwrap();
        let state = manager.get_state().await;
        assert_eq!(state.status, NodeStatus::Running);
        assert!(state.started_at.is_some());
        
        // Test block update
        manager.update_block_info(100, "test_hash".to_string()).await.unwrap();
        let state = manager.get_state().await;
        assert_eq!(state.block_height, 100);
        assert_eq!(state.last_block_hash, Some("test_hash".to_string()));
    }
}