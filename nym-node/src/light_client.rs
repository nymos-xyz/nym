use crate::error::{NodeError, Result};
use crate::config::NodeConfig;
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::sync::Arc;

/// Light client for Nym network
/// Provides lightweight access to the network without full node requirements
#[derive(Debug)]
pub struct LightClient {
    config: NodeConfig,
    peers: Arc<RwLock<Vec<String>>>,
    state: Arc<RwLock<LightClientState>>,
    is_running: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LightClientState {
    pub latest_block_height: u64,
    pub latest_block_hash: String,
    pub synced_at: chrono::DateTime<chrono::Utc>,
    pub peer_count: usize,
    pub sync_progress: f64,
}

impl Default for LightClientState {
    fn default() -> Self {
        Self {
            latest_block_height: 0,
            latest_block_hash: String::new(),
            synced_at: chrono::Utc::now(),
            peer_count: 0,
            sync_progress: 0.0,
        }
    }
}

impl LightClient {
    pub fn new(config: NodeConfig) -> Self {
        Self {
            config,
            peers: Arc::new(RwLock::new(Vec::new())),
            state: Arc::new(RwLock::new(LightClientState::default())),
            is_running: Arc::new(RwLock::new(false)),
        }
    }
    
    pub async fn start(&self) -> Result<()> {
        let mut is_running = self.is_running.write().await;
        if *is_running {
            return Err(NodeError::AlreadyRunning);
        }
        
        println!("🚀 Starting Nym Light Client...");
        
        // Initialize peer connections
        self.initialize_peers().await?;
        
        // Start sync process
        self.start_sync().await?;
        
        *is_running = true;
        println!("✅ Light client started successfully");
        
        Ok(())
    }
    
    pub async fn stop(&self) -> Result<()> {
        let mut is_running = self.is_running.write().await;
        if !*is_running {
            return Err(NodeError::NotRunning);
        }
        
        println!("🛑 Stopping Nym Light Client...");
        
        *is_running = false;
        println!("✅ Light client stopped");
        
        Ok(())
    }
    
    async fn initialize_peers(&self) -> Result<()> {
        let mut peers = self.peers.write().await;
        
        // Connect to bootstrap peers
        for bootstrap_peer in &self.config.network.bootstrap_peers {
            if self.connect_to_peer(bootstrap_peer).await.is_ok() {
                peers.push(bootstrap_peer.clone());
            }
        }
        
        if peers.is_empty() {
            return Err(NodeError::Config("No bootstrap peers available".to_string()));
        }
        
        println!("🔗 Connected to {} bootstrap peers", peers.len());
        Ok(())
    }
    
    async fn connect_to_peer(&self, peer_addr: &str) -> Result<()> {
        // Simulate peer connection
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // In a real implementation, this would establish a connection
        // and perform handshake with the peer
        Ok(())
    }
    
    async fn start_sync(&self) -> Result<()> {
        let state = self.state.clone();
        let peers = self.peers.clone();
        let is_running = self.is_running.clone();
        
        tokio::spawn(async move {
            while *is_running.read().await {
                // Perform light sync
                if let Err(e) = Self::perform_sync(&state, &peers).await {
                    eprintln!("Sync error: {}", e);
                }
                
                // Wait before next sync
                tokio::time::sleep(tokio::time::Duration::from_secs(30)).await;
            }
        });
        
        Ok(())
    }
    
    async fn perform_sync(
        state: &Arc<RwLock<LightClientState>>,
        peers: &Arc<RwLock<Vec<String>>>,
    ) -> Result<()> {
        let peer_list = peers.read().await;
        if peer_list.is_empty() {
            return Err(NodeError::Config("No peers available for sync".to_string()));
        }
        
        // Simulate getting latest block info from peers
        let latest_height = 12345; // In real implementation, query peers
        let latest_hash = "abc123def456...".to_string();
        
        let mut current_state = state.write().await;
        current_state.latest_block_height = latest_height;
        current_state.latest_block_hash = latest_hash;
        current_state.synced_at = chrono::Utc::now();
        current_state.peer_count = peer_list.len();
        current_state.sync_progress = 1.0; // 100% synced
        
        Ok(())
    }
    
    pub async fn get_balance(&self, address: &str) -> Result<u64> {
        // Simulate balance query
        tokio::time::sleep(tokio::time::Duration::from_millis(50)).await;
        
        // In real implementation, this would query peers for account balance
        match address {
            "nym1test1" => Ok(1000000),
            "nym1test2" => Ok(500000),
            _ => Ok(0),
        }
    }
    
    pub async fn send_transaction(&self, to: &str, amount: u64) -> Result<String> {
        // Simulate transaction broadcast
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // In real implementation, this would create and broadcast transaction
        let tx_hash = format!("tx_{}_{}_{}", 
            chrono::Utc::now().timestamp(), 
            to, 
            amount
        );
        
        println!("📤 Transaction sent: {} ({} NYM to {})", tx_hash, amount, to);
        Ok(tx_hash)
    }
    
    pub async fn get_transaction_status(&self, tx_hash: &str) -> Result<String> {
        // Simulate transaction status query
        tokio::time::sleep(tokio::time::Duration::from_millis(30)).await;
        
        // In real implementation, this would query peers for transaction status
        if tx_hash.starts_with("tx_") {
            Ok("confirmed".to_string())
        } else {
            Ok("pending".to_string())
        }
    }
    
    pub async fn get_state(&self) -> LightClientState {
        self.state.read().await.clone()
    }
    
    pub async fn is_running(&self) -> bool {
        *self.is_running.read().await
    }
    
    pub async fn add_peer(&self, peer_addr: String) -> Result<()> {
        if self.connect_to_peer(&peer_addr).await.is_ok() {
            let mut peers = self.peers.write().await;
            if !peers.contains(&peer_addr) {
                peers.push(peer_addr.clone());
                println!("🔗 Added peer: {}", peer_addr);
            }
            Ok(())
        } else {
            Err(NodeError::Config(format!("Failed to connect to peer: {}", peer_addr)))
        }
    }
    
    pub async fn remove_peer(&self, peer_addr: &str) -> Result<()> {
        let mut peers = self.peers.write().await;
        if let Some(pos) = peers.iter().position(|p| p == peer_addr) {
            peers.remove(pos);
            println!("🔌 Removed peer: {}", peer_addr);
            Ok(())
        } else {
            Err(NodeError::Config(format!("Peer not found: {}", peer_addr)))
        }
    }
    
    pub async fn get_peers(&self) -> Vec<String> {
        self.peers.read().await.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    
    #[tokio::test]
    async fn test_light_client_creation() {
        let config = NodeConfig::default();
        let client = LightClient::new(config);
        
        assert!(!client.is_running().await);
        assert_eq!(client.get_peers().await.len(), 0);
    }
    
    #[tokio::test]
    async fn test_light_client_balance_query() {
        let config = NodeConfig::default();
        let client = LightClient::new(config);
        
        let balance = client.get_balance("nym1test1").await.unwrap();
        assert_eq!(balance, 1000000);
        
        let balance = client.get_balance("nym1unknown").await.unwrap();
        assert_eq!(balance, 0);
    }
    
    #[tokio::test]
    async fn test_light_client_transaction() {
        let config = NodeConfig::default();
        let client = LightClient::new(config);
        
        let tx_hash = client.send_transaction("nym1test2", 100).await.unwrap();
        assert!(tx_hash.starts_with("tx_"));
        
        let status = client.get_transaction_status(&tx_hash).await.unwrap();
        assert_eq!(status, "confirmed");
    }
}