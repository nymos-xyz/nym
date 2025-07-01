//! Network synchronization mechanisms

use std::collections::{HashMap, BTreeSet};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use tokio::time::{interval, timeout};
use nym_crypto::{Hash256, SecurityLevel};
use nym_core::{Block, Transaction, NymIdentity};
use crate::{
    NetworkError, NetworkResult, PeerId, PeerInfo,
    NetworkMessage, MessageType, MessagePayload, SyncRequestPayload, SyncResponsePayload
};

/// Synchronization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncConfig {
    /// Sync interval in seconds
    pub sync_interval: u64,
    /// Maximum blocks per sync request
    pub max_blocks_per_sync: u32,
    /// Sync timeout in seconds
    pub sync_timeout: u64,
    /// Maximum concurrent sync requests
    pub max_concurrent_syncs: usize,
    /// Block validation timeout
    pub block_validation_timeout: u64,
    /// Retry attempts for failed syncs
    pub max_retry_attempts: u32,
}

/// Synchronization state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncState {
    Idle,
    Syncing,
    Completed,
    Failed,
    Paused,
}

/// Sync request status
#[derive(Debug, Clone)]
pub struct SyncRequest {
    /// Request ID
    pub request_id: Hash256,
    /// Target peer
    pub peer_id: PeerId,
    /// Starting height
    pub start_height: u64,
    /// Maximum blocks requested
    pub max_blocks: u32,
    /// Request timestamp
    pub timestamp: u64,
    /// Current status
    pub status: SyncRequestStatus,
    /// Retry count
    pub retry_count: u32,
}

/// Sync request status
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncRequestStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Timeout,
}

/// Synchronization statistics
#[derive(Debug, Clone, Default)]
pub struct SyncStats {
    /// Total sync requests
    pub sync_requests: u64,
    /// Successful syncs
    pub successful_syncs: u64,
    /// Failed syncs
    pub failed_syncs: u64,
    /// Blocks synced
    pub blocks_synced: u64,
    /// Transactions synced
    pub transactions_synced: u64,
    /// Average sync time
    pub avg_sync_time: f64,
    /// Last sync timestamp
    pub last_sync: Option<u64>,
}

/// Chain synchronization information
#[derive(Debug, Clone)]
pub struct ChainSyncInfo {
    /// Current local height
    pub local_height: u64,
    /// Current local tip hash
    pub local_tip: Hash256,
    /// Best known height from peers
    pub best_height: u64,
    /// Best known tip hash
    pub best_tip: Hash256,
    /// Blocks behind best chain
    pub blocks_behind: u64,
    /// Sync progress percentage
    pub sync_progress: f64,
}

/// Peer synchronization status
#[derive(Debug, Clone)]
pub struct PeerSyncStatus {
    /// Peer ID
    pub peer_id: PeerId,
    /// Peer's chain height
    pub height: u64,
    /// Peer's tip hash
    pub tip_hash: Hash256,
    /// Last sync attempt
    pub last_sync: Option<u64>,
    /// Sync reliability score
    pub reliability: f64,
    /// Response time
    pub avg_response_time: u64,
}

/// Synchronization manager
pub struct SyncManager {
    /// Sync configuration
    config: SyncConfig,
    /// Local identity
    identity: NymIdentity,
    /// Current sync state
    state: SyncState,
    /// Chain sync information
    chain_info: ChainSyncInfo,
    /// Active sync requests
    active_requests: HashMap<Hash256, SyncRequest>,
    /// Peer sync status
    peer_status: HashMap<PeerId, PeerSyncStatus>,
    /// Sync statistics
    stats: SyncStats,
    /// Pending blocks for validation
    pending_blocks: HashMap<u64, Block>,
    /// Recently synced block hashes
    synced_blocks: BTreeSet<Hash256>,
}

/// Sync protocol implementation
pub struct SyncProtocol {
    /// Sync manager reference
    sync_manager: SyncManager,
}

impl Default for SyncConfig {
    fn default() -> Self {
        Self {
            sync_interval: 30, // 30 seconds
            max_blocks_per_sync: 100,
            sync_timeout: 60, // 1 minute
            max_concurrent_syncs: 5,
            block_validation_timeout: 10,
            max_retry_attempts: 3,
        }
    }
}

impl SyncRequest {
    /// Create a new sync request
    pub fn new(peer_id: PeerId, start_height: u64, max_blocks: u32) -> Self {
        Self {
            request_id: Hash256::from(rand::random::<[u8; 32]>()),
            peer_id,
            start_height,
            max_blocks,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            status: SyncRequestStatus::Pending,
            retry_count: 0,
        }
    }
    
    /// Check if request has timed out
    pub fn is_timed_out(&self, timeout: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now - self.timestamp > timeout.as_secs()
    }
    
    /// Mark as in progress
    pub fn start(&mut self) {
        self.status = SyncRequestStatus::InProgress;
        self.timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    /// Mark as completed
    pub fn complete(&mut self) {
        self.status = SyncRequestStatus::Completed;
    }
    
    /// Mark as failed and increment retry count
    pub fn fail(&mut self) {
        self.status = SyncRequestStatus::Failed;
        self.retry_count += 1;
    }
    
    /// Check if should retry
    pub fn should_retry(&self, max_retries: u32) -> bool {
        self.retry_count < max_retries && 
        matches!(self.status, SyncRequestStatus::Failed | SyncRequestStatus::Timeout)
    }
}

impl ChainSyncInfo {
    /// Create new chain sync info
    pub fn new(local_height: u64, local_tip: Hash256) -> Self {
        Self {
            local_height,
            local_tip,
            best_height: local_height,
            best_tip: local_tip,
            blocks_behind: 0,
            sync_progress: 100.0,
        }
    }
    
    /// Update with peer information
    pub fn update_from_peer(&mut self, peer_height: u64, peer_tip: Hash256) {
        if peer_height > self.best_height {
            self.best_height = peer_height;
            self.best_tip = peer_tip;
            self.update_progress();
        }
    }
    
    /// Update sync progress
    fn update_progress(&mut self) {
        if self.best_height > 0 {
            self.blocks_behind = self.best_height.saturating_sub(self.local_height);
            self.sync_progress = if self.best_height == self.local_height {
                100.0
            } else {
                (self.local_height as f64 / self.best_height as f64) * 100.0
            };
        }
    }
    
    /// Check if sync is needed
    pub fn needs_sync(&self, threshold: u64) -> bool {
        self.blocks_behind > threshold
    }
    
    /// Update local chain info
    pub fn update_local(&mut self, height: u64, tip: Hash256) {
        self.local_height = height;
        self.local_tip = tip;
        self.update_progress();
    }
}

impl PeerSyncStatus {
    /// Create new peer sync status
    pub fn new(peer_id: PeerId, height: u64, tip_hash: Hash256) -> Self {
        Self {
            peer_id,
            height,
            tip_hash,
            last_sync: None,
            reliability: 1.0,
            avg_response_time: 0,
        }
    }
    
    /// Update with sync result
    pub fn update_sync_result(&mut self, success: bool, response_time: u64) {
        const ALPHA: f64 = 0.1; // Learning rate
        
        let new_sample = if success { 1.0 } else { 0.0 };
        self.reliability = (1.0 - ALPHA) * self.reliability + ALPHA * new_sample;
        
        // Update average response time
        if self.avg_response_time == 0 {
            self.avg_response_time = response_time;
        } else {
            self.avg_response_time = ((self.avg_response_time as f64 * 0.9) + 
                                   (response_time as f64 * 0.1)) as u64;
        }
        
        self.last_sync = Some(SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs());
    }
    
    /// Check if peer is reliable
    pub fn is_reliable(&self) -> bool {
        self.reliability > 0.7
    }
}

impl SyncManager {
    /// Create a new sync manager
    pub fn new(config: SyncConfig, identity: NymIdentity, local_height: u64, local_tip: Hash256) -> Self {
        Self {
            config,
            identity,
            state: SyncState::Idle,
            chain_info: ChainSyncInfo::new(local_height, local_tip),
            active_requests: HashMap::new(),
            peer_status: HashMap::new(),
            stats: SyncStats::default(),
            pending_blocks: HashMap::new(),
            synced_blocks: BTreeSet::new(),
        }
    }
    
    /// Start synchronization process
    pub async fn start_sync(&mut self) -> NetworkResult<()> {
        if self.state != SyncState::Idle {
            return Err(NetworkError::SyncFailed {
                reason: "Sync already in progress".to_string(),
            });
        }
        
        self.state = SyncState::Syncing;
        
        // Find best peers to sync from
        let sync_peers = self.select_sync_peers();
        
        if sync_peers.is_empty() {
            self.state = SyncState::Failed;
            return Err(NetworkError::SyncFailed {
                reason: "No suitable peers for sync".to_string(),
            });
        }
        
        // Start sync requests
        for peer_id in sync_peers {
            self.initiate_sync_request(peer_id).await?;
        }
        
        Ok(())
    }
    
    /// Select best peers for synchronization
    fn select_sync_peers(&self) -> Vec<PeerId> {
        let mut candidates: Vec<_> = self.peer_status
            .values()
            .filter(|status| {
                status.height > self.chain_info.local_height && 
                status.is_reliable()
            })
            .collect();
        
        // Sort by height (descending) and reliability
        candidates.sort_by(|a, b| {
            b.height.cmp(&a.height)
                .then(b.reliability.partial_cmp(&a.reliability).unwrap_or(std::cmp::Ordering::Equal))
        });
        
        candidates
            .into_iter()
            .take(self.config.max_concurrent_syncs)
            .map(|status| status.peer_id.clone())
            .collect()
    }
    
    /// Initiate sync request with peer
    async fn initiate_sync_request(&mut self, peer_id: PeerId) -> NetworkResult<()> {
        if self.active_requests.len() >= self.config.max_concurrent_syncs {
            return Err(NetworkError::SyncFailed {
                reason: "Too many concurrent sync requests".to_string(),
            });
        }
        
        let start_height = self.chain_info.local_height + 1;
        let mut request = SyncRequest::new(peer_id, start_height, self.config.max_blocks_per_sync);
        request.start();
        
        let request_id = request.request_id;
        self.active_requests.insert(request_id, request);
        self.stats.sync_requests += 1;
        
        Ok(())
    }
    
    /// Create sync request message
    pub fn create_sync_request(&self, peer_id: PeerId) -> NetworkResult<NetworkMessage> {
        let sync_payload = SyncRequestPayload {
            current_height: self.chain_info.local_height,
            current_tip: self.chain_info.local_tip,
            max_blocks: self.config.max_blocks_per_sync,
        };
        
        let message = NetworkMessage::new(
            MessageType::SyncRequest,
            PeerId::from_identity(&self.identity),
            Some(peer_id),
            MessagePayload::SyncRequest(sync_payload),
        );
        
        Ok(message)
    }
    
    /// Handle sync request from peer
    pub async fn handle_sync_request(&self, message: &NetworkMessage) -> NetworkResult<Option<NetworkMessage>> {
        if let MessagePayload::SyncRequest(sync_request) = &message.payload {
            // Create sync response with available blocks
            let response = self.create_sync_response(sync_request, &message.sender).await?;
            Ok(Some(response))
        } else {
            Err(NetworkError::MessageError {
                reason: "Invalid sync request payload".to_string(),
            })
        }
    }
    
    /// Create sync response message
    async fn create_sync_response(&self, request: &SyncRequestPayload, peer_id: &PeerId) -> NetworkResult<NetworkMessage> {
        // In a real implementation, this would fetch blocks from storage
        // For now, create a mock response
        
        let start_height = request.current_height + 1;
        let end_height = std::cmp::min(
            start_height + request.max_blocks as u64 - 1,
            self.chain_info.local_height
        );
        
        let mut block_hashes = Vec::new();
        for height in start_height..=end_height {
            // Create mock block hash based on height
            let hash_bytes = [height as u8; 32];
            block_hashes.push(Hash256::from(hash_bytes));
        }
        
        let has_more = end_height < self.chain_info.local_height;
        
        let sync_response = SyncResponsePayload {
            start_height,
            block_hashes,
            has_more,
        };
        
        let message = NetworkMessage::new(
            MessageType::SyncResponse,
            PeerId::from_identity(&self.identity),
            Some(peer_id.clone()),
            MessagePayload::SyncResponse(sync_response),
        );
        
        Ok(message)
    }
    
    /// Handle sync response from peer
    pub async fn handle_sync_response(&mut self, message: &NetworkMessage) -> NetworkResult<()> {
        if let MessagePayload::SyncResponse(sync_response) = &message.payload {
            // Find corresponding request
            let request_id = self.find_request_by_peer(&message.sender)?;
            
            if let Some(request) = self.active_requests.get_mut(&request_id) {
                request.complete();
                
                // Process received block hashes
                self.process_sync_response(sync_response, &message.sender).await?;
                
                // Update statistics
                self.stats.successful_syncs += 1;
                self.stats.blocks_synced += sync_response.block_hashes.len() as u64;
                
                // Update peer status
                if let Some(peer_status) = self.peer_status.get_mut(&message.sender) {
                    peer_status.update_sync_result(true, 100); // Mock response time
                }
                
                // Check if more blocks are available
                if sync_response.has_more {
                    self.initiate_sync_request(message.sender.clone()).await?;
                } else {
                    // Sync complete
                    self.check_sync_completion();
                }
            }
        }
        
        Ok(())
    }
    
    /// Process sync response data
    async fn process_sync_response(&mut self, response: &SyncResponsePayload, peer_id: &PeerId) -> NetworkResult<()> {
        // Validate block hashes
        for (i, block_hash) in response.block_hashes.iter().enumerate() {
            let height = response.start_height + i as u64;
            
            // Add to synced blocks
            self.synced_blocks.insert(*block_hash);
            
            // In a real implementation, this would:
            // 1. Request full block data
            // 2. Validate blocks
            // 3. Add to pending blocks
            // 4. Update chain state
        }
        
        // Update chain info if we've synced new blocks
        if let Some(last_hash) = response.block_hashes.last() {
            let new_height = response.start_height + response.block_hashes.len() as u64 - 1;
            if new_height > self.chain_info.local_height {
                self.chain_info.update_local(new_height, *last_hash);
            }
        }
        
        Ok(())
    }
    
    /// Find sync request by peer
    fn find_request_by_peer(&self, peer_id: &PeerId) -> NetworkResult<Hash256> {
        self.active_requests
            .iter()
            .find(|(_, request)| &request.peer_id == peer_id)
            .map(|(id, _)| *id)
            .ok_or_else(|| NetworkError::SyncFailed {
                reason: "No active sync request for peer".to_string(),
            })
    }
    
    /// Check if synchronization is complete
    fn check_sync_completion(&mut self) {
        if self.active_requests.is_empty() || 
           self.active_requests.values().all(|req| matches!(req.status, SyncRequestStatus::Completed)) {
            if self.chain_info.blocks_behind <= 1 {
                self.state = SyncState::Completed;
                self.stats.last_sync = Some(SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs());
            } else {
                // Need more sync rounds
                self.state = SyncState::Idle;
            }
        }
    }
    
    /// Update peer chain information
    pub fn update_peer_info(&mut self, peer_id: PeerId, height: u64, tip_hash: Hash256) {
        let peer_status = self.peer_status
            .entry(peer_id.clone())
            .or_insert_with(|| PeerSyncStatus::new(peer_id, height, tip_hash));
        
        peer_status.height = height;
        peer_status.tip_hash = tip_hash;
        
        // Update chain info with peer data
        self.chain_info.update_from_peer(height, tip_hash);
    }
    
    /// Cleanup timed out requests
    pub fn cleanup_timed_out_requests(&mut self) {
        let timeout = Duration::from_secs(self.config.sync_timeout);
        let mut timed_out_requests = Vec::new();
        
        for (id, request) in &mut self.active_requests {
            if request.is_timed_out(timeout) {
                request.status = SyncRequestStatus::Timeout;
                timed_out_requests.push(*id);
                
                // Update peer reliability
                if let Some(peer_status) = self.peer_status.get_mut(&request.peer_id) {
                    peer_status.update_sync_result(false, u64::MAX); // Max response time for timeout
                }
            }
        }
        
        for id in timed_out_requests {
            self.active_requests.remove(&id);
            self.stats.failed_syncs += 1;
        }
    }
    
    /// Retry failed requests
    pub async fn retry_failed_requests(&mut self) -> NetworkResult<()> {
        let mut retry_requests = Vec::new();
        
        for (id, request) in &self.active_requests {
            if request.should_retry(self.config.max_retry_attempts) {
                retry_requests.push((*id, request.peer_id.clone()));
            }
        }
        
        for (old_id, peer_id) in retry_requests {
            self.active_requests.remove(&old_id);
            self.initiate_sync_request(peer_id).await?;
        }
        
        Ok(())
    }
    
    /// Get sync state
    pub fn state(&self) -> &SyncState {
        &self.state
    }
    
    /// Get chain sync info
    pub fn chain_info(&self) -> &ChainSyncInfo {
        &self.chain_info
    }
    
    /// Get sync statistics
    pub fn stats(&self) -> &SyncStats {
        &self.stats
    }
    
    /// Get active request count
    pub fn active_request_count(&self) -> usize {
        self.active_requests.len()
    }
    
    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peer_status.len()
    }
}

impl SyncProtocol {
    /// Create a new sync protocol
    pub fn new(sync_manager: SyncManager) -> Self {
        Self { sync_manager }
    }
    
    /// Run sync protocol loop
    pub async fn run(&mut self) -> NetworkResult<()> {
        let mut sync_interval = interval(Duration::from_secs(self.sync_manager.config.sync_interval));
        
        loop {
            sync_interval.tick().await;
            
            // Cleanup timed out requests
            self.sync_manager.cleanup_timed_out_requests();
            
            // Retry failed requests
            self.sync_manager.retry_failed_requests().await?;
            
            // Check if sync is needed
            if self.sync_manager.chain_info.needs_sync(1) && 
               matches!(self.sync_manager.state, SyncState::Idle | SyncState::Completed) {
                match self.sync_manager.start_sync().await {
                    Ok(_) => tracing::info!("Started synchronization"),
                    Err(e) => tracing::error!("Failed to start sync: {:?}", e),
                }
            }
        }
    }
    
    /// Handle sync message
    pub async fn handle_message(&mut self, message: &NetworkMessage) -> NetworkResult<Option<NetworkMessage>> {
        match message.message_type {
            MessageType::SyncRequest => {
                self.sync_manager.handle_sync_request(message).await
            }
            MessageType::SyncResponse => {
                self.sync_manager.handle_sync_response(message).await?;
                Ok(None)
            }
            _ => Ok(None),
        }
    }
    
    /// Get sync manager reference
    pub fn sync_manager(&self) -> &SyncManager {
        &self.sync_manager
    }
    
    /// Get mutable sync manager reference
    pub fn sync_manager_mut(&mut self) -> &mut SyncManager {
        &mut self.sync_manager
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nym_crypto::{QuIDAuth, SecurityLevel};
    
    fn create_test_identity() -> NymIdentity {
        let quid_auth = QuIDAuth::new(vec![1u8; 32], SecurityLevel::Level1);
        quid_auth.create_nym_identity(0).unwrap()
    }
    
    #[test]
    fn test_sync_config_default() {
        let config = SyncConfig::default();
        assert_eq!(config.sync_interval, 30);
        assert_eq!(config.max_blocks_per_sync, 100);
    }
    
    #[test]
    fn test_sync_request_creation() {
        let peer_id = PeerId::new(Hash256::from([1u8; 32]));
        let request = SyncRequest::new(peer_id.clone(), 100, 50);
        
        assert_eq!(request.peer_id, peer_id);
        assert_eq!(request.start_height, 100);
        assert_eq!(request.max_blocks, 50);
        assert_eq!(request.status, SyncRequestStatus::Pending);
        assert_eq!(request.retry_count, 0);
    }
    
    #[test]
    fn test_sync_request_lifecycle() {
        let peer_id = PeerId::new(Hash256::from([1u8; 32]));
        let mut request = SyncRequest::new(peer_id, 100, 50);
        
        request.start();
        assert_eq!(request.status, SyncRequestStatus::InProgress);
        
        request.complete();
        assert_eq!(request.status, SyncRequestStatus::Completed);
        
        let mut failed_request = SyncRequest::new(peer_id, 100, 50);
        failed_request.fail();
        assert_eq!(failed_request.status, SyncRequestStatus::Failed);
        assert_eq!(failed_request.retry_count, 1);
        assert!(failed_request.should_retry(3));
    }
    
    #[test]
    fn test_chain_sync_info() {
        let tip_hash = Hash256::from([1u8; 32]);
        let mut chain_info = ChainSyncInfo::new(100, tip_hash);
        
        assert_eq!(chain_info.local_height, 100);
        assert_eq!(chain_info.best_height, 100);
        assert_eq!(chain_info.blocks_behind, 0);
        assert_eq!(chain_info.sync_progress, 100.0);
        
        // Update with peer info
        let peer_tip = Hash256::from([2u8; 32]);
        chain_info.update_from_peer(150, peer_tip);
        
        assert_eq!(chain_info.best_height, 150);
        assert_eq!(chain_info.blocks_behind, 50);
        assert!(chain_info.sync_progress < 100.0);
        assert!(chain_info.needs_sync(10));
    }
    
    #[test]
    fn test_peer_sync_status() {
        let peer_id = PeerId::new(Hash256::from([1u8; 32]));
        let tip_hash = Hash256::from([2u8; 32]);
        let mut peer_status = PeerSyncStatus::new(peer_id.clone(), 100, tip_hash);
        
        assert_eq!(peer_status.peer_id, peer_id);
        assert_eq!(peer_status.height, 100);
        assert_eq!(peer_status.reliability, 1.0);
        assert!(peer_status.is_reliable());
        
        // Update with failed sync
        peer_status.update_sync_result(false, 1000);
        assert!(peer_status.reliability < 1.0);
        assert_eq!(peer_status.avg_response_time, 1000);
        assert!(peer_status.last_sync.is_some());
    }
    
    #[test]
    fn test_sync_manager_creation() {
        let config = SyncConfig::default();
        let identity = create_test_identity();
        let tip_hash = Hash256::from([1u8; 32]);
        
        let sync_manager = SyncManager::new(config, identity, 100, tip_hash);
        assert_eq!(sync_manager.state, SyncState::Idle);
        assert_eq!(sync_manager.chain_info.local_height, 100);
        assert_eq!(sync_manager.active_request_count(), 0);
        assert_eq!(sync_manager.peer_count(), 0);
    }
    
    #[test]
    fn test_peer_selection() {
        let config = SyncConfig::default();
        let identity = create_test_identity();
        let tip_hash = Hash256::from([1u8; 32]);
        let mut sync_manager = SyncManager::new(config, identity, 100, tip_hash);
        
        // Add peers with different heights
        for i in 1..=5 {
            let peer_id = PeerId::new(Hash256::from([i; 32]));
            let height = 100 + (i as u64 * 10);
            let tip = Hash256::from([i + 10; 32]);
            sync_manager.update_peer_info(peer_id, height, tip);
        }
        
        let selected_peers = sync_manager.select_sync_peers();
        assert!(!selected_peers.is_empty());
        assert!(selected_peers.len() <= sync_manager.config.max_concurrent_syncs);
    }
    
    #[tokio::test]
    async fn test_sync_request_creation() {
        let config = SyncConfig::default();
        let identity = create_test_identity();
        let tip_hash = Hash256::from([1u8; 32]);
        let sync_manager = SyncManager::new(config, identity.clone(), 100, tip_hash);
        
        let peer_id = PeerId::new(Hash256::from([1u8; 32]));
        let message = sync_manager.create_sync_request(peer_id.clone()).unwrap();
        
        assert_eq!(message.message_type, MessageType::SyncRequest);
        assert_eq!(message.recipient, Some(peer_id));
        assert_eq!(message.sender, PeerId::from_identity(&identity));
    }
    
    #[tokio::test]
    async fn test_sync_response_handling() {
        let config = SyncConfig::default();
        let identity = create_test_identity();
        let tip_hash = Hash256::from([1u8; 32]);
        let mut sync_manager = SyncManager::new(config, identity.clone(), 100, tip_hash);
        
        // Add a peer and start sync
        let peer_id = PeerId::new(Hash256::from([1u8; 32]));
        sync_manager.update_peer_info(peer_id.clone(), 150, Hash256::from([2u8; 32]));
        sync_manager.initiate_sync_request(peer_id.clone()).await.unwrap();
        
        // Create mock sync response
        let sync_response = SyncResponsePayload {
            start_height: 101,
            block_hashes: vec![Hash256::from([3u8; 32]), Hash256::from([4u8; 32])],
            has_more: false,
        };
        
        let response_message = NetworkMessage::new(
            MessageType::SyncResponse,
            peer_id,
            Some(PeerId::from_identity(&identity)),
            MessagePayload::SyncResponse(sync_response),
        );
        
        // Handle response
        let result = sync_manager.handle_sync_response(&response_message).await;
        assert!(result.is_ok());
        assert_eq!(sync_manager.stats.successful_syncs, 1);
        assert_eq!(sync_manager.stats.blocks_synced, 2);
    }
    
    #[test]
    fn test_timeout_cleanup() {
        let config = SyncConfig {
            sync_timeout: 1, // 1 second timeout
            ..Default::default()
        };
        let identity = create_test_identity();
        let tip_hash = Hash256::from([1u8; 32]);
        let mut sync_manager = SyncManager::new(config, identity, 100, tip_hash);
        
        // Add a request
        let peer_id = PeerId::new(Hash256::from([1u8; 32]));
        let mut request = SyncRequest::new(peer_id, 100, 50);
        request.start();
        let request_id = request.request_id;
        sync_manager.active_requests.insert(request_id, request);
        
        assert_eq!(sync_manager.active_request_count(), 1);
        
        // Wait for timeout
        std::thread::sleep(Duration::from_secs(2));
        
        // Cleanup should remove timed out request
        sync_manager.cleanup_timed_out_requests();
        assert_eq!(sync_manager.active_request_count(), 0);
        assert_eq!(sync_manager.stats.failed_syncs, 1);
    }
}