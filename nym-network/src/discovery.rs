//! Node discovery mechanisms

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use tokio::time::{interval, timeout};
use nym_crypto::{Hash256, SecurityLevel};
use nym_core::NymIdentity;
use crate::{
    NetworkError, NetworkResult, PeerId, PeerInfo, PeerCapabilities,
    NetworkMessage, MessageType, MessagePayload, DiscoveryPayload, PeerInfoPayload
};

/// Discovery configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryConfig {
    pub bootstrap_nodes: Vec<SocketAddr>,
    pub discovery_interval: u64,
    pub max_peers_per_round: usize,
    pub discovery_timeout: u64,
    pub min_peer_exchange_interval: u64,
    pub max_peer_age: u64,
}

/// Discovery state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryState {
    Initializing,
    Bootstrapping,
    Active,
    Paused,
    Stopped,
}

/// Discovery statistics
#[derive(Debug, Clone, Default)]
pub struct DiscoveryStats {
    pub discovery_rounds: u64,
    pub successful_discoveries: u64,
    pub failed_discoveries: u64,
    pub peers_discovered: u64,
    pub bootstrap_attempts: u64,
    pub last_discovery: Option<u64>,
}

/// Node discovery service
pub struct NodeDiscovery {
    config: DiscoveryConfig,
    state: DiscoveryState,
    known_peers: HashMap<PeerId, PeerDiscoveryInfo>,
    pending_requests: HashMap<Hash256, DiscoveryRequest>,
    stats: DiscoveryStats,
    identity: NymIdentity,
    last_peer_exchange: HashMap<PeerId, u64>,
}

/// Peer discovery information
#[derive(Debug, Clone)]
struct PeerDiscoveryInfo {
    peer_info: PeerInfo,
    discovered_at: u64,
    last_seen: u64,
    source: DiscoverySource,
    verified: bool,
}

/// Discovery source
#[derive(Debug, Clone)]
enum DiscoverySource {
    Bootstrap,
    PeerExchange(PeerId),
    Manual,
    Incoming,
}

/// Discovery request
#[derive(Debug, Clone)]
struct DiscoveryRequest {
    request_id: Hash256,
    target_peer: PeerId,
    timestamp: u64,
    request_type: DiscoveryRequestType,
}

/// Discovery request types
#[derive(Debug, Clone)]
enum DiscoveryRequestType {
    Bootstrap,
    PeerExchange,
    Refresh,
}

impl Default for DiscoveryConfig {
    fn default() -> Self {
        Self {
            bootstrap_nodes: vec![
                "127.0.0.1:8080".parse().unwrap(),
                "127.0.0.1:8081".parse().unwrap(),
            ],
            discovery_interval: 300,
            max_peers_per_round: 10,
            discovery_timeout: 30,
            min_peer_exchange_interval: 60,
            max_peer_age: 3600,
        }
    }
}

impl NodeDiscovery {
    pub fn new(config: DiscoveryConfig, identity: NymIdentity) -> Self {
        Self {
            config,
            state: DiscoveryState::Initializing,
            known_peers: HashMap::new(),
            pending_requests: HashMap::new(),
            stats: DiscoveryStats::default(),
            identity,
            last_peer_exchange: HashMap::new(),
        }
    }
    
    pub async fn start(&mut self) -> NetworkResult<()> {
        self.state = DiscoveryState::Bootstrapping;
        self.bootstrap().await?;
        self.state = DiscoveryState::Active;
        Ok(())
    }
    
    pub async fn stop(&mut self) {
        self.state = DiscoveryState::Stopped;
        self.pending_requests.clear();
    }
    
    async fn bootstrap(&mut self) -> NetworkResult<()> {
        self.stats.bootstrap_attempts += 1;
        
        for bootstrap_addr in &self.config.bootstrap_nodes.clone() {
            match self.discover_from_bootstrap(*bootstrap_addr).await {
                Ok(_) => {
                    self.stats.successful_discoveries += 1;
                    return Ok(());
                }
                Err(e) => {
                    tracing::warn!("Bootstrap failed for {}: {:?}", bootstrap_addr, e);
                    self.stats.failed_discoveries += 1;
                }
            }
        }
        
        Err(NetworkError::DiscoveryFailed {
            reason: "All bootstrap nodes failed".to_string(),
        })
    }
    
    async fn discover_from_bootstrap(&mut self, addr: SocketAddr) -> NetworkResult<()> {
        tracing::info!("Discovering peers from bootstrap node: {}", addr);
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        let mock_peers = self.create_mock_bootstrap_peers(addr);
        for peer_info in mock_peers {
            self.add_discovered_peer(peer_info, DiscoverySource::Bootstrap)?;
        }
        
        Ok(())
    }
    
    fn create_mock_bootstrap_peers(&self, bootstrap_addr: SocketAddr) -> Vec<PeerInfo> {
        let mut peers = Vec::new();
        
        for i in 1..=3 {
            let mut addr = bootstrap_addr;
            addr.set_port(addr.port() + i);
            
            let peer_id = PeerId::new(Hash256::from([
                (addr.port() % 256) as u8; 32
            ]));
            
            let mut peer_info = PeerInfo::new(peer_id, vec![addr]);
            peer_info.capabilities = PeerCapabilities {
                full_node: true,
                consensus: i <= 2,
                tx_relay: true,
                archival: i == 1,
                privacy_level: SecurityLevel::Level1,
            };
            
            peers.push(peer_info);
        }
        
        peers
    }
    
    pub async fn discovery_round(&mut self) -> NetworkResult<()> {
        if self.state != DiscoveryState::Active {
            return Err(NetworkError::DiscoveryFailed {
                reason: "Discovery not active".to_string(),
            });
        }
        
        self.stats.discovery_rounds += 1;
        self.cleanup_old_peers();
        self.request_peer_exchanges().await?;
        
        self.stats.last_discovery = Some(
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()
        );
        
        Ok(())
    }
    
    async fn request_peer_exchanges(&mut self) -> NetworkResult<()> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let mut exchange_count = 0;
        
        for (peer_id, peer_info) in &self.known_peers {
            if let Some(&last_exchange) = self.last_peer_exchange.get(peer_id) {
                if now - last_exchange < self.config.min_peer_exchange_interval {
                    continue;
                }
            }
            
            if peer_info.verified && peer_info.peer_info.is_online() {
                self.request_peer_exchange(peer_id.clone()).await?;
                self.last_peer_exchange.insert(peer_id.clone(), now);
                exchange_count += 1;
                
                if exchange_count >= self.config.max_peers_per_round {
                    break;
                }
            }
        }
        
        Ok(())
    }
    
    async fn request_peer_exchange(&mut self, peer_id: PeerId) -> NetworkResult<()> {
        let request_id = Hash256::from(rand::random::<[u8; 32]>());
        
        let request = DiscoveryRequest {
            request_id,
            target_peer: peer_id.clone(),
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            request_type: DiscoveryRequestType::PeerExchange,
        };
        
        self.pending_requests.insert(request_id, request);
        tracing::debug!("Requesting peer exchange from: {:?}", peer_id);
        
        Ok(())
    }
    
    pub async fn handle_discovery_message(
        &mut self,
        message: &NetworkMessage,
    ) -> NetworkResult<Option<NetworkMessage>> {
        match &message.payload {
            MessagePayload::Discovery(discovery) => {
                self.process_discovery_payload(discovery, &message.sender).await
            }
            _ => Err(NetworkError::MessageError {
                reason: "Invalid discovery message payload".to_string(),
            }),
        }
    }
    
    async fn process_discovery_payload(
        &mut self,
        discovery: &DiscoveryPayload,
        sender: &PeerId,
    ) -> NetworkResult<Option<NetworkMessage>> {
        match discovery.request_type.as_str() {
            "peer_exchange" => {
                for peer_payload in &discovery.peers {
                    if let Ok(peer_info) = self.peer_info_from_payload(peer_payload) {
                        self.add_discovered_peer(
                            peer_info,
                            DiscoverySource::PeerExchange(sender.clone()),
                        )?;
                    }
                }
                self.create_peer_exchange_response(sender.clone()).await
            }
            "bootstrap" => {
                self.create_bootstrap_response(sender.clone()).await
            }
            _ => Ok(None),
        }
    }
    
    async fn create_peer_exchange_response(
        &self,
        recipient: PeerId,
    ) -> NetworkResult<Option<NetworkMessage>> {
        let our_peers: Vec<PeerInfoPayload> = self
            .known_peers
            .values()
            .filter(|info| info.verified)
            .take(self.config.max_peers_per_round)
            .map(|info| self.peer_info_to_payload(&info.peer_info))
            .collect();
        
        let discovery_payload = DiscoveryPayload {
            peers: our_peers,
            request_type: "peer_exchange_response".to_string(),
        };
        
        let message = NetworkMessage::new(
            MessageType::Discovery,
            PeerId::from_identity(&self.identity),
            Some(recipient),
            MessagePayload::Discovery(discovery_payload),
        );
        
        Ok(Some(message))
    }
    
    async fn create_bootstrap_response(
        &self,
        recipient: PeerId,
    ) -> NetworkResult<Option<NetworkMessage>> {
        let bootstrap_peers: Vec<PeerInfoPayload> = self
            .known_peers
            .values()
            .filter(|info| info.verified && info.peer_info.capabilities.full_node)
            .take(10)
            .map(|info| self.peer_info_to_payload(&info.peer_info))
            .collect();
        
        let discovery_payload = DiscoveryPayload {
            peers: bootstrap_peers,
            request_type: "bootstrap_response".to_string(),
        };
        
        let message = NetworkMessage::new(
            MessageType::Discovery,
            PeerId::from_identity(&self.identity),
            Some(recipient),
            MessagePayload::Discovery(discovery_payload),
        );
        
        Ok(Some(message))
    }
    
    fn add_discovered_peer(
        &mut self,
        peer_info: PeerInfo,
        source: DiscoverySource,
    ) -> NetworkResult<()> {
        let peer_id = peer_info.id.clone();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        if peer_id == PeerId::from_identity(&self.identity) {
            return Ok(());
        }
        
        let discovery_info = PeerDiscoveryInfo {
            peer_info,
            discovered_at: now,
            last_seen: now,
            source,
            verified: false,
        };
        
        if self.known_peers.insert(peer_id, discovery_info).is_none() {
            self.stats.peers_discovered += 1;
        }
        
        Ok(())
    }
    
    fn peer_info_to_payload(&self, peer_info: &PeerInfo) -> PeerInfoPayload {
        PeerInfoPayload {
            peer_id: peer_info.id.clone(),
            addresses: peer_info
                .addresses
                .iter()
                .map(|addr| addr.to_string())
                .collect(),
            last_seen: peer_info.last_seen,
            capabilities: vec![
                if peer_info.capabilities.full_node {
                    "full-node".to_string()
                } else {
                    "light-node".to_string()
                },
                if peer_info.capabilities.consensus {
                    "consensus".to_string()
                } else {
                    "no-consensus".to_string()
                },
            ],
        }
    }
    
    fn peer_info_from_payload(&self, payload: &PeerInfoPayload) -> NetworkResult<PeerInfo> {
        let addresses: Result<Vec<SocketAddr>, _> = payload
            .addresses
            .iter()
            .map(|addr_str| addr_str.parse())
            .collect();
        
        let addresses = addresses.map_err(|e| NetworkError::DiscoveryFailed {
            reason: format!("Invalid peer address: {}", e),
        })?;
        
        let mut peer_info = PeerInfo::new(payload.peer_id.clone(), addresses);
        peer_info.last_seen = payload.last_seen;
        peer_info.capabilities.full_node = payload.capabilities.contains(&"full-node".to_string());
        peer_info.capabilities.consensus = payload.capabilities.contains(&"consensus".to_string());
        
        Ok(peer_info)
    }
    
    pub fn verify_peer(&mut self, peer_id: &PeerId) -> NetworkResult<()> {
        if let Some(discovery_info) = self.known_peers.get_mut(peer_id) {
            discovery_info.verified = true;
            discovery_info.last_seen = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            Ok(())
        } else {
            Err(NetworkError::PeerError {
                reason: "Peer not found for verification".to_string(),
            })
        }
    }
    
    pub fn get_known_peers(&self) -> Vec<&PeerInfo> {
        self.known_peers
            .values()
            .map(|info| &info.peer_info)
            .collect()
    }
    
    pub fn get_verified_peers(&self) -> Vec<&PeerInfo> {
        self.known_peers
            .values()
            .filter(|info| info.verified)
            .map(|info| &info.peer_info)
            .collect()
    }
    
    fn cleanup_old_peers(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let old_peers: Vec<PeerId> = self
            .known_peers
            .iter()
            .filter(|(_, info)| now - info.last_seen > self.config.max_peer_age)
            .map(|(peer_id, _)| peer_id.clone())
            .collect();
        
        for peer_id in old_peers {
            self.known_peers.remove(&peer_id);
            self.last_peer_exchange.remove(&peer_id);
        }
    }
    
    pub fn state(&self) -> &DiscoveryState {
        &self.state
    }
    
    pub fn stats(&self) -> &DiscoveryStats {
        &self.stats
    }
    
    pub fn peer_count(&self) -> usize {
        self.known_peers.len()
    }
    
    pub fn verified_peer_count(&self) -> usize {
        self.known_peers.values().filter(|info| info.verified).count()
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
    fn test_discovery_config_default() {
        let config = DiscoveryConfig::default();
        assert_eq!(config.bootstrap_nodes.len(), 2);
        assert_eq!(config.discovery_interval, 300);
    }
    
    #[test]
    fn test_node_discovery_creation() {
        let config = DiscoveryConfig::default();
        let identity = create_test_identity();
        let discovery = NodeDiscovery::new(config, identity);
        
        assert_eq!(discovery.state, DiscoveryState::Initializing);
        assert_eq!(discovery.peer_count(), 0);
    }
    
    #[tokio::test]
    async fn test_bootstrap() {
        let config = DiscoveryConfig::default();
        let identity = create_test_identity();
        let mut discovery = NodeDiscovery::new(config, identity);
        
        let result = discovery.start().await;
        assert!(result.is_ok());
        assert_eq!(discovery.state, DiscoveryState::Active);
        assert!(discovery.peer_count() > 0);
    }
    
    #[test]
    fn test_add_discovered_peer() {
        let config = DiscoveryConfig::default();
        let identity = create_test_identity();
        let mut discovery = NodeDiscovery::new(config, identity);
        
        let peer_id = PeerId::new(Hash256::from([2u8; 32]));
        let addr = "127.0.0.1:8080".parse().unwrap();
        let peer_info = PeerInfo::new(peer_id.clone(), vec![addr]);
        
        let result = discovery.add_discovered_peer(peer_info, DiscoverySource::Bootstrap);
        assert!(result.is_ok());
        assert_eq!(discovery.peer_count(), 1);
        
        let known_peers = discovery.get_known_peers();
        assert_eq!(known_peers.len(), 1);
        assert_eq!(known_peers[0].id, peer_id);
    }
}