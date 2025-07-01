//! Peer management and information

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use nym_crypto::{Hash256, SecurityLevel};
use nym_core::NymIdentity;
use crate::{NetworkError, NetworkResult};

/// Unique peer identifier
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct PeerId(Hash256);

/// Peer connection status
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PeerStatus {
    Connecting,
    Connected,
    Disconnecting,
    Disconnected,
    Banned,
}

/// Peer capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerCapabilities {
    pub full_node: bool,
    pub consensus: bool,
    pub tx_relay: bool,
    pub archival: bool,
    pub privacy_level: SecurityLevel,
}

/// Information about a network peer
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfo {
    pub id: PeerId,
    pub addresses: Vec<SocketAddr>,
    pub identity: Option<NymIdentity>,
    pub status: PeerStatus,
    pub capabilities: PeerCapabilities,
    pub last_seen: u64,
    pub connection_attempts: u32,
    pub reputation: u8,
    pub protocol_version: String,
    pub user_agent: String,
}

/// Peer statistics
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PeerStats {
    pub messages_sent: u64,
    pub messages_received: u64,
    pub bytes_sent: u64,
    pub bytes_received: u64,
    pub uptime: u64,
    pub avg_response_time: u64,
}

/// Manages peer connections and information
pub struct PeerManager {
    peers: HashMap<PeerId, PeerInfo>,
    stats: HashMap<PeerId, PeerStats>,
    max_peers: usize,
    min_reputation: u8,
}

impl PeerId {
    pub fn new(hash: Hash256) -> Self {
        Self(hash)
    }
    
    pub fn from_identity(identity: &NymIdentity) -> Self {
        Self(identity.account_id())
    }
    
    pub fn hash(&self) -> &Hash256 {
        &self.0
    }
    
    pub fn to_hex(&self) -> String {
        hex::encode(self.0.as_bytes())
    }
    
    pub fn from_hex(hex_str: &str) -> NetworkResult<Self> {
        let bytes = hex::decode(hex_str)
            .map_err(|e| NetworkError::PeerError { 
                reason: format!("Invalid hex peer ID: {}", e) 
            })?;
        
        if bytes.len() != 32 {
            return Err(NetworkError::PeerError { 
                reason: "Peer ID must be 32 bytes".to_string() 
            });
        }
        
        let mut hash_bytes = [0u8; 32];
        hash_bytes.copy_from_slice(&bytes);
        Ok(Self(Hash256::from(hash_bytes)))
    }
}

impl Default for PeerCapabilities {
    fn default() -> Self {
        Self {
            full_node: false,
            consensus: false,
            tx_relay: true,
            archival: false,
            privacy_level: SecurityLevel::Level1,
        }
    }
}

impl PeerInfo {
    pub fn new(id: PeerId, addresses: Vec<SocketAddr>) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            id,
            addresses,
            identity: None,
            status: PeerStatus::Disconnected,
            capabilities: PeerCapabilities::default(),
            last_seen: now,
            connection_attempts: 0,
            reputation: 50,
            protocol_version: "1.0".to_string(),
            user_agent: "nym-node/0.1.0".to_string(),
        }
    }
    
    pub fn update_last_seen(&mut self) {
        self.last_seen = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    pub fn is_online(&self) -> bool {
        matches!(self.status, PeerStatus::Connected)
    }
    
    pub fn should_ban(&self) -> bool {
        self.connection_attempts > 10 || self.reputation < 10
    }
    
    pub fn increase_reputation(&mut self, amount: u8) {
        self.reputation = (self.reputation.saturating_add(amount)).min(100);
    }
    
    pub fn decrease_reputation(&mut self, amount: u8) {
        self.reputation = self.reputation.saturating_sub(amount);
    }
}

impl PeerManager {
    pub fn new(max_peers: usize, min_reputation: u8) -> Self {
        Self {
            peers: HashMap::new(),
            stats: HashMap::new(),
            max_peers,
            min_reputation,
        }
    }
    
    pub fn add_peer(&mut self, peer_info: PeerInfo) -> NetworkResult<()> {
        if self.peers.len() >= self.max_peers {
            return Err(NetworkError::PeerError { 
                reason: "Maximum peers reached".to_string() 
            });
        }
        
        let peer_id = peer_info.id.clone();
        self.peers.insert(peer_id.clone(), peer_info);
        self.stats.insert(peer_id, PeerStats::default());
        
        Ok(())
    }
    
    pub fn remove_peer(&mut self, peer_id: &PeerId) -> Option<PeerInfo> {
        self.stats.remove(peer_id);
        self.peers.remove(peer_id)
    }
    
    pub fn get_peer(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peers.get(peer_id)
    }
    
    pub fn get_peer_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerInfo> {
        self.peers.get_mut(peer_id)
    }
    
    pub fn get_peer_stats(&self, peer_id: &PeerId) -> Option<&PeerStats> {
        self.stats.get(peer_id)
    }
    
    pub fn get_peer_stats_mut(&mut self, peer_id: &PeerId) -> Option<&mut PeerStats> {
        self.stats.get_mut(peer_id)
    }
    
    pub fn connected_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values()
            .filter(|peer| peer.is_online())
            .collect()
    }
    
    pub fn good_peers(&self) -> Vec<&PeerInfo> {
        self.peers.values()
            .filter(|peer| peer.reputation >= self.min_reputation)
            .collect()
    }
    
    pub fn ban_peer(&mut self, peer_id: &PeerId) -> NetworkResult<()> {
        if let Some(peer) = self.get_peer_mut(peer_id) {
            peer.status = PeerStatus::Banned;
            peer.reputation = 0;
            Ok(())
        } else {
            Err(NetworkError::PeerError { 
                reason: "Peer not found".to_string() 
            })
        }
    }
    
    pub fn update_peer_status(&mut self, peer_id: &PeerId, status: PeerStatus) -> NetworkResult<()> {
        if let Some(peer) = self.get_peer_mut(peer_id) {
            peer.status = status;
            peer.update_last_seen();
            Ok(())
        } else {
            Err(NetworkError::PeerError { 
                reason: "Peer not found".to_string() 
            })
        }
    }
    
    pub fn random_peer(&self) -> Option<&PeerInfo> {
        let connected = self.connected_peers();
        if connected.is_empty() {
            return None;
        }
        
        let index = rand::random::<usize>() % connected.len();
        connected.get(index).copied()
    }
    
    pub fn cleanup(&mut self) -> usize {
        let mut to_remove = Vec::new();
        
        for (peer_id, peer) in &self.peers {
            if matches!(peer.status, PeerStatus::Banned) || peer.should_ban() {
                to_remove.push(peer_id.clone());
            }
        }
        
        let removed_count = to_remove.len();
        for peer_id in to_remove {
            self.remove_peer(&peer_id);
        }
        
        removed_count
    }
    
    pub fn peer_count(&self) -> usize {
        self.peers.len()
    }
    
    pub fn connected_peer_count(&self) -> usize {
        self.connected_peers().len()
    }
    
    pub fn update_stats(
        &mut self, 
        peer_id: &PeerId, 
        bytes_sent: u64, 
        bytes_received: u64
    ) -> NetworkResult<()> {
        if let Some(stats) = self.get_peer_stats_mut(peer_id) {
            stats.bytes_sent += bytes_sent;
            stats.bytes_received += bytes_received;
            if bytes_sent > 0 {
                stats.messages_sent += 1;
            }
            if bytes_received > 0 {
                stats.messages_received += 1;
            }
            Ok(())
        } else {
            Err(NetworkError::PeerError { 
                reason: "Peer stats not found".to_string() 
            })
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};
    
    #[test]
    fn test_peer_id_creation() {
        let hash = Hash256::from([1u8; 32]);
        let peer_id = PeerId::new(hash);
        assert_eq!(peer_id.hash(), &hash);
    }
    
    #[test]
    fn test_peer_id_hex_conversion() {
        let hash = Hash256::from([1u8; 32]);
        let peer_id = PeerId::new(hash);
        
        let hex = peer_id.to_hex();
        let peer_id2 = PeerId::from_hex(&hex).unwrap();
        
        assert_eq!(peer_id, peer_id2);
    }
    
    #[test]
    fn test_peer_info_creation() {
        let peer_id = PeerId::new(Hash256::from([1u8; 32]));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        
        let peer_info = PeerInfo::new(peer_id.clone(), vec![addr]);
        assert_eq!(peer_info.id, peer_id);
        assert_eq!(peer_info.addresses.len(), 1);
        assert_eq!(peer_info.reputation, 50);
    }
    
    #[test]
    fn test_peer_manager() {
        let mut manager = PeerManager::new(10, 20);
        
        let peer_id = PeerId::new(Hash256::from([1u8; 32]));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let peer_info = PeerInfo::new(peer_id.clone(), vec![addr]);
        
        manager.add_peer(peer_info).unwrap();
        assert_eq!(manager.peer_count(), 1);
        
        let retrieved = manager.get_peer(&peer_id).unwrap();
        assert_eq!(retrieved.id, peer_id);
    }
    
    #[test]
    fn test_peer_reputation() {
        let peer_id = PeerId::new(Hash256::from([1u8; 32]));
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let mut peer_info = PeerInfo::new(peer_id, vec![addr]);
        
        peer_info.increase_reputation(30);
        assert_eq!(peer_info.reputation, 80);
        
        peer_info.decrease_reputation(50);
        assert_eq!(peer_info.reputation, 30);
        
        // Test bounds
        peer_info.increase_reputation(100);
        assert_eq!(peer_info.reputation, 100);
        
        peer_info.decrease_reputation(150);
        assert_eq!(peer_info.reputation, 0);
    }
}