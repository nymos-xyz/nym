//! Message routing and privacy protection

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use nym_crypto::{Hash256, SecurityLevel};
use nym_core::NymIdentity;
use crate::{
    NetworkError, NetworkResult, PeerId, PeerInfo,
    NetworkMessage, MessageType, MessagePayload, PrivacyRoutedPayload
};

/// Routing configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingConfig {
    /// Maximum hops for privacy routing
    pub max_hops: u8,
    /// Default number of hops
    pub default_hops: u8,
    /// Routing table size
    pub routing_table_size: usize,
    /// Route refresh interval
    pub route_refresh_interval: Duration,
    /// Message cache size
    pub message_cache_size: usize,
    /// Message TTL
    pub message_ttl: Duration,
}

/// Routing table entry
#[derive(Debug, Clone)]
pub struct RouteEntry {
    /// Destination peer
    pub destination: PeerId,
    /// Next hop peer
    pub next_hop: PeerId,
    /// Route cost (latency/hops)
    pub cost: u32,
    /// Last updated timestamp
    pub last_updated: u64,
    /// Route reliability score
    pub reliability: f64,
}

/// Privacy route for anonymous communication
#[derive(Debug, Clone)]
pub struct PrivacyRoute {
    /// Route ID
    pub route_id: Hash256,
    /// Sequence of peers in the route
    pub hops: Vec<PeerId>,
    /// Route creation timestamp
    pub created_at: u64,
    /// Route usage count
    pub usage_count: u32,
    /// Route reliability
    pub reliability: f64,
}

/// Message cache entry
#[derive(Debug, Clone)]
struct MessageCacheEntry {
    /// Message ID
    message_id: Hash256,
    /// Cached message
    message: NetworkMessage,
    /// Cache timestamp
    cached_at: u64,
    /// Access count
    access_count: u32,
}

/// Routing statistics
#[derive(Debug, Clone, Default)]
pub struct RoutingStats {
    /// Messages routed
    pub messages_routed: u64,
    /// Privacy routes created
    pub privacy_routes_created: u64,
    /// Routing failures
    pub routing_failures: u64,
    /// Average routing latency
    pub avg_routing_latency: f64,
    /// Cache hits
    pub cache_hits: u64,
    /// Cache misses
    pub cache_misses: u64,
}

/// Message router with privacy features
pub struct MessageRouter {
    /// Routing configuration
    config: RoutingConfig,
    /// Local identity
    identity: NymIdentity,
    /// Routing table
    routing_table: HashMap<PeerId, RouteEntry>,
    /// Privacy routes
    privacy_routes: HashMap<Hash256, PrivacyRoute>,
    /// Message cache
    message_cache: VecDeque<MessageCacheEntry>,
    /// Message ID tracking (for duplicate detection)
    seen_messages: HashMap<Hash256, u64>,
    /// Routing statistics
    stats: RoutingStats,
    /// Connected peers
    connected_peers: HashMap<PeerId, PeerInfo>,
}

/// Routing table for peer discovery and path finding
pub struct RoutingTable {
    /// Route entries
    entries: HashMap<PeerId, RouteEntry>,
    /// Table capacity
    max_entries: usize,
    /// Last update timestamp
    last_updated: u64,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            max_hops: 5,
            default_hops: 3,
            routing_table_size: 1000,
            route_refresh_interval: Duration::from_secs(300), // 5 minutes
            message_cache_size: 100,
            message_ttl: Duration::from_secs(3600), // 1 hour
        }
    }
}

impl RouteEntry {
    /// Create a new route entry
    pub fn new(destination: PeerId, next_hop: PeerId, cost: u32) -> Self {
        Self {
            destination,
            next_hop,
            cost,
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            reliability: 1.0,
        }
    }
    
    /// Update route reliability
    pub fn update_reliability(&mut self, success: bool) {
        const ALPHA: f64 = 0.1; // Learning rate
        
        let new_sample = if success { 1.0 } else { 0.0 };
        self.reliability = (1.0 - ALPHA) * self.reliability + ALPHA * new_sample;
        
        self.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    /// Check if route is stale
    pub fn is_stale(&self, max_age: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now - self.last_updated > max_age.as_secs()
    }
}

impl PrivacyRoute {
    /// Create a new privacy route
    pub fn new(hops: Vec<PeerId>) -> Self {
        let route_id = Hash256::from(rand::random::<[u8; 32]>());
        
        Self {
            route_id,
            hops,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            usage_count: 0,
            reliability: 1.0,
        }
    }
    
    /// Get next hop in route
    pub fn next_hop(&self, current_hop: usize) -> Option<PeerId> {
        if current_hop < self.hops.len() {
            Some(self.hops[current_hop].clone())
        } else {
            None
        }
    }
    
    /// Increment usage count
    pub fn use_route(&mut self) {
        self.usage_count += 1;
    }
    
    /// Update route reliability
    pub fn update_reliability(&mut self, success: bool) {
        const ALPHA: f64 = 0.1;
        
        let new_sample = if success { 1.0 } else { 0.0 };
        self.reliability = (1.0 - ALPHA) * self.reliability + ALPHA * new_sample;
    }
    
    /// Check if route should be refreshed
    pub fn should_refresh(&self, max_age: Duration, max_usage: u32) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        (now - self.created_at > max_age.as_secs()) || 
        (self.usage_count >= max_usage) ||
        (self.reliability < 0.5)
    }
}

impl MessageRouter {
    /// Create a new message router
    pub fn new(config: RoutingConfig, identity: NymIdentity) -> Self {
        Self {
            config,
            identity,
            routing_table: HashMap::new(),
            privacy_routes: HashMap::new(),
            message_cache: VecDeque::new(),
            seen_messages: HashMap::new(),
            stats: RoutingStats::default(),
            connected_peers: HashMap::new(),
        }
    }
    
    /// Update connected peers
    pub fn update_connected_peers(&mut self, peers: HashMap<PeerId, PeerInfo>) {
        self.connected_peers = peers;
        self.refresh_routing_table();
    }
    
    /// Route a message to destination
    pub async fn route_message(
        &mut self,
        mut message: NetworkMessage,
        use_privacy: bool,
    ) -> NetworkResult<Vec<(PeerId, NetworkMessage)>> {
        // Check for duplicate messages
        if self.is_duplicate_message(&message) {
            return Ok(vec![]);
        }
        
        // Add to seen messages
        self.add_seen_message(&message);
        
        // Decrease TTL
        if !message.decrease_ttl() {
            return Err(NetworkError::RoutingFailed {
                reason: "Message TTL expired".to_string(),
            });
        }
        
        if use_privacy && message.recipient.is_some() {
            // Use privacy routing
            self.route_with_privacy(message).await
        } else {
            // Use direct routing
            self.route_direct(message).await
        }
    }
    
    /// Route message directly
    async fn route_direct(&mut self, message: NetworkMessage) -> NetworkResult<Vec<(PeerId, NetworkMessage)>> {
        if let Some(recipient) = &message.recipient {
            // Find next hop for recipient
            if let Some(next_hop) = self.find_next_hop(recipient) {
                self.stats.messages_routed += 1;
                Ok(vec![(next_hop, message)])
            } else {
                self.stats.routing_failures += 1;
                Err(NetworkError::RoutingFailed {
                    reason: format!("No route to peer: {:?}", recipient),
                })
            }
        } else {
            // Broadcast message
            self.broadcast_message(message).await
        }
    }
    
    /// Route message with privacy protection
    async fn route_with_privacy(&mut self, message: NetworkMessage) -> NetworkResult<Vec<(PeerId, NetworkMessage)>> {
        let recipient = message.recipient.as_ref().ok_or_else(|| {
            NetworkError::RoutingFailed {
                reason: "Privacy routing requires recipient".to_string(),
            }
        })?;
        
        // Find or create privacy route
        let route = self.get_or_create_privacy_route(recipient.clone()).await?;
        
        // Encrypt message for privacy routing
        let encrypted_message = self.encrypt_for_privacy_route(&message, &route)?;
        
        // Send to first hop
        if let Some(first_hop) = route.hops.first() {
            self.stats.messages_routed += 1;
            Ok(vec![(first_hop.clone(), encrypted_message)])
        } else {
            self.stats.routing_failures += 1;
            Err(NetworkError::RoutingFailed {
                reason: "Empty privacy route".to_string(),
            })
        }
    }
    
    /// Broadcast message to all connected peers
    async fn broadcast_message(&mut self, message: NetworkMessage) -> NetworkResult<Vec<(PeerId, NetworkMessage)>> {
        let mut routes = Vec::new();
        
        for peer_id in self.connected_peers.keys() {
            // Don't send back to sender
            if peer_id != &message.sender {
                routes.push((peer_id.clone(), message.clone()));
            }
        }
        
        self.stats.messages_routed += routes.len() as u64;
        Ok(routes)
    }
    
    /// Find next hop for destination
    fn find_next_hop(&self, destination: &PeerId) -> Option<PeerId> {
        // Check if peer is directly connected
        if self.connected_peers.contains_key(destination) {
            return Some(destination.clone());
        }
        
        // Check routing table
        if let Some(entry) = self.routing_table.get(destination) {
            return Some(entry.next_hop.clone());
        }
        
        // Use random connected peer as fallback
        self.connected_peers.keys().next().cloned()
    }
    
    /// Get or create privacy route
    async fn get_or_create_privacy_route(&mut self, destination: PeerId) -> NetworkResult<PrivacyRoute> {
        // Look for existing route
        for route in self.privacy_routes.values_mut() {
            if route.hops.last() == Some(&destination) && 
               !route.should_refresh(self.config.route_refresh_interval, 100) {
                route.use_route();
                return Ok(route.clone());
            }
        }
        
        // Create new privacy route
        self.create_privacy_route(destination).await
    }
    
    /// Create new privacy route
    async fn create_privacy_route(&mut self, destination: PeerId) -> NetworkResult<PrivacyRoute> {
        let hops = self.select_privacy_hops(destination, self.config.default_hops)?;
        let mut route = PrivacyRoute::new(hops);
        
        let route_id = route.route_id;
        self.privacy_routes.insert(route_id, route.clone());
        self.stats.privacy_routes_created += 1;
        
        route.use_route();
        Ok(route)
    }
    
    /// Select hops for privacy route
    fn select_privacy_hops(&self, destination: PeerId, num_hops: u8) -> NetworkResult<Vec<PeerId>> {
        let mut available_peers: Vec<PeerId> = self.connected_peers.keys().cloned().collect();
        
        if available_peers.is_empty() {
            return Err(NetworkError::RoutingFailed {
                reason: "No connected peers for privacy routing".to_string(),
            });
        }
        
        let mut hops = Vec::new();
        
        // Select random intermediate hops
        for _ in 0..(num_hops - 1) {
            if available_peers.is_empty() {
                break;
            }
            
            let index = rand::random::<usize>() % available_peers.len();
            let hop = available_peers.remove(index);
            hops.push(hop);
        }
        
        // Add destination as final hop
        hops.push(destination);
        
        Ok(hops)
    }
    
    /// Encrypt message for privacy route
    fn encrypt_for_privacy_route(&self, message: &NetworkMessage, route: &PrivacyRoute) -> NetworkResult<NetworkMessage> {
        // Serialize original message
        let message_bytes = message.to_bytes()?;
        
        // Create routing information
        let routing_info = bincode::serialize(&route.hops)
            .map_err(|e| NetworkError::Serialization {
                reason: e.to_string(),
            })?;
        
        // Simple encryption (placeholder - use proper layered encryption in production)
        let encrypted_data = self.simple_encrypt(&message_bytes)?;
        
        let privacy_payload = PrivacyRoutedPayload {
            encrypted_data,
            routing_info,
            hops_remaining: route.hops.len() as u8,
        };
        
        let privacy_message = NetworkMessage::new(
            MessageType::PrivacyRouting,
            PeerId::from_identity(&self.identity),
            route.hops.first().cloned(),
            MessagePayload::PrivacyRouted(privacy_payload),
        );
        
        Ok(privacy_message)
    }
    
    /// Handle privacy routed message
    pub async fn handle_privacy_message(&mut self, message: &NetworkMessage) -> NetworkResult<Option<NetworkMessage>> {
        if let MessagePayload::PrivacyRouted(privacy_payload) = &message.payload {
            if privacy_payload.hops_remaining == 0 {
                // Final destination - decrypt and deliver
                let decrypted_bytes = self.simple_decrypt(&privacy_payload.encrypted_data)?;
                let original_message = NetworkMessage::from_bytes(&decrypted_bytes)?;
                return Ok(Some(original_message));
            } else {
                // Intermediate hop - forward to next hop
                let hops: Vec<PeerId> = bincode::deserialize(&privacy_payload.routing_info)
                    .map_err(|e| NetworkError::Serialization {
                        reason: e.to_string(),
                    })?;
                
                let current_hop = (hops.len() as u8) - privacy_payload.hops_remaining;
                if let Some(next_hop) = hops.get(current_hop as usize + 1) {
                    let mut forwarded_payload = privacy_payload.clone();
                    forwarded_payload.hops_remaining -= 1;
                    
                    let forwarded_message = NetworkMessage::new(
                        MessageType::PrivacyRouting,
                        PeerId::from_identity(&self.identity),
                        Some(next_hop.clone()),
                        MessagePayload::PrivacyRouted(forwarded_payload),
                    );
                    
                    return Ok(Some(forwarded_message));
                }
            }
        }
        
        Err(NetworkError::RoutingFailed {
            reason: "Invalid privacy routing message".to_string(),
        })
    }
    
    /// Simple encryption (placeholder)
    fn simple_encrypt(&self, data: &[u8]) -> NetworkResult<Vec<u8>> {
        // Use identity-based key for simple XOR encryption
        let key = self.identity.account_id().as_bytes();
        let mut encrypted = Vec::new();
        
        for (i, &byte) in data.iter().enumerate() {
            let key_byte = key[i % key.len()];
            encrypted.push(byte ^ key_byte);
        }
        
        Ok(encrypted)
    }
    
    /// Simple decryption (placeholder)
    fn simple_decrypt(&self, data: &[u8]) -> NetworkResult<Vec<u8>> {
        // XOR decryption is same as encryption
        self.simple_encrypt(data)
    }
    
    /// Check if message is duplicate
    fn is_duplicate_message(&self, message: &NetworkMessage) -> bool {
        self.seen_messages.contains_key(&message.message_id)
    }
    
    /// Add message to seen messages
    fn add_seen_message(&mut self, message: &NetworkMessage) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        self.seen_messages.insert(message.message_id, now);
        
        // Cleanup old entries
        if self.seen_messages.len() > self.config.message_cache_size * 2 {
            self.cleanup_seen_messages();
        }
    }
    
    /// Cleanup old seen messages
    fn cleanup_seen_messages(&mut self) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let ttl = self.config.message_ttl.as_secs();
        
        self.seen_messages.retain(|_, &mut timestamp| {
            now - timestamp <= ttl
        });
    }
    
    /// Refresh routing table
    fn refresh_routing_table(&mut self) {
        self.routing_table.clear();
        
        // Add direct routes to connected peers
        for (peer_id, peer_info) in &self.connected_peers {
            let entry = RouteEntry::new(
                peer_id.clone(),
                peer_id.clone(), // Direct connection
                1, // Cost of 1 for direct connection
            );
            self.routing_table.insert(peer_id.clone(), entry);
        }
    }
    
    /// Get routing statistics
    pub fn stats(&self) -> &RoutingStats {
        &self.stats
    }
    
    /// Get active privacy routes count
    pub fn active_privacy_routes(&self) -> usize {
        self.privacy_routes.len()
    }
    
    /// Get routing table size
    pub fn routing_table_size(&self) -> usize {
        self.routing_table.len()
    }
    
    /// Cleanup old privacy routes
    pub fn cleanup_old_routes(&mut self) {
        let routes_to_remove: Vec<Hash256> = self
            .privacy_routes
            .iter()
            .filter(|(_, route)| route.should_refresh(self.config.route_refresh_interval, 100))
            .map(|(id, _)| *id)
            .collect();
        
        for route_id in routes_to_remove {
            self.privacy_routes.remove(&route_id);
        }
    }
}

impl RoutingTable {
    /// Create a new routing table
    pub fn new(max_entries: usize) -> Self {
        Self {
            entries: HashMap::new(),
            max_entries,
            last_updated: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
    
    /// Add route entry
    pub fn add_entry(&mut self, entry: RouteEntry) -> bool {
        if self.entries.len() >= self.max_entries {
            // Remove oldest entry
            if let Some((oldest_peer, _)) = self.entries
                .iter()
                .min_by_key(|(_, entry)| entry.last_updated)
                .map(|(peer, entry)| (peer.clone(), entry.clone()))
            {
                self.entries.remove(&oldest_peer);
            }
        }
        
        let peer_id = entry.destination.clone();
        self.entries.insert(peer_id, entry).is_none()
    }
    
    /// Get route to destination
    pub fn get_route(&self, destination: &PeerId) -> Option<&RouteEntry> {
        self.entries.get(destination)
    }
    
    /// Remove stale entries
    pub fn cleanup_stale_entries(&mut self, max_age: Duration) {
        self.entries.retain(|_, entry| !entry.is_stale(max_age));
        
        self.last_updated = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
    }
    
    /// Get all entries
    pub fn entries(&self) -> &HashMap<PeerId, RouteEntry> {
        &self.entries
    }
    
    /// Get entry count
    pub fn entry_count(&self) -> usize {
        self.entries.len()
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
    
    fn create_test_peer_info(id: u8) -> (PeerId, PeerInfo) {
        let peer_id = PeerId::new(Hash256::from([id; 32]));
        let addr = format!("127.0.0.1:808{}", id).parse().unwrap();
        let peer_info = PeerInfo::new(peer_id.clone(), vec![addr]);
        (peer_id, peer_info)
    }
    
    #[test]
    fn test_routing_config_default() {
        let config = RoutingConfig::default();
        assert_eq!(config.max_hops, 5);
        assert_eq!(config.default_hops, 3);
    }
    
    #[test]
    fn test_route_entry_creation() {
        let dest = PeerId::new(Hash256::from([1u8; 32]));
        let next_hop = PeerId::new(Hash256::from([2u8; 32]));
        
        let entry = RouteEntry::new(dest.clone(), next_hop.clone(), 10);
        assert_eq!(entry.destination, dest);
        assert_eq!(entry.next_hop, next_hop);
        assert_eq!(entry.cost, 10);
        assert_eq!(entry.reliability, 1.0);
    }
    
    #[test]
    fn test_route_entry_reliability() {
        let dest = PeerId::new(Hash256::from([1u8; 32]));
        let next_hop = PeerId::new(Hash256::from([2u8; 32]));
        
        let mut entry = RouteEntry::new(dest, next_hop, 10);
        
        // Success should increase reliability slightly
        let initial_reliability = entry.reliability;
        entry.update_reliability(true);
        assert!(entry.reliability >= initial_reliability);
        
        // Failure should decrease reliability
        entry.update_reliability(false);
        assert!(entry.reliability < 1.0);
    }
    
    #[test]
    fn test_privacy_route_creation() {
        let hop1 = PeerId::new(Hash256::from([1u8; 32]));
        let hop2 = PeerId::new(Hash256::from([2u8; 32]));
        let hops = vec![hop1.clone(), hop2.clone()];
        
        let route = PrivacyRoute::new(hops.clone());
        assert_eq!(route.hops, hops);
        assert_eq!(route.usage_count, 0);
        assert_eq!(route.reliability, 1.0);
        
        assert_eq!(route.next_hop(0), Some(hop1));
        assert_eq!(route.next_hop(1), Some(hop2));
        assert_eq!(route.next_hop(2), None);
    }
    
    #[test]
    fn test_message_router_creation() {
        let config = RoutingConfig::default();
        let identity = create_test_identity();
        
        let router = MessageRouter::new(config, identity);
        assert_eq!(router.routing_table_size(), 0);
        assert_eq!(router.active_privacy_routes(), 0);
    }
    
    #[test]
    fn test_routing_table() {
        let mut table = RoutingTable::new(10);
        
        let dest = PeerId::new(Hash256::from([1u8; 32]));
        let next_hop = PeerId::new(Hash256::from([2u8; 32]));
        let entry = RouteEntry::new(dest.clone(), next_hop, 5);
        
        assert!(table.add_entry(entry));
        assert_eq!(table.entry_count(), 1);
        
        let retrieved = table.get_route(&dest);
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().cost, 5);
    }
    
    #[tokio::test]
    async fn test_direct_routing() {
        let config = RoutingConfig::default();
        let identity = create_test_identity();
        let mut router = MessageRouter::new(config, identity.clone());
        
        // Add connected peer
        let (peer_id, peer_info) = create_test_peer_info(1);
        let mut peers = HashMap::new();
        peers.insert(peer_id.clone(), peer_info);
        router.update_connected_peers(peers);
        
        // Create test message
        let message = NetworkMessage::new(
            MessageType::Ping,
            PeerId::from_identity(&identity),
            Some(peer_id.clone()),
            MessagePayload::Raw(vec![1, 2, 3]),
        );
        
        // Route message
        let routes = router.route_message(message, false).await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].0, peer_id);
    }
    
    #[tokio::test]
    async fn test_broadcast_routing() {
        let config = RoutingConfig::default();
        let identity = create_test_identity();
        let mut router = MessageRouter::new(config, identity.clone());
        
        // Add multiple connected peers
        let mut peers = HashMap::new();
        for i in 1..=3 {
            let (peer_id, peer_info) = create_test_peer_info(i);
            peers.insert(peer_id, peer_info);
        }
        router.update_connected_peers(peers);
        
        // Create broadcast message
        let message = NetworkMessage::new(
            MessageType::BlockAnnouncement,
            PeerId::from_identity(&identity),
            None, // Broadcast
            MessagePayload::Raw(vec![1, 2, 3]),
        );
        
        // Route message
        let routes = router.route_message(message, false).await.unwrap();
        assert_eq!(routes.len(), 3); // Should route to all 3 peers
    }
    
    #[tokio::test]
    async fn test_privacy_routing() {
        let config = RoutingConfig::default();
        let identity = create_test_identity();
        let mut router = MessageRouter::new(config, identity.clone());
        
        // Add connected peers
        let mut peers = HashMap::new();
        for i in 1..=5 {
            let (peer_id, peer_info) = create_test_peer_info(i);
            peers.insert(peer_id, peer_info);
        }
        router.update_connected_peers(peers.clone());
        
        // Create message for privacy routing
        let target_peer = peers.keys().next().unwrap().clone();
        let message = NetworkMessage::new(
            MessageType::TransactionAnnouncement,
            PeerId::from_identity(&identity),
            Some(target_peer),
            MessagePayload::Raw(vec![1, 2, 3]),
        );
        
        // Route with privacy
        let routes = router.route_message(message, true).await.unwrap();
        assert_eq!(routes.len(), 1);
        assert_eq!(routes[0].1.message_type, MessageType::PrivacyRouting);
        
        // Should have created a privacy route
        assert!(router.active_privacy_routes() > 0);
    }
    
    #[test]
    fn test_duplicate_message_detection() {
        let config = RoutingConfig::default();
        let identity = create_test_identity();
        let mut router = MessageRouter::new(config, identity.clone());
        
        let message = NetworkMessage::new(
            MessageType::Ping,
            PeerId::from_identity(&identity),
            None,
            MessagePayload::Raw(vec![1, 2, 3]),
        );
        
        // First time should not be duplicate
        assert!(!router.is_duplicate_message(&message));
        
        // Add to seen messages
        router.add_seen_message(&message);
        
        // Second time should be duplicate
        assert!(router.is_duplicate_message(&message));
    }
    
    #[test]
    fn test_privacy_route_selection() {
        let config = RoutingConfig::default();
        let identity = create_test_identity();
        let router = MessageRouter::new(config, identity);
        
        // Create connected peers
        let mut peers = HashMap::new();
        for i in 1..=5 {
            let (peer_id, peer_info) = create_test_peer_info(i);
            peers.insert(peer_id, peer_info);
        }
        
        let destination = peers.keys().next().unwrap().clone();
        let available_peers: Vec<PeerId> = peers.keys().cloned().collect();
        
        // Mock the connected_peers field for testing
        let mut test_router = router;
        test_router.connected_peers = peers;
        
        let hops = test_router.select_privacy_hops(destination.clone(), 3).unwrap();
        assert_eq!(hops.len(), 3);
        assert_eq!(hops.last().unwrap(), &destination);
    }
}