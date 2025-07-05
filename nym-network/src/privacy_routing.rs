use crate::{NetworkError, NetworkResult, PeerId, NetworkMessage, MessageType};
use nym_core::NymIdentity;
use nym_crypto::{Hash256, SecurityLevel};

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime};
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use serde::{Deserialize, Serialize};
use rand::{Rng, thread_rng, seq::SliceRandom};

#[derive(Debug, Clone)]
pub struct PrivacyRoutingConfig {
    pub min_route_length: usize,
    pub max_route_length: usize,
    pub route_timeout: Duration,
    pub max_pending_routes: usize,
    pub onion_layer_count: usize,
    pub enable_cover_traffic: bool,
    pub cover_traffic_interval: Duration,
    pub mix_strategy: MixStrategy,
    pub enable_traffic_analysis_protection: bool,
}

impl Default for PrivacyRoutingConfig {
    fn default() -> Self {
        Self {
            min_route_length: 3,
            max_route_length: 6,
            route_timeout: Duration::from_secs(300),
            max_pending_routes: 1000,
            onion_layer_count: 3,
            enable_cover_traffic: true,
            cover_traffic_interval: Duration::from_secs(30),
            mix_strategy: MixStrategy::RandomDelay,
            enable_traffic_analysis_protection: true,
        }
    }
}

#[derive(Debug, Clone)]
pub enum MixStrategy {
    RandomDelay,
    BatchAndShuffle,
    PoissonDelay,
    AdaptiveDelay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionMessage {
    pub message_id: String,
    pub layers: Vec<OnionLayer>,
    pub final_destination: PeerId,
    pub created_at: SystemTime,
    pub ttl: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OnionLayer {
    pub next_hop: PeerId,
    pub encrypted_payload: Vec<u8>,
    pub layer_hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RouteHop {
    pub peer_id: PeerId,
    pub relay_key: Vec<u8>,
    pub next_hop: Option<PeerId>,
}

#[derive(Debug, Clone)]
pub struct PrivacyRoute {
    pub route_id: String,
    pub hops: Vec<RouteHop>,
    pub destination: PeerId,
    pub created_at: SystemTime,
    pub last_used: SystemTime,
    pub usage_count: u32,
    pub success_rate: f64,
}

#[derive(Debug, Clone)]
pub struct MixNode {
    pub peer_id: PeerId,
    pub mixing_delay: Duration,
    pub message_queue: VecDeque<(OnionMessage, SystemTime)>,
    pub last_batch_time: SystemTime,
    pub reputation_score: f64,
}

pub struct PrivacyRouter {
    config: PrivacyRoutingConfig,
    local_identity: NymIdentity,
    local_peer_id: PeerId,
    active_routes: Arc<RwLock<HashMap<String, PrivacyRoute>>>,
    mix_nodes: Arc<RwLock<HashMap<PeerId, MixNode>>>,
    pending_messages: Arc<RwLock<HashMap<String, OnionMessage>>>,
    route_statistics: Arc<RwLock<RoutingStatistics>>,
    known_peers: Arc<RwLock<Vec<PeerId>>>,
}

#[derive(Debug, Default)]
pub struct RoutingStatistics {
    pub total_routes_created: u64,
    pub total_messages_routed: u64,
    pub successful_deliveries: u64,
    pub failed_deliveries: u64,
    pub average_route_length: f64,
    pub average_delivery_time: Duration,
    pub cover_traffic_sent: u64,
}

impl PrivacyRouter {
    pub fn new(
        config: PrivacyRoutingConfig,
        local_identity: NymIdentity,
    ) -> Self {
        info!("Initializing privacy-preserving message router");
        
        let local_peer_id = PeerId::from_identity(&local_identity);

        Self {
            config,
            local_identity,
            local_peer_id,
            active_routes: Arc::new(RwLock::new(HashMap::new())),
            mix_nodes: Arc::new(RwLock::new(HashMap::new())),
            pending_messages: Arc::new(RwLock::new(HashMap::new())),
            route_statistics: Arc::new(RwLock::new(RoutingStatistics::default())),
            known_peers: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn route_message_privately(
        &self,
        destination: PeerId,
        message: NetworkMessage,
    ) -> NetworkResult<String> {
        info!("Routing message privately to destination: {}", destination);

        let route = self.find_or_create_route(&destination).await?;
        
        let onion_message = self.create_onion_message(&route, message).await?;
        
        let message_id = onion_message.message_id.clone();
        
        self.pending_messages.write().await.insert(message_id.clone(), onion_message.clone());
        
        self.forward_onion_message(onion_message).await?;
        
        self.update_route_usage(&route.route_id).await?;
        
        let mut stats = self.route_statistics.write().await;
        stats.total_messages_routed += 1;

        Ok(message_id)
    }

    pub async fn handle_onion_message(&self, onion_message: OnionMessage) -> NetworkResult<()> {
        debug!("Handling onion message: {}", onion_message.message_id);

        if self.is_message_expired(&onion_message) {
            warn!("Dropping expired onion message: {}", onion_message.message_id);
            return Ok(());
        }

        if onion_message.final_destination == self.local_peer_id {
            return self.deliver_final_message(onion_message).await;
        }

        self.process_onion_layer(onion_message).await
    }

    pub async fn register_mix_node(&self, peer_id: PeerId) -> NetworkResult<()> {
        info!("Registering mix node: {}", peer_id);

        let mix_node = MixNode {
            peer_id: peer_id.clone(),
            mixing_delay: self.calculate_mixing_delay(),
            message_queue: VecDeque::new(),
            last_batch_time: SystemTime::now(),
            reputation_score: 0.5,
        };

        self.mix_nodes.write().await.insert(peer_id.clone(), mix_node);
        
        let mut known_peers = self.known_peers.write().await;
        if !known_peers.contains(&peer_id) {
            known_peers.push(peer_id);
        }

        Ok(())
    }

    pub async fn update_peer_reputation(&self, peer_id: &PeerId, delta: f64) -> NetworkResult<()> {
        let mut mix_nodes = self.mix_nodes.write().await;
        
        if let Some(mix_node) = mix_nodes.get_mut(peer_id) {
            mix_node.reputation_score = (mix_node.reputation_score + delta).clamp(0.0, 1.0);
            debug!("Updated reputation for peer {}: {}", peer_id, mix_node.reputation_score);
        }

        Ok(())
    }

    pub async fn generate_cover_traffic(&self) -> NetworkResult<()> {
        if !self.config.enable_cover_traffic {
            return Ok(());
        }

        debug!("Generating cover traffic");

        let known_peers = self.known_peers.read().await;
        if known_peers.len() < 2 {
            return Ok(());
        }

        let mut rng = thread_rng();
        let random_destination = known_peers.choose(&mut rng)
            .ok_or_else(|| NetworkError::RoutingError {
                reason: "No peers available for cover traffic".to_string(),
            })?;

        let cover_message = NetworkMessage::new(
            MessageType::CoverTraffic,
            self.local_peer_id.clone(),
            Some(random_destination.clone()),
            crate::MessagePayload::Raw(self.generate_random_payload()),
        );

        self.route_message_privately(random_destination.clone(), cover_message).await?;

        let mut stats = self.route_statistics.write().await;
        stats.cover_traffic_sent += 1;

        Ok(())
    }

    async fn find_or_create_route(&self, destination: &PeerId) -> NetworkResult<PrivacyRoute> {
        let routes = self.active_routes.read().await;
        
        for route in routes.values() {
            if route.destination == *destination && !self.is_route_expired(route) {
                return Ok(route.clone());
            }
        }
        
        drop(routes);
        
        self.create_new_route(destination).await
    }

    async fn create_new_route(&self, destination: &PeerId) -> NetworkResult<PrivacyRoute> {
        info!("Creating new privacy route to: {}", destination);

        let known_peers = self.known_peers.read().await;
        if known_peers.len() < self.config.min_route_length {
            return Err(NetworkError::RoutingError {
                reason: format!(
                    "Insufficient peers for routing: need {}, have {}",
                    self.config.min_route_length,
                    known_peers.len()
                ),
            });
        }

        let route_length = thread_rng().gen_range(
            self.config.min_route_length..=self.config.max_route_length.min(known_peers.len())
        );

        let mut available_peers: Vec<PeerId> = known_peers.iter()
            .filter(|&peer| peer != destination && peer != &self.local_peer_id)
            .cloned()
            .collect();

        available_peers.shuffle(&mut thread_rng());

        let mut hops = Vec::new();
        for i in 0..route_length {
            if available_peers.is_empty() {
                break;
            }

            let peer_id = available_peers.remove(0);
            let relay_key = self.generate_relay_key();
            let next_hop = if i == route_length - 1 {
                Some(destination.clone())
            } else if i + 1 < available_peers.len() {
                Some(available_peers[0].clone())
            } else {
                Some(destination.clone())
            };

            hops.push(RouteHop {
                peer_id,
                relay_key,
                next_hop,
            });
        }

        if hops.is_empty() {
            return Err(NetworkError::RoutingError {
                reason: "Failed to create route hops".to_string(),
            });
        }

        let route_id = self.generate_route_id();
        let route = PrivacyRoute {
            route_id: route_id.clone(),
            hops,
            destination: destination.clone(),
            created_at: SystemTime::now(),
            last_used: SystemTime::now(),
            usage_count: 0,
            success_rate: 1.0,
        };

        self.active_routes.write().await.insert(route_id, route.clone());

        let mut stats = self.route_statistics.write().await;
        stats.total_routes_created += 1;
        stats.average_route_length = (stats.average_route_length * (stats.total_routes_created - 1) as f64 + route.hops.len() as f64) / stats.total_routes_created as f64;

        info!("Created new route {} with {} hops", route.route_id, route.hops.len());
        Ok(route)
    }

    async fn create_onion_message(
        &self,
        route: &PrivacyRoute,
        message: NetworkMessage,
    ) -> NetworkResult<OnionMessage> {
        debug!("Creating onion message for route: {}", route.route_id);

        let message_data = bincode::serialize(&message)
            .map_err(|e| NetworkError::Serialization {
                reason: format!("Failed to serialize message: {}", e),
            })?;

        let mut layers = Vec::new();
        let mut current_payload = message_data;

        for (i, hop) in route.hops.iter().enumerate().rev() {
            let encrypted_payload = self.encrypt_for_hop(&current_payload, &hop.relay_key)?;
            
            let layer = OnionLayer {
                next_hop: hop.next_hop.clone().unwrap_or_else(|| route.destination.clone()),
                encrypted_payload: encrypted_payload.clone(),
                layer_hash: self.calculate_layer_hash(&encrypted_payload),
            };

            layers.insert(0, layer);
            current_payload = bincode::serialize(&layer)
                .map_err(|e| NetworkError::Serialization {
                    reason: format!("Failed to serialize layer: {}", e),
                })?;
        }

        let message_id = self.generate_message_id();
        
        let onion_message = OnionMessage {
            message_id,
            layers,
            final_destination: route.destination.clone(),
            created_at: SystemTime::now(),
            ttl: 64,
        };

        Ok(onion_message)
    }

    async fn forward_onion_message(&self, onion_message: OnionMessage) -> NetworkResult<()> {
        if onion_message.layers.is_empty() {
            return Err(NetworkError::RoutingError {
                reason: "Cannot forward onion message with no layers".to_string(),
            });
        }

        let first_layer = &onion_message.layers[0];
        let next_hop = &first_layer.next_hop;

        debug!("Forwarding onion message {} to next hop: {}", onion_message.message_id, next_hop);

        self.apply_mixing_strategy(&onion_message).await?;

        Ok(())
    }

    async fn process_onion_layer(&self, mut onion_message: OnionMessage) -> NetworkResult<()> {
        if onion_message.layers.is_empty() {
            return Err(NetworkError::RoutingError {
                reason: "No layers left to process".to_string(),
            });
        }

        if onion_message.ttl == 0 {
            warn!("Dropping onion message with TTL=0: {}", onion_message.message_id);
            return Ok(());
        }

        onion_message.ttl -= 1;
        let layer = onion_message.layers.remove(0);

        let decrypted_payload = self.decrypt_layer(&layer.encrypted_payload)?;

        if onion_message.layers.is_empty() {
            let final_message: NetworkMessage = bincode::deserialize(&decrypted_payload)
                .map_err(|e| NetworkError::Serialization {
                    reason: format!("Failed to deserialize final message: {}", e),
                })?;
            
            info!("Delivering final message to: {}", onion_message.final_destination);
            return Ok(());
        }

        self.forward_onion_message(onion_message).await
    }

    async fn deliver_final_message(&self, onion_message: OnionMessage) -> NetworkResult<()> {
        info!("Delivering final message: {}", onion_message.message_id);

        let mut stats = self.route_statistics.write().await;
        stats.successful_deliveries += 1;

        Ok(())
    }

    async fn apply_mixing_strategy(&self, onion_message: &OnionMessage) -> NetworkResult<()> {
        match self.config.mix_strategy {
            MixStrategy::RandomDelay => {
                let delay = Duration::from_millis(thread_rng().gen_range(100..=2000));
                tokio::time::sleep(delay).await;
            }
            MixStrategy::BatchAndShuffle => {
                
            }
            MixStrategy::PoissonDelay => {
                let lambda = 1.0;
                let delay_ms = (-lambda.ln() / thread_rng().gen::<f64>()) * 1000.0;
                let delay = Duration::from_millis(delay_ms.max(100.0).min(5000.0) as u64);
                tokio::time::sleep(delay).await;
            }
            MixStrategy::AdaptiveDelay => {
                let base_delay = 500;
                let adaptive_component = thread_rng().gen_range(0..=1000);
                let delay = Duration::from_millis(base_delay + adaptive_component);
                tokio::time::sleep(delay).await;
            }
        }

        Ok(())
    }

    async fn update_route_usage(&self, route_id: &str) -> NetworkResult<()> {
        let mut routes = self.active_routes.write().await;
        
        if let Some(route) = routes.get_mut(route_id) {
            route.usage_count += 1;
            route.last_used = SystemTime::now();
        }

        Ok(())
    }

    fn encrypt_for_hop(&self, data: &[u8], relay_key: &[u8]) -> NetworkResult<Vec<u8>> {
        use sha3::{Digest, Sha3_256};
        
        let mut hasher = Sha3_256::new();
        hasher.update(relay_key);
        hasher.update(data);
        let encrypted = hasher.finalize().to_vec();
        
        Ok(encrypted)
    }

    fn decrypt_layer(&self, encrypted_data: &[u8]) -> NetworkResult<Vec<u8>> {
        Ok(encrypted_data.to_vec())
    }

    fn calculate_layer_hash(&self, data: &[u8]) -> String {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(data);
        hex::encode(hasher.finalize())
    }

    fn generate_route_id(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&thread_rng().gen::<[u8; 16]>());
        hasher.update(&SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_nanos().to_be_bytes());
        hex::encode(hasher.finalize())[..16].to_string()
    }

    fn generate_message_id(&self) -> String {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        hasher.update(&thread_rng().gen::<[u8; 16]>());
        hasher.update(&SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_nanos().to_be_bytes());
        hex::encode(hasher.finalize())[..24].to_string()
    }

    fn generate_relay_key(&self) -> Vec<u8> {
        let mut key = vec![0u8; 32];
        thread_rng().fill(&mut key[..]);
        key
    }

    fn generate_random_payload(&self) -> Vec<u8> {
        let size = thread_rng().gen_range(128..=1024);
        let mut payload = vec![0u8; size];
        thread_rng().fill(&mut payload[..]);
        payload
    }

    fn calculate_mixing_delay(&self) -> Duration {
        match self.config.mix_strategy {
            MixStrategy::RandomDelay => Duration::from_millis(thread_rng().gen_range(500..=3000)),
            MixStrategy::BatchAndShuffle => Duration::from_secs(10),
            MixStrategy::PoissonDelay => Duration::from_millis(1000),
            MixStrategy::AdaptiveDelay => Duration::from_millis(1500),
        }
    }

    fn is_message_expired(&self, onion_message: &OnionMessage) -> bool {
        if let Ok(age) = SystemTime::now().duration_since(onion_message.created_at) {
            age > self.config.route_timeout
        } else {
            true
        }
    }

    fn is_route_expired(&self, route: &PrivacyRoute) -> bool {
        if let Ok(age) = SystemTime::now().duration_since(route.last_used) {
            age > self.config.route_timeout
        } else {
            true
        }
    }

    pub async fn cleanup_expired_routes(&self) {
        let mut routes = self.active_routes.write().await;
        let initial_count = routes.len();
        
        routes.retain(|_, route| !self.is_route_expired(route));
        
        let removed_count = initial_count - routes.len();
        if removed_count > 0 {
            debug!("Cleaned up {} expired routes", removed_count);
        }
    }

    pub async fn get_routing_statistics(&self) -> RoutingStatistics {
        self.route_statistics.read().await.clone()
    }

    pub async fn get_active_routes_count(&self) -> usize {
        self.active_routes.read().await.len()
    }
}

pub async fn create_privacy_router(
    config: PrivacyRoutingConfig,
    local_identity: NymIdentity,
) -> PrivacyRouter {
    PrivacyRouter::new(config, local_identity)
}