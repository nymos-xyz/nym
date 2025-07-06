//! Node Registry System
//! Manages network node information, capabilities, and status tracking

use crate::error::{NetworkError, NetworkResult};
use nym_core::NymIdentity;
use quid_core::QuIDIdentity;

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, debug, warn};
use serde::{Deserialize, Serialize};

/// Node status enumeration
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum NodeStatus {
    /// Node is active and responsive
    Active,
    /// Node is temporarily unavailable
    Inactive,
    /// Node is under maintenance
    Maintenance,
    /// Node has been banned
    Banned,
    /// Node status is unknown
    Unknown,
}

/// Node capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    /// Can relay messages
    pub relay: bool,
    /// Can store data
    pub storage: bool,
    /// Can perform computations
    pub compute: bool,
    /// Can act as mix node
    pub mixing: bool,
    /// Maximum concurrent connections
    pub max_connections: u32,
    /// Bandwidth capacity (bytes per second)
    pub bandwidth_capacity: u64,
    /// Storage capacity (bytes)
    pub storage_capacity: u64,
    /// Supported protocol versions
    pub protocol_versions: Vec<String>,
}

impl Default for NodeCapabilities {
    fn default() -> Self {
        Self {
            relay: true,
            storage: false,
            compute: false,
            mixing: false,
            max_connections: 100,
            bandwidth_capacity: 1_000_000, // 1 MB/s
            storage_capacity: 0,
            protocol_versions: vec!["1.0".to_string()],
        }
    }
}

/// Node hardware information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeHardware {
    /// CPU cores
    pub cpu_cores: u32,
    /// RAM in bytes
    pub memory_bytes: u64,
    /// Disk space in bytes
    pub disk_bytes: u64,
    /// Network interface speed (bytes per second)
    pub network_speed: u64,
    /// Operating system
    pub os_type: Option<String>,
    /// Architecture (x86_64, arm64, etc.)
    pub architecture: Option<String>,
}

impl Default for NodeHardware {
    fn default() -> Self {
        Self {
            cpu_cores: 1,
            memory_bytes: 1_073_741_824, // 1 GB
            disk_bytes: 10_737_418_240,  // 10 GB
            network_speed: 1_000_000,    // 1 MB/s
            os_type: None,
            architecture: None,
        }
    }
}

/// Performance metrics for a node
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeMetrics {
    /// Current CPU usage (0.0 to 1.0)
    pub cpu_usage: f32,
    /// Current memory usage (0.0 to 1.0)
    pub memory_usage: f32,
    /// Current disk usage (0.0 to 1.0)
    pub disk_usage: f32,
    /// Current bandwidth usage (bytes per second)
    pub bandwidth_usage: u64,
    /// Number of active connections
    pub active_connections: u32,
    /// Messages processed per second
    pub message_throughput: f32,
    /// Average response time (milliseconds)
    pub response_time_ms: f32,
    /// Uptime since last restart (seconds)
    pub uptime_seconds: u64,
    /// Last updated timestamp
    pub last_updated: SystemTime,
}

impl Default for NodeMetrics {
    fn default() -> Self {
        Self {
            cpu_usage: 0.0,
            memory_usage: 0.0,
            disk_usage: 0.0,
            bandwidth_usage: 0,
            active_connections: 0,
            message_throughput: 0.0,
            response_time_ms: 0.0,
            uptime_seconds: 0,
            last_updated: SystemTime::now(),
        }
    }
}

/// Complete node record
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRecord {
    /// Unique node identity
    pub node_id: NymIdentity,
    /// Associated QuID identity (optional)
    pub quid_identity: Option<QuIDIdentity>,
    /// Network addresses where node can be reached
    pub addresses: Vec<SocketAddr>,
    /// Node status
    pub status: NodeStatus,
    /// Node capabilities
    pub capabilities: NodeCapabilities,
    /// Hardware specifications
    pub hardware: NodeHardware,
    /// Current performance metrics
    pub metrics: NodeMetrics,
    /// Node version information
    pub version: String,
    /// When node was first registered
    pub registered_at: SystemTime,
    /// Last time node was seen active
    pub last_seen: SystemTime,
    /// Last successful health check
    pub last_health_check: Option<SystemTime>,
    /// Number of successful connections
    pub successful_connections: u64,
    /// Number of failed connections
    pub failed_connections: u64,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl NodeRecord {
    pub fn new(
        node_id: NymIdentity,
        addresses: Vec<SocketAddr>,
        capabilities: NodeCapabilities,
    ) -> Self {
        let now = SystemTime::now();
        
        Self {
            node_id,
            quid_identity: None,
            addresses,
            status: NodeStatus::Unknown,
            capabilities,
            hardware: NodeHardware::default(),
            metrics: NodeMetrics::default(),
            version: "1.0.0".to_string(),
            registered_at: now,
            last_seen: now,
            last_health_check: None,
            successful_connections: 0,
            failed_connections: 0,
            metadata: HashMap::new(),
        }
    }

    /// Check if node is considered healthy
    pub fn is_healthy(&self) -> bool {
        matches!(self.status, NodeStatus::Active) &&
        self.last_seen.elapsed().unwrap_or(Duration::from_secs(u64::MAX)) < Duration::from_secs(300) // 5 minutes
    }

    /// Update node metrics
    pub fn update_metrics(&mut self, metrics: NodeMetrics) {
        self.metrics = metrics;
        self.last_seen = SystemTime::now();
    }

    /// Record successful connection
    pub fn record_successful_connection(&mut self) {
        self.successful_connections += 1;
        self.last_seen = SystemTime::now();
        if self.status == NodeStatus::Unknown {
            self.status = NodeStatus::Active;
        }
    }

    /// Record failed connection
    pub fn record_failed_connection(&mut self) {
        self.failed_connections += 1;
        
        // If too many failures, mark as inactive
        let total_connections = self.successful_connections + self.failed_connections;
        if total_connections > 10 {
            let failure_rate = self.failed_connections as f64 / total_connections as f64;
            if failure_rate > 0.8 {
                self.status = NodeStatus::Inactive;
            }
        }
    }

    /// Get connection success rate
    pub fn connection_success_rate(&self) -> f64 {
        let total = self.successful_connections + self.failed_connections;
        if total == 0 {
            return 1.0; // Assume good for new nodes
        }
        self.successful_connections as f64 / total as f64
    }
}

/// Node registry configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegistryConfig {
    /// Maximum number of nodes to track
    pub max_nodes: usize,
    /// How long to keep inactive nodes (seconds)
    pub inactive_retention: u64,
    /// How often to perform health checks (seconds)
    pub health_check_interval: u64,
    /// Timeout for health check responses (seconds)
    pub health_check_timeout: u64,
    /// Enable automatic node discovery
    pub enable_discovery: bool,
    /// Enable metrics collection
    pub enable_metrics: bool,
}

impl Default for NodeRegistryConfig {
    fn default() -> Self {
        Self {
            max_nodes: 10000,
            inactive_retention: 86400 * 7, // 1 week
            health_check_interval: 300,    // 5 minutes
            health_check_timeout: 30,      // 30 seconds
            enable_discovery: true,
            enable_metrics: true,
        }
    }
}

/// Main node registry
pub struct NodeRegistry {
    config: NodeRegistryConfig,
    nodes: RwLock<HashMap<NymIdentity, NodeRecord>>,
    nodes_by_capability: RwLock<HashMap<String, HashSet<NymIdentity>>>,
    active_nodes: RwLock<HashSet<NymIdentity>>,
    banned_nodes: RwLock<HashSet<NymIdentity>>,
    last_cleanup: RwLock<Instant>,
}

impl NodeRegistry {
    pub fn new(config: NodeRegistryConfig) -> Self {
        info!("Initializing node registry with max {} nodes", config.max_nodes);
        
        Self {
            config,
            nodes: RwLock::new(HashMap::new()),
            nodes_by_capability: RwLock::new(HashMap::new()),
            active_nodes: RwLock::new(HashSet::new()),
            banned_nodes: RwLock::new(HashSet::new()),
            last_cleanup: RwLock::new(Instant::now()),
        }
    }

    /// Register a new node
    pub async fn register_node(&self, mut node: NodeRecord) -> NetworkResult<()> {
        info!("Registering node: {}", node.node_id.to_string());
        
        // Check if we're at capacity
        let nodes = self.nodes.read().await;
        if nodes.len() >= self.config.max_nodes {
            return Err(NetworkError::RegistrationFailed(
                "Node registry at capacity".to_string()
            ));
        }
        drop(nodes);
        
        // Check if node is banned
        let banned = self.banned_nodes.read().await;
        if banned.contains(&node.node_id) {
            return Err(NetworkError::RegistrationFailed(
                "Node is banned".to_string()
            ));
        }
        drop(banned);
        
        node.registered_at = SystemTime::now();
        node.last_seen = SystemTime::now();
        
        // Store node
        let mut nodes = self.nodes.write().await;
        nodes.insert(node.node_id.clone(), node.clone());
        drop(nodes);
        
        // Update capability indices
        self.update_capability_indices(&node).await;
        
        // Add to active nodes if appropriate
        if node.is_healthy() {
            let mut active = self.active_nodes.write().await;
            active.insert(node.node_id.clone());
        }
        
        Ok(())
    }

    /// Update existing node information
    pub async fn update_node(&self, node_id: &NymIdentity, update_fn: impl FnOnce(&mut NodeRecord)) -> NetworkResult<()> {
        let mut nodes = self.nodes.write().await;
        
        if let Some(node) = nodes.get_mut(node_id) {
            update_fn(node);
            node.last_seen = SystemTime::now();
            
            // Update capability indices
            self.update_capability_indices(node).await;
            
            // Update active status
            let mut active = self.active_nodes.write().await;
            if node.is_healthy() {
                active.insert(node_id.clone());
            } else {
                active.remove(node_id);
            }
            
            Ok(())
        } else {
            Err(NetworkError::NodeNotFound(node_id.to_string()))
        }
    }

    /// Get node by ID
    pub async fn get_node(&self, node_id: &NymIdentity) -> Option<NodeRecord> {
        let nodes = self.nodes.read().await;
        nodes.get(node_id).cloned()
    }

    /// Get all active nodes
    pub async fn get_active_nodes(&self) -> Vec<NodeRecord> {
        let active = self.active_nodes.read().await;
        let nodes = self.nodes.read().await;
        
        active.iter()
            .filter_map(|id| nodes.get(id))
            .cloned()
            .collect()
    }

    /// Find nodes by capability
    pub async fn find_nodes_by_capability(&self, capability: &str, limit: usize) -> Vec<NodeRecord> {
        let capability_index = self.nodes_by_capability.read().await;
        let nodes = self.nodes.read().await;
        
        if let Some(node_ids) = capability_index.get(capability) {
            node_ids.iter()
                .filter_map(|id| nodes.get(id))
                .filter(|node| node.is_healthy())
                .take(limit)
                .cloned()
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Find nodes in a geographic region
    pub async fn find_nodes_by_region(&self, region: &str, limit: usize) -> Vec<NodeRecord> {
        let nodes = self.nodes.read().await;
        
        nodes.values()
            .filter(|node| {
                node.is_healthy() && 
                node.metadata.get("region").map_or(false, |r| r == region)
            })
            .take(limit)
            .cloned()
            .collect()
    }

    /// Ban a node
    pub async fn ban_node(&self, node_id: &NymIdentity, reason: String) -> NetworkResult<()> {
        warn!("Banning node {}: {}", node_id.to_string(), reason);
        
        // Update node status
        let mut nodes = self.nodes.write().await;
        if let Some(node) = nodes.get_mut(node_id) {
            node.status = NodeStatus::Banned;
            node.metadata.insert("ban_reason".to_string(), reason);
        }
        drop(nodes);
        
        // Add to banned list
        let mut banned = self.banned_nodes.write().await;
        banned.insert(node_id.clone());
        
        // Remove from active nodes
        let mut active = self.active_nodes.write().await;
        active.remove(node_id);
        
        Ok(())
    }

    /// Unban a node
    pub async fn unban_node(&self, node_id: &NymIdentity) -> NetworkResult<()> {
        info!("Unbanning node {}", node_id.to_string());
        
        // Remove from banned list
        let mut banned = self.banned_nodes.write().await;
        banned.remove(node_id);
        drop(banned);
        
        // Update node status
        let mut nodes = self.nodes.write().await;
        if let Some(node) = nodes.get_mut(node_id) {
            node.status = NodeStatus::Unknown; // Will be updated on next health check
            node.metadata.remove("ban_reason");
        }
        
        Ok(())
    }

    /// Perform periodic cleanup
    pub async fn cleanup(&self) -> NetworkResult<()> {
        let mut last_cleanup = self.last_cleanup.write().await;
        let now = Instant::now();
        
        // Only cleanup every hour
        if now.duration_since(*last_cleanup) < Duration::from_secs(3600) {
            return Ok(());
        }
        
        debug!("Performing node registry cleanup");
        
        let cutoff = SystemTime::now() - Duration::from_secs(self.config.inactive_retention);
        let mut nodes_to_remove = Vec::new();
        
        // Find nodes to remove
        {
            let nodes = self.nodes.read().await;
            for (node_id, node) in nodes.iter() {
                if node.last_seen < cutoff && !matches!(node.status, NodeStatus::Active) {
                    nodes_to_remove.push(node_id.clone());
                }
            }
        }
        
        // Remove inactive nodes
        if !nodes_to_remove.is_empty() {
            info!("Removing {} inactive nodes", nodes_to_remove.len());
            
            let mut nodes = self.nodes.write().await;
            let mut active = self.active_nodes.write().await;
            let mut capabilities = self.nodes_by_capability.write().await;
            
            for node_id in nodes_to_remove {
                if let Some(node) = nodes.remove(&node_id) {
                    active.remove(&node_id);
                    
                    // Remove from capability indices
                    if node.capabilities.relay {
                        if let Some(set) = capabilities.get_mut("relay") {
                            set.remove(&node_id);
                        }
                    }
                    if node.capabilities.storage {
                        if let Some(set) = capabilities.get_mut("storage") {
                            set.remove(&node_id);
                        }
                    }
                    if node.capabilities.compute {
                        if let Some(set) = capabilities.get_mut("compute") {
                            set.remove(&node_id);
                        }
                    }
                    if node.capabilities.mixing {
                        if let Some(set) = capabilities.get_mut("mixing") {
                            set.remove(&node_id);
                        }
                    }
                }
            }
        }
        
        *last_cleanup = now;
        Ok(())
    }

    /// Update capability indices for a node
    async fn update_capability_indices(&self, node: &NodeRecord) {
        let mut capabilities = self.nodes_by_capability.write().await;
        
        if node.capabilities.relay {
            capabilities.entry("relay".to_string())
                .or_insert_with(HashSet::new)
                .insert(node.node_id.clone());
        }
        
        if node.capabilities.storage {
            capabilities.entry("storage".to_string())
                .or_insert_with(HashSet::new)
                .insert(node.node_id.clone());
        }
        
        if node.capabilities.compute {
            capabilities.entry("compute".to_string())
                .or_insert_with(HashSet::new)
                .insert(node.node_id.clone());
        }
        
        if node.capabilities.mixing {
            capabilities.entry("mixing".to_string())
                .or_insert_with(HashSet::new)
                .insert(node.node_id.clone());
        }
    }

    /// Get registry statistics
    pub async fn get_stats(&self) -> NodeRegistryStats {
        let nodes = self.nodes.read().await;
        let active = self.active_nodes.read().await;
        let banned = self.banned_nodes.read().await;
        
        let mut status_counts = HashMap::new();
        let mut capability_counts = HashMap::new();
        
        for node in nodes.values() {
            *status_counts.entry(format!("{:?}", node.status)).or_insert(0) += 1;
            
            if node.capabilities.relay {
                *capability_counts.entry("relay".to_string()).or_insert(0) += 1;
            }
            if node.capabilities.storage {
                *capability_counts.entry("storage".to_string()).or_insert(0) += 1;
            }
            if node.capabilities.compute {
                *capability_counts.entry("compute".to_string()).or_insert(0) += 1;
            }
            if node.capabilities.mixing {
                *capability_counts.entry("mixing".to_string()).or_insert(0) += 1;
            }
        }
        
        NodeRegistryStats {
            total_nodes: nodes.len(),
            active_nodes: active.len(),
            banned_nodes: banned.len(),
            status_breakdown: status_counts,
            capability_breakdown: capability_counts,
        }
    }
}

/// Node registry statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeRegistryStats {
    pub total_nodes: usize,
    pub active_nodes: usize,
    pub banned_nodes: usize,
    pub status_breakdown: HashMap<String, usize>,
    pub capability_breakdown: HashMap<String, usize>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr};

    #[tokio::test]
    async fn test_node_registration() {
        let config = NodeRegistryConfig::default();
        let registry = NodeRegistry::new(config);
        
        let node_id = NymIdentity::from_bytes(&[1; 32]).unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let capabilities = NodeCapabilities::default();
        
        let node = NodeRecord::new(node_id.clone(), vec![addr], capabilities);
        
        assert!(registry.register_node(node).await.is_ok());
        
        let retrieved = registry.get_node(&node_id).await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap().node_id, node_id);
    }

    #[tokio::test]
    async fn test_node_capabilities() {
        let config = NodeRegistryConfig::default();
        let registry = NodeRegistry::new(config);
        
        // Register nodes with different capabilities
        for i in 0..4 {
            let node_id = NymIdentity::from_bytes(&[i; 32]).unwrap();
            let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080 + i as u16);
            
            let mut capabilities = NodeCapabilities::default();
            match i {
                0 => capabilities.storage = true,
                1 => capabilities.compute = true,
                2 => capabilities.mixing = true,
                _ => {} // Just relay
            }
            
            let mut node = NodeRecord::new(node_id, vec![addr], capabilities);
            node.status = NodeStatus::Active; // Mark as active for testing
            
            registry.register_node(node).await.unwrap();
        }
        
        // Test finding nodes by capability
        let storage_nodes = registry.find_nodes_by_capability("storage", 10).await;
        assert_eq!(storage_nodes.len(), 1);
        
        let compute_nodes = registry.find_nodes_by_capability("compute", 10).await;
        assert_eq!(compute_nodes.len(), 1);
        
        let relay_nodes = registry.find_nodes_by_capability("relay", 10).await;
        assert_eq!(relay_nodes.len(), 4); // All nodes have relay capability
    }

    #[tokio::test]
    async fn test_node_banning() {
        let config = NodeRegistryConfig::default();
        let registry = NodeRegistry::new(config);
        
        let node_id = NymIdentity::from_bytes(&[1; 32]).unwrap();
        let addr = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)), 8080);
        let capabilities = NodeCapabilities::default();
        
        let mut node = NodeRecord::new(node_id.clone(), vec![addr], capabilities);
        node.status = NodeStatus::Active;
        
        registry.register_node(node).await.unwrap();
        
        // Ban the node
        registry.ban_node(&node_id, "Test ban".to_string()).await.unwrap();
        
        // Check that node is banned
        let retrieved = registry.get_node(&node_id).await.unwrap();
        assert_eq!(retrieved.status, NodeStatus::Banned);
        
        // Check that active nodes doesn't include banned node
        let active_nodes = registry.get_active_nodes().await;
        assert!(!active_nodes.iter().any(|n| n.node_id == node_id));
    }
}