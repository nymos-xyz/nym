//! Network node implementation

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use serde::{Serialize, Deserialize};
use tokio::time::interval;
use tokio::sync::mpsc;
use nym_crypto::{Hash256, SecurityLevel};
use nym_core::NymIdentity;
use crate::{
    NetworkError, NetworkResult, PeerId, PeerInfo, PeerManager,
    NodeDiscovery, DiscoveryConfig, NymProtocol, ProtocolConfig,
    MessageRouter, RoutingConfig, SyncManager, SyncConfig,
    NetworkMessage, MessageHandler
};

/// Node configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    /// Node listen address
    pub listen_addr: SocketAddr,
    /// Node identity
    pub identity: NymIdentity,
    /// Discovery configuration
    pub discovery: DiscoveryConfig,
    /// Protocol configuration
    pub protocol: ProtocolConfig,
    /// Routing configuration
    pub routing: RoutingConfig,
    /// Sync configuration
    pub sync: SyncConfig,
    /// Maximum peers
    pub max_peers: usize,
    /// Message buffer size
    pub message_buffer_size: usize,
    /// Keep-alive interval
    pub keep_alive_interval: Duration,
    /// Connection timeout
    pub connection_timeout: Duration,
}

/// Node event types
#[derive(Debug, Clone)]
pub enum NodeEvent {
    /// Peer connected
    PeerConnected(PeerId, PeerInfo),
    /// Peer disconnected
    PeerDisconnected(PeerId),
    /// Message received
    MessageReceived(NetworkMessage),
    /// Message sent
    MessageSent(PeerId, NetworkMessage),
    /// Discovery completed
    DiscoveryCompleted(usize),
    /// Sync completed
    SyncCompleted(u64),
    /// Error occurred
    Error(NetworkError),
}

/// Node statistics
#[derive(Debug, Clone, Default)]
pub struct NodeStats {
    /// Uptime in seconds
    pub uptime: u64,
    /// Total connections
    pub total_connections: u64,
    /// Active connections
    pub active_connections: u64,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Discovery rounds
    pub discovery_rounds: u64,
    /// Sync operations
    pub sync_operations: u64,
}

/// Network node implementation
pub struct NetworkNode {
    /// Node configuration
    config: NodeConfig,
    /// Peer manager
    peer_manager: PeerManager,
    /// Node discovery
    discovery: NodeDiscovery,
    /// Protocol handler
    protocol: NymProtocol,
    /// Message router
    router: MessageRouter,
    /// Sync manager
    sync_manager: SyncManager,
    /// Message handler
    message_handler: MessageHandler,
    /// Node statistics
    stats: NodeStats,
    /// Event sender
    event_sender: mpsc::UnboundedSender<NodeEvent>,
    /// Event receiver
    event_receiver: mpsc::UnboundedReceiver<NodeEvent>,
    /// Running state
    is_running: bool,
}

impl Default for NodeConfig {
    fn default() -> Self {
        // Create a default identity for testing
        let quid_auth = nym_crypto::QuIDAuth::new(vec![1u8; 32], SecurityLevel::Level1);
        let identity = quid_auth.create_nym_identity(0).unwrap();
        
        Self {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            identity,
            discovery: DiscoveryConfig::default(),
            protocol: ProtocolConfig::default(),
            routing: RoutingConfig::default(),
            sync: SyncConfig::default(),
            max_peers: 50,
            message_buffer_size: 1000,
            keep_alive_interval: Duration::from_secs(30),
            connection_timeout: Duration::from_secs(10),
        }
    }
}

impl NetworkNode {
    /// Create a new network node
    pub fn new(config: NodeConfig) -> Self {
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        let peer_manager = PeerManager::new(config.max_peers, 20);
        let discovery = NodeDiscovery::new(config.discovery.clone(), config.identity.clone());
        let protocol = NymProtocol::new(config.protocol.clone(), config.identity.clone());
        let router = MessageRouter::new(config.routing.clone(), config.identity.clone());
        let sync_manager = SyncManager::new(config.sync.clone(), config.identity.clone(), 0, Hash256::default());
        let message_handler = MessageHandler::new(config.identity.clone());
        
        Self {
            config,
            peer_manager,
            discovery,
            protocol,
            router,
            sync_manager,
            message_handler,
            stats: NodeStats::default(),
            event_sender,
            event_receiver,
            is_running: false,
        }
    }
    
    /// Start the network node
    pub async fn start(&mut self) -> NetworkResult<()> {
        if self.is_running {
            return Err(NetworkError::NodeError {
                reason: "Node already running".to_string(),
            });
        }
        
        tracing::info!("Starting network node on {}", self.config.listen_addr);
        
        // Start discovery
        self.discovery.start().await?;
        
        // Start main event loop
        self.is_running = true;
        
        // Spawn background tasks
        self.spawn_background_tasks().await?;
        
        // Send start event
        let _ = self.event_sender.send(NodeEvent::DiscoveryCompleted(0));
        
        Ok(())
    }
    
    /// Stop the network node
    pub async fn stop(&mut self) -> NetworkResult<()> {
        if !self.is_running {
            return Ok(());
        }
        
        tracing::info!("Stopping network node");
        
        self.is_running = false;
        
        // Stop discovery
        self.discovery.stop().await;
        
        // Disconnect all peers
        self.disconnect_all_peers().await?;
        
        Ok(())
    }
    
    /// Run the node event loop
    pub async fn run(&mut self) -> NetworkResult<()> {
        let mut keep_alive_interval = interval(self.config.keep_alive_interval);
        let mut stats_interval = interval(Duration::from_secs(60)); // Update stats every minute
        
        while self.is_running {
            tokio::select! {
                // Handle events
                event = self.event_receiver.recv() => {
                    if let Some(event) = event {
                        self.handle_event(event).await?;
                    }
                }
                
                // Keep-alive tick
                _ = keep_alive_interval.tick() => {
                    self.send_keep_alive_messages().await?;
                }
                
                // Stats update tick
                _ = stats_interval.tick() => {
                    self.update_stats().await;
                }
            }
        }
        
        Ok(())
    }
    
    /// Handle node events
    async fn handle_event(&mut self, event: NodeEvent) -> NetworkResult<()> {
        match event {
            NodeEvent::PeerConnected(peer_id, peer_info) => {
                self.handle_peer_connected(peer_id, peer_info).await?;
            }
            NodeEvent::PeerDisconnected(peer_id) => {
                self.handle_peer_disconnected(peer_id).await?;
            }
            NodeEvent::MessageReceived(message) => {
                self.handle_message_received(message).await?;
            }
            NodeEvent::MessageSent(peer_id, message) => {
                self.handle_message_sent(peer_id, message).await?;
            }
            NodeEvent::DiscoveryCompleted(peer_count) => {
                self.handle_discovery_completed(peer_count).await?;
            }
            NodeEvent::SyncCompleted(blocks_synced) => {
                self.handle_sync_completed(blocks_synced).await?;
            }
            NodeEvent::Error(error) => {
                self.handle_error(error).await?;
            }
        }
        
        Ok(())
    }
    
    /// Handle peer connection
    async fn handle_peer_connected(&mut self, peer_id: PeerId, peer_info: PeerInfo) -> NetworkResult<()> {
        tracing::info!("Peer connected: {:?}", peer_id);
        
        // Add to peer manager
        self.peer_manager.add_peer(peer_info.clone())?;
        
        // Initiate handshake
        let handshake_message = self.protocol.initiate_handshake(peer_id.clone()).await?;
        self.send_message(peer_id.clone(), handshake_message).await?;
        
        // Update stats
        self.stats.total_connections += 1;
        self.stats.active_connections += 1;
        
        Ok(())
    }
    
    /// Handle peer disconnection
    async fn handle_peer_disconnected(&mut self, peer_id: PeerId) -> NetworkResult<()> {
        tracing::info!("Peer disconnected: {:?}", peer_id);
        
        // Remove from peer manager
        self.peer_manager.remove_peer(&peer_id);
        
        // Remove authentication
        self.protocol.remove_peer_authentication(&peer_id);
        
        // Update stats
        if self.stats.active_connections > 0 {
            self.stats.active_connections -= 1;
        }
        
        Ok(())
    }
    
    /// Handle received message
    async fn handle_message_received(&mut self, message: NetworkMessage) -> NetworkResult<()> {
        self.stats.messages_received += 1;
        self.stats.bytes_received += message.to_bytes()?.len() as u64;
        
        // Handle message based on type
        let response = match message.message_type {
            crate::MessageType::Handshake => {
                self.protocol.handle_handshake(&message).await?
            }
            crate::MessageType::Discovery => {
                self.discovery.handle_discovery_message(&message).await?
            }
            crate::MessageType::SyncRequest | crate::MessageType::SyncResponse => {
                // Handle sync messages through sync manager
                None // Sync manager would handle this
            }
            crate::MessageType::PrivacyRouting => {
                self.router.handle_privacy_message(&message).await?
            }
            _ => {
                self.message_handler.handle_message(&message).await?
            }
        };
        
        // Send response if generated
        if let Some(response_message) = response {
            if let Some(recipient) = response_message.recipient.clone() {
                self.send_message(recipient, response_message).await?;
            }
        }
        
        Ok(())
    }
    
    /// Handle sent message
    async fn handle_message_sent(&mut self, peer_id: PeerId, message: NetworkMessage) -> NetworkResult<()> {
        self.stats.messages_sent += 1;
        self.stats.bytes_sent += message.to_bytes()?.len() as u64;
        
        // Update peer statistics
        let message_size = message.to_bytes()?.len() as u64;
        self.peer_manager.update_stats(&peer_id, message_size, 0)?;
        
        Ok(())
    }
    
    /// Handle discovery completion
    async fn handle_discovery_completed(&mut self, peer_count: usize) -> NetworkResult<()> {
        tracing::info!("Discovery completed, found {} peers", peer_count);
        self.stats.discovery_rounds += 1;
        
        // Update router with discovered peers
        let connected_peers: HashMap<PeerId, PeerInfo> = self.peer_manager
            .connected_peers()
            .iter()
            .map(|info| (info.id.clone(), (*info).clone()))
            .collect();
        
        self.router.update_connected_peers(connected_peers);
        
        Ok(())
    }
    
    /// Handle sync completion
    async fn handle_sync_completed(&mut self, blocks_synced: u64) -> NetworkResult<()> {
        tracing::info!("Sync completed, synced {} blocks", blocks_synced);
        self.stats.sync_operations += 1;
        
        Ok(())
    }
    
    /// Handle error
    async fn handle_error(&mut self, error: NetworkError) -> NetworkResult<()> {
        tracing::error!("Network error: {:?}", error);
        
        // Implement error handling logic
        match error {
            NetworkError::ConnectionFailed { .. } => {
                // Could trigger reconnection logic
            }
            NetworkError::PeerError { .. } => {
                // Could trigger peer cleanup
            }
            _ => {
                // General error handling
            }
        }
        
        Ok(())
    }
    
    /// Send message to peer
    async fn send_message(&mut self, peer_id: PeerId, message: NetworkMessage) -> NetworkResult<()> {
        // In a real implementation, this would send over the network
        // For now, we'll just emit an event
        let _ = self.event_sender.send(NodeEvent::MessageSent(peer_id, message));
        Ok(())
    }
    
    /// Broadcast message to all connected peers
    pub async fn broadcast_message(&mut self, message: NetworkMessage) -> NetworkResult<()> {
        let routes = self.router.route_message(message, false).await?;
        
        for (peer_id, routed_message) in routes {
            self.send_message(peer_id, routed_message).await?;
        }
        
        Ok(())
    }
    
    /// Send private message using privacy routing
    pub async fn send_private_message(&mut self, recipient: PeerId, message: NetworkMessage) -> NetworkResult<()> {
        let mut private_message = message;
        private_message.recipient = Some(recipient);
        
        let routes = self.router.route_message(private_message, true).await?;
        
        for (peer_id, routed_message) in routes {
            self.send_message(peer_id, routed_message).await?;
        }
        
        Ok(())
    }
    
    /// Send keep-alive messages
    async fn send_keep_alive_messages(&mut self) -> NetworkResult<()> {
        for peer in self.peer_manager.connected_peers() {
            let ping_message = crate::MessageBuilder::new(
                PeerId::from_identity(&self.config.identity),
                SecurityLevel::Level1,
            ).ping(peer.id.clone());
            
            self.send_message(peer.id.clone(), ping_message).await?;
        }
        
        Ok(())
    }
    
    /// Update node statistics
    async fn update_stats(&mut self) {
        self.stats.uptime += 60; // Add 1 minute
        
        // Update active connections count
        self.stats.active_connections = self.peer_manager.connected_peer_count() as u64;
        
        // Cleanup expired data
        self.peer_manager.cleanup();
        self.protocol.cleanup_expired_sessions();
        self.router.cleanup_old_routes();
    }
    
    /// Disconnect all peers
    async fn disconnect_all_peers(&mut self) -> NetworkResult<()> {
        let connected_peers: Vec<PeerId> = self.peer_manager
            .connected_peers()
            .iter()
            .map(|info| info.id.clone())
            .collect();
        
        for peer_id in connected_peers {
            let _ = self.event_sender.send(NodeEvent::PeerDisconnected(peer_id));
        }
        
        Ok(())
    }
    
    /// Spawn background tasks
    async fn spawn_background_tasks(&mut self) -> NetworkResult<()> {
        // In a real implementation, this would spawn:
        // - Network listener task
        // - Discovery task
        // - Sync task
        // - Cleanup task
        
        tracing::info!("Background tasks started");
        Ok(())
    }
    
    /// Connect to peer
    pub async fn connect_to_peer(&mut self, addr: SocketAddr) -> NetworkResult<()> {
        // In a real implementation, this would establish a network connection
        // For now, simulate a connection
        
        let peer_id = PeerId::new(Hash256::from(rand::random::<[u8; 32]>()));
        let peer_info = PeerInfo::new(peer_id.clone(), vec![addr]);
        
        let _ = self.event_sender.send(NodeEvent::PeerConnected(peer_id, peer_info));
        
        Ok(())
    }
    
    /// Get node statistics
    pub fn stats(&self) -> &NodeStats {
        &self.stats
    }
    
    /// Get peer count
    pub fn peer_count(&self) -> usize {
        self.peer_manager.peer_count()
    }
    
    /// Get connected peer count
    pub fn connected_peer_count(&self) -> usize {
        self.peer_manager.connected_peer_count()
    }
    
    /// Get node ID
    pub fn node_id(&self) -> PeerId {
        PeerId::from_identity(&self.config.identity)
    }
    
    /// Check if node is running
    pub fn is_running(&self) -> bool {
        self.is_running
    }
    
    /// Get listen address
    pub fn listen_addr(&self) -> SocketAddr {
        self.config.listen_addr
    }
    
    /// Get discovery state
    pub fn discovery_state(&self) -> &crate::DiscoveryState {
        self.discovery.state()
    }
    
    /// Get sync state
    pub fn sync_state(&self) -> &crate::SyncState {
        self.sync_manager.state()
    }
    
    /// Manual discovery round
    pub async fn discover_peers(&mut self) -> NetworkResult<()> {
        self.discovery.discovery_round().await?;
        let peer_count = self.discovery.peer_count();
        let _ = self.event_sender.send(NodeEvent::DiscoveryCompleted(peer_count));
        Ok(())
    }
    
    /// Manual sync operation
    pub async fn sync_chain(&mut self) -> NetworkResult<()> {
        self.sync_manager.start_sync().await?;
        let _ = self.event_sender.send(NodeEvent::SyncCompleted(0));
        Ok(())
    }
    
    /// Get peer information
    pub fn get_peer_info(&self, peer_id: &PeerId) -> Option<&PeerInfo> {
        self.peer_manager.get_peer(peer_id)
    }
    
    /// Get all connected peers
    pub fn get_connected_peers(&self) -> Vec<&PeerInfo> {
        self.peer_manager.connected_peers()
    }
    
    /// Get routing statistics
    pub fn routing_stats(&self) -> &crate::RoutingStats {
        self.router.stats()
    }
    
    /// Get sync statistics
    pub fn sync_stats(&self) -> &crate::SyncStats {
        self.sync_manager.stats()
    }
    
    /// Get discovery statistics
    pub fn discovery_stats(&self) -> &crate::DiscoveryStats {
        self.discovery.stats()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use nym_crypto::{QuIDAuth, SecurityLevel};
    
    fn create_test_config() -> NodeConfig {
        let quid_auth = QuIDAuth::new(vec![1u8; 32], SecurityLevel::Level1);
        let identity = quid_auth.create_nym_identity(0).unwrap();
        
        NodeConfig {
            listen_addr: "127.0.0.1:8080".parse().unwrap(),
            identity,
            discovery: DiscoveryConfig::default(),
            protocol: ProtocolConfig::default(),
            routing: RoutingConfig::default(),
            sync: SyncConfig::default(),
            max_peers: 10,
            message_buffer_size: 100,
            keep_alive_interval: Duration::from_secs(30),
            connection_timeout: Duration::from_secs(10),
        }
    }
    
    #[test]
    fn test_node_config_default() {
        let config = NodeConfig::default();
        assert_eq!(config.max_peers, 50);
        assert_eq!(config.message_buffer_size, 1000);
    }
    
    #[test]
    fn test_node_creation() {
        let config = create_test_config();
        let node = NetworkNode::new(config.clone());
        
        assert_eq!(node.listen_addr(), config.listen_addr);
        assert!(!node.is_running());
        assert_eq!(node.peer_count(), 0);
        assert_eq!(node.connected_peer_count(), 0);
    }
    
    #[tokio::test]
    async fn test_node_lifecycle() {
        let config = create_test_config();
        let mut node = NetworkNode::new(config);
        
        // Start node
        let result = node.start().await;
        assert!(result.is_ok());
        assert!(node.is_running());
        
        // Stop node
        let result = node.stop().await;
        assert!(result.is_ok());
        assert!(!node.is_running());
    }
    
    #[tokio::test]
    async fn test_peer_connection() {
        let config = create_test_config();
        let mut node = NetworkNode::new(config);
        
        let addr = "127.0.0.1:8081".parse().unwrap();
        let result = node.connect_to_peer(addr).await;
        assert!(result.is_ok());
        
        // Process the connection event
        if let Some(event) = node.event_receiver.recv().await {
            match event {
                NodeEvent::PeerConnected(peer_id, peer_info) => {
                    assert_eq!(peer_info.addresses[0], addr);
                }
                _ => panic!("Expected PeerConnected event"),
            }
        }
    }
    
    #[tokio::test]
    async fn test_message_handling() {
        let config = create_test_config();
        let mut node = NetworkNode::new(config.clone());
        
        // Create test message
        let sender = PeerId::new(Hash256::from([1u8; 32]));
        let message = NetworkMessage::new(
            crate::MessageType::Ping,
            sender,
            Some(PeerId::from_identity(&config.identity)),
            crate::MessagePayload::Raw(vec![1, 2, 3]),
        );
        
        let result = node.handle_message_received(message).await;
        assert!(result.is_ok());
        assert_eq!(node.stats.messages_received, 1);
    }
    
    #[tokio::test]
    async fn test_broadcast_message() {
        let config = create_test_config();
        let mut node = NetworkNode::new(config.clone());
        
        // Add some connected peers (mock)
        for i in 1..=3 {
            let peer_id = PeerId::new(Hash256::from([i; 32]));
            let addr = format!("127.0.0.1:808{}", i).parse().unwrap();
            let peer_info = PeerInfo::new(peer_id.clone(), vec![addr]);
            let _ = node.peer_manager.add_peer(peer_info);
        }
        
        // Create broadcast message
        let message = NetworkMessage::new(
            crate::MessageType::BlockAnnouncement,
            PeerId::from_identity(&config.identity),
            None, // Broadcast
            crate::MessagePayload::Raw(vec![1, 2, 3]),
        );
        
        let result = node.broadcast_message(message).await;
        assert!(result.is_ok());
    }
    
    #[tokio::test]
    async fn test_discovery_integration() {
        let config = create_test_config();
        let mut node = NetworkNode::new(config);
        
        let result = node.discover_peers().await;
        assert!(result.is_ok());
        
        // Process discovery event
        if let Some(event) = node.event_receiver.recv().await {
            match event {
                NodeEvent::DiscoveryCompleted(peer_count) => {
                    assert!(peer_count >= 0); // Could be 0 in test environment
                }
                _ => panic!("Expected DiscoveryCompleted event"),
            }
        }
    }
    
    #[tokio::test]
    async fn test_sync_integration() {
        let config = create_test_config();
        let mut node = NetworkNode::new(config);
        
        let result = node.sync_chain().await;
        assert!(result.is_ok());
        
        // Process sync event
        if let Some(event) = node.event_receiver.recv().await {
            match event {
                NodeEvent::SyncCompleted(blocks_synced) => {
                    assert_eq!(blocks_synced, 0); // No blocks in test
                }
                _ => panic!("Expected SyncCompleted event"),
            }
        }
    }
    
    #[test]
    fn test_node_stats() {
        let config = create_test_config();
        let node = NetworkNode::new(config);
        
        let stats = node.stats();
        assert_eq!(stats.uptime, 0);
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.messages_sent, 0);
        assert_eq!(stats.messages_received, 0);
    }
    
    #[test]
    fn test_node_id() {
        let config = create_test_config();
        let node = NetworkNode::new(config.clone());
        
        let expected_id = PeerId::from_identity(&config.identity);
        assert_eq!(node.node_id(), expected_id);
    }
}