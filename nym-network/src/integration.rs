//! Integration module for P2P networking with existing Nym node
//! 
//! This module demonstrates how the new P2P networking layer integrates
//! with the existing NetworkNode implementation for Week 15-16 of the roadmap.

use std::net::SocketAddr;
use std::time::Duration;
use tokio::sync::mpsc;
use tracing::{info, warn, error};

use nym_core::NymIdentity;
use crate::{
    NetworkNode, NodeConfig, NetworkMessage, MessageType, NetworkResult,
    SimpleP2PNetwork, SimpleP2PConfig, SimpleP2PEvent, PeerId
};

/// Enhanced node configuration with P2P networking
#[derive(Debug, Clone)]
pub struct EnhancedNodeConfig {
    /// Original node configuration
    pub node_config: NodeConfig,
    /// P2P network configuration
    pub p2p_config: SimpleP2PConfig,
    /// Enable P2P networking
    pub enable_p2p: bool,
}

/// Enhanced network node with P2P capabilities
pub struct EnhancedNetworkNode {
    /// Original network node
    network_node: NetworkNode,
    /// P2P network
    p2p_network: Option<SimpleP2PNetwork>,
    /// P2P event receiver
    p2p_events: Option<mpsc::UnboundedReceiver<SimpleP2PEvent>>,
    /// Configuration
    config: EnhancedNodeConfig,
}

impl Default for EnhancedNodeConfig {
    fn default() -> Self {
        Self {
            node_config: NodeConfig::default(),
            p2p_config: SimpleP2PConfig::default(),
            enable_p2p: true,
        }
    }
}

impl EnhancedNetworkNode {
    /// Create a new enhanced network node
    pub fn new(config: EnhancedNodeConfig) -> Self {
        let network_node = NetworkNode::new(config.node_config.clone());
        
        let (p2p_network, p2p_events) = if config.enable_p2p {
            let (net, events) = SimpleP2PNetwork::new(
                config.p2p_config.clone(),
                config.node_config.identity.clone(),
            );
            (Some(net), Some(events))
        } else {
            (None, None)
        };
        
        Self {
            network_node,
            p2p_network,
            p2p_events,
            config,
        }
    }
    
    /// Start the enhanced network node
    pub async fn start(&mut self) -> NetworkResult<()> {
        info!("Starting enhanced network node with P2P capabilities");
        
        // Start original network node
        self.network_node.start().await?;
        
        // Start P2P network if enabled
        if let Some(p2p_network) = &self.p2p_network {
            p2p_network.start().await?;
            info!("P2P network started successfully");
        }
        
        Ok(())
    }
    
    /// Run the enhanced network node
    pub async fn run(&mut self) -> NetworkResult<()> {
        info!("Running enhanced network node event loop");
        
        // If P2P is disabled, just run the original node
        if self.p2p_network.is_none() {
            return self.network_node.run().await;
        }
        
        // Run both the original node and P2P network
        let p2p_events = self.p2p_events.take().unwrap();
        self.run_with_p2p(p2p_events).await
    }
    
    /// Run with P2P event handling
    async fn run_with_p2p(
        &mut self,
        mut p2p_events: mpsc::UnboundedReceiver<SimpleP2PEvent>,
    ) -> NetworkResult<()> {
        // This would be integrated with the original node's event loop
        // For now, we'll demonstrate P2P event handling
        
        loop {
            tokio::select! {
                // Handle P2P events
                event = p2p_events.recv() => {
                    if let Some(event) = event {
                        self.handle_p2p_event(event).await?;
                    }
                }
                
                // Handle original node events (simplified)
                _ = tokio::time::sleep(Duration::from_millis(100)) => {
                    // In a real implementation, this would be the original node's event loop
                    // For now, just continue
                }
            }
        }
    }
    
    /// Handle P2P events
    async fn handle_p2p_event(&mut self, event: SimpleP2PEvent) -> NetworkResult<()> {
        match event {
            SimpleP2PEvent::PeerConnected { peer_id, addr } => {
                self.handle_peer_connected(peer_id, addr).await?;
            }
            SimpleP2PEvent::PeerDisconnected { peer_id } => {
                self.handle_peer_disconnected(peer_id).await?;
            }
            SimpleP2PEvent::MessageReceived { from, message } => {
                self.handle_p2p_message_received(from, message).await?;
            }
            SimpleP2PEvent::ConnectionError { addr, error } => {
                self.handle_connection_error(addr, error).await?;
            }
        }
        
        Ok(())
    }
    
    /// Handle peer connection
    async fn handle_peer_connected(&mut self, peer_id: PeerId, addr: SocketAddr) -> NetworkResult<()> {
        info!("P2P peer connected: {} at {}", peer_id, addr);
        
        // Integration: Notify the original network node about the new peer
        // This could involve updating routing tables, peer lists, etc.
        
        // Example: Send a discovery message to the new peer
        if let Some(p2p_network) = &self.p2p_network {
            let discovery_message = NetworkMessage::new(
                MessageType::Discovery,
                self.local_peer_id(),
                Some(peer_id.clone()),
                crate::MessagePayload::Raw(b"hello".to_vec()),
            );
            
            let _ = p2p_network.send_to_peer(&peer_id, discovery_message).await;
        }
        
        Ok(())
    }
    
    /// Handle peer disconnection
    async fn handle_peer_disconnected(&mut self, peer_id: PeerId) -> NetworkResult<()> {
        info!("P2P peer disconnected: {}", peer_id);
        
        // Integration: Update the original network node about peer disconnection
        // This could involve removing from routing tables, peer lists, etc.
        
        Ok(())
    }
    
    /// Handle received P2P message
    async fn handle_p2p_message_received(
        &mut self,
        from: PeerId,
        message: NetworkMessage,
    ) -> NetworkResult<()> {
        info!("Received P2P message from {}: {:?}", from, message.message_type);
        
        // Integration: Forward message to appropriate handler in the original node
        match message.message_type {
            MessageType::Discovery => {
                // Handle discovery message
                self.handle_discovery_message(from, message).await?;
            }
            MessageType::BlockAnnouncement => {
                // Handle block announcement
                self.handle_block_announcement(from, message).await?;
            }
            MessageType::TransactionAnnouncement => {
                // Handle transaction announcement
                self.handle_transaction_announcement(from, message).await?;
            }
            MessageType::Ping => {
                // Handle ping
                self.handle_ping(from, message).await?;
            }
            _ => {
                // Forward to original network node for handling
                warn!("Unhandled P2P message type: {:?}", message.message_type);
            }
        }
        
        Ok(())
    }
    
    /// Handle connection error
    async fn handle_connection_error(&mut self, addr: SocketAddr, error: String) -> NetworkResult<()> {
        warn!("P2P connection error to {}: {}", addr, error);
        
        // Could implement retry logic, peer blacklisting, etc.
        
        Ok(())
    }
    
    /// Handle discovery message
    async fn handle_discovery_message(&mut self, from: PeerId, _message: NetworkMessage) -> NetworkResult<()> {
        info!("Handling discovery message from: {}", from);
        
        // Example: Send back our peer information
        if let Some(p2p_network) = &self.p2p_network {
            let response = NetworkMessage::new(
                MessageType::PeerExchange,
                self.local_peer_id(),
                Some(from),
                crate::MessagePayload::Raw(b"peer_info".to_vec()),
            );
            
            let _ = p2p_network.send_to_peer(&from, response).await;
        }
        
        Ok(())
    }
    
    /// Handle block announcement
    async fn handle_block_announcement(&mut self, from: PeerId, message: NetworkMessage) -> NetworkResult<()> {
        info!("Handling block announcement from: {}", from);
        
        // Integration: Forward to the original node's block handling logic
        // This would typically involve:
        // 1. Validating the block announcement
        // 2. Requesting the full block if needed
        // 3. Adding to block processing queue
        
        Ok(())
    }
    
    /// Handle transaction announcement
    async fn handle_transaction_announcement(&mut self, from: PeerId, message: NetworkMessage) -> NetworkResult<()> {
        info!("Handling transaction announcement from: {}", from);
        
        // Integration: Forward to the original node's transaction handling logic
        // This would typically involve:
        // 1. Validating the transaction announcement
        // 2. Requesting the full transaction if needed
        // 3. Adding to transaction pool
        
        Ok(())
    }
    
    /// Handle ping message
    async fn handle_ping(&mut self, from: PeerId, _message: NetworkMessage) -> NetworkResult<()> {
        // Send pong response
        if let Some(p2p_network) = &self.p2p_network {
            let pong = NetworkMessage::new(
                MessageType::Pong,
                self.local_peer_id(),
                Some(from),
                crate::MessagePayload::Raw(b"pong".to_vec()),
            );
            
            let _ = p2p_network.send_to_peer(&from, pong).await;
        }
        
        Ok(())
    }
    
    /// Broadcast message through P2P network
    pub async fn broadcast_p2p_message(&self, message: NetworkMessage) -> NetworkResult<()> {
        if let Some(p2p_network) = &self.p2p_network {
            p2p_network.broadcast_message(message).await?;
        }
        
        Ok(())
    }
    
    /// Connect to a new peer through P2P
    pub async fn connect_to_p2p_peer(&self, addr: SocketAddr) {
        if let Some(p2p_network) = &self.p2p_network {
            p2p_network.connect_to_peer(addr).await;
        }
    }
    
    /// Get P2P peer count
    pub async fn p2p_peer_count(&self) -> usize {
        if let Some(p2p_network) = &self.p2p_network {
            p2p_network.peer_count().await
        } else {
            0
        }
    }
    
    /// Get local peer ID
    pub fn local_peer_id(&self) -> PeerId {
        self.network_node.node_id()
    }
    
    /// Check if P2P is enabled
    pub fn is_p2p_enabled(&self) -> bool {
        self.p2p_network.is_some()
    }
    
    /// Get P2P network statistics
    pub async fn p2p_stats(&self) -> Option<crate::p2p_simple::NetworkStats> {
        if let Some(p2p_network) = &self.p2p_network {
            Some(p2p_network.stats().await)
        } else {
            None
        }
    }
    
    /// Stop the enhanced network node
    pub async fn stop(&mut self) -> NetworkResult<()> {
        info!("Stopping enhanced network node");
        
        // Stop original network node
        self.network_node.stop().await?;
        
        // P2P network will be dropped automatically
        
        Ok(())
    }
    
    /// Get reference to original network node
    pub fn network_node(&self) -> &NetworkNode {
        &self.network_node
    }
    
    /// Get mutable reference to original network node
    pub fn network_node_mut(&mut self) -> &mut NetworkNode {
        &mut self.network_node
    }
}

/// Helper function to create a basic enhanced node configuration
pub fn create_enhanced_config(
    identity: NymIdentity,
    listen_addr: SocketAddr,
    known_peers: Vec<SocketAddr>,
) -> EnhancedNodeConfig {
    let mut node_config = NodeConfig::default();
    node_config.identity = identity;
    node_config.listen_addr = listen_addr;
    
    let p2p_config = SimpleP2PConfig {
        listen_addr,
        known_peers,
        max_connections: 50,
        connection_timeout: Duration::from_secs(30),
        heartbeat_interval: Duration::from_secs(30),
        message_buffer_size: 1000,
    };
    
    EnhancedNodeConfig {
        node_config,
        p2p_config,
        enable_p2p: true,
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
    fn test_enhanced_config_creation() {
        let identity = create_test_identity();
        let listen_addr = "127.0.0.1:8080".parse().unwrap();
        let known_peers = vec!["127.0.0.1:8081".parse().unwrap()];
        
        let config = create_enhanced_config(identity.clone(), listen_addr, known_peers.clone());
        
        assert_eq!(config.node_config.identity, identity);
        assert_eq!(config.node_config.listen_addr, listen_addr);
        assert_eq!(config.p2p_config.listen_addr, listen_addr);
        assert_eq!(config.p2p_config.known_peers, known_peers);
        assert!(config.enable_p2p);
    }
    
    #[test]
    fn test_enhanced_node_creation() {
        let config = EnhancedNodeConfig::default();
        let node = EnhancedNetworkNode::new(config);
        
        assert!(node.is_p2p_enabled());
    }
    
    #[test]
    fn test_enhanced_node_without_p2p() {
        let mut config = EnhancedNodeConfig::default();
        config.enable_p2p = false;
        
        let node = EnhancedNetworkNode::new(config);
        
        assert!(!node.is_p2p_enabled());
    }
    
    #[tokio::test]
    async fn test_enhanced_node_lifecycle() {
        let config = EnhancedNodeConfig::default();
        let mut node = EnhancedNetworkNode::new(config);
        
        // Start node
        let result = node.start().await;
        assert!(result.is_ok());
        
        // Check P2P peer count
        let peer_count = node.p2p_peer_count().await;
        assert_eq!(peer_count, 0);
        
        // Stop node
        let result = node.stop().await;
        assert!(result.is_ok());
    }
}