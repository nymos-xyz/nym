//! Simplified P2P networking implementation for Nym
//! 
//! This provides a basic P2P network implementation for Week 15-16 of the roadmap:
//! - Basic peer discovery and connection management
//! - Message broadcasting and routing
//! - Integration with QuID identity system
//! - Foundation for encrypted communication

use std::collections::HashMap;
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener as TokioTcpListener, TcpStream as TokioTcpStream};
use tokio::sync::{mpsc, RwLock};
use tokio::time::{interval, timeout};
use tracing::{debug, error, info, warn};

use nym_core::NymIdentity;
use nym_crypto::{Hash256, SecurityLevel};
use crate::{NetworkError, NetworkResult, PeerId, NetworkMessage, MessageType};

/// P2P network configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SimpleP2PConfig {
    /// Listen address
    pub listen_addr: SocketAddr,
    /// Known peer addresses
    pub known_peers: Vec<SocketAddr>,
    /// Maximum connections
    pub max_connections: usize,
    /// Connection timeout
    pub connection_timeout: Duration,
    /// Heartbeat interval
    pub heartbeat_interval: Duration,
    /// Message buffer size
    pub message_buffer_size: usize,
}

/// P2P network events
#[derive(Debug, Clone)]
pub enum SimpleP2PEvent {
    /// Peer connected
    PeerConnected {
        peer_id: PeerId,
        addr: SocketAddr,
    },
    /// Peer disconnected
    PeerDisconnected {
        peer_id: PeerId,
    },
    /// Message received
    MessageReceived {
        from: PeerId,
        message: NetworkMessage,
    },
    /// Connection error
    ConnectionError {
        addr: SocketAddr,
        error: String,
    },
}

/// Connected peer information
#[derive(Debug, Clone)]
pub struct ConnectedPeer {
    /// Peer ID
    pub peer_id: PeerId,
    /// Network address
    pub addr: SocketAddr,
    /// Connection handle
    pub sender: mpsc::UnboundedSender<NetworkMessage>,
    /// Last activity timestamp
    pub last_activity: SystemTime,
    /// Peer identity
    pub identity: Option<NymIdentity>,
}

/// Simple P2P network implementation
pub struct SimpleP2PNetwork {
    /// Network configuration
    config: SimpleP2PConfig,
    /// Local identity
    identity: NymIdentity,
    /// Local peer ID
    local_peer_id: PeerId,
    /// Connected peers
    peers: Arc<RwLock<HashMap<PeerId, ConnectedPeer>>>,
    /// Event sender
    event_sender: mpsc::UnboundedSender<SimpleP2PEvent>,
    /// Network statistics
    stats: Arc<RwLock<NetworkStats>>,
}

/// Network statistics
#[derive(Debug, Default)]
pub struct NetworkStats {
    /// Total connections established
    pub total_connections: u64,
    /// Current active connections
    pub active_connections: u64,
    /// Messages sent
    pub messages_sent: u64,
    /// Messages received
    pub messages_received: u64,
    /// Bytes sent
    pub bytes_sent: u64,
    /// Bytes received
    pub bytes_received: u64,
    /// Connection errors
    pub connection_errors: u64,
}

impl Default for SimpleP2PConfig {
    fn default() -> Self {
        Self {
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            known_peers: Vec::new(),
            max_connections: 50,
            connection_timeout: Duration::from_secs(30),
            heartbeat_interval: Duration::from_secs(30),
            message_buffer_size: 1000,
        }
    }
}

impl SimpleP2PNetwork {
    /// Create a new simple P2P network
    pub fn new(
        config: SimpleP2PConfig,
        identity: NymIdentity,
    ) -> (Self, mpsc::UnboundedReceiver<SimpleP2PEvent>) {
        let local_peer_id = PeerId::from_identity(&identity);
        let (event_sender, event_receiver) = mpsc::unbounded_channel();
        
        let network = Self {
            config,
            identity,
            local_peer_id,
            peers: Arc::new(RwLock::new(HashMap::new())),
            event_sender,
            stats: Arc::new(RwLock::new(NetworkStats::default())),
        };
        
        (network, event_receiver)
    }
    
    /// Start the P2P network
    pub async fn start(&self) -> NetworkResult<()> {
        info!("Starting simple P2P network on {}", self.config.listen_addr);
        
        // Start listening for incoming connections
        let listener = TokioTcpListener::bind(self.config.listen_addr).await
            .map_err(|e| NetworkError::ConnectionFailed {
                reason: format!("Failed to bind to {}: {}", self.config.listen_addr, e),
            })?;
        
        let actual_addr = listener.local_addr()
            .map_err(|e| NetworkError::ConnectionFailed {
                reason: format!("Failed to get local address: {}", e),
            })?;
        
        info!("P2P network listening on: {}", actual_addr);
        
        // Start accepting connections
        let peers = self.peers.clone();
        let event_sender = self.event_sender.clone();
        let identity = self.identity.clone();
        let stats = self.stats.clone();
        
        tokio::spawn(async move {
            Self::accept_connections(listener, peers, event_sender, identity, stats).await;
        });
        
        // Connect to known peers
        self.connect_to_known_peers().await;
        
        // Start heartbeat task
        self.start_heartbeat().await;
        
        Ok(())
    }
    
    /// Accept incoming connections
    async fn accept_connections(
        listener: TokioTcpListener,
        peers: Arc<RwLock<HashMap<PeerId, ConnectedPeer>>>,
        event_sender: mpsc::UnboundedSender<SimpleP2PEvent>,
        identity: NymIdentity,
        stats: Arc<RwLock<NetworkStats>>,
    ) {
        loop {
            match listener.accept().await {
                Ok((stream, addr)) => {
                    info!("Accepted connection from: {}", addr);
                    
                    let peers = peers.clone();
                    let event_sender = event_sender.clone();
                    let identity = identity.clone();
                    let stats = stats.clone();
                    
                    tokio::spawn(async move {
                        if let Err(e) = Self::handle_connection(
                            stream, addr, peers, event_sender, identity, stats
                        ).await {
                            error!("Connection handling error for {}: {}", addr, e);
                        }
                    });
                }
                Err(e) => {
                    error!("Failed to accept connection: {}", e);
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
            }
        }
    }
    
    /// Handle a connection (incoming or outgoing)
    async fn handle_connection(
        mut stream: TokioTcpStream,
        addr: SocketAddr,
        peers: Arc<RwLock<HashMap<PeerId, ConnectedPeer>>>,
        event_sender: mpsc::UnboundedSender<SimpleP2PEvent>,
        local_identity: NymIdentity,
        stats: Arc<RwLock<NetworkStats>>,
    ) -> NetworkResult<()> {
        // Perform handshake
        let peer_identity = Self::perform_handshake(&mut stream, &local_identity).await?;
        let peer_id = PeerId::from_identity(&peer_identity);
        
        info!("Handshake completed with peer: {} at {}", peer_id, addr);
        
        // Create message channel for this peer
        let (tx, mut rx) = mpsc::unbounded_channel();
        
        // Add to connected peers
        let connected_peer = ConnectedPeer {
            peer_id: peer_id.clone(),
            addr,
            sender: tx,
            last_activity: SystemTime::now(),
            identity: Some(peer_identity),
        };
        
        {
            let mut peers_lock = peers.write().await;
            peers_lock.insert(peer_id.clone(), connected_peer);
            
            let mut stats_lock = stats.write().await;
            stats_lock.total_connections += 1;
            stats_lock.active_connections += 1;
        }
        
        // Send connection event
        let _ = event_sender.send(SimpleP2PEvent::PeerConnected {
            peer_id: peer_id.clone(),
            addr,
        });
        
        // Split stream for reading and writing
        let (mut read_half, mut write_half) = stream.split();
        
        // Spawn write task
        let write_stats = stats.clone();
        let write_task = tokio::spawn(async move {
            while let Some(message) = rx.recv().await {
                if let Ok(data) = bincode::serialize(&message) {
                    let size = data.len() as u32;
                    
                    // Send message size first, then message data
                    if write_half.write_all(&size.to_be_bytes()).await.is_ok() 
                        && write_half.write_all(&data).await.is_ok() {
                        
                        let mut stats_lock = write_stats.write().await;
                        stats_lock.messages_sent += 1;
                        stats_lock.bytes_sent += data.len() as u64;
                    } else {
                        break;
                    }
                } else {
                    break;
                }
            }
        });
        
        // Read messages
        let mut buffer = vec![0u8; 4096];
        loop {
            // Read message size
            let mut size_buffer = [0u8; 4];
            match read_half.read_exact(&mut size_buffer).await {
                Ok(_) => {
                    let message_size = u32::from_be_bytes(size_buffer) as usize;
                    
                    if message_size > buffer.len() {
                        buffer.resize(message_size, 0);
                    }
                    
                    // Read message data
                    match read_half.read_exact(&mut buffer[..message_size]).await {
                        Ok(_) => {
                            if let Ok(message) = bincode::deserialize::<NetworkMessage>(&buffer[..message_size]) {
                                // Update stats
                                {
                                    let mut stats_lock = stats.write().await;
                                    stats_lock.messages_received += 1;
                                    stats_lock.bytes_received += message_size as u64;
                                }
                                
                                // Send message event
                                let _ = event_sender.send(SimpleP2PEvent::MessageReceived {
                                    from: peer_id.clone(),
                                    message,
                                });
                            }
                        }
                        Err(_) => break,
                    }
                }
                Err(_) => break,
            }
        }
        
        // Connection closed
        write_task.abort();
        
        // Remove from connected peers
        {
            let mut peers_lock = peers.write().await;
            peers_lock.remove(&peer_id);
            
            let mut stats_lock = stats.write().await;
            if stats_lock.active_connections > 0 {
                stats_lock.active_connections -= 1;
            }
        }
        
        // Send disconnection event
        let _ = event_sender.send(SimpleP2PEvent::PeerDisconnected { peer_id });
        
        Ok(())
    }
    
    /// Perform handshake with peer
    async fn perform_handshake(
        stream: &mut TokioTcpStream,
        local_identity: &NymIdentity,
    ) -> NetworkResult<NymIdentity> {
        // Send our identity
        let handshake_data = bincode::serialize(local_identity)
            .map_err(|e| NetworkError::Serialization {
                reason: format!("Failed to serialize identity: {}", e),
            })?;
        
        let size = handshake_data.len() as u32;
        stream.write_all(&size.to_be_bytes()).await
            .map_err(|e| NetworkError::ConnectionFailed {
                reason: format!("Failed to send handshake size: {}", e),
            })?;
        
        stream.write_all(&handshake_data).await
            .map_err(|e| NetworkError::ConnectionFailed {
                reason: format!("Failed to send handshake: {}", e),
            })?;
        
        // Receive peer identity
        let mut size_buffer = [0u8; 4];
        stream.read_exact(&mut size_buffer).await
            .map_err(|e| NetworkError::ConnectionFailed {
                reason: format!("Failed to read handshake size: {}", e),
            })?;
        
        let message_size = u32::from_be_bytes(size_buffer) as usize;
        let mut data_buffer = vec![0u8; message_size];
        
        stream.read_exact(&mut data_buffer).await
            .map_err(|e| NetworkError::ConnectionFailed {
                reason: format!("Failed to read handshake data: {}", e),
            })?;
        
        let peer_identity = bincode::deserialize::<NymIdentity>(&data_buffer)
            .map_err(|e| NetworkError::Serialization {
                reason: format!("Failed to deserialize peer identity: {}", e),
            })?;
        
        Ok(peer_identity)
    }
    
    /// Connect to known peers
    async fn connect_to_known_peers(&self) {
        for addr in &self.config.known_peers {
            let addr = *addr;
            let peers = self.peers.clone();
            let event_sender = self.event_sender.clone();
            let identity = self.identity.clone();
            let stats = self.stats.clone();
            let timeout_duration = self.config.connection_timeout;
            
            tokio::spawn(async move {
                match timeout(timeout_duration, TokioTcpStream::connect(addr)).await {
                    Ok(Ok(stream)) => {
                        info!("Connected to peer at: {}", addr);
                        if let Err(e) = Self::handle_connection(
                            stream, addr, peers, event_sender, identity, stats
                        ).await {
                            error!("Connection handling error for {}: {}", addr, e);
                        }
                    }
                    Ok(Err(e)) => {
                        warn!("Failed to connect to {}: {}", addr, e);
                    }
                    Err(_) => {
                        warn!("Connection timeout to {}", addr);
                    }
                }
            });
        }
    }
    
    /// Start heartbeat task
    async fn start_heartbeat(&self) {
        let peers = self.peers.clone();
        let local_peer_id = self.local_peer_id.clone();
        let heartbeat_interval = self.config.heartbeat_interval;
        
        tokio::spawn(async move {
            let mut interval = interval(heartbeat_interval);
            
            loop {
                interval.tick().await;
                
                let ping_message = NetworkMessage::new(
                    MessageType::Ping,
                    local_peer_id.clone(),
                    None,
                    crate::MessagePayload::Raw(b"ping".to_vec()),
                );
                
                let peers_lock = peers.read().await;
                for peer in peers_lock.values() {
                    let _ = peer.sender.send(ping_message.clone());
                }
            }
        });
    }
    
    /// Send message to specific peer
    pub async fn send_to_peer(&self, peer_id: &PeerId, message: NetworkMessage) -> NetworkResult<()> {
        let peers = self.peers.read().await;
        
        if let Some(peer) = peers.get(peer_id) {
            peer.sender.send(message)
                .map_err(|_| NetworkError::PeerError {
                    reason: "Failed to send message to peer".to_string(),
                })?;
            Ok(())
        } else {
            Err(NetworkError::PeerError {
                reason: format!("Peer {} not connected", peer_id),
            })
        }
    }
    
    /// Broadcast message to all connected peers
    pub async fn broadcast_message(&self, message: NetworkMessage) -> NetworkResult<()> {
        let peers = self.peers.read().await;
        
        for peer in peers.values() {
            let _ = peer.sender.send(message.clone());
        }
        
        Ok(())
    }
    
    /// Connect to a new peer
    pub async fn connect_to_peer(&self, addr: SocketAddr) {
        let peers = self.peers.clone();
        let event_sender = self.event_sender.clone();
        let identity = self.identity.clone();
        let stats = self.stats.clone();
        let timeout_duration = self.config.connection_timeout;
        
        tokio::spawn(async move {
            match timeout(timeout_duration, TokioTcpStream::connect(addr)).await {
                Ok(Ok(stream)) => {
                    info!("Connected to new peer at: {}", addr);
                    if let Err(e) = Self::handle_connection(
                        stream, addr, peers, event_sender, identity, stats
                    ).await {
                        error!("Connection handling error for {}: {}", addr, e);
                    }
                }
                Ok(Err(e)) => {
                    let _ = event_sender.send(SimpleP2PEvent::ConnectionError {
                        addr,
                        error: e.to_string(),
                    });
                }
                Err(_) => {
                    let _ = event_sender.send(SimpleP2PEvent::ConnectionError {
                        addr,
                        error: "Connection timeout".to_string(),
                    });
                }
            }
        });
    }
    
    /// Get connected peers
    pub async fn connected_peers(&self) -> Vec<PeerId> {
        let peers = self.peers.read().await;
        peers.keys().cloned().collect()
    }
    
    /// Get peer count
    pub async fn peer_count(&self) -> usize {
        let peers = self.peers.read().await;
        peers.len()
    }
    
    /// Get local peer ID
    pub fn local_peer_id(&self) -> &PeerId {
        &self.local_peer_id
    }
    
    /// Get network statistics
    pub async fn stats(&self) -> NetworkStats {
        let stats = self.stats.read().await;
        NetworkStats {
            total_connections: stats.total_connections,
            active_connections: stats.active_connections,
            messages_sent: stats.messages_sent,
            messages_received: stats.messages_received,
            bytes_sent: stats.bytes_sent,
            bytes_received: stats.bytes_received,
            connection_errors: stats.connection_errors,
        }
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
    fn test_simple_p2p_config_default() {
        let config = SimpleP2PConfig::default();
        assert_eq!(config.max_connections, 50);
        assert!(config.known_peers.is_empty());
    }
    
    #[test]
    fn test_simple_p2p_network_creation() {
        let config = SimpleP2PConfig::default();
        let identity = create_test_identity();
        
        let (network, _receiver) = SimpleP2PNetwork::new(config, identity.clone());
        assert_eq!(network.local_peer_id(), &PeerId::from_identity(&identity));
    }
    
    #[tokio::test]
    async fn test_network_stats() {
        let config = SimpleP2PConfig::default();
        let identity = create_test_identity();
        
        let (network, _receiver) = SimpleP2PNetwork::new(config, identity);
        let stats = network.stats().await;
        
        assert_eq!(stats.total_connections, 0);
        assert_eq!(stats.active_connections, 0);
        assert_eq!(stats.messages_sent, 0);
        assert_eq!(stats.messages_received, 0);
    }
    
    #[tokio::test]
    async fn test_peer_management() {
        let config = SimpleP2PConfig::default();
        let identity = create_test_identity();
        
        let (network, _receiver) = SimpleP2PNetwork::new(config, identity);
        
        let peer_count = network.peer_count().await;
        assert_eq!(peer_count, 0);
        
        let connected_peers = network.connected_peers().await;
        assert!(connected_peers.is_empty());
    }
    
    #[tokio::test]
    async fn test_message_broadcasting() {
        let config = SimpleP2PConfig::default();
        let identity = create_test_identity();
        
        let (network, _receiver) = SimpleP2PNetwork::new(config, identity.clone());
        
        let message = NetworkMessage::new(
            MessageType::Ping,
            PeerId::from_identity(&identity),
            None,
            crate::MessagePayload::Raw(b"test".to_vec()),
        );
        
        // Should not error even with no connected peers
        let result = network.broadcast_message(message).await;
        assert!(result.is_ok());
    }
}