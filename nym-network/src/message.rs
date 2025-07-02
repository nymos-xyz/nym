//! Network message types and handling

use serde::{Serialize, Deserialize};
use nym_crypto::{Hash256, SecurityLevel};
use nym_core::{Block, Transaction, NymIdentity};
use crate::{PeerId, NetworkError, NetworkResult};

/// Types of network messages
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum MessageType {
    /// Handshake and authentication
    Handshake,
    /// Peer discovery
    Discovery,
    /// Block announcement
    BlockAnnouncement,
    /// Transaction announcement
    TransactionAnnouncement,
    /// Block request
    BlockRequest,
    /// Block response
    BlockResponse,
    /// Transaction request
    TransactionRequest,
    /// Transaction response
    TransactionResponse,
    /// Peer information exchange
    PeerExchange,
    /// Sync request
    SyncRequest,
    /// Sync response
    SyncResponse,
    /// Ping/Pong for keep-alive
    Ping,
    /// Ping response
    Pong,
    /// Privacy routing
    PrivacyRouting,
    /// Error message
    Error,
}

/// Network message envelope
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMessage {
    /// Message type
    pub message_type: MessageType,
    /// Message ID for correlation
    pub message_id: Hash256,
    /// Sender peer ID
    pub sender: PeerId,
    /// Recipient peer ID (None for broadcast)
    pub recipient: Option<PeerId>,
    /// Message timestamp
    pub timestamp: u64,
    /// Message TTL (hops)
    pub ttl: u8,
    /// Privacy level
    pub privacy_level: SecurityLevel,
    /// Message payload
    pub payload: MessagePayload,
    /// Message signature (for authentication)
    pub signature: Option<Vec<u8>>,
}

/// Message payload variants
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MessagePayload {
    /// Handshake request/response
    Handshake(HandshakePayload),
    /// Node discovery
    Discovery(DiscoveryPayload),
    /// Block data
    Block(Block),
    /// Transaction data
    Transaction(Transaction),
    /// Block hash for announcements
    BlockHash(Hash256),
    /// Transaction hash for announcements
    TransactionHash(Hash256),
    /// Block request by hash or height
    BlockRequest(BlockRequestPayload),
    /// Transaction request by hash
    TransactionRequest(Hash256),
    /// Peer information
    PeerInfo(PeerInfoPayload),
    /// Sync request
    SyncRequest(SyncRequestPayload),
    /// Sync response
    SyncResponse(SyncResponsePayload),
    /// Ping data
    Ping(PingPayload),
    /// Pong response
    Pong(PongPayload),
    /// Privacy-routed message
    PrivacyRouted(PrivacyRoutedPayload),
    /// Error information
    Error(ErrorPayload),
    /// Raw bytes for encrypted payloads
    Raw(Vec<u8>),
}

/// Handshake payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HandshakePayload {
    /// Protocol version
    pub protocol_version: String,
    /// Node identity
    pub identity: NymIdentity,
    /// Supported capabilities
    pub capabilities: Vec<String>,
    /// Challenge for authentication
    pub challenge: Option<Vec<u8>>,
    /// Challenge response
    pub challenge_response: Option<Vec<u8>>,
}

/// Discovery payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryPayload {
    /// Discovered peers
    pub peers: Vec<PeerInfoPayload>,
    /// Request type (bootstrap, refresh, etc.)
    pub request_type: String,
}

/// Block request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BlockRequestPayload {
    /// Request by hash
    ByHash(Hash256),
    /// Request by height
    ByHeight(u64),
    /// Request range
    Range { start: u64, end: u64 },
}

/// Peer information payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerInfoPayload {
    /// Peer ID
    pub peer_id: PeerId,
    /// Network addresses
    pub addresses: Vec<String>,
    /// Last seen timestamp
    pub last_seen: u64,
    /// Capabilities
    pub capabilities: Vec<String>,
}

/// Sync request payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncRequestPayload {
    /// Current chain height
    pub current_height: u64,
    /// Current chain tip hash
    pub current_tip: Hash256,
    /// Maximum blocks to sync
    pub max_blocks: u32,
}

/// Sync response payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SyncResponsePayload {
    /// Starting height
    pub start_height: u64,
    /// Block hashes
    pub block_hashes: Vec<Hash256>,
    /// Has more blocks
    pub has_more: bool,
}

/// Ping payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingPayload {
    /// Ping nonce
    pub nonce: u64,
    /// Timestamp
    pub timestamp: u64,
}

/// Pong payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PongPayload {
    /// Original ping nonce
    pub nonce: u64,
    /// Response timestamp
    pub timestamp: u64,
}

/// Privacy-routed message payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyRoutedPayload {
    /// Encrypted payload
    pub encrypted_data: Vec<u8>,
    /// Routing information
    pub routing_info: Vec<u8>,
    /// Number of hops remaining
    pub hops_remaining: u8,
}

/// Error payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPayload {
    /// Error code
    pub error_code: u32,
    /// Error message
    pub error_message: String,
    /// Related message ID
    pub related_message_id: Option<Hash256>,
}

/// Message builder for creating network messages
pub struct MessageBuilder {
    sender: PeerId,
    privacy_level: SecurityLevel,
}

/// Message handler for processing incoming messages
pub struct MessageHandler {
    identity: NymIdentity,
}

impl NetworkMessage {
    /// Create a new network message
    pub fn new(
        message_type: MessageType,
        sender: PeerId,
        recipient: Option<PeerId>,
        payload: MessagePayload,
    ) -> Self {
        let message_id = Hash256::from_bytes(rand::random::<[u8; 32]>());
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        Self {
            message_type,
            message_id,
            sender,
            recipient,
            timestamp,
            ttl: 10, // Default TTL
            privacy_level: SecurityLevel::Level1,
            payload,
            signature: None,
        }
    }
    
    /// Serialize message to bytes
    pub fn to_bytes(&self) -> NetworkResult<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| NetworkError::Serialization { 
                reason: e.to_string() 
            })
    }
    
    /// Deserialize message from bytes
    pub fn from_bytes(data: &[u8]) -> NetworkResult<Self> {
        bincode::deserialize(data)
            .map_err(|e| NetworkError::Serialization { 
                reason: e.to_string() 
            })
    }
}

impl MessageBuilder {
    /// Create a new message builder
    pub fn new(sender: PeerId, privacy_level: SecurityLevel) -> Self {
        Self {
            sender,
            privacy_level,
        }
    }
    
    /// Build a ping message
    pub fn ping(&self, recipient: PeerId) -> NetworkMessage {
        let payload = MessagePayload::Ping(PingPayload {
            nonce: rand::random(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        });
        
        NetworkMessage::new(
            MessageType::Ping,
            self.sender.clone(),
            Some(recipient),
            payload,
        )
    }
}

impl MessageHandler {
    /// Create a new message handler
    pub fn new(identity: NymIdentity) -> Self {
        Self { identity }
    }
    
    /// Process an incoming message
    pub async fn handle_message(&self, message: &NetworkMessage) -> NetworkResult<Option<NetworkMessage>> {
        // Process based on message type
        match &message.message_type {
            MessageType::Ping => self.handle_ping(message).await,
            _ => {
                // Other message types would be handled by specific components
                Ok(None)
            }
        }
    }
    
    /// Handle ping message
    async fn handle_ping(&self, message: &NetworkMessage) -> NetworkResult<Option<NetworkMessage>> {
        if let MessagePayload::Ping(ping) = &message.payload {
            let pong_payload = MessagePayload::Pong(PongPayload {
                nonce: ping.nonce,
                timestamp: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            });
            
            let response = NetworkMessage::new(
                MessageType::Pong,
                PeerId::from_identity(&self.identity),
                Some(message.sender.clone()),
                pong_payload,
            );
            
            Ok(Some(response))
        } else {
            Err(NetworkError::MessageError { 
                reason: "Invalid ping payload".to_string() 
            })
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
    fn test_message_creation() {
        let sender = PeerId::new(Hash256::from([1u8; 32]));
        let recipient = PeerId::new(Hash256::from([2u8; 32]));
        
        let message = NetworkMessage::new(
            MessageType::Ping,
            sender.clone(),
            Some(recipient.clone()),
            MessagePayload::Raw(vec![1, 2, 3]),
        );
        
        assert_eq!(message.sender, sender);
        assert_eq!(message.recipient, Some(recipient));
        assert_eq!(message.message_type, MessageType::Ping);
    }
    
    #[test]
    fn test_message_serialization() {
        let sender = PeerId::new(Hash256::from([1u8; 32]));
        
        let message = NetworkMessage::new(
            MessageType::Ping,
            sender,
            None,
            MessagePayload::Raw(vec![1, 2, 3]),
        );
        
        let bytes = message.to_bytes().unwrap();
        let deserialized = NetworkMessage::from_bytes(&bytes).unwrap();
        
        assert_eq!(message.message_id, deserialized.message_id);
        assert_eq!(message.message_type, deserialized.message_type);
    }
}