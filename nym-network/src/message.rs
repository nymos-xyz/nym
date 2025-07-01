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
        let message_id = Hash256::from(rand::random::<[u8; 32]>());\n        let timestamp = std::time::SystemTime::now()\n            .duration_since(std::time::UNIX_EPOCH)\n            .unwrap()\n            .as_secs();\n        \n        Self {\n            message_type,\n            message_id,\n            sender,\n            recipient,\n            timestamp,\n            ttl: 10, // Default TTL\n            privacy_level: SecurityLevel::Level1,\n            payload,\n            signature: None,\n        }\n    }\n    \n    /// Serialize message to bytes\n    pub fn to_bytes(&self) -> NetworkResult<Vec<u8>> {\n        bincode::serialize(self)\n            .map_err(|e| NetworkError::Serialization { \n                reason: e.to_string() \n            })\n    }\n    \n    /// Deserialize message from bytes\n    pub fn from_bytes(data: &[u8]) -> NetworkResult<Self> {\n        bincode::deserialize(data)\n            .map_err(|e| NetworkError::Serialization { \n                reason: e.to_string() \n            })\n    }\n    \n    /// Check if message has expired\n    pub fn is_expired(&self, max_age_seconds: u64) -> bool {\n        let now = std::time::SystemTime::now()\n            .duration_since(std::time::UNIX_EPOCH)\n            .unwrap()\n            .as_secs();\n        \n        now - self.timestamp > max_age_seconds\n    }\n    \n    /// Decrease TTL (returns false if TTL reaches 0)\n    pub fn decrease_ttl(&mut self) -> bool {\n        if self.ttl > 0 {\n            self.ttl -= 1;\n            true\n        } else {\n            false\n        }\n    }\n    \n    /// Sign message with identity\n    pub fn sign(&mut self, identity: &NymIdentity) -> NetworkResult<()> {\n        let message_bytes = self.payload_hash();\n        // Placeholder signature - in real implementation, use proper signing\n        self.signature = Some(message_bytes.as_bytes().to_vec());\n        Ok(())\n    }\n    \n    /// Verify message signature\n    pub fn verify_signature(&self, identity: &NymIdentity) -> NetworkResult<bool> {\n        // Placeholder verification - in real implementation, use proper verification\n        Ok(self.signature.is_some())\n    }\n    \n    /// Get payload hash for signing\n    fn payload_hash(&self) -> Hash256 {\n        let payload_bytes = bincode::serialize(&self.payload).unwrap_or_default();\n        nym_crypto::hash(&payload_bytes)\n    }\n}\n\nimpl MessageBuilder {\n    /// Create a new message builder\n    pub fn new(sender: PeerId, privacy_level: SecurityLevel) -> Self {\n        Self {\n            sender,\n            privacy_level,\n        }\n    }\n    \n    /// Build a handshake message\n    pub fn handshake(\n        &self,\n        recipient: PeerId,\n        identity: &NymIdentity,\n        challenge: Option<Vec<u8>>,\n    ) -> NetworkMessage {\n        let payload = MessagePayload::Handshake(HandshakePayload {\n            protocol_version: \"1.0\".to_string(),\n            identity: identity.clone(),\n            capabilities: vec![\n                \"full-node\".to_string(),\n                \"tx-relay\".to_string(),\n            ],\n            challenge,\n            challenge_response: None,\n        });\n        \n        NetworkMessage::new(\n            MessageType::Handshake,\n            self.sender.clone(),\n            Some(recipient),\n            payload,\n        )\n    }\n    \n    /// Build a ping message\n    pub fn ping(&self, recipient: PeerId) -> NetworkMessage {\n        let payload = MessagePayload::Ping(PingPayload {\n            nonce: rand::random(),\n            timestamp: std::time::SystemTime::now()\n                .duration_since(std::time::UNIX_EPOCH)\n                .unwrap()\n                .as_secs(),\n        });\n        \n        NetworkMessage::new(\n            MessageType::Ping,\n            self.sender.clone(),\n            Some(recipient),\n            payload,\n        )\n    }\n    \n    /// Build a block announcement\n    pub fn block_announcement(&self, block_hash: Hash256) -> NetworkMessage {\n        let payload = MessagePayload::BlockHash(block_hash);\n        \n        NetworkMessage::new(\n            MessageType::BlockAnnouncement,\n            self.sender.clone(),\n            None, // Broadcast\n            payload,\n        )\n    }\n    \n    /// Build a transaction announcement\n    pub fn transaction_announcement(&self, tx_hash: Hash256) -> NetworkMessage {\n        let payload = MessagePayload::TransactionHash(tx_hash);\n        \n        NetworkMessage::new(\n            MessageType::TransactionAnnouncement,\n            self.sender.clone(),\n            None, // Broadcast\n            payload,\n        )\n    }\n    \n    /// Build a block request\n    pub fn block_request(&self, recipient: PeerId, request: BlockRequestPayload) -> NetworkMessage {\n        let payload = MessagePayload::BlockRequest(request);\n        \n        NetworkMessage::new(\n            MessageType::BlockRequest,\n            self.sender.clone(),\n            Some(recipient),\n            payload,\n        )\n    }\n    \n    /// Build an error message\n    pub fn error(\n        &self,\n        recipient: PeerId,\n        error_code: u32,\n        error_message: String,\n        related_message_id: Option<Hash256>,\n    ) -> NetworkMessage {\n        let payload = MessagePayload::Error(ErrorPayload {\n            error_code,\n            error_message,\n            related_message_id,\n        });\n        \n        NetworkMessage::new(\n            MessageType::Error,\n            self.sender.clone(),\n            Some(recipient),\n            payload,\n        )\n    }\n}\n\nimpl MessageHandler {\n    /// Create a new message handler\n    pub fn new(identity: NymIdentity) -> Self {\n        Self { identity }\n    }\n    \n    /// Process an incoming message\n    pub async fn handle_message(&self, message: &NetworkMessage) -> NetworkResult<Option<NetworkMessage>> {\n        // Verify message signature if present\n        if message.signature.is_some() {\n            if !message.verify_signature(&self.identity)? {\n                return Err(NetworkError::AuthenticationFailed { \n                    reason: \"Invalid message signature\".to_string() \n                });\n            }\n        }\n        \n        // Check TTL\n        if message.ttl == 0 {\n            return Err(NetworkError::MessageError { \n                reason: \"Message TTL expired\".to_string() \n            });\n        }\n        \n        // Process based on message type\n        match &message.message_type {\n            MessageType::Handshake => self.handle_handshake(message).await,\n            MessageType::Ping => self.handle_ping(message).await,\n            MessageType::Discovery => self.handle_discovery(message).await,\n            MessageType::BlockRequest => self.handle_block_request(message).await,\n            MessageType::TransactionRequest => self.handle_transaction_request(message).await,\n            MessageType::SyncRequest => self.handle_sync_request(message).await,\n            _ => {\n                // Other message types would be handled by specific components\n                Ok(None)\n            }\n        }\n    }\n    \n    /// Handle handshake message\n    async fn handle_handshake(&self, message: &NetworkMessage) -> NetworkResult<Option<NetworkMessage>> {\n        if let MessagePayload::Handshake(handshake) = &message.payload {\n            // Verify protocol compatibility\n            if handshake.protocol_version != \"1.0\" {\n                let builder = MessageBuilder::new(\n                    PeerId::from_identity(&self.identity),\n                    SecurityLevel::Level1,\n                );\n                \n                return Ok(Some(builder.error(\n                    message.sender.clone(),\n                    400,\n                    \"Unsupported protocol version\".to_string(),\n                    Some(message.message_id),\n                )));\n            }\n            \n            // Create handshake response\n            let response_payload = MessagePayload::Handshake(HandshakePayload {\n                protocol_version: \"1.0\".to_string(),\n                identity: self.identity.clone(),\n                capabilities: vec![\n                    \"full-node\".to_string(),\n                    \"tx-relay\".to_string(),\n                ],\n                challenge: None,\n                challenge_response: handshake.challenge.clone(), // Echo challenge back\n            });\n            \n            let response = NetworkMessage::new(\n                MessageType::Handshake,\n                PeerId::from_identity(&self.identity),\n                Some(message.sender.clone()),\n                response_payload,\n            );\n            \n            Ok(Some(response))\n        } else {\n            Err(NetworkError::MessageError { \n                reason: \"Invalid handshake payload\".to_string() \n            })\n        }\n    }\n    \n    /// Handle ping message\n    async fn handle_ping(&self, message: &NetworkMessage) -> NetworkResult<Option<NetworkMessage>> {\n        if let MessagePayload::Ping(ping) = &message.payload {\n            let pong_payload = MessagePayload::Pong(PongPayload {\n                nonce: ping.nonce,\n                timestamp: std::time::SystemTime::now()\n                    .duration_since(std::time::UNIX_EPOCH)\n                    .unwrap()\n                    .as_secs(),\n            });\n            \n            let response = NetworkMessage::new(\n                MessageType::Pong,\n                PeerId::from_identity(&self.identity),\n                Some(message.sender.clone()),\n                pong_payload,\n            );\n            \n            Ok(Some(response))\n        } else {\n            Err(NetworkError::MessageError { \n                reason: \"Invalid ping payload\".to_string() \n            })\n        }\n    }\n    \n    /// Handle discovery message\n    async fn handle_discovery(&self, _message: &NetworkMessage) -> NetworkResult<Option<NetworkMessage>> {\n        // Discovery would be handled by the discovery component\n        Ok(None)\n    }\n    \n    /// Handle block request\n    async fn handle_block_request(&self, _message: &NetworkMessage) -> NetworkResult<Option<NetworkMessage>> {\n        // Block requests would be handled by the chain component\n        Ok(None)\n    }\n    \n    /// Handle transaction request\n    async fn handle_transaction_request(&self, _message: &NetworkMessage) -> NetworkResult<Option<NetworkMessage>> {\n        // Transaction requests would be handled by the transaction component\n        Ok(None)\n    }\n    \n    /// Handle sync request\n    async fn handle_sync_request(&self, _message: &NetworkMessage) -> NetworkResult<Option<NetworkMessage>> {\n        // Sync requests would be handled by the sync component\n        Ok(None)\n    }\n}\n\n#[cfg(test)]\nmod tests {\n    use super::*;\n    use nym_crypto::{QuIDAuth, SecurityLevel};\n    \n    fn create_test_identity() -> NymIdentity {\n        let quid_auth = QuIDAuth::new(vec![1u8; 32], SecurityLevel::Level1);\n        quid_auth.create_nym_identity(0).unwrap()\n    }\n    \n    #[test]\n    fn test_message_creation() {\n        let sender = PeerId::new(Hash256::from([1u8; 32]));\n        let recipient = PeerId::new(Hash256::from([2u8; 32]));\n        \n        let message = NetworkMessage::new(\n            MessageType::Ping,\n            sender.clone(),\n            Some(recipient.clone()),\n            MessagePayload::Raw(vec![1, 2, 3]),\n        );\n        \n        assert_eq!(message.sender, sender);\n        assert_eq!(message.recipient, Some(recipient));\n        assert_eq!(message.message_type, MessageType::Ping);\n    }\n    \n    #[test]\n    fn test_message_serialization() {\n        let sender = PeerId::new(Hash256::from([1u8; 32]));\n        \n        let message = NetworkMessage::new(\n            MessageType::Ping,\n            sender,\n            None,\n            MessagePayload::Raw(vec![1, 2, 3]),\n        );\n        \n        let bytes = message.to_bytes().unwrap();\n        let deserialized = NetworkMessage::from_bytes(&bytes).unwrap();\n        \n        assert_eq!(message.message_id, deserialized.message_id);\n        assert_eq!(message.message_type, deserialized.message_type);\n    }\n    \n    #[test]\n    fn test_message_builder() {\n        let sender = PeerId::new(Hash256::from([1u8; 32]));\n        let recipient = PeerId::new(Hash256::from([2u8; 32]));\n        let identity = create_test_identity();\n        \n        let builder = MessageBuilder::new(sender.clone(), SecurityLevel::Level1);\n        let message = builder.handshake(recipient.clone(), &identity, None);\n        \n        assert_eq!(message.message_type, MessageType::Handshake);\n        assert_eq!(message.sender, sender);\n        assert_eq!(message.recipient, Some(recipient));\n    }\n    \n    #[test]\n    fn test_ttl_decrease() {\n        let sender = PeerId::new(Hash256::from([1u8; 32]));\n        \n        let mut message = NetworkMessage::new(\n            MessageType::Ping,\n            sender,\n            None,\n            MessagePayload::Raw(vec![]),\n        );\n        \n        assert_eq!(message.ttl, 10);\n        \n        for i in (1..=10).rev() {\n            assert!(message.decrease_ttl());\n            assert_eq!(message.ttl, i - 1);\n        }\n        \n        assert!(!message.decrease_ttl());\n        assert_eq!(message.ttl, 0);\n    }\n    \n    #[tokio::test]\n    async fn test_message_handler() {\n        let identity = create_test_identity();\n        let handler = MessageHandler::new(identity.clone());\n        \n        let sender = PeerId::new(Hash256::from([1u8; 32]));\n        let ping_payload = MessagePayload::Ping(PingPayload {\n            nonce: 12345,\n            timestamp: 1000,\n        });\n        \n        let ping_message = NetworkMessage::new(\n            MessageType::Ping,\n            sender,\n            Some(PeerId::from_identity(&identity)),\n            ping_payload,\n        );\n        \n        let response = handler.handle_message(&ping_message).await.unwrap();\n        assert!(response.is_some());\n        \n        let pong = response.unwrap();\n        assert_eq!(pong.message_type, MessageType::Pong);\n        \n        if let MessagePayload::Pong(pong_payload) = pong.payload {\n            assert_eq!(pong_payload.nonce, 12345);\n        } else {\n            panic!(\"Expected pong payload\");\n        }\n    }\n}"