//! Network protocol and handshake implementation

use std::collections::HashMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use tokio::time::timeout;
use nym_crypto::{Hash256, SecurityLevel};
use nym_core::NymIdentity;
use crate::{
    NetworkError, NetworkResult, PeerId, PeerInfo,
    NetworkMessage, MessageType, MessagePayload, HandshakePayload
};

/// Protocol version
pub const PROTOCOL_VERSION: &str = "1.0";

/// Handshake timeout in seconds
pub const HANDSHAKE_TIMEOUT: u64 = 30;

/// Protocol configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProtocolConfig {
    /// Protocol version
    pub version: String,
    /// Handshake timeout
    pub handshake_timeout: Duration,
    /// Challenge size in bytes
    pub challenge_size: usize,
    /// Maximum message size
    pub max_message_size: usize,
    /// Keep-alive interval
    pub keep_alive_interval: Duration,
}

/// Handshake state
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeState {
    Idle,
    Initiating,
    Responding,
    Completed,
    Failed,
}

/// Handshake session
#[derive(Debug, Clone)]
pub struct HandshakeSession {
    /// Session ID
    pub session_id: Hash256,
    /// Peer ID
    pub peer_id: PeerId,
    /// Current state
    pub state: HandshakeState,
    /// Local challenge
    pub local_challenge: Option<Vec<u8>>,
    /// Remote challenge
    pub remote_challenge: Option<Vec<u8>>,
    /// Start timestamp
    pub started_at: u64,
    /// Peer identity
    pub peer_identity: Option<NymIdentity>,
    /// Capabilities exchanged
    pub capabilities: Vec<String>,
}

/// Nym network protocol handler
pub struct NymProtocol {
    /// Protocol configuration
    config: ProtocolConfig,
    /// Local identity
    identity: NymIdentity,
    /// Active handshake sessions
    handshake_sessions: HashMap<Hash256, HandshakeSession>,
    /// Completed handshakes
    completed_handshakes: HashMap<PeerId, NymIdentity>,
}

/// Handshake protocol implementation
pub struct HandshakeProtocol {
    /// Protocol reference
    protocol: NymProtocol,
}

impl Default for ProtocolConfig {
    fn default() -> Self {
        Self {
            version: PROTOCOL_VERSION.to_string(),
            handshake_timeout: Duration::from_secs(HANDSHAKE_TIMEOUT),
            challenge_size: 32,
            max_message_size: 1024 * 1024, // 1MB
            keep_alive_interval: Duration::from_secs(60),
        }
    }
}

impl HandshakeSession {
    /// Create a new handshake session
    pub fn new(session_id: Hash256, peer_id: PeerId) -> Self {
        Self {
            session_id,
            peer_id,
            state: HandshakeState::Idle,
            local_challenge: None,
            remote_challenge: None,
            started_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            peer_identity: None,
            capabilities: Vec::new(),
        }
    }
    
    /// Check if session has timed out
    pub fn is_expired(&self, timeout: Duration) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        now - self.started_at > timeout.as_secs()
    }
    
    /// Generate challenge
    pub fn generate_challenge(&mut self, size: usize) {
        let challenge: Vec<u8> = (0..size).map(|_| rand::random()).collect();
        self.local_challenge = Some(challenge);
    }
    
    /// Set remote challenge
    pub fn set_remote_challenge(&mut self, challenge: Vec<u8>) {
        self.remote_challenge = Some(challenge);
    }
    
    /// Mark as completed
    pub fn complete(&mut self, peer_identity: NymIdentity, capabilities: Vec<String>) {
        self.state = HandshakeState::Completed;
        self.peer_identity = Some(peer_identity);
        self.capabilities = capabilities;
    }
    
    /// Mark as failed
    pub fn fail(&mut self) {
        self.state = HandshakeState::Failed;
    }
}

impl NymProtocol {
    /// Create a new protocol handler
    pub fn new(config: ProtocolConfig, identity: NymIdentity) -> Self {
        Self {
            config,
            identity,
            handshake_sessions: HashMap::new(),
            completed_handshakes: HashMap::new(),
        }
    }
    
    /// Initiate handshake with peer
    pub async fn initiate_handshake(&mut self, peer_id: PeerId) -> NetworkResult<NetworkMessage> {
        let session_id = Hash256::from(rand::random::<[u8; 32]>());
        let mut session = HandshakeSession::new(session_id, peer_id.clone());
        
        // Generate challenge
        session.generate_challenge(self.config.challenge_size);
        session.state = HandshakeState::Initiating;
        
        // Create handshake message
        let handshake_payload = HandshakePayload {
            protocol_version: self.config.version.clone(),
            identity: self.identity.clone(),
            capabilities: vec![
                "full-node".to_string(),
                "tx-relay".to_string(),
                "privacy-level-1".to_string(),
            ],
            challenge: session.local_challenge.clone(),
            challenge_response: None,
        };
        
        let message = NetworkMessage::new(
            MessageType::Handshake,
            PeerId::from_identity(&self.identity),
            Some(peer_id),
            MessagePayload::Handshake(handshake_payload),
        );
        
        // Store session
        self.handshake_sessions.insert(session_id, session);
        
        Ok(message)
    }
    
    /// Handle incoming handshake message
    pub async fn handle_handshake(&mut self, message: &NetworkMessage) -> NetworkResult<Option<NetworkMessage>> {
        if let MessagePayload::Handshake(handshake) = &message.payload {
            // Check protocol version compatibility
            if handshake.protocol_version != self.config.version {
                return Err(NetworkError::ProtocolError {
                    reason: format!(
                        "Incompatible protocol version: {} (expected {})",
                        handshake.protocol_version, self.config.version
                    ),
                });
            }
            
            // Find or create session
            let session_id = Hash256::from(rand::random::<[u8; 32]>());
            let peer_id = message.sender.clone();
            
            if let Some(session) = self.find_session_by_peer(&peer_id) {
                // Handle response to our initiated handshake
                self.handle_handshake_response(session, handshake).await
            } else {
                // Handle incoming handshake initiation
                self.handle_handshake_initiation(session_id, peer_id, handshake).await
            }
        } else {
            Err(NetworkError::MessageError {
                reason: "Invalid handshake message payload".to_string(),
            })
        }
    }
    
    /// Handle handshake initiation
    async fn handle_handshake_initiation(
        &mut self,
        session_id: Hash256,
        peer_id: PeerId,
        handshake: &HandshakePayload,
    ) -> NetworkResult<Option<NetworkMessage>> {
        let mut session = HandshakeSession::new(session_id, peer_id.clone());
        session.state = HandshakeState::Responding;
        
        // Store remote challenge
        if let Some(challenge) = &handshake.challenge {
            session.set_remote_challenge(challenge.clone());
        }
        
        // Generate our own challenge
        session.generate_challenge(self.config.challenge_size);
        
        // Verify peer identity (simplified)
        let peer_identity = handshake.identity.clone();
        let expected_peer_id = PeerId::from_identity(&peer_identity);
        
        if expected_peer_id != peer_id {
            session.fail();
            return Err(NetworkError::AuthenticationFailed {
                reason: "Peer ID mismatch".to_string(),
            });
        }
        
        // Create response
        let response_payload = HandshakePayload {
            protocol_version: self.config.version.clone(),
            identity: self.identity.clone(),
            capabilities: vec![
                "full-node".to_string(),
                "tx-relay".to_string(),
                "privacy-level-1".to_string(),
            ],
            challenge: session.local_challenge.clone(),
            challenge_response: handshake.challenge.clone(), // Echo back their challenge
        };
        
        let response = NetworkMessage::new(
            MessageType::Handshake,
            PeerId::from_identity(&self.identity),
            Some(peer_id),
            MessagePayload::Handshake(response_payload),
        );
        
        // Complete handshake
        session.complete(peer_identity.clone(), handshake.capabilities.clone());
        self.completed_handshakes.insert(peer_id, peer_identity);
        self.handshake_sessions.insert(session_id, session);
        
        Ok(Some(response))
    }
    
    /// Handle handshake response
    async fn handle_handshake_response(
        &mut self,
        session_id: Hash256,
        handshake: &HandshakePayload,
    ) -> NetworkResult<Option<NetworkMessage>> {
        if let Some(session) = self.handshake_sessions.get_mut(&session_id) {
            // Verify challenge response
            if let Some(expected_challenge) = &session.local_challenge {
                if let Some(response) = &handshake.challenge_response {
                    if response != expected_challenge {
                        session.fail();
                        return Err(NetworkError::AuthenticationFailed {
                            reason: "Invalid challenge response".to_string(),
                        });
                    }
                } else {
                    session.fail();
                    return Err(NetworkError::AuthenticationFailed {
                        reason: "Missing challenge response".to_string(),
                    });
                }
            }
            
            // Verify peer identity
            let peer_identity = handshake.identity.clone();
            let expected_peer_id = PeerId::from_identity(&peer_identity);
            
            if expected_peer_id != session.peer_id {
                session.fail();
                return Err(NetworkError::AuthenticationFailed {
                    reason: "Peer ID mismatch in response".to_string(),
                });
            }
            
            // Complete handshake
            session.complete(peer_identity.clone(), handshake.capabilities.clone());
            self.completed_handshakes.insert(session.peer_id.clone(), peer_identity);
            
            // Send final handshake completion if needed
            if let Some(remote_challenge) = &handshake.challenge {
                let completion_payload = HandshakePayload {
                    protocol_version: self.config.version.clone(),
                    identity: self.identity.clone(),
                    capabilities: vec![
                        "full-node".to_string(),
                        "tx-relay".to_string(),
                        "privacy-level-1".to_string(),
                    ],
                    challenge: None,
                    challenge_response: Some(remote_challenge.clone()),
                };
                
                let completion = NetworkMessage::new(
                    MessageType::Handshake,
                    PeerId::from_identity(&self.identity),
                    Some(session.peer_id.clone()),
                    MessagePayload::Handshake(completion_payload),
                );
                
                return Ok(Some(completion));
            }
        }
        
        Ok(None)
    }
    
    /// Find session by peer ID
    fn find_session_by_peer(&self, peer_id: &PeerId) -> Option<Hash256> {
        self.handshake_sessions
            .iter()
            .find(|(_, session)| &session.peer_id == peer_id)
            .map(|(session_id, _)| *session_id)
    }
    
    /// Check if peer is authenticated
    pub fn is_peer_authenticated(&self, peer_id: &PeerId) -> bool {
        self.completed_handshakes.contains_key(peer_id)
    }
    
    /// Get peer identity
    pub fn get_peer_identity(&self, peer_id: &PeerId) -> Option<&NymIdentity> {
        self.completed_handshakes.get(peer_id)
    }
    
    /// Cleanup expired sessions
    pub fn cleanup_expired_sessions(&mut self) {
        let expired_sessions: Vec<Hash256> = self
            .handshake_sessions
            .iter()
            .filter(|(_, session)| session.is_expired(self.config.handshake_timeout))
            .map(|(session_id, _)| *session_id)
            .collect();
        
        for session_id in expired_sessions {
            if let Some(session) = self.handshake_sessions.remove(&session_id) {
                tracing::warn!("Handshake session expired: {:?}", session.peer_id);
                // Remove from completed if it was there
                self.completed_handshakes.remove(&session.peer_id);
            }
        }
    }
    
    /// Get active session count
    pub fn active_session_count(&self) -> usize {
        self.handshake_sessions.len()
    }
    
    /// Get completed handshake count
    pub fn completed_handshake_count(&self) -> usize {
        self.completed_handshakes.len()
    }
    
    /// Remove peer authentication
    pub fn remove_peer_authentication(&mut self, peer_id: &PeerId) {
        self.completed_handshakes.remove(peer_id);
        
        // Remove any active sessions for this peer
        let sessions_to_remove: Vec<Hash256> = self
            .handshake_sessions
            .iter()
            .filter(|(_, session)| &session.peer_id == peer_id)
            .map(|(session_id, _)| *session_id)
            .collect();
        
        for session_id in sessions_to_remove {
            self.handshake_sessions.remove(&session_id);
        }
    }
    
    /// Get protocol configuration
    pub fn config(&self) -> &ProtocolConfig {
        &self.config
    }
    
    /// Get local identity
    pub fn identity(&self) -> &NymIdentity {
        &self.identity
    }
}

impl HandshakeProtocol {
    /// Create a new handshake protocol
    pub fn new(protocol: NymProtocol) -> Self {
        Self { protocol }
    }
    
    /// Perform full handshake with timeout
    pub async fn perform_handshake(&mut self, peer_id: PeerId) -> NetworkResult<NymIdentity> {
        let handshake_future = self.do_handshake(peer_id.clone());
        
        match timeout(self.protocol.config.handshake_timeout, handshake_future).await {
            Ok(result) => result,
            Err(_) => {
                self.protocol.remove_peer_authentication(&peer_id);
                Err(NetworkError::Timeout {
                    reason: "Handshake timeout".to_string(),
                })
            }
        }
    }
    
    /// Actual handshake implementation
    async fn do_handshake(&mut self, peer_id: PeerId) -> NetworkResult<NymIdentity> {
        // Initiate handshake
        let _handshake_message = self.protocol.initiate_handshake(peer_id.clone()).await?;
        
        // In a real implementation, this would involve actual network communication
        // For now, we'll simulate a successful handshake
        
        // Simulate network delay
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Create a mock peer identity for testing
        let mock_peer_identity = self.create_mock_peer_identity(&peer_id)?;
        
        // Store as completed
        self.protocol.completed_handshakes.insert(peer_id, mock_peer_identity.clone());
        
        Ok(mock_peer_identity)
    }
    
    /// Create mock peer identity for testing
    fn create_mock_peer_identity(&self, peer_id: &PeerId) -> NetworkResult<NymIdentity> {
        // In a real implementation, this would come from the actual handshake
        // For testing, create a mock identity based on peer ID
        let mock_key = peer_id.hash().as_bytes().to_vec();
        let quid_auth = nym_crypto::QuIDAuth::new(mock_key, SecurityLevel::Level1);
        quid_auth.create_nym_identity(0).map_err(|e| NetworkError::Crypto(e))
    }
    
    /// Check handshake status
    pub fn is_handshake_complete(&self, peer_id: &PeerId) -> bool {
        self.protocol.is_peer_authenticated(peer_id)
    }
    
    /// Get protocol reference
    pub fn protocol(&self) -> &NymProtocol {
        &self.protocol
    }
    
    /// Get mutable protocol reference
    pub fn protocol_mut(&mut self) -> &mut NymProtocol {
        &mut self.protocol
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
    fn test_protocol_config_default() {
        let config = ProtocolConfig::default();
        assert_eq!(config.version, PROTOCOL_VERSION);
        assert_eq!(config.challenge_size, 32);
    }
    
    #[test]
    fn test_handshake_session_creation() {
        let session_id = Hash256::from([1u8; 32]);
        let peer_id = PeerId::new(Hash256::from([2u8; 32]));
        
        let session = HandshakeSession::new(session_id, peer_id.clone());
        assert_eq!(session.session_id, session_id);
        assert_eq!(session.peer_id, peer_id);
        assert_eq!(session.state, HandshakeState::Idle);
    }
    
    #[test]
    fn test_handshake_session_challenge() {
        let session_id = Hash256::from([1u8; 32]);
        let peer_id = PeerId::new(Hash256::from([2u8; 32]));
        
        let mut session = HandshakeSession::new(session_id, peer_id);
        session.generate_challenge(32);
        
        assert!(session.local_challenge.is_some());
        assert_eq!(session.local_challenge.as_ref().unwrap().len(), 32);
    }
    
    #[test]
    fn test_protocol_creation() {
        let config = ProtocolConfig::default();
        let identity = create_test_identity();
        
        let protocol = NymProtocol::new(config, identity.clone());
        assert_eq!(protocol.identity(), &identity);
        assert_eq!(protocol.active_session_count(), 0);
        assert_eq!(protocol.completed_handshake_count(), 0);
    }
    
    #[tokio::test]
    async fn test_handshake_initiation() {
        let config = ProtocolConfig::default();
        let identity = create_test_identity();
        let mut protocol = NymProtocol::new(config, identity);
        
        let peer_id = PeerId::new(Hash256::from([2u8; 32]));
        let message = protocol.initiate_handshake(peer_id.clone()).await.unwrap();
        
        assert_eq!(message.message_type, MessageType::Handshake);
        assert_eq!(message.recipient, Some(peer_id));
        assert_eq!(protocol.active_session_count(), 1);
    }
    
    #[test]
    fn test_peer_authentication() {
        let config = ProtocolConfig::default();
        let identity = create_test_identity();
        let mut protocol = NymProtocol::new(config, identity.clone());
        
        let peer_id = PeerId::new(Hash256::from([2u8; 32]));
        let peer_identity = create_test_identity();
        
        assert!(!protocol.is_peer_authenticated(&peer_id));
        
        protocol.completed_handshakes.insert(peer_id.clone(), peer_identity.clone());
        
        assert!(protocol.is_peer_authenticated(&peer_id));
        assert_eq!(protocol.get_peer_identity(&peer_id), Some(&peer_identity));
    }
    
    #[test]
    fn test_session_expiration() {
        let session_id = Hash256::from([1u8; 32]);
        let peer_id = PeerId::new(Hash256::from([2u8; 32]));
        
        let session = HandshakeSession::new(session_id, peer_id);
        
        // Should not be expired immediately
        assert!(!session.is_expired(Duration::from_secs(30)));
        
        // Should be expired with very short timeout
        assert!(session.is_expired(Duration::from_millis(1)));
    }
    
    #[tokio::test]
    async fn test_handshake_protocol() {
        let config = ProtocolConfig::default();
        let identity = create_test_identity();
        let protocol = NymProtocol::new(config, identity);
        let mut handshake_protocol = HandshakeProtocol::new(protocol);
        
        let peer_id = PeerId::new(Hash256::from([2u8; 32]));
        
        // Perform handshake
        let result = handshake_protocol.perform_handshake(peer_id.clone()).await;
        assert!(result.is_ok());
        
        // Check that handshake is complete
        assert!(handshake_protocol.is_handshake_complete(&peer_id));
    }
    
    #[test]
    fn test_cleanup_expired_sessions() {
        let config = ProtocolConfig {
            handshake_timeout: Duration::from_millis(1), // Very short timeout
            ..Default::default()
        };
        let identity = create_test_identity();
        let mut protocol = NymProtocol::new(config, identity);
        
        let session_id = Hash256::from([1u8; 32]);
        let peer_id = PeerId::new(Hash256::from([2u8; 32]));
        let session = HandshakeSession::new(session_id, peer_id);
        
        protocol.handshake_sessions.insert(session_id, session);
        assert_eq!(protocol.active_session_count(), 1);
        
        // Wait for session to expire
        std::thread::sleep(Duration::from_millis(10));
        
        protocol.cleanup_expired_sessions();
        assert_eq!(protocol.active_session_count(), 0);
    }
}