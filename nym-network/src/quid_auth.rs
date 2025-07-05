use crate::{NetworkError, NetworkResult, PeerId, NetworkMessage, MessageType};
use nym_core::NymIdentity;
use nym_crypto::{Hash256, SecurityLevel};

use std::collections::HashMap;
use std::time::{Duration, SystemTime};
use std::sync::Arc;

use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use serde::{Deserialize, Serialize};
use rand::{Rng, thread_rng};

#[derive(Debug, Clone)]
pub struct QuIDAuthConfig {
    pub challenge_size: usize,
    pub challenge_timeout: Duration,
    pub max_auth_attempts: u32,
    pub auth_cache_duration: Duration,
    pub require_identity_verification: bool,
    pub min_security_level: SecurityLevel,
}

impl Default for QuIDAuthConfig {
    fn default() -> Self {
        Self {
            challenge_size: 32,
            challenge_timeout: Duration::from_secs(30),
            max_auth_attempts: 3,
            auth_cache_duration: Duration::from_secs(3600),
            require_identity_verification: true,
            min_security_level: SecurityLevel::Level1,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthChallenge {
    pub challenge_id: String,
    pub challenge_data: Vec<u8>,
    pub peer_id: PeerId,
    pub timestamp: SystemTime,
    pub required_security_level: SecurityLevel,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub challenge_id: String,
    pub signature: Vec<u8>,
    pub identity: NymIdentity,
    pub peer_id: PeerId,
    pub timestamp: SystemTime,
}

#[derive(Debug, Clone)]
pub struct AuthSession {
    pub peer_id: PeerId,
    pub challenge: AuthChallenge,
    pub attempts: u32,
    pub created_at: SystemTime,
    pub status: AuthStatus,
}

#[derive(Debug, Clone, PartialEq)]
pub enum AuthStatus {
    Pending,
    Challenged,
    Authenticated,
    Failed,
    Expired,
}

#[derive(Debug, Clone)]
pub struct AuthenticatedPeer {
    pub peer_id: PeerId,
    pub identity: NymIdentity,
    pub security_level: SecurityLevel,
    pub authenticated_at: SystemTime,
    pub last_verified: SystemTime,
    pub trust_score: f64,
}

pub struct QuIDAuthenticator {
    config: QuIDAuthConfig,
    local_identity: NymIdentity,
    auth_sessions: Arc<RwLock<HashMap<String, AuthSession>>>,
    authenticated_peers: Arc<RwLock<HashMap<PeerId, AuthenticatedPeer>>>,
    failed_attempts: Arc<RwLock<HashMap<PeerId, u32>>>,
}

impl QuIDAuthenticator {
    pub fn new(config: QuIDAuthConfig, local_identity: NymIdentity) -> Self {
        info!("Initializing QuID-based network authentication");
        
        Self {
            config,
            local_identity,
            auth_sessions: Arc::new(RwLock::new(HashMap::new())),
            authenticated_peers: Arc::new(RwLock::new(HashMap::new())),
            failed_attempts: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn create_auth_challenge(&self, peer_id: PeerId) -> NetworkResult<AuthChallenge> {
        debug!("Creating authentication challenge for peer: {}", peer_id);

        if self.is_peer_rate_limited(&peer_id).await? {
            return Err(NetworkError::AuthenticationError {
                reason: format!("Peer {} is rate limited due to failed attempts", peer_id),
            });
        }

        let challenge_id = self.generate_challenge_id();
        let mut challenge_data = vec![0u8; self.config.challenge_size];
        thread_rng().fill(&mut challenge_data[..]);

        let challenge = AuthChallenge {
            challenge_id: challenge_id.clone(),
            challenge_data,
            peer_id: peer_id.clone(),
            timestamp: SystemTime::now(),
            required_security_level: self.config.min_security_level,
        };

        let auth_session = AuthSession {
            peer_id: peer_id.clone(),
            challenge: challenge.clone(),
            attempts: 0,
            created_at: SystemTime::now(),
            status: AuthStatus::Challenged,
        };

        self.auth_sessions.write().await.insert(challenge_id.clone(), auth_session);

        info!("Created auth challenge {} for peer {}", challenge_id, peer_id);
        Ok(challenge)
    }

    pub async fn handle_auth_challenge(&self, challenge: AuthChallenge) -> NetworkResult<AuthResponse> {
        info!("Handling authentication challenge: {}", challenge.challenge_id);

        if challenge.required_security_level > self.local_identity.security_level() {
            return Err(NetworkError::AuthenticationError {
                reason: format!(
                    "Insufficient security level: required {:?}, have {:?}",
                    challenge.required_security_level,
                    self.local_identity.security_level()
                ),
            });
        }

        if self.is_challenge_expired(&challenge) {
            return Err(NetworkError::AuthenticationError {
                reason: "Authentication challenge has expired".to_string(),
            });
        }

        let signature = self.local_identity.sign_data(&challenge.challenge_data)
            .map_err(|e| NetworkError::CryptoError {
                reason: format!("Failed to sign challenge: {}", e),
            })?;

        let response = AuthResponse {
            challenge_id: challenge.challenge_id,
            signature,
            identity: self.local_identity.clone(),
            peer_id: PeerId::from_identity(&self.local_identity),
            timestamp: SystemTime::now(),
        };

        Ok(response)
    }

    pub async fn verify_auth_response(&self, response: AuthResponse) -> NetworkResult<bool> {
        info!("Verifying authentication response for challenge: {}", response.challenge_id);

        let mut sessions = self.auth_sessions.write().await;
        let session = sessions.get_mut(&response.challenge_id)
            .ok_or_else(|| NetworkError::AuthenticationError {
                reason: format!("Unknown challenge ID: {}", response.challenge_id),
            })?;

        session.attempts += 1;

        if session.attempts > self.config.max_auth_attempts {
            session.status = AuthStatus::Failed;
            self.record_failed_attempt(&session.peer_id).await;
            return Err(NetworkError::AuthenticationError {
                reason: "Maximum authentication attempts exceeded".to_string(),
            });
        }

        if self.is_challenge_expired(&session.challenge) {
            session.status = AuthStatus::Expired;
            return Err(NetworkError::AuthenticationError {
                reason: "Authentication challenge has expired".to_string(),
            });
        }

        let is_valid = response.identity.verify_signature(
            &session.challenge.challenge_data,
            &response.signature,
        ).map_err(|e| NetworkError::CryptoError {
            reason: format!("Signature verification failed: {}", e),
        })?;

        if !is_valid {
            session.status = AuthStatus::Failed;
            self.record_failed_attempt(&session.peer_id).await;
            return Err(NetworkError::AuthenticationError {
                reason: "Invalid signature in authentication response".to_string(),
            });
        }

        if response.identity.security_level() < self.config.min_security_level {
            session.status = AuthStatus::Failed;
            return Err(NetworkError::AuthenticationError {
                reason: format!(
                    "Insufficient security level: required {:?}, provided {:?}",
                    self.config.min_security_level,
                    response.identity.security_level()
                ),
            });
        }

        session.status = AuthStatus::Authenticated;

        let authenticated_peer = AuthenticatedPeer {
            peer_id: response.peer_id.clone(),
            identity: response.identity,
            security_level: session.challenge.required_security_level,
            authenticated_at: SystemTime::now(),
            last_verified: SystemTime::now(),
            trust_score: 1.0,
        };

        self.authenticated_peers.write().await.insert(response.peer_id, authenticated_peer);

        info!("Successfully authenticated peer: {}", session.peer_id);
        Ok(true)
    }

    pub async fn is_peer_authenticated(&self, peer_id: &PeerId) -> bool {
        let authenticated_peers = self.authenticated_peers.read().await;
        
        if let Some(peer) = authenticated_peers.get(peer_id) {
            !self.is_authentication_expired(peer)
        } else {
            false
        }
    }

    pub async fn get_peer_security_level(&self, peer_id: &PeerId) -> Option<SecurityLevel> {
        let authenticated_peers = self.authenticated_peers.read().await;
        authenticated_peers.get(peer_id).map(|p| p.security_level)
    }

    pub async fn get_peer_trust_score(&self, peer_id: &PeerId) -> Option<f64> {
        let authenticated_peers = self.authenticated_peers.read().await;
        authenticated_peers.get(peer_id).map(|p| p.trust_score)
    }

    pub async fn update_peer_trust_score(&self, peer_id: &PeerId, delta: f64) -> NetworkResult<()> {
        let mut authenticated_peers = self.authenticated_peers.write().await;
        
        if let Some(peer) = authenticated_peers.get_mut(peer_id) {
            peer.trust_score = (peer.trust_score + delta).clamp(0.0, 1.0);
            peer.last_verified = SystemTime::now();
            debug!("Updated trust score for peer {}: {}", peer_id, peer.trust_score);
            Ok(())
        } else {
            Err(NetworkError::AuthenticationError {
                reason: format!("Peer {} not authenticated", peer_id),
            })
        }
    }

    pub async fn revoke_peer_authentication(&self, peer_id: &PeerId) -> NetworkResult<()> {
        info!("Revoking authentication for peer: {}", peer_id);
        
        self.authenticated_peers.write().await.remove(peer_id);
        
        let mut sessions = self.auth_sessions.write().await;
        sessions.retain(|_, session| session.peer_id != *peer_id);
        
        Ok(())
    }

    pub async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.auth_sessions.write().await;
        let mut authenticated_peers = self.authenticated_peers.write().await;
        
        let now = SystemTime::now();
        
        sessions.retain(|_, session| {
            if let Ok(duration) = now.duration_since(session.created_at) {
                duration < self.config.challenge_timeout
            } else {
                false
            }
        });
        
        authenticated_peers.retain(|_, peer| {
            !self.is_authentication_expired(peer)
        });
        
        debug!("Cleaned up expired auth sessions and peer authentications");
    }

    pub async fn get_authenticated_peers(&self) -> Vec<PeerId> {
        let authenticated_peers = self.authenticated_peers.read().await;
        authenticated_peers.keys().cloned().collect()
    }

    pub async fn get_auth_statistics(&self) -> AuthStatistics {
        let sessions = self.auth_sessions.read().await;
        let authenticated_peers = self.authenticated_peers.read().await;
        let failed_attempts = self.failed_attempts.read().await;

        AuthStatistics {
            active_sessions: sessions.len(),
            authenticated_peers: authenticated_peers.len(),
            total_failed_attempts: failed_attempts.values().sum(),
            average_trust_score: if authenticated_peers.is_empty() {
                0.0
            } else {
                authenticated_peers.values().map(|p| p.trust_score).sum::<f64>() / authenticated_peers.len() as f64
            },
        }
    }

    async fn is_peer_rate_limited(&self, peer_id: &PeerId) -> NetworkResult<bool> {
        let failed_attempts = self.failed_attempts.read().await;
        
        if let Some(&attempts) = failed_attempts.get(peer_id) {
            Ok(attempts >= self.config.max_auth_attempts)
        } else {
            Ok(false)
        }
    }

    async fn record_failed_attempt(&self, peer_id: &PeerId) {
        let mut failed_attempts = self.failed_attempts.write().await;
        let attempts = failed_attempts.entry(peer_id.clone()).or_insert(0);
        *attempts += 1;
        
        warn!("Recorded failed auth attempt for peer {}: {} total", peer_id, attempts);
    }

    fn generate_challenge_id(&self) -> String {
        use sha3::{Digest, Sha3_256};
        
        let mut rng = thread_rng();
        let mut random_bytes = [0u8; 16];
        rng.fill(&mut random_bytes);
        
        let mut hasher = Sha3_256::new();
        hasher.update(&random_bytes);
        hasher.update(&SystemTime::now().duration_since(SystemTime::UNIX_EPOCH)
            .unwrap_or_default().as_nanos().to_be_bytes());
        
        hex::encode(hasher.finalize())[..16].to_string()
    }

    fn is_challenge_expired(&self, challenge: &AuthChallenge) -> bool {
        if let Ok(duration) = SystemTime::now().duration_since(challenge.timestamp) {
            duration > self.config.challenge_timeout
        } else {
            true
        }
    }

    fn is_authentication_expired(&self, peer: &AuthenticatedPeer) -> bool {
        if let Ok(duration) = SystemTime::now().duration_since(peer.authenticated_at) {
            duration > self.config.auth_cache_duration
        } else {
            true
        }
    }
}

#[derive(Debug, Clone)]
pub struct AuthStatistics {
    pub active_sessions: usize,
    pub authenticated_peers: usize,
    pub total_failed_attempts: u32,
    pub average_trust_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuthMessage {
    Challenge(AuthChallenge),
    Response(AuthResponse),
    AuthSuccess { peer_id: PeerId },
    AuthFailure { peer_id: PeerId, reason: String },
}

pub async fn create_quid_authenticator(
    config: QuIDAuthConfig,
    local_identity: NymIdentity,
) -> QuIDAuthenticator {
    QuIDAuthenticator::new(config, local_identity)
}