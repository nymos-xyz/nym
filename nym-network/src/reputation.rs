//! Network Reputation System
//! Peer reputation tracking and management for network security and quality

use crate::error::{NetworkError, NetworkResult};
use nym_core::NymIdentity;

use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, debug, warn};
use serde::{Deserialize, Serialize};

/// Reputation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationConfig {
    /// Initial reputation score for new peers
    pub initial_score: f64,
    /// Minimum reputation score (can go negative)
    pub min_score: f64,
    /// Maximum reputation score
    pub max_score: f64,
    /// Score decay rate per day
    pub decay_rate: f64,
    /// Positive behavior reward multiplier
    pub positive_multiplier: f64,
    /// Negative behavior penalty multiplier
    pub negative_multiplier: f64,
    /// Time window for behavior aggregation (seconds)
    pub behavior_window: u64,
}

impl Default for ReputationConfig {
    fn default() -> Self {
        Self {
            initial_score: 0.5,
            min_score: -1.0,
            max_score: 1.0,
            decay_rate: 0.01, // 1% decay per day
            positive_multiplier: 1.0,
            negative_multiplier: 2.0, // Penalties are stronger
            behavior_window: 3600, // 1 hour
        }
    }
}

/// Types of behaviors that affect reputation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BehaviorType {
    // Positive behaviors
    SuccessfulConnection,
    ValidMessage,
    HelpfulResponse,
    DataSharing,
    NetworkContribution,
    
    // Negative behaviors  
    FailedConnection,
    InvalidMessage,
    RateLimitViolation,
    SuspiciousActivity,
    NetworkDisruption,
    MaliciousActivity,
}

impl BehaviorType {
    /// Get the reputation impact of this behavior type
    pub fn reputation_impact(&self) -> f64 {
        match self {
            // Positive behaviors
            BehaviorType::SuccessfulConnection => 0.01,
            BehaviorType::ValidMessage => 0.005,
            BehaviorType::HelpfulResponse => 0.02,
            BehaviorType::DataSharing => 0.03,
            BehaviorType::NetworkContribution => 0.05,
            
            // Negative behaviors
            BehaviorType::FailedConnection => -0.005,
            BehaviorType::InvalidMessage => -0.01,
            BehaviorType::RateLimitViolation => -0.02,
            BehaviorType::SuspiciousActivity => -0.05,
            BehaviorType::NetworkDisruption => -0.1,
            BehaviorType::MaliciousActivity => -0.2,
        }
    }
}

/// Reputation score with history tracking
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    current_score: f64,
    base_score: f64,
    last_updated: SystemTime,
    total_interactions: u64,
    positive_interactions: u64,
    negative_interactions: u64,
}

impl ReputationScore {
    pub fn new(initial_score: f64) -> Self {
        Self {
            current_score: initial_score,
            base_score: initial_score,
            last_updated: SystemTime::now(),
            total_interactions: 0,
            positive_interactions: 0,
            negative_interactions: 0,
        }
    }

    pub fn score(&self) -> f64 {
        self.current_score
    }

    pub fn total_interactions(&self) -> u64 {
        self.total_interactions
    }

    pub fn positive_ratio(&self) -> f64 {
        if self.total_interactions == 0 {
            return 0.5; // Neutral for new peers
        }
        self.positive_interactions as f64 / self.total_interactions as f64
    }

    /// Apply time-based decay to the reputation score
    pub fn apply_decay(&mut self, config: &ReputationConfig) {
        let now = SystemTime::now();
        if let Ok(duration) = now.duration_since(self.last_updated) {
            let days = duration.as_secs() as f64 / 86400.0;
            let decay_factor = 1.0 - (config.decay_rate * days);
            
            // Apply decay towards the base score
            let score_diff = self.current_score - self.base_score;
            self.current_score = self.base_score + (score_diff * decay_factor);
            
            // Ensure score stays within bounds
            self.current_score = self.current_score.max(config.min_score).min(config.max_score);
            self.last_updated = now;
        }
    }

    /// Update score based on behavior
    pub fn update_for_behavior(&mut self, behavior: &BehaviorType, config: &ReputationConfig) {
        let impact = behavior.reputation_impact();
        let multiplier = if impact > 0.0 {
            config.positive_multiplier
        } else {
            config.negative_multiplier
        };
        
        let adjusted_impact = impact * multiplier;
        self.current_score += adjusted_impact;
        
        // Apply bounds
        self.current_score = self.current_score.max(config.min_score).min(config.max_score);
        
        // Update interaction counters
        self.total_interactions += 1;
        if impact > 0.0 {
            self.positive_interactions += 1;
        } else {
            self.negative_interactions += 1;
        }
        
        self.last_updated = SystemTime::now();
    }
}

/// Behavior record for tracking peer activities
#[derive(Debug, Clone)]
struct BehaviorRecord {
    behavior_type: BehaviorType,
    timestamp: Instant,
    impact: f64,
    context: Option<String>,
}

/// Peer reputation data
#[derive(Debug)]
struct PeerReputation {
    score: ReputationScore,
    behavior_history: Vec<BehaviorRecord>,
    first_seen: Instant,
    last_activity: Instant,
    connection_count: u32,
    message_count: u64,
}

impl PeerReputation {
    fn new(initial_score: f64) -> Self {
        let now = Instant::now();
        Self {
            score: ReputationScore::new(initial_score),
            behavior_history: Vec::new(),
            first_seen: now,
            last_activity: now,
            connection_count: 0,
            message_count: 0,
        }
    }

    fn add_behavior(&mut self, behavior: BehaviorType, config: &ReputationConfig, context: Option<String>) {
        let now = Instant::now();
        
        // Clean up old behavior records
        let cutoff = now - Duration::from_secs(config.behavior_window);
        self.behavior_history.retain(|record| record.timestamp > cutoff);
        
        // Add new behavior record
        let impact = behavior.reputation_impact();
        self.behavior_history.push(BehaviorRecord {
            behavior_type: behavior.clone(),
            timestamp: now,
            impact,
            context,
        });
        
        // Update reputation score
        self.score.update_for_behavior(&behavior, config);
        self.last_activity = now;
        
        // Update counters
        match behavior {
            BehaviorType::SuccessfulConnection => self.connection_count += 1,
            BehaviorType::ValidMessage | BehaviorType::HelpfulResponse => self.message_count += 1,
            _ => {}
        }
    }

    fn get_recent_behavior_summary(&self, window: Duration) -> (u32, u32) {
        let cutoff = Instant::now() - window;
        let mut positive = 0;
        let mut negative = 0;
        
        for record in &self.behavior_history {
            if record.timestamp > cutoff {
                if record.impact > 0.0 {
                    positive += 1;
                } else {
                    negative += 1;
                }
            }
        }
        
        (positive, negative)
    }
}

/// Main reputation manager
pub struct ReputationManager {
    config: ReputationConfig,
    peer_reputations: RwLock<HashMap<NymIdentity, PeerReputation>>,
    global_stats: RwLock<ReputationGlobalStats>,
}

#[derive(Debug, Default)]
struct ReputationGlobalStats {
    total_peers: usize,
    average_score: f64,
    high_reputation_peers: usize,
    low_reputation_peers: usize,
    total_behaviors_recorded: u64,
}

impl ReputationManager {
    pub fn new(config: ReputationConfig) -> Self {
        info!("Initializing reputation manager");
        
        Self {
            config,
            peer_reputations: RwLock::new(HashMap::new()),
            global_stats: RwLock::new(ReputationGlobalStats::default()),
        }
    }

    /// Get or create reputation score for a peer
    pub async fn get_reputation(&self, peer: &NymIdentity) -> ReputationScore {
        let mut reputations = self.peer_reputations.write().await;
        
        let peer_rep = reputations.entry(peer.clone())
            .or_insert_with(|| PeerReputation::new(self.config.initial_score));
        
        // Apply time-based decay
        peer_rep.score.apply_decay(&self.config);
        
        peer_rep.score.clone()
    }

    /// Record a behavior for a peer
    pub async fn record_behavior(
        &self, 
        peer: &NymIdentity, 
        behavior: BehaviorType,
        context: Option<String>
    ) -> NetworkResult<()> {
        debug!("Recording behavior {:?} for peer {}", behavior, peer.to_string());
        
        let mut reputations = self.peer_reputations.write().await;
        
        let peer_rep = reputations.entry(peer.clone())
            .or_insert_with(|| PeerReputation::new(self.config.initial_score));
        
        peer_rep.add_behavior(behavior, &self.config, context);
        
        // Update global statistics
        drop(reputations);
        self.update_global_stats().await;
        
        Ok(())
    }

    /// Get peers above a certain reputation threshold
    pub async fn get_high_reputation_peers(&self, threshold: f64) -> Vec<(NymIdentity, f64)> {
        let reputations = self.peer_reputations.read().await;
        
        reputations.iter()
            .filter_map(|(peer, peer_rep)| {
                if peer_rep.score.score() >= threshold {
                    Some((peer.clone(), peer_rep.score.score()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get peers below a certain reputation threshold
    pub async fn get_low_reputation_peers(&self, threshold: f64) -> Vec<(NymIdentity, f64)> {
        let reputations = self.peer_reputations.read().await;
        
        reputations.iter()
            .filter_map(|(peer, peer_rep)| {
                if peer_rep.score.score() < threshold {
                    Some((peer.clone(), peer_rep.score.score()))
                } else {
                    None
                }
            })
            .collect()
    }

    /// Get detailed peer information
    pub async fn get_peer_details(&self, peer: &NymIdentity) -> Option<PeerReputationDetails> {
        let reputations = self.peer_reputations.read().await;
        
        if let Some(peer_rep) = reputations.get(peer) {
            let (recent_positive, recent_negative) = peer_rep.get_recent_behavior_summary(
                Duration::from_secs(self.config.behavior_window)
            );
            
            Some(PeerReputationDetails {
                current_score: peer_rep.score.score(),
                total_interactions: peer_rep.score.total_interactions(),
                positive_ratio: peer_rep.score.positive_ratio(),
                connection_count: peer_rep.connection_count,
                message_count: peer_rep.message_count,
                recent_positive_behaviors: recent_positive,
                recent_negative_behaviors: recent_negative,
                first_seen: peer_rep.first_seen,
                last_activity: peer_rep.last_activity,
            })
        } else {
            None
        }
    }

    /// Perform periodic maintenance
    pub async fn periodic_maintenance(&self) -> NetworkResult<()> {
        debug!("Performing reputation system maintenance");
        
        let mut reputations = self.peer_reputations.write().await;
        
        // Apply decay to all scores and clean up old data
        let cutoff = Instant::now() - Duration::from_secs(86400 * 30); // 30 days
        
        reputations.retain(|peer, peer_rep| {
            // Apply decay
            peer_rep.score.apply_decay(&self.config);
            
            // Remove peers that haven't been seen in 30 days
            if peer_rep.last_activity < cutoff {
                debug!("Removing stale peer reputation: {}", peer.to_string());
                false
            } else {
                true
            }
        });
        
        drop(reputations);
        
        // Update global statistics
        self.update_global_stats().await;
        
        Ok(())
    }

    /// Update global reputation statistics
    async fn update_global_stats(&self) {
        let reputations = self.peer_reputations.read().await;
        let mut stats = self.global_stats.write().await;
        
        stats.total_peers = reputations.len();
        
        if stats.total_peers > 0 {
            let total_score: f64 = reputations.values()
                .map(|rep| rep.score.score())
                .sum();
            
            stats.average_score = total_score / stats.total_peers as f64;
            
            stats.high_reputation_peers = reputations.values()
                .filter(|rep| rep.score.score() > 0.7)
                .count();
            
            stats.low_reputation_peers = reputations.values()
                .filter(|rep| rep.score.score() < 0.3)
                .count();
            
            stats.total_behaviors_recorded = reputations.values()
                .map(|rep| rep.score.total_interactions())
                .sum();
        }
    }

    /// Get global reputation statistics
    pub async fn get_global_stats(&self) -> ReputationGlobalStats {
        self.global_stats.read().await.clone()
    }
}

/// Detailed peer reputation information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PeerReputationDetails {
    pub current_score: f64,
    pub total_interactions: u64,
    pub positive_ratio: f64,
    pub connection_count: u32,
    pub message_count: u64,
    pub recent_positive_behaviors: u32,
    pub recent_negative_behaviors: u32,
    pub first_seen: Instant,
    pub last_activity: Instant,
}

/// Clone trait for global stats
impl Clone for ReputationGlobalStats {
    fn clone(&self) -> Self {
        Self {
            total_peers: self.total_peers,
            average_score: self.average_score,
            high_reputation_peers: self.high_reputation_peers,
            low_reputation_peers: self.low_reputation_peers,
            total_behaviors_recorded: self.total_behaviors_recorded,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_reputation_scoring() {
        let config = ReputationConfig::default();
        let manager = ReputationManager::new(config);
        
        let peer = NymIdentity::from_bytes(&[1; 32]).unwrap();
        
        // Initial score should be the default
        let initial_score = manager.get_reputation(&peer).await;
        assert_eq!(initial_score.score(), 0.5);
        
        // Record positive behavior
        manager.record_behavior(&peer, BehaviorType::SuccessfulConnection, None).await.unwrap();
        let updated_score = manager.get_reputation(&peer).await;
        assert!(updated_score.score() > 0.5);
        
        // Record negative behavior
        manager.record_behavior(&peer, BehaviorType::MaliciousActivity, None).await.unwrap();
        let final_score = manager.get_reputation(&peer).await;
        assert!(final_score.score() < updated_score.score());
    }

    #[tokio::test]
    async fn test_reputation_bounds() {
        let config = ReputationConfig::default();
        let manager = ReputationManager::new(config);
        
        let peer = NymIdentity::from_bytes(&[2; 32]).unwrap();
        
        // Record many negative behaviors
        for _ in 0..50 {
            manager.record_behavior(&peer, BehaviorType::MaliciousActivity, None).await.unwrap();
        }
        
        let score = manager.get_reputation(&peer).await;
        assert!(score.score() >= -1.0); // Should not go below minimum
        
        // Record many positive behaviors
        for _ in 0..100 {
            manager.record_behavior(&peer, BehaviorType::NetworkContribution, None).await.unwrap();
        }
        
        let score = manager.get_reputation(&peer).await;
        assert!(score.score() <= 1.0); // Should not exceed maximum
    }

    #[tokio::test]
    async fn test_reputation_filtering() {
        let config = ReputationConfig::default();
        let manager = ReputationManager::new(config);
        
        // Create peers with different reputation levels
        for i in 0..10 {
            let peer = NymIdentity::from_bytes(&[i; 32]).unwrap();
            
            if i < 5 {
                // High reputation peers
                for _ in 0..10 {
                    manager.record_behavior(&peer, BehaviorType::NetworkContribution, None).await.unwrap();
                }
            } else {
                // Low reputation peers
                for _ in 0..5 {
                    manager.record_behavior(&peer, BehaviorType::SuspiciousActivity, None).await.unwrap();
                }
            }
        }
        
        let high_rep_peers = manager.get_high_reputation_peers(0.6).await;
        let low_rep_peers = manager.get_low_reputation_peers(0.4).await;
        
        assert!(high_rep_peers.len() > 0);
        assert!(low_rep_peers.len() > 0);
        assert!(high_rep_peers.len() + low_rep_peers.len() <= 10);
    }
}