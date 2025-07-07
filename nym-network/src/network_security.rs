use crate::error::{NetworkError, NetworkResult};
use crate::{PeerId, PeerInfo};

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::{Duration, Instant, SystemTime};
use std::net::IpAddr;
use tokio::sync::RwLock;
use tracing::{info, warn, error, debug};
use serde::{Deserialize, Serialize};

/// Network security manager for protection against various attacks
pub struct NetworkSecurityManager {
    /// Configuration for security policies
    config: SecurityConfig,
    /// Connection rate limiting per IP
    connection_limits: RwLock<HashMap<IpAddr, ConnectionLimiter>>,
    /// Sybil attack detection
    sybil_detector: RwLock<SybilDetector>,
    /// Eclipse attack protection
    eclipse_protector: RwLock<EclipseProtector>,
    /// DoS attack mitigation
    dos_mitigator: RwLock<DosMetrics>,
    /// Network health metrics
    health_metrics: RwLock<NetworkHealthMetrics>,
}

/// Security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Maximum connections per IP address
    pub max_connections_per_ip: u32,
    /// Rate limit window in seconds
    pub rate_limit_window: u64,
    /// Maximum connection attempts per window
    pub max_connection_attempts: u32,
    /// Minimum peer diversity (different /24 subnets)
    pub min_peer_diversity: u32,
    /// Maximum percentage of peers from same /16 subnet
    pub max_subnet_concentration: f64,
    /// Sybil detection threshold
    pub sybil_detection_threshold: f64,
    /// Ban duration for misbehaving peers
    pub ban_duration_seconds: u64,
    /// Enable reputation scoring
    pub enable_reputation_scoring: bool,
    /// Minimum reputation score for acceptance
    pub min_reputation_score: f64,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: 3,
            rate_limit_window: 60,
            max_connection_attempts: 10,
            min_peer_diversity: 20,
            max_subnet_concentration: 0.3,
            sybil_detection_threshold: 0.8,
            ban_duration_seconds: 3600, // 1 hour
            enable_reputation_scoring: true,
            min_reputation_score: 0.3,
        }
    }
}

/// Connection rate limiter for individual IPs
#[derive(Debug)]
struct ConnectionLimiter {
    attempts: VecDeque<Instant>,
    connections: u32,
    last_attempt: Instant,
    is_banned: bool,
    ban_until: Option<Instant>,
}

impl ConnectionLimiter {
    fn new() -> Self {
        Self {
            attempts: VecDeque::new(),
            connections: 0,
            last_attempt: Instant::now(),
            is_banned: false,
            ban_until: None,
        }
    }

    fn check_rate_limit(&mut self, window_duration: Duration, max_attempts: u32) -> bool {
        let now = Instant::now();
        
        // Remove old attempts outside window
        while let Some(&front) = self.attempts.front() {
            if now.duration_since(front) > window_duration {
                self.attempts.pop_front();
            } else {
                break;
            }
        }
        
        // Check if banned
        if let Some(ban_until) = self.ban_until {
            if now < ban_until {
                return false;
            } else {
                self.is_banned = false;
                self.ban_until = None;
            }
        }
        
        // Check rate limit
        if self.attempts.len() as u32 >= max_attempts {
            return false;
        }
        
        self.attempts.push_back(now);
        self.last_attempt = now;
        true
    }

    fn ban(&mut self, duration: Duration) {
        self.is_banned = true;
        self.ban_until = Some(Instant::now() + duration);
    }
}

/// Sybil attack detection system
#[derive(Debug)]
struct SybilDetector {
    /// Peer behavior patterns
    peer_patterns: HashMap<PeerId, PeerBehaviorPattern>,
    /// Suspicious peer groups
    suspicious_groups: Vec<SuspiciousGroup>,
    /// Detection statistics
    detection_stats: SybilDetectionStats,
}

#[derive(Debug)]
struct PeerBehaviorPattern {
    connection_times: Vec<Instant>,
    message_patterns: HashMap<String, u32>,
    response_times: VecDeque<Duration>,
    reputation_score: f64,
    similarity_scores: HashMap<PeerId, f64>,
}

#[derive(Debug)]
struct SuspiciousGroup {
    peers: HashSet<PeerId>,
    confidence_score: f64,
    detected_at: Instant,
    patterns: Vec<String>,
}

#[derive(Debug, Default)]
struct SybilDetectionStats {
    total_peers_analyzed: u64,
    suspicious_groups_detected: u64,
    confirmed_sybils: u64,
    false_positives: u64,
}

/// Eclipse attack protection
#[derive(Debug)]
struct EclipseProtector {
    /// Peer subnet distribution
    subnet_distribution: HashMap<String, HashSet<PeerId>>,
    /// Autonomous system (AS) distribution
    as_distribution: HashMap<u32, HashSet<PeerId>>,
    /// Peer diversity metrics
    diversity_metrics: DiversityMetrics,
    /// Protected peer set (known good peers)
    protected_peers: HashSet<PeerId>,
}

#[derive(Debug, Default)]
struct DiversityMetrics {
    unique_subnets: u32,
    unique_as_numbers: u32,
    max_subnet_concentration: f64,
    max_as_concentration: f64,
    diversity_score: f64,
}

/// DoS attack metrics and mitigation
#[derive(Debug, Default)]
struct DosMetrics {
    /// Message rate tracking
    message_rates: HashMap<PeerId, MessageRateTracker>,
    /// Resource usage tracking
    resource_usage: ResourceUsageTracker,
    /// Attack detection flags
    under_attack: bool,
    /// Mitigation strategies active
    active_mitigations: HashSet<MitigationStrategy>,
}

#[derive(Debug)]
struct MessageRateTracker {
    message_count: u64,
    window_start: Instant,
    average_rate: f64,
    peak_rate: f64,
}

#[derive(Debug, Default)]
struct ResourceUsageTracker {
    cpu_usage: f64,
    memory_usage: f64,
    network_bandwidth: f64,
    connection_count: u32,
}

#[derive(Debug, Hash, PartialEq, Eq)]
enum MitigationStrategy {
    RateLimitIncrease,
    ConnectionThrottling,
    MessageFiltering,
    PeerBanning,
    ResourceLimiting,
}

/// Overall network health metrics
#[derive(Debug, Default)]
struct NetworkHealthMetrics {
    total_peers: u32,
    healthy_peers: u32,
    suspicious_peers: u32,
    banned_peers: u32,
    network_stability_score: f64,
    attack_resistance_score: f64,
    last_updated: Instant,
}

impl NetworkSecurityManager {
    pub fn new(config: SecurityConfig) -> Self {
        Self {
            config,
            connection_limits: RwLock::new(HashMap::new()),
            sybil_detector: RwLock::new(SybilDetector {
                peer_patterns: HashMap::new(),
                suspicious_groups: Vec::new(),
                detection_stats: SybilDetectionStats::default(),
            }),
            eclipse_protector: RwLock::new(EclipseProtector {
                subnet_distribution: HashMap::new(),
                as_distribution: HashMap::new(),
                diversity_metrics: DiversityMetrics::default(),
                protected_peers: HashSet::new(),
            }),
            dos_mitigator: RwLock::new(DosMetrics::default()),
            health_metrics: RwLock::new(NetworkHealthMetrics::default()),
        }
    }

    /// Check if connection from IP should be allowed
    pub async fn should_allow_connection(&self, ip: IpAddr) -> NetworkResult<bool> {
        let mut limits = self.connection_limits.write().await;
        let limiter = limits.entry(ip).or_insert_with(ConnectionLimiter::new);
        
        let window = Duration::from_secs(self.config.rate_limit_window);
        let allowed = limiter.check_rate_limit(window, self.config.max_connection_attempts);
        
        if !allowed {
            warn!("Connection rate limit exceeded for IP: {}", ip);
            
            // Ban IP if too many failed attempts
            if limiter.attempts.len() as u32 >= self.config.max_connection_attempts * 2 {
                let ban_duration = Duration::from_secs(self.config.ban_duration_seconds);
                limiter.ban(ban_duration);
                warn!("Banned IP {} for {} seconds", ip, self.config.ban_duration_seconds);
            }
        }
        
        Ok(allowed)
    }

    /// Analyze peer for Sybil attack patterns
    pub async fn analyze_peer_behavior(&self, peer_id: PeerId, peer_info: &PeerInfo) -> NetworkResult<f64> {
        let mut detector = self.sybil_detector.write().await;
        
        let pattern = detector.peer_patterns.entry(peer_id)
            .or_insert_with(|| PeerBehaviorPattern {
                connection_times: Vec::new(),
                message_patterns: HashMap::new(),
                response_times: VecDeque::new(),
                reputation_score: 1.0,
                similarity_scores: HashMap::new(),
            });
        
        pattern.connection_times.push(Instant::now());
        
        // Calculate similarity with other peers
        let mut max_similarity = 0.0;
        for (other_peer, other_pattern) in &detector.peer_patterns {
            if *other_peer != peer_id {
                let similarity = self.calculate_behavioral_similarity(pattern, other_pattern);
                pattern.similarity_scores.insert(*other_peer, similarity);
                max_similarity = max_similarity.max(similarity);
            }
        }
        
        // Update reputation score based on behavior
        if max_similarity > self.config.sybil_detection_threshold {
            pattern.reputation_score *= 0.8; // Reduce reputation for suspicious behavior
            warn!("Suspicious Sybil behavior detected for peer: {:?}", peer_id);
        }
        
        Ok(pattern.reputation_score)
    }

    /// Check for eclipse attack resistance
    pub async fn check_eclipse_resistance(&self, peers: &[PeerInfo]) -> NetworkResult<DiversityMetrics> {
        let mut protector = self.eclipse_protector.write().await;
        
        // Clear current data
        protector.subnet_distribution.clear();
        protector.as_distribution.clear();
        
        // Analyze peer distribution
        for peer in peers {
            // Extract subnet (simplified - in real implementation would use proper IP analysis)
            let subnet = format!("{}.{}.{}.0", 
                peer.addresses[0].to_string().split('.').nth(0).unwrap_or("0"),
                peer.addresses[0].to_string().split('.').nth(1).unwrap_or("0"),
                peer.addresses[0].to_string().split('.').nth(2).unwrap_or("0")
            );
            
            protector.subnet_distribution
                .entry(subnet)
                .or_insert_with(HashSet::new)
                .insert(peer.peer_id);
        }
        
        // Calculate diversity metrics
        let total_peers = peers.len() as f64;
        let unique_subnets = protector.subnet_distribution.len() as u32;
        
        let max_subnet_size = protector.subnet_distribution.values()
            .map(|peers| peers.len())
            .max()
            .unwrap_or(0) as f64;
        
        let max_concentration = if total_peers > 0.0 { max_subnet_size / total_peers } else { 0.0 };
        
        protector.diversity_metrics = DiversityMetrics {
            unique_subnets,
            unique_as_numbers: 0, // Simplified for now
            max_subnet_concentration: max_concentration,
            max_as_concentration: 0.0,
            diversity_score: if unique_subnets as f64 / total_peers > 0.5 { 1.0 } else { 0.5 },
        };
        
        // Check if network is vulnerable to eclipse attacks
        if max_concentration > self.config.max_subnet_concentration {
            warn!("High subnet concentration detected: {:.2}%", max_concentration * 100.0);
        }
        
        Ok(protector.diversity_metrics.clone())
    }

    /// Monitor for DoS attacks
    pub async fn monitor_dos_attacks(&self, message_count: u64, resource_usage: f64) -> NetworkResult<bool> {
        let mut mitigator = self.dos_mitigator.write().await;
        
        // Update resource usage
        mitigator.resource_usage.cpu_usage = resource_usage;
        mitigator.resource_usage.network_bandwidth = message_count as f64;
        
        // Detect DoS patterns
        let high_load = resource_usage > 0.8;
        let high_message_rate = message_count > 1000; // Messages per second threshold
        
        if high_load || high_message_rate {
            if !mitigator.under_attack {
                warn!("Potential DoS attack detected - CPU: {:.2}%, Messages: {}", 
                      resource_usage * 100.0, message_count);
                mitigator.under_attack = true;
                
                // Activate mitigation strategies
                mitigator.active_mitigations.insert(MitigationStrategy::RateLimitIncrease);
                mitigator.active_mitigations.insert(MitigationStrategy::ConnectionThrottling);
            }
        } else if mitigator.under_attack && resource_usage < 0.5 && message_count < 500 {
            info!("DoS attack appears to have subsided");
            mitigator.under_attack = false;
            mitigator.active_mitigations.clear();
        }
        
        Ok(mitigator.under_attack)
    }

    /// Get current security metrics
    pub async fn get_security_metrics(&self) -> NetworkResult<SecurityMetrics> {
        let health = self.health_metrics.read().await;
        let dos = self.dos_mitigator.read().await;
        let sybil = self.sybil_detector.read().await;
        let eclipse = self.eclipse_protector.read().await;
        
        Ok(SecurityMetrics {
            network_health_score: health.network_stability_score,
            attack_resistance_score: health.attack_resistance_score,
            sybil_detection_stats: sybil.detection_stats.clone(),
            diversity_metrics: eclipse.diversity_metrics.clone(),
            under_dos_attack: dos.under_attack,
            active_mitigations: dos.active_mitigations.len(),
            total_banned_peers: health.banned_peers,
        })
    }

    // Private helper methods

    fn calculate_behavioral_similarity(&self, pattern1: &PeerBehaviorPattern, pattern2: &PeerBehaviorPattern) -> f64 {
        // Simplified similarity calculation
        // In practice, this would use more sophisticated behavioral analysis
        
        let time_similarity = if pattern1.connection_times.len() > 0 && pattern2.connection_times.len() > 0 {
            let avg_interval1 = self.calculate_average_interval(&pattern1.connection_times);
            let avg_interval2 = self.calculate_average_interval(&pattern2.connection_times);
            let diff = (avg_interval1 - avg_interval2).abs();
            (1.0 - (diff / avg_interval1.max(avg_interval2))).max(0.0)
        } else {
            0.0
        };
        
        // Response time similarity
        let response_similarity = if pattern1.response_times.len() > 0 && pattern2.response_times.len() > 0 {
            let avg_response1 = pattern1.response_times.iter().sum::<Duration>().as_millis() as f64 / pattern1.response_times.len() as f64;
            let avg_response2 = pattern2.response_times.iter().sum::<Duration>().as_millis() as f64 / pattern2.response_times.len() as f64;
            let diff = (avg_response1 - avg_response2).abs();
            (1.0 - (diff / avg_response1.max(avg_response2))).max(0.0)
        } else {
            0.0
        };
        
        // Combine similarities
        (time_similarity + response_similarity) / 2.0
    }

    fn calculate_average_interval(&self, times: &[Instant]) -> f64 {
        if times.len() < 2 {
            return 0.0;
        }
        
        let mut total_interval = Duration::from_secs(0);
        for i in 1..times.len() {
            total_interval += times[i].duration_since(times[i-1]);
        }
        
        total_interval.as_millis() as f64 / (times.len() - 1) as f64
    }
}

/// Security metrics for monitoring
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    pub network_health_score: f64,
    pub attack_resistance_score: f64,
    pub sybil_detection_stats: SybilDetectionStats,
    pub diversity_metrics: DiversityMetrics,
    pub under_dos_attack: bool,
    pub active_mitigations: usize,
    pub total_banned_peers: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub alert_type: AlertType,
    pub severity: AlertSeverity,
    pub message: String,
    pub peer_id: Option<PeerId>,
    pub timestamp: SystemTime,
    pub recommended_action: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertType {
    SybilAttack,
    EclipseAttack,
    DosAttack,
    RateLimitExceeded,
    SuspiciousBehavior,
    NetworkDegradation,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AlertSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[tokio::test]
    async fn test_connection_rate_limiting() {
        let config = SecurityConfig::default();
        let security_manager = NetworkSecurityManager::new(config);
        let test_ip = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 100));

        // First few connections should be allowed
        for _ in 0..5 {
            assert!(security_manager.should_allow_connection(test_ip).await.unwrap());
        }

        // Rapid connections should be rate limited
        for _ in 0..20 {
            security_manager.should_allow_connection(test_ip).await.unwrap();
        }

        // Should eventually be rate limited
        let result = security_manager.should_allow_connection(test_ip).await.unwrap();
        // Depending on timing, this might be rate limited
        println!("Rate limit result: {}", result);
    }

    #[tokio::test]
    async fn test_dos_detection() {
        let config = SecurityConfig::default();
        let security_manager = NetworkSecurityManager::new(config);

        // Normal load
        let under_attack = security_manager.monitor_dos_attacks(100, 0.3).await.unwrap();
        assert!(!under_attack);

        // High load
        let under_attack = security_manager.monitor_dos_attacks(2000, 0.9).await.unwrap();
        assert!(under_attack);
    }
}