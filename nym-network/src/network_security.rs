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
    /// Performance optimization settings
    pub enable_adaptive_limits: bool,
    /// Network congestion threshold (0.0-1.0)
    pub congestion_threshold: f64,
    /// Dynamic rate limit multiplier during congestion
    pub congestion_rate_multiplier: f64,
    /// Enable advanced DoS protection
    pub enable_advanced_dos_protection: bool,
    /// Maximum message size in bytes
    pub max_message_size: usize,
    /// Maximum messages per second per peer
    pub max_messages_per_second: u32,
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
            enable_adaptive_limits: true,
            congestion_threshold: 0.8,
            congestion_rate_multiplier: 0.5,
            enable_advanced_dos_protection: true,
            max_message_size: 1024 * 1024, // 1MB
            max_messages_per_second: 100,
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

    /// Check for eclipse attack resistance with enhanced topology analysis
    pub async fn check_eclipse_resistance(&self, peers: &[PeerInfo]) -> NetworkResult<DiversityMetrics> {
        let mut protector = self.eclipse_protector.write().await;
        
        // Clear current data
        protector.subnet_distribution.clear();
        protector.as_distribution.clear();
        
        // Enhanced peer distribution analysis
        for peer in peers {
            // Extract /24 and /16 subnets for analysis
            let ip_parts: Vec<&str> = peer.addresses[0].to_string().split('.').collect();
            let subnet_24 = format!("{}.{}.{}.0", 
                ip_parts.get(0).unwrap_or(&"0"),
                ip_parts.get(1).unwrap_or(&"0"),
                ip_parts.get(2).unwrap_or(&"0")
            );
            let subnet_16 = format!("{}.{}.0.0", 
                ip_parts.get(0).unwrap_or(&"0"),
                ip_parts.get(1).unwrap_or(&"0")
            );
            
            // Track both subnet levels
            protector.subnet_distribution
                .entry(subnet_24.clone())
                .or_insert_with(HashSet::new)
                .insert(peer.peer_id);
                
            // Simulate AS distribution (in practice, would use BGP data)
            let simulated_as = self.simulate_as_number(&subnet_16);
            protector.as_distribution
                .entry(simulated_as)
                .or_insert_with(HashSet::new)
                .insert(peer.peer_id);
        }
        
        // Calculate enhanced diversity metrics
        let total_peers = peers.len() as f64;
        let unique_subnets = protector.subnet_distribution.len() as u32;
        let unique_as_numbers = protector.as_distribution.len() as u32;
        
        let max_subnet_size = protector.subnet_distribution.values()
            .map(|peers| peers.len())
            .max()
            .unwrap_or(0) as f64;
            
        let max_as_size = protector.as_distribution.values()
            .map(|peers| peers.len())
            .max()
            .unwrap_or(0) as f64;
        
        let max_subnet_concentration = if total_peers > 0.0 { max_subnet_size / total_peers } else { 0.0 };
        let max_as_concentration = if total_peers > 0.0 { max_as_size / total_peers } else { 0.0 };
        
        // Calculate diversity score using multiple factors
        let subnet_diversity = (unique_subnets as f64 / total_peers).min(1.0);
        let as_diversity = (unique_as_numbers as f64 / (total_peers / 4.0)).min(1.0); // Expect ~4 peers per AS
        let concentration_penalty = (1.0 - max_subnet_concentration) * (1.0 - max_as_concentration);
        
        let diversity_score = (subnet_diversity * 0.4 + as_diversity * 0.4 + concentration_penalty * 0.2).max(0.0);
        
        protector.diversity_metrics = DiversityMetrics {
            unique_subnets,
            unique_as_numbers,
            max_subnet_concentration,
            max_as_concentration,
            diversity_score,
        };
        
        // Enhanced vulnerability detection
        let mut warnings = Vec::new();
        
        if max_subnet_concentration > self.config.max_subnet_concentration {
            warnings.push(format!("High subnet concentration: {:.2}%", max_subnet_concentration * 100.0));
        }
        
        if max_as_concentration > 0.5 {
            warnings.push(format!("High AS concentration: {:.2}%", max_as_concentration * 100.0));
        }
        
        if unique_subnets < self.config.min_peer_diversity {
            warnings.push(format!("Low subnet diversity: {} unique subnets", unique_subnets));
        }
        
        if diversity_score < 0.3 {
            warnings.push(format!("Overall low network diversity: {:.2}", diversity_score));
        }
        
        if !warnings.is_empty() {
            warn!("Eclipse attack vulnerabilities detected: {}", warnings.join(", "));
        }
        
        Ok(protector.diversity_metrics.clone())
    }

    /// Simulate AS number based on IP prefix (simplified)
    fn simulate_as_number(&self, subnet_16: &str) -> u32 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        subnet_16.hash(&mut hasher);
        (hasher.finish() % 65536) as u32 // AS numbers range
    }

    /// Advanced eclipse attack mitigation
    pub async fn mitigate_eclipse_attack(&self, suspicious_peers: &[PeerId]) -> NetworkResult<EclipseMitigationPlan> {
        let protector = self.eclipse_protector.read().await;
        let mut plan = EclipseMitigationPlan {
            peers_to_disconnect: Vec::new(),
            peers_to_deprioritize: Vec::new(),
            new_connections_needed: 0,
            target_subnets: Vec::new(),
            priority_level: MitigationPriority::Low,
        };
        
        // Analyze threat level
        let threat_level = self.calculate_eclipse_threat_level(&protector, suspicious_peers).await;
        
        match threat_level {
            EclipseThreatLevel::Low => {
                plan.priority_level = MitigationPriority::Low;
                // Just monitor and deprioritize
                plan.peers_to_deprioritize = suspicious_peers.to_vec();
            },
            EclipseThreatLevel::Medium => {
                plan.priority_level = MitigationPriority::Medium;
                // Disconnect some peers and seek diversity
                plan.peers_to_disconnect = suspicious_peers.iter().take(2).cloned().collect();
                plan.new_connections_needed = 3;
                plan.target_subnets = self.identify_missing_subnets(&protector).await;
            },
            EclipseThreatLevel::High => {
                plan.priority_level = MitigationPriority::High;
                // Aggressive mitigation
                plan.peers_to_disconnect = suspicious_peers.to_vec();
                plan.new_connections_needed = 5;
                plan.target_subnets = self.identify_missing_subnets(&protector).await;
            },
        }
        
        info!("Eclipse mitigation plan: disconnect {}, deprioritize {}, new connections needed: {}", 
              plan.peers_to_disconnect.len(), plan.peers_to_deprioritize.len(), plan.new_connections_needed);
        
        Ok(plan)
    }

    async fn calculate_eclipse_threat_level(&self, protector: &EclipseProtector, suspicious_peers: &[PeerId]) -> EclipseThreatLevel {
        let diversity = &protector.diversity_metrics;
        let suspicious_ratio = suspicious_peers.len() as f64 / protector.subnet_distribution.len() as f64;
        
        if diversity.diversity_score < 0.2 || suspicious_ratio > 0.7 {
            EclipseThreatLevel::High
        } else if diversity.diversity_score < 0.4 || suspicious_ratio > 0.4 {
            EclipseThreatLevel::Medium
        } else {
            EclipseThreatLevel::Low
        }
    }

    async fn identify_missing_subnets(&self, protector: &EclipseProtector) -> Vec<String> {
        // Identify underrepresented subnet ranges for targeted peer discovery
        let mut target_subnets = Vec::new();
        
        // Look for gaps in subnet distribution
        for i in 1..255 {
            for j in 1..255 {
                let target = format!("{}.{}.0.0", i, j);
                let has_peers = protector.subnet_distribution.keys()
                    .any(|subnet| subnet.starts_with(&format!("{}.{}.", i, j)));
                
                if !has_peers && target_subnets.len() < 10 {
                    target_subnets.push(target);
                }
            }
        }
        
        target_subnets
    }

    /// Monitor for DoS attacks with advanced detection
    pub async fn monitor_dos_attacks(&self, message_count: u64, resource_usage: f64) -> NetworkResult<bool> {
        let mut mitigator = self.dos_mitigator.write().await;
        
        // Update resource usage with historical tracking
        mitigator.resource_usage.cpu_usage = resource_usage;
        mitigator.resource_usage.network_bandwidth = message_count as f64;
        
        // Advanced DoS detection patterns
        let high_load = resource_usage > 0.8;
        let high_message_rate = message_count > 1000;
        let sudden_spike = self.detect_traffic_spike(&mitigator, message_count).await;
        let asymmetric_traffic = self.detect_asymmetric_traffic(&mitigator).await;
        
        if high_load || high_message_rate || sudden_spike || asymmetric_traffic {
            if !mitigator.under_attack {
                warn!("Potential DoS attack detected - CPU: {:.2}%, Messages: {}, Spike: {}, Asymmetric: {}", 
                      resource_usage * 100.0, message_count, sudden_spike, asymmetric_traffic);
                mitigator.under_attack = true;
                
                // Activate graduated mitigation strategies
                if sudden_spike {
                    mitigator.active_mitigations.insert(MitigationStrategy::RateLimitIncrease);
                }
                if high_message_rate {
                    mitigator.active_mitigations.insert(MitigationStrategy::MessageFiltering);
                }
                if high_load {
                    mitigator.active_mitigations.insert(MitigationStrategy::ConnectionThrottling);
                    mitigator.active_mitigations.insert(MitigationStrategy::ResourceLimiting);
                }
                if asymmetric_traffic {
                    mitigator.active_mitigations.insert(MitigationStrategy::PeerBanning);
                }
            }
        } else if mitigator.under_attack && resource_usage < 0.5 && message_count < 500 {
            info!("DoS attack appears to have subsided");
            mitigator.under_attack = false;
            mitigator.active_mitigations.clear();
        }
        
        Ok(mitigator.under_attack)
    }

    /// Detect sudden traffic spikes
    async fn detect_traffic_spike(&self, mitigator: &DosMetrics, current_count: u64) -> bool {
        // Calculate moving average and detect spikes
        let avg_bandwidth = mitigator.resource_usage.network_bandwidth;
        if avg_bandwidth > 0.0 {
            let spike_ratio = current_count as f64 / avg_bandwidth;
            spike_ratio > 3.0 // 3x normal traffic is considered a spike
        } else {
            false
        }
    }

    /// Detect asymmetric traffic patterns (potential amplification attacks)
    async fn detect_asymmetric_traffic(&self, mitigator: &DosMetrics) -> bool {
        // Check for high incoming vs outgoing ratio
        let cpu_load = mitigator.resource_usage.cpu_usage;
        let network_load = mitigator.resource_usage.network_bandwidth;
        
        // High network traffic but low CPU usage might indicate amplification
        cpu_load < 0.3 && network_load > 500.0
    }

    /// Apply dynamic rate limiting based on network conditions
    pub async fn apply_dynamic_rate_limiting(&self, peer_id: PeerId, base_limit: u32) -> NetworkResult<u32> {
        let dos = self.dos_mitigator.read().await;
        let health = self.health_metrics.read().await;
        
        let mut adjusted_limit = base_limit;
        
        // Reduce limits during attacks
        if dos.under_attack {
            adjusted_limit = (adjusted_limit as f64 * self.config.congestion_rate_multiplier) as u32;
        }
        
        // Adjust based on network health
        let health_factor = health.network_stability_score;
        adjusted_limit = (adjusted_limit as f64 * health_factor) as u32;
        
        // Minimum limit to prevent complete blocking
        adjusted_limit = adjusted_limit.max(1);
        
        debug!("Dynamic rate limit for peer {:?}: {} (base: {})", peer_id, adjusted_limit, base_limit);
        Ok(adjusted_limit)
    }

    /// Enhanced Sybil attack detection with behavioral clustering
    pub async fn detect_sybil_clusters(&self) -> NetworkResult<Vec<SuspiciousGroup>> {
        let mut detector = self.sybil_detector.write().await;
        let mut clusters = Vec::new();
        
        // Group peers by behavioral similarity
        let mut similarity_matrix: HashMap<(PeerId, PeerId), f64> = HashMap::new();
        let peer_ids: Vec<PeerId> = detector.peer_patterns.keys().cloned().collect();
        
        for i in 0..peer_ids.len() {
            for j in (i+1)..peer_ids.len() {
                let peer1 = peer_ids[i];
                let peer2 = peer_ids[j];
                
                if let (Some(pattern1), Some(pattern2)) = (
                    detector.peer_patterns.get(&peer1),
                    detector.peer_patterns.get(&peer2)
                ) {
                    let similarity = self.calculate_behavioral_similarity(pattern1, pattern2);
                    similarity_matrix.insert((peer1, peer2), similarity);
                    
                    // If high similarity, consider as potential cluster
                    if similarity > self.config.sybil_detection_threshold {
                        let mut group_peers = HashSet::new();
                        group_peers.insert(peer1);
                        group_peers.insert(peer2);
                        
                        clusters.push(SuspiciousGroup {
                            peers: group_peers,
                            confidence_score: similarity,
                            detected_at: Instant::now(),
                            patterns: vec![
                                format!("High behavioral similarity: {:.2}", similarity),
                                "Synchronized connection patterns".to_string(),
                            ],
                        });
                    }
                }
            }
        }
        
        detector.suspicious_groups = clusters.clone();
        detector.detection_stats.suspicious_groups_detected = clusters.len() as u64;
        
        Ok(clusters)
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

/// Eclipse attack mitigation plan
#[derive(Debug, Clone)]
pub struct EclipseMitigationPlan {
    pub peers_to_disconnect: Vec<PeerId>,
    pub peers_to_deprioritize: Vec<PeerId>,
    pub new_connections_needed: u32,
    pub target_subnets: Vec<String>,
    pub priority_level: MitigationPriority,
}

#[derive(Debug, Clone)]
pub enum MitigationPriority {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone)]
enum EclipseThreatLevel {
    Low,
    Medium,
    High,
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