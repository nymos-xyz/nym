//! Network Security Optimization
//! Advanced security mechanisms for Nym P2P network including Sybil resistance,
//! eclipse attack prevention, DoS mitigation, and intrusion detection.

use crate::{
    error::{NetworkError, NetworkResult},
    node_registry::NodeRecord,
    reputation::ReputationScore,
};
use nym_core::NymIdentity;
use nym_crypto::Hash256;
use quid_core::QuIDIdentity;

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::IpAddr;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::{RwLock, mpsc};
use tracing::{info, debug, warn, error};
use serde::{Deserialize, Serialize};

/// Network security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityConfig {
    /// Maximum connections per IP address
    pub max_connections_per_ip: usize,
    /// Rate limiting: requests per second per peer
    pub rate_limit_per_peer: u32,
    /// Time window for rate limiting (seconds)
    pub rate_limit_window: u64,
    /// Minimum reputation score to establish connections
    pub min_reputation_threshold: f64,
    /// Maximum failed connection attempts before temporary ban
    pub max_failed_attempts: u32,
    /// Duration of temporary bans (seconds)
    pub ban_duration: u64,
    /// Enable advanced intrusion detection
    pub enable_intrusion_detection: bool,
    /// Enable Sybil attack detection
    pub enable_sybil_detection: bool,
    /// Enable eclipse attack prevention
    pub enable_eclipse_prevention: bool,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            max_connections_per_ip: 10,
            rate_limit_per_peer: 100,
            rate_limit_window: 60,
            min_reputation_threshold: 0.3,
            max_failed_attempts: 5,
            ban_duration: 300, // 5 minutes
            enable_intrusion_detection: true,
            enable_sybil_detection: true,
            enable_eclipse_prevention: true,
        }
    }
}

/// Security threat types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatType {
    SybilAttack,
    EclipseAttack,
    DoSAttack,
    RateLimitViolation,
    SuspiciousActivity,
    InvalidBehavior,
    ConnectionFlooding,
    DataPoisoning,
}

/// Security alert structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAlert {
    pub alert_id: String,
    pub threat_type: ThreatType,
    pub severity: ThreatSeverity,
    pub source_peer: Option<NymIdentity>,
    pub source_ip: Option<IpAddr>,
    pub description: String,
    pub evidence: Vec<String>,
    pub timestamp: SystemTime,
    pub action_taken: SecurityAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ThreatSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityAction {
    None,
    Warning,
    RateLimit,
    TemporaryBan,
    PermanentBan,
    IsolateNode,
    AlertOperator,
}

/// Rate limiting tracker for individual peers
#[derive(Debug)]
struct RateTracker {
    requests: VecDeque<Instant>,
    total_requests: u64,
    violations: u32,
    last_violation: Option<Instant>,
}

impl RateTracker {
    fn new() -> Self {
        Self {
            requests: VecDeque::new(),
            total_requests: 0,
            violations: 0,
            last_violation: None,
        }
    }

    fn check_rate_limit(&mut self, limit: u32, window: Duration) -> bool {
        let now = Instant::now();
        
        // Remove old requests outside the window
        while let Some(&front) = self.requests.front() {
            if now.duration_since(front) > window {
                self.requests.pop_front();
            } else {
                break;
            }
        }
        
        // Check if we're under the limit
        if self.requests.len() < limit as usize {
            self.requests.push_back(now);
            self.total_requests += 1;
            true
        } else {
            self.violations += 1;
            self.last_violation = Some(now);
            false
        }
    }
}

/// Connection tracking for IP-based limits
#[derive(Debug)]
struct ConnectionTracker {
    connections_per_ip: HashMap<IpAddr, usize>,
    failed_attempts: HashMap<IpAddr, (u32, Instant)>,
    banned_ips: HashMap<IpAddr, Instant>,
}

impl ConnectionTracker {
    fn new() -> Self {
        Self {
            connections_per_ip: HashMap::new(),
            failed_attempts: HashMap::new(),
            banned_ips: HashMap::new(),
        }
    }

    fn can_connect(&self, ip: &IpAddr, max_connections: usize) -> bool {
        // Check if IP is banned
        if let Some(&ban_time) = self.banned_ips.get(ip) {
            // Check if ban has expired (handled separately)
            return false;
        }

        // Check connection limit
        let current_connections = self.connections_per_ip.get(ip).unwrap_or(&0);
        *current_connections < max_connections
    }

    fn add_connection(&mut self, ip: IpAddr) {
        *self.connections_per_ip.entry(ip).or_insert(0) += 1;
    }

    fn remove_connection(&mut self, ip: &IpAddr) {
        if let Some(count) = self.connections_per_ip.get_mut(ip) {
            if *count > 0 {
                *count -= 1;
                if *count == 0 {
                    self.connections_per_ip.remove(ip);
                }
            }
        }
    }

    fn record_failed_attempt(&mut self, ip: IpAddr, max_attempts: u32) -> bool {
        let now = Instant::now();
        let (attempts, _) = self.failed_attempts.entry(ip).or_insert((0, now));
        *attempts += 1;
        
        if *attempts >= max_attempts {
            self.banned_ips.insert(ip, now);
            true // IP should be banned
        } else {
            false
        }
    }

    fn cleanup_expired_bans(&mut self, ban_duration: Duration) {
        let now = Instant::now();
        self.banned_ips.retain(|_, &mut ban_time| {
            now.duration_since(ban_time) < ban_duration
        });
    }
}

/// Sybil attack detection using identity clustering
#[derive(Debug)]
struct SybilDetector {
    identity_clusters: HashMap<String, Vec<NymIdentity>>,
    identity_behaviors: HashMap<NymIdentity, BehaviorProfile>,
    suspicious_clusters: HashSet<String>,
}

#[derive(Debug, Clone)]
struct BehaviorProfile {
    connection_patterns: Vec<Instant>,
    message_patterns: Vec<(Instant, u32)>, // (timestamp, message_count)
    peer_interactions: HashSet<NymIdentity>,
    reputation_history: Vec<(Instant, f64)>,
    suspicious_activities: u32,
}

impl BehaviorProfile {
    fn new() -> Self {
        Self {
            connection_patterns: Vec::new(),
            message_patterns: Vec::new(),
            peer_interactions: HashSet::new(),
            reputation_history: Vec::new(),
            suspicious_activities: 0,
        }
    }

    fn is_suspicious(&self) -> bool {
        // Multiple heuristics for suspicious behavior
        let recent_connections = self.connection_patterns.iter()
            .filter(|&&t| Instant::now().duration_since(t) < Duration::from_secs(3600))
            .count();
        
        let low_interaction_count = self.peer_interactions.len() < 3;
        let high_activity_rate = recent_connections > 50;
        let suspicious_count = self.suspicious_activities > 5;
        
        (low_interaction_count && high_activity_rate) || suspicious_count
    }
}

impl SybilDetector {
    fn new() -> Self {
        Self {
            identity_clusters: HashMap::new(),
            identity_behaviors: HashMap::new(),
            suspicious_clusters: HashSet::new(),
        }
    }

    fn analyze_identity(&mut self, identity: &NymIdentity) -> bool {
        let profile = self.identity_behaviors.entry(identity.clone())
            .or_insert_with(BehaviorProfile::new);
        
        profile.connection_patterns.push(Instant::now());
        
        // Cluster identities by behavioral similarities
        let cluster_key = self.generate_cluster_key(profile);
        self.identity_clusters.entry(cluster_key.clone())
            .or_insert_with(Vec::new)
            .push(identity.clone());
        
        // Check if cluster is suspicious
        if let Some(cluster) = self.identity_clusters.get(&cluster_key) {
            if cluster.len() > 10 { // Too many similar identities
                self.suspicious_clusters.insert(cluster_key);
                return true;
            }
        }
        
        profile.is_suspicious()
    }

    fn generate_cluster_key(&self, profile: &BehaviorProfile) -> String {
        // Simple clustering based on behavior patterns
        let connection_frequency = profile.connection_patterns.len();
        let interaction_diversity = profile.peer_interactions.len();
        
        format!("cluster_{}_{}", 
                connection_frequency / 10, 
                interaction_diversity / 5)
    }
}

/// Eclipse attack prevention using diverse peer selection
#[derive(Debug)]
struct EclipsePreventionSystem {
    peer_diversity_map: HashMap<NymIdentity, DiversityMetrics>,
    geographic_distribution: HashMap<String, Vec<NymIdentity>>,
    network_topology: HashMap<NymIdentity, HashSet<NymIdentity>>,
}

#[derive(Debug, Clone)]
struct DiversityMetrics {
    geographic_region: Option<String>,
    autonomous_system: Option<String>,
    connection_count: usize,
    first_seen: Instant,
    last_seen: Instant,
}

impl EclipsePreventionSystem {
    fn new() -> Self {
        Self {
            peer_diversity_map: HashMap::new(),
            geographic_distribution: HashMap::new(),
            network_topology: HashMap::new(),
        }
    }

    fn should_accept_peer(&self, peer: &NymIdentity, peer_ip: &IpAddr) -> bool {
        // Ensure peer diversity to prevent eclipse attacks
        let region = self.estimate_geographic_region(peer_ip);
        
        // Check if we have too many peers from the same region
        if let Some(peers_in_region) = self.geographic_distribution.get(&region) {
            if peers_in_region.len() > 20 { // Max peers per region
                return false;
            }
        }
        
        // Check network topology diversity
        if let Some(connections) = self.network_topology.get(peer) {
            if connections.len() > 100 { // Prevent super-connected nodes
                return false;
            }
        }
        
        true
    }

    fn estimate_geographic_region(&self, ip: &IpAddr) -> String {
        // Simple geographic estimation based on IP ranges
        match ip {
            IpAddr::V4(ipv4) => {
                let octets = ipv4.octets();
                format!("region_{}_{}", octets[0], octets[1] / 64)
            }
            IpAddr::V6(_) => "ipv6_region".to_string(),
        }
    }

    fn update_peer_info(&mut self, peer: &NymIdentity, peer_ip: &IpAddr) {
        let now = Instant::now();
        let region = self.estimate_geographic_region(peer_ip);
        
        let metrics = self.peer_diversity_map.entry(peer.clone())
            .or_insert_with(|| DiversityMetrics {
                geographic_region: Some(region.clone()),
                autonomous_system: None, // Would be determined via BGP lookup
                connection_count: 0,
                first_seen: now,
                last_seen: now,
            });
        
        metrics.last_seen = now;
        metrics.connection_count += 1;
        
        self.geographic_distribution.entry(region)
            .or_insert_with(Vec::new)
            .push(peer.clone());
    }
}

/// Main network security manager
pub struct NetworkSecurityManager {
    config: SecurityConfig,
    rate_trackers: RwLock<HashMap<NymIdentity, RateTracker>>,
    connection_tracker: RwLock<ConnectionTracker>,
    sybil_detector: RwLock<SybilDetector>,
    eclipse_prevention: RwLock<EclipsePreventionSystem>,
    security_alerts: RwLock<Vec<SecurityAlert>>,
    alert_sender: Option<mpsc::UnboundedSender<SecurityAlert>>,
    alert_counter: std::sync::atomic::AtomicU64,
}

impl NetworkSecurityManager {
    pub fn new(config: SecurityConfig) -> Self {
        info!("Initializing network security manager with advanced protection");
        
        Self {
            config,
            rate_trackers: RwLock::new(HashMap::new()),
            connection_tracker: RwLock::new(ConnectionTracker::new()),
            sybil_detector: RwLock::new(SybilDetector::new()),
            eclipse_prevention: RwLock::new(EclipsePreventionSystem::new()),
            security_alerts: RwLock::new(Vec::new()),
            alert_sender: None,
            alert_counter: std::sync::atomic::AtomicU64::new(0),
        }
    }

    pub fn set_alert_channel(&mut self, sender: mpsc::UnboundedSender<SecurityAlert>) {
        self.alert_sender = Some(sender);
    }

    /// Check if a peer can establish a new connection
    pub async fn can_peer_connect(
        &self, 
        peer: &NymIdentity, 
        peer_ip: &IpAddr,
        reputation: &ReputationScore
    ) -> NetworkResult<bool> {
        debug!("Checking connection permission for peer: {} from IP: {}", 
               peer.to_string(), peer_ip);

        // Check reputation threshold
        if reputation.score() < self.config.min_reputation_threshold {
            self.generate_alert(
                ThreatType::SuspiciousActivity,
                ThreatSeverity::Medium,
                Some(peer.clone()),
                Some(*peer_ip),
                "Peer reputation below threshold".to_string(),
                SecurityAction::Warning,
            ).await;
            return Ok(false);
        }

        // Check IP-based connection limits
        let mut conn_tracker = self.connection_tracker.write().await;
        if !conn_tracker.can_connect(peer_ip, self.config.max_connections_per_ip) {
            self.generate_alert(
                ThreatType::ConnectionFlooding,
                ThreatSeverity::High,
                Some(peer.clone()),
                Some(*peer_ip),
                "IP connection limit exceeded".to_string(),
                SecurityAction::TemporaryBan,
            ).await;
            return Ok(false);
        }

        // Sybil attack detection
        if self.config.enable_sybil_detection {
            let mut sybil_detector = self.sybil_detector.write().await;
            if sybil_detector.analyze_identity(peer) {
                self.generate_alert(
                    ThreatType::SybilAttack,
                    ThreatSeverity::High,
                    Some(peer.clone()),
                    Some(*peer_ip),
                    "Potential Sybil attack detected".to_string(),
                    SecurityAction::IsolateNode,
                ).await;
                return Ok(false);
            }
        }

        // Eclipse attack prevention
        if self.config.enable_eclipse_prevention {
            let eclipse_prevention = self.eclipse_prevention.read().await;
            if !eclipse_prevention.should_accept_peer(peer, peer_ip) {
                self.generate_alert(
                    ThreatType::EclipseAttack,
                    ThreatSeverity::Medium,
                    Some(peer.clone()),
                    Some(*peer_ip),
                    "Peer diversity limit reached".to_string(),
                    SecurityAction::Warning,
                ).await;
                return Ok(false);
            }
        }

        // Update tracking information
        conn_tracker.add_connection(*peer_ip);
        drop(conn_tracker);

        let mut eclipse_prevention = self.eclipse_prevention.write().await;
        eclipse_prevention.update_peer_info(peer, peer_ip);

        Ok(true)
    }

    /// Check rate limiting for peer requests
    pub async fn check_rate_limit(&self, peer: &NymIdentity) -> NetworkResult<bool> {
        let mut trackers = self.rate_trackers.write().await;
        let tracker = trackers.entry(peer.clone()).or_insert_with(RateTracker::new);
        
        let rate_window = Duration::from_secs(self.config.rate_limit_window);
        let allowed = tracker.check_rate_limit(self.config.rate_limit_per_peer, rate_window);
        
        if !allowed {
            self.generate_alert(
                ThreatType::RateLimitViolation,
                ThreatSeverity::Medium,
                Some(peer.clone()),
                None,
                format!("Rate limit exceeded: {} violations", tracker.violations),
                SecurityAction::RateLimit,
            ).await;
        }
        
        Ok(allowed)
    }

    /// Record a failed connection attempt
    pub async fn record_failed_connection(&self, ip: IpAddr) -> NetworkResult<()> {
        let mut conn_tracker = self.connection_tracker.write().await;
        let should_ban = conn_tracker.record_failed_attempt(ip, self.config.max_failed_attempts);
        
        if should_ban {
            self.generate_alert(
                ThreatType::SuspiciousActivity,
                ThreatSeverity::High,
                None,
                Some(ip),
                format!("IP banned after {} failed attempts", self.config.max_failed_attempts),
                SecurityAction::TemporaryBan,
            ).await;
        }
        
        Ok(())
    }

    /// Disconnect a peer and update tracking
    pub async fn disconnect_peer(&self, peer: &NymIdentity, peer_ip: &IpAddr) -> NetworkResult<()> {
        let mut conn_tracker = self.connection_tracker.write().await;
        conn_tracker.remove_connection(peer_ip);
        
        debug!("Peer disconnected: {} from IP: {}", peer.to_string(), peer_ip);
        Ok(())
    }

    /// Perform periodic security maintenance
    pub async fn periodic_maintenance(&self) -> NetworkResult<()> {
        debug!("Performing periodic security maintenance");
        
        // Clean up expired bans
        let mut conn_tracker = self.connection_tracker.write().await;
        conn_tracker.cleanup_expired_bans(Duration::from_secs(self.config.ban_duration));
        drop(conn_tracker);
        
        // Clean up old rate tracking data
        let mut trackers = self.rate_trackers.write().await;
        let cutoff = Instant::now() - Duration::from_secs(3600); // 1 hour
        trackers.retain(|_, tracker| {
            if let Some(last_request) = tracker.requests.back() {
                *last_request > cutoff
            } else {
                false
            }
        });
        drop(trackers);
        
        // Maintain alert history (keep last 1000 alerts)
        let mut alerts = self.security_alerts.write().await;
        if alerts.len() > 1000 {
            alerts.drain(0..alerts.len() - 1000);
        }
        
        Ok(())
    }

    /// Generate and store security alert
    async fn generate_alert(
        &self,
        threat_type: ThreatType,
        severity: ThreatSeverity,
        source_peer: Option<NymIdentity>,
        source_ip: Option<IpAddr>,
        description: String,
        action: SecurityAction,
    ) {
        let alert_id = format!("alert_{}_{}", 
                             SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
                             self.alert_counter.fetch_add(1, std::sync::atomic::Ordering::SeqCst));
        
        let alert = SecurityAlert {
            alert_id,
            threat_type,
            severity,
            source_peer,
            source_ip,
            description,
            evidence: Vec::new(), // Would be populated with specific evidence
            timestamp: SystemTime::now(),
            action_taken: action,
        };
        
        match &alert.severity {
            ThreatSeverity::Low => debug!("Security alert: {}", alert.description),
            ThreatSeverity::Medium => warn!("Security alert: {}", alert.description),
            ThreatSeverity::High => error!("Security alert: {}", alert.description),
            ThreatSeverity::Critical => error!("CRITICAL security alert: {}", alert.description),
        }
        
        // Store alert
        let mut alerts = self.security_alerts.write().await;
        alerts.push(alert.clone());
        drop(alerts);
        
        // Send alert to monitoring system
        if let Some(sender) = &self.alert_sender {
            let _ = sender.send(alert);
        }
    }

    /// Get recent security alerts
    pub async fn get_recent_alerts(&self, limit: usize) -> Vec<SecurityAlert> {
        let alerts = self.security_alerts.read().await;
        alerts.iter()
            .rev()
            .take(limit)
            .cloned()
            .collect()
    }

    /// Get security statistics
    pub async fn get_security_stats(&self) -> SecurityStats {
        let conn_tracker = self.connection_tracker.read().await;
        let alerts = self.security_alerts.read().await;
        let trackers = self.rate_trackers.read().await;
        
        let threat_counts = alerts.iter().fold(HashMap::new(), |mut acc, alert| {
            *acc.entry(format!("{:?}", alert.threat_type)).or_insert(0) += 1;
            acc
        });
        
        SecurityStats {
            total_connections: conn_tracker.connections_per_ip.values().sum(),
            banned_ips: conn_tracker.banned_ips.len(),
            rate_limited_peers: trackers.len(),
            total_alerts: alerts.len(),
            threat_breakdown: threat_counts,
            uptime: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        }
    }
}

/// Security statistics structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityStats {
    pub total_connections: usize,
    pub banned_ips: usize,
    pub rate_limited_peers: usize,
    pub total_alerts: usize,
    pub threat_breakdown: HashMap<String, usize>,
    pub uptime: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_connection_limiting() {
        let config = SecurityConfig::default();
        let security_manager = NetworkSecurityManager::new(config);
        
        let test_ip = "192.168.1.1".parse().unwrap();
        let mut conn_tracker = security_manager.connection_tracker.write().await;
        
        // Should allow connections up to the limit
        for i in 0..10 {
            assert!(conn_tracker.can_connect(&test_ip, 10));
            conn_tracker.add_connection(test_ip);
        }
        
        // Should deny additional connections
        assert!(!conn_tracker.can_connect(&test_ip, 10));
    }

    #[tokio::test]
    async fn test_rate_limiting() {
        let config = SecurityConfig {
            rate_limit_per_peer: 5,
            rate_limit_window: 60,
            ..Default::default()
        };
        
        let security_manager = NetworkSecurityManager::new(config);
        let test_peer = NymIdentity::from_bytes(&[1; 32]).unwrap();
        
        // Should allow requests up to the limit
        for _ in 0..5 {
            assert!(security_manager.check_rate_limit(&test_peer).await.unwrap());
        }
        
        // Should deny additional requests
        assert!(!security_manager.check_rate_limit(&test_peer).await.unwrap());
    }

    #[tokio::test]
    async fn test_failed_connection_tracking() {
        let config = SecurityConfig {
            max_failed_attempts: 3,
            ..Default::default()
        };
        
        let security_manager = NetworkSecurityManager::new(config);
        let test_ip = "192.168.1.100".parse().unwrap();
        
        // Record failed attempts
        for _ in 0..2 {
            security_manager.record_failed_connection(test_ip).await.unwrap();
        }
        
        // Should not be banned yet
        let conn_tracker = security_manager.connection_tracker.read().await;
        assert!(!conn_tracker.banned_ips.contains_key(&test_ip));
        drop(conn_tracker);
        
        // Third failure should trigger ban
        security_manager.record_failed_connection(test_ip).await.unwrap();
        
        let conn_tracker = security_manager.connection_tracker.read().await;
        assert!(conn_tracker.banned_ips.contains_key(&test_ip));
    }

    #[tokio::test]
    async fn test_sybil_detection() {
        let mut detector = SybilDetector::new();
        
        // Create multiple similar identities
        let base_bytes = [1; 32];
        for i in 0..15 {
            let mut identity_bytes = base_bytes;
            identity_bytes[31] = i; // Small variation
            let identity = NymIdentity::from_bytes(&identity_bytes).unwrap();
            
            let is_suspicious = detector.analyze_identity(&identity);
            if i >= 10 {
                // Should detect as suspicious after 10+ similar identities
                assert!(is_suspicious);
            }
        }
    }

    #[tokio::test]
    async fn test_eclipse_prevention() {
        let mut eclipse_system = EclipsePreventionSystem::new();
        
        let test_ip = "192.168.1.1".parse().unwrap();
        
        // Should accept diverse peers
        for i in 0..20 {
            let identity_bytes = [i; 32];
            let identity = NymIdentity::from_bytes(&identity_bytes).unwrap();
            
            assert!(eclipse_system.should_accept_peer(&identity, &test_ip));
            eclipse_system.update_peer_info(&identity, &test_ip);
        }
        
        // Should reject additional peers from same region
        let new_identity = NymIdentity::from_bytes(&[99; 32]).unwrap();
        assert!(!eclipse_system.should_accept_peer(&new_identity, &test_ip));
    }
}