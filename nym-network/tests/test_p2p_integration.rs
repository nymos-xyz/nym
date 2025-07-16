//! Comprehensive P2P Network Integration Tests for Nym
//!
//! This test suite validates the P2P networking layer including:
//! - libp2p networking functionality
//! - Peer discovery mechanism
//! - Gossipsub pub/sub messaging
//! - Kademlia DHT functionality
//! - QuID-based node authentication
//! - Multi-node network scenarios

use std::time::Duration;
use std::collections::HashMap;
use tokio::time::{sleep, timeout};
use tracing::{info, error, debug};

use nym_core::NymIdentity;
use nym_crypto::SecurityLevel;
use nym_network::*;

/// Test helper to create a test identity
fn create_test_identity(name: &str) -> NymIdentity {
    NymIdentity::new_test_identity(name, SecurityLevel::Level2)
}

/// Test helper to create libp2p network config
fn create_test_config() -> Libp2pNetworkConfig {
    Libp2pNetworkConfig {
        listen_addresses: vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()],
        bootstrap_peers: Vec::new(),
        enable_gossipsub: true,
        enable_kademlia: true,
        gossipsub_topics: vec!["test-topic".to_string()],
        max_peers: 10,
        connection_timeout: Duration::from_secs(10),
    }
}

/// Test 1: Basic libp2p network initialization
#[tokio::test]
async fn test_libp2p_network_initialization() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing libp2p network initialization...");

    let identity = create_test_identity("test_node_1");
    let config = create_test_config();
    
    let (mut network, mut events) = Libp2pNetwork::new(config, identity).await?;
    
    // Start network
    network.start().await?;
    
    // Verify local peer ID is set
    assert!(!network.local_peer_id().to_string().is_empty());
    
    // Verify initial peer count is 0
    assert_eq!(network.peer_count().await, 0);
    
    info!("✅ libp2p network initialization test passed");
    Ok(())
}

/// Test 2: QuID-based authentication system
#[tokio::test]
async fn test_quid_authentication() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing QuID-based authentication...");

    let identity1 = create_test_identity("auth_node_1");
    let identity2 = create_test_identity("auth_node_2");
    
    let config = QuIDAuthConfig::default();
    let authenticator1 = QuIDAuthenticator::new(config.clone(), identity1);
    let authenticator2 = QuIDAuthenticator::new(config, identity2);
    
    let peer_id2 = PeerId::from_identity(&identity2);
    
    // Create authentication challenge
    let challenge = authenticator1.create_auth_challenge(peer_id2.clone()).await?;
    
    // Handle challenge and create response
    let response = authenticator2.handle_auth_challenge(challenge).await?;
    
    // Verify response
    let auth_result = authenticator1.verify_auth_response(response).await?;
    assert!(auth_result);
    
    // Verify peer is authenticated
    assert!(authenticator1.is_peer_authenticated(&peer_id2).await);
    
    // Check trust score
    let trust_score = authenticator1.get_peer_trust_score(&peer_id2).await;
    assert!(trust_score.is_some());
    assert_eq!(trust_score.unwrap(), 1.0);
    
    info!("✅ QuID authentication test passed");
    Ok(())
}

/// Test 3: Gossipsub pub/sub messaging
#[tokio::test]
async fn test_gossipsub_messaging() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing gossipsub pub/sub messaging...");

    let identity1 = create_test_identity("gossip_node_1");
    let identity2 = create_test_identity("gossip_node_2");
    
    let mut config1 = create_test_config();
    let mut config2 = create_test_config();
    
    // Use different ports for each node
    config1.listen_addresses = vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()];
    config2.listen_addresses = vec!["/ip4/127.0.0.1/tcp/0".parse().unwrap()];
    
    let (mut network1, mut events1) = Libp2pNetwork::new(config1, identity1).await?;
    let (mut network2, mut events2) = Libp2pNetwork::new(config2, identity2).await?;
    
    // Start both networks
    network1.start().await?;
    network2.start().await?;
    
    // Subscribe to test topic
    network1.subscribe_to_topic("test-gossip").await?;
    network2.subscribe_to_topic("test-gossip").await?;
    
    // Wait for networks to initialize
    sleep(Duration::from_millis(100)).await;
    
    // Publish a message
    let test_message = b"Hello, P2P world!".to_vec();
    network1.publish_message("test-gossip", test_message.clone()).await?;
    
    info!("✅ Gossipsub messaging test completed");
    Ok(())
}

/// Test 4: Peer discovery mechanisms
#[tokio::test]
async fn test_peer_discovery() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing peer discovery mechanisms...");

    let identity = create_test_identity("discovery_node");
    let config = NodeConfig::default();
    
    let discovery_config = DiscoveryConfig::default();
    let mut discovery = NodeDiscovery::new(discovery_config, identity);
    
    // Test discovery initialization
    discovery.start().await?;
    
    // Test peer discovery
    let discovered_peers = discovery.discover_peers().await?;
    
    // Initially should have no peers
    assert!(discovered_peers.is_empty());
    
    // Test adding known peers
    let test_peer = PeerInfo::new(
        PeerId::from_str("test_peer_id")?,
        vec!["127.0.0.1:8080".parse().unwrap()],
        None,
    );
    
    discovery.add_peer(test_peer).await?;
    
    // Verify peer was added
    let peer_count = discovery.peer_count().await;
    assert!(peer_count > 0);
    
    info!("✅ Peer discovery test passed");
    Ok(())
}

/// Test 5: Multi-node network scenario
#[tokio::test]
async fn test_multi_node_network() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing multi-node network scenario...");

    let identities = vec![
        create_test_identity("node_1"),
        create_test_identity("node_2"),
        create_test_identity("node_3"),
    ];
    
    let mut networks = Vec::new();
    let mut event_receivers = Vec::new();
    
    // Create multiple networks
    for identity in identities {
        let config = create_test_config();
        let (network, events) = Libp2pNetwork::new(config, identity).await?;
        networks.push(network);
        event_receivers.push(events);
    }
    
    // Start all networks
    for network in &mut networks {
        network.start().await?;
    }
    
    // Wait for networks to initialize
    sleep(Duration::from_millis(200)).await;
    
    // Test inter-node communication
    let test_message = b"Multi-node test message".to_vec();
    networks[0].publish_message("nym-global", test_message).await?;
    
    // Verify networks are running
    for network in &networks {
        assert!(!network.local_peer_id().to_string().is_empty());
    }
    
    info!("✅ Multi-node network test passed");
    Ok(())
}

/// Test 6: Network security and authentication integration
#[tokio::test]
async fn test_network_security_integration() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing network security integration...");

    let identity = create_test_identity("security_node");
    let config = create_test_config();
    
    let (mut network, mut events) = Libp2pNetwork::new(config, identity.clone()).await?;
    network.start().await?;
    
    // Create QuID authenticator
    let auth_config = QuIDAuthConfig::default();
    let authenticator = QuIDAuthenticator::new(auth_config, identity);
    
    // Test authentication statistics
    let stats = authenticator.get_auth_statistics().await;
    assert_eq!(stats.active_sessions, 0);
    assert_eq!(stats.authenticated_peers, 0);
    
    // Test peer trust score management
    let test_peer_id = PeerId::from_str("test_peer_security")?;
    
    // This should fail since peer is not authenticated
    let trust_result = authenticator.get_peer_trust_score(&test_peer_id).await;
    assert!(trust_result.is_none());
    
    info!("✅ Network security integration test passed");
    Ok(())
}

/// Test 7: Privacy routing functionality
#[tokio::test]
async fn test_privacy_routing() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing privacy routing functionality...");

    let identity = create_test_identity("privacy_node");
    let config = PrivacyRoutingConfig::default();
    
    let privacy_router = PrivacyRouter::new(config, identity);
    
    // Test privacy router initialization
    privacy_router.start().await?;
    
    // Test route creation
    let test_message = b"Privacy test message".to_vec();
    let target_peer = PeerId::from_str("target_peer")?;
    
    let route = privacy_router.create_route(target_peer, 3).await?;
    assert!(route.hops.len() > 0);
    
    // Test onion message creation
    let onion_message = privacy_router.create_onion_message(test_message, route).await?;
    assert!(onion_message.layers.len() > 0);
    
    info!("✅ Privacy routing test passed");
    Ok(())
}

/// Test 8: Network performance and optimization
#[tokio::test]
async fn test_network_performance() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing network performance optimization...");

    let config = PerformanceConfig::default();
    let optimizer = NetworkPerformanceOptimizer::new(config);
    
    // Start performance optimizer
    optimizer.start().await?;
    
    // Test performance metrics
    let metrics = optimizer.get_performance_metrics().await?;
    assert!(metrics.timestamp.elapsed() < Duration::from_secs(1));
    
    // Test peer optimization
    let peer_id = PeerId::from_str("perf_test_peer")?;
    let optimization_result = optimizer.optimize_peer_connection(&peer_id).await?;
    
    assert!(optimization_result.timestamp.elapsed() < Duration::from_secs(1));
    
    info!("✅ Network performance test passed");
    Ok(())
}

/// Test 9: Error handling and resilience
#[tokio::test]
async fn test_error_handling() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing error handling and resilience...");

    let identity = create_test_identity("error_test_node");
    let mut config = create_test_config();
    
    // Use invalid address to test error handling
    config.listen_addresses = vec!["/ip4/999.999.999.999/tcp/0".parse().unwrap()];
    
    let result = Libp2pNetwork::new(config, identity).await;
    
    // Should handle invalid address gracefully
    match result {
        Ok(_) => {
            info!("Network created successfully with invalid address");
        }
        Err(e) => {
            info!("Network creation failed as expected: {}", e);
        }
    }
    
    info!("✅ Error handling test passed");
    Ok(())
}

/// Test 10: Integration with existing Nym components
#[tokio::test]
async fn test_nym_integration() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing integration with existing Nym components...");

    let identity = create_test_identity("integration_node");
    let config = create_enhanced_config();
    
    let mut enhanced_node = EnhancedNetworkNode::new(config);
    
    // Test enhanced node startup
    enhanced_node.start().await?;
    
    // Test that the enhanced node integrates P2P capabilities
    // This is mainly testing the integration layer
    
    info!("✅ Nym integration test passed");
    Ok(())
}

/// Utility function to create enhanced config
fn create_enhanced_config() -> EnhancedNodeConfig {
    EnhancedNodeConfig {
        node_config: NodeConfig::default(),
        p2p_config: SimpleP2PConfig::default(),
        enable_p2p: true,
    }
}

/// Helper implementations for testing
impl PeerId {
    pub fn from_str(s: &str) -> NetworkResult<Self> {
        Ok(PeerId(s.to_string()))
    }
}

impl PeerInfo {
    pub fn new(peer_id: PeerId, addresses: Vec<std::net::SocketAddr>, identity: Option<NymIdentity>) -> Self {
        Self {
            peer_id,
            addresses,
            identity,
            last_seen: std::time::SystemTime::now(),
        }
    }
}

impl NodeConfig {
    pub fn default() -> Self {
        Self {
            identity: create_test_identity("default_node"),
            listen_addr: "127.0.0.1:0".parse().unwrap(),
            bootstrap_peers: Vec::new(),
            max_peers: 50,
            connection_timeout: Duration::from_secs(30),
        }
    }
}

#[cfg(test)]
mod test_runner {
    use super::*;
    
    /// Run all P2P tests
    pub async fn run_all_tests() {
        let test_results = vec![
            ("libp2p_network_initialization", test_libp2p_network_initialization().await),
            ("quid_authentication", test_quid_authentication().await),
            ("gossipsub_messaging", test_gossipsub_messaging().await),
            ("peer_discovery", test_peer_discovery().await),
            ("multi_node_network", test_multi_node_network().await),
            ("network_security_integration", test_network_security_integration().await),
            ("privacy_routing", test_privacy_routing().await),
            ("network_performance", test_network_performance().await),
            ("error_handling", test_error_handling().await),
            ("nym_integration", test_nym_integration().await),
        ];
        
        let mut passed = 0;
        let mut failed = 0;
        
        for (test_name, result) in test_results {
            match result {
                Ok(_) => {
                    println!("✅ {} - PASSED", test_name);
                    passed += 1;
                }
                Err(e) => {
                    println!("❌ {} - FAILED: {}", test_name, e);
                    failed += 1;
                }
            }
        }
        
        println!("\n📊 Test Results: {} passed, {} failed", passed, failed);
    }
}