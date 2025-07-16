//! Core P2P Network Tests for Nym (without libp2p dependency)
//!
//! This test suite focuses on testing the core P2P networking components
//! that don't require libp2p to function.

use std::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::{sleep, timeout};
use tracing::{info, error, debug};
use rand;

use nym_network::{
    NetworkError, NetworkResult, PeerId, PeerInfo, PeerStatus, PeerCapabilities,
    PeerManager, PeerStats, NodeConfig, SimpleP2PConfig, SimpleP2PNetwork, SimpleP2PEvent,
    QuIDAuthConfig, QuIDAuthenticator, AuthChallenge, AuthResponse, AuthStatus,
    PrivacyRouter, PrivacyRoutingConfig, NetworkPerformanceOptimizer, PerformanceConfig,
    EnhancedNetworkNode, EnhancedNodeConfig
};

use nym_core::NymIdentity;
use nym_crypto::{Hash256, SecurityLevel};

/// Test 1: Basic PeerManager functionality
#[tokio::test]
async fn test_peer_manager_basic() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing PeerManager basic functionality...");

    let mut manager = PeerManager::new(10, 50);

    // Test initial state
    assert_eq!(manager.peer_count(), 0);
    assert!(manager.connected_peers().is_empty());

    // Create a test peer
    let peer_id = PeerId::new(Hash256::random(&mut rand::thread_rng()));
    let peer_info = PeerInfo {
        id: peer_id.clone(),
        addresses: vec!["127.0.0.1:8080".parse().unwrap()],
        identity: None,
        status: PeerStatus::Connected,
        capabilities: PeerCapabilities {
            full_node: true,
            consensus: true,
            tx_relay: true,
            archival: false,
            privacy_level: SecurityLevel::Level1,
        },
        last_seen: 12345,
        connection_attempts: 1,
        reputation: 100,
        protocol_version: "1.0.0".to_string(),
        user_agent: "nym-test".to_string(),
    };

    // Add peer
    manager.add_peer(peer_info)?;
    assert_eq!(manager.peer_count(), 1);

    // Test peer lookup
    let retrieved_peer = manager.get_peer(&peer_id);
    assert!(retrieved_peer.is_some());
    assert_eq!(retrieved_peer.unwrap().id, peer_id);

    info!("✅ PeerManager basic functionality test passed");
    Ok(())
}

/// Test 2: QuID Authentication workflow
#[tokio::test]
async fn test_quid_auth_workflow() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing QuID authentication workflow...");

    let auth_config = QuIDAuthConfig {
        challenge_size: 32,
        challenge_timeout: Duration::from_secs(30),
        max_auth_attempts: 3,
        auth_cache_duration: Duration::from_secs(3600),
        require_identity_verification: true,
        min_security_level: SecurityLevel::Level1,
    };

    let identity1 = create_mock_identity("auth_node_1");
    let identity2 = create_mock_identity("auth_node_2");

    let authenticator1 = QuIDAuthenticator::new(auth_config.clone(), identity1);
    let authenticator2 = QuIDAuthenticator::new(auth_config, identity2.clone());

    let peer_id2 = PeerId::from_identity(&identity2);

    // Create and handle authentication challenge
    let challenge = authenticator1.create_auth_challenge(peer_id2.clone()).await?;
    assert_eq!(challenge.peer_id, peer_id2);
    assert_eq!(challenge.challenge_data.len(), 32);

    // Test authentication statistics
    let stats = authenticator1.get_auth_statistics().await;
    assert_eq!(stats.active_sessions, 1);
    assert_eq!(stats.authenticated_peers, 0);

    info!("✅ QuID authentication workflow test passed");
    Ok(())
}

/// Test 3: Privacy Router configuration
#[tokio::test]
async fn test_privacy_router_config() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing PrivacyRouter configuration...");

    let config = PrivacyRoutingConfig::default();
    let identity = create_mock_identity("privacy_node");

    let router = PrivacyRouter::new(config, identity);

    // Test router initialization
    router.start().await?;

    // Test route statistics
    let stats = router.get_routing_statistics().await;
    assert_eq!(stats.total_routes_created, 0);
    assert_eq!(stats.active_routes, 0);

    info!("✅ PrivacyRouter configuration test passed");
    Ok(())
}

/// Test 4: Performance optimizer functionality
#[tokio::test]
async fn test_performance_optimizer() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing NetworkPerformanceOptimizer...");

    let config = PerformanceConfig {
        enable_auto_optimization: true,
        optimization_interval: Duration::from_secs(60),
        optimization_aggressiveness: 0.5,
        max_optimization_iterations: 10,
        enable_connection_pooling: true,
        enable_load_balancing: true,
        enable_adaptive_bandwidth: true,
    };

    let optimizer = NetworkPerformanceOptimizer::new(config);

    // Start optimizer
    optimizer.start().await?;

    // Test performance metrics
    let metrics = optimizer.get_performance_metrics().await?;
    assert!(metrics.timestamp.elapsed() < Duration::from_secs(1));

    info!("✅ NetworkPerformanceOptimizer test passed");
    Ok(())
}

/// Test 5: PeerId creation and manipulation
#[tokio::test]
async fn test_peer_id_operations() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing PeerId operations...");

    let identity = create_mock_identity("peer_id_test");
    let peer_id = PeerId::from_identity(&identity);

    // Test hex conversion
    let hex_str = peer_id.to_hex();
    assert!(hex_str.len() == 64); // 32 bytes * 2 hex chars

    let peer_id_from_hex = PeerId::from_hex(&hex_str)?;
    assert_eq!(peer_id.hash(), peer_id_from_hex.hash());

    // Test random peer ID
    let random_peer_id = PeerId::new(Hash256::random(&mut rand::thread_rng()));
    assert_ne!(peer_id.hash(), random_peer_id.hash());

    info!("✅ PeerId operations test passed");
    Ok(())
}

/// Test 6: Concurrent operations
#[tokio::test]
async fn test_concurrent_operations() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing concurrent operations...");

    let manager = Arc::new(Mutex::new(PeerManager::new(100, 50)));
    let mut handles = Vec::new();

    // Create multiple peers concurrently
    for i in 0..10 {
        let manager_clone = manager.clone();
        let handle = tokio::spawn(async move {
            let peer_id = PeerId::new(Hash256::random(&mut rand::thread_rng()));
            let peer_info = PeerInfo {
                id: peer_id.clone(),
                addresses: vec![format!("127.0.0.1:{}", 8080 + i).parse().unwrap()],
                identity: None,
                status: PeerStatus::Connected,
                capabilities: PeerCapabilities {
                    full_node: true,
                    consensus: true,
                    tx_relay: true,
                    archival: false,
                    privacy_level: SecurityLevel::Level1,
                },
                last_seen: 12345,
                connection_attempts: 1,
                reputation: 100,
                protocol_version: "1.0.0".to_string(),
                user_agent: "nym-test".to_string(),
            };
            manager_clone.lock().unwrap().add_peer(peer_info)
        });
        handles.push(handle);
    }

    // Wait for all operations to complete
    for handle in handles {
        let _ = handle.await.unwrap();
    }

    // Verify all peers were added
    assert_eq!(manager.lock().unwrap().peer_count(), 10);

    info!("✅ Concurrent operations test passed");
    Ok(())
}

/// Test 7: Configuration validation
#[tokio::test]
async fn test_configuration_validation() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing configuration validation...");

    // Test valid P2P configuration
    let valid_config = SimpleP2PConfig {
        listen_addr: "127.0.0.1:8080".parse().unwrap(),
        known_peers: vec!["127.0.0.1:8081".parse().unwrap()],
        max_connections: 50,
        connection_timeout: Duration::from_secs(30),
        heartbeat_interval: Duration::from_secs(60),
        message_buffer_size: 1000,
    };

    assert!(valid_config.max_connections > 0);
    assert!(valid_config.connection_timeout > Duration::from_secs(0));

    // Test QuID auth configuration
    let auth_config = QuIDAuthConfig {
        challenge_size: 64,
        challenge_timeout: Duration::from_secs(60),
        max_auth_attempts: 5,
        auth_cache_duration: Duration::from_secs(7200),
        require_identity_verification: true,
        min_security_level: SecurityLevel::Level2,
    };

    assert!(auth_config.challenge_size >= 32);
    assert!(auth_config.max_auth_attempts > 0);

    info!("✅ Configuration validation test passed");
    Ok(())
}

/// Test 8: Network error handling
#[tokio::test]
async fn test_network_error_handling() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing network error handling...");

    // Test invalid peer ID creation
    let invalid_hex = "invalid_hex_string";
    let result = PeerId::from_hex(invalid_hex);
    assert!(result.is_err());

    // Test peer manager with invalid configuration
    let manager = PeerManager::new(0, 0); // Invalid config
    assert_eq!(manager.peer_count(), 0);

    info!("✅ Network error handling test passed");
    Ok(())
}

/// Test 9: Authentication flow integration
#[tokio::test]
async fn test_auth_integration() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing authentication integration...");

    let identity1 = create_mock_identity("auth_node_1");
    let identity2 = create_mock_identity("auth_node_2");
    
    let auth_config = QuIDAuthConfig::default();
    let authenticator1 = QuIDAuthenticator::new(auth_config.clone(), identity1);
    let authenticator2 = QuIDAuthenticator::new(auth_config, identity2.clone());
    
    let peer_id2 = PeerId::from_identity(&identity2);
    
    // Create and handle challenge
    let challenge = authenticator1.create_auth_challenge(peer_id2.clone()).await?;
    let response = authenticator2.handle_auth_challenge(challenge).await?;
    let auth_result = authenticator1.verify_auth_response(response).await?;
    
    assert!(auth_result);
    assert!(authenticator1.is_peer_authenticated(&peer_id2).await);
    
    info!("✅ Authentication integration test passed");
    Ok(())
}

/// Test 10: Full workflow without libp2p
#[tokio::test]
async fn test_full_workflow_no_libp2p() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing full workflow without libp2p...");

    // Create identities
    let identity1 = create_mock_identity("node1");
    let identity2 = create_mock_identity("node2");
    
    // Create peer managers
    let mut manager1 = PeerManager::new(50, 30);
    let mut manager2 = PeerManager::new(50, 30);
    
    // Create authenticators
    let auth_config = QuIDAuthConfig::default();
    let authenticator1 = QuIDAuthenticator::new(auth_config.clone(), identity1);
    let authenticator2 = QuIDAuthenticator::new(auth_config, identity2.clone());
    
    // Create peer info
    let peer_id1 = PeerId::from_identity(&identity1);
    let peer_id2 = PeerId::from_identity(&identity2);
    
    let peer_info1 = PeerInfo {
        id: peer_id1.clone(),
        addresses: vec!["127.0.0.1:8080".parse().unwrap()],
        identity: Some(identity1.clone()),
        status: PeerStatus::Connected,
        capabilities: PeerCapabilities::default(),
        last_seen: 12345,
        connection_attempts: 1,
        reputation: 75,
        protocol_version: "1.0.0".to_string(),
        user_agent: "nym-test".to_string(),
    };
    
    let peer_info2 = PeerInfo {
        id: peer_id2.clone(),
        addresses: vec!["127.0.0.1:8081".parse().unwrap()],
        identity: Some(identity2.clone()),
        status: PeerStatus::Connected,
        capabilities: PeerCapabilities::default(),
        last_seen: 12345,
        connection_attempts: 1,
        reputation: 85,
        protocol_version: "1.0.0".to_string(),
        user_agent: "nym-test".to_string(),
    };
    
    // Add peers to managers
    manager1.add_peer(peer_info2)?;
    manager2.add_peer(peer_info1)?;
    
    // Perform authentication
    let challenge = authenticator1.create_auth_challenge(peer_id2.clone()).await?;
    let response = authenticator2.handle_auth_challenge(challenge).await?;
    let auth_result = authenticator1.verify_auth_response(response).await?;
    
    // Verify everything worked
    assert!(auth_result);
    assert!(authenticator1.is_peer_authenticated(&peer_id2).await);
    assert_eq!(manager1.peer_count(), 1);
    assert_eq!(manager2.peer_count(), 1);
    
    info!("✅ Full workflow test passed");
    Ok(())
}

/// Helper function to create a mock identity for testing
fn create_mock_identity(name: &str) -> NymIdentity {
    use nym_crypto::derive_key;
    
    let master_key = derive_key(name.as_bytes(), b"test-key", SecurityLevel::Level1);
    let quid_auth = nym_core::QuIDAuth::new(master_key, SecurityLevel::Level1);
    
    NymIdentity::from_quid_auth(&quid_auth, 0)
        .expect("Failed to create mock identity")
}

#[cfg(test)]
mod test_runner {
    use super::*;
    
    /// Run all core P2P tests
    pub async fn run_all_core_tests() -> NetworkResult<()> {
        let test_results = vec![
            ("peer_manager_basic", test_peer_manager_basic().await),
            ("quid_auth_workflow", test_quid_auth_workflow().await),
            ("privacy_router_config", test_privacy_router_config().await),
            ("performance_optimizer", test_performance_optimizer().await),
            ("peer_id_operations", test_peer_id_operations().await),
            ("concurrent_operations", test_concurrent_operations().await),
            ("configuration_validation", test_configuration_validation().await),
            ("network_error_handling", test_network_error_handling().await),
            ("auth_integration", test_auth_integration().await),
            ("full_workflow_no_libp2p", test_full_workflow_no_libp2p().await),
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
        
        println!("\n📊 Core Test Results: {} passed, {} failed", passed, failed);
        
        if failed > 0 {
            Err(NetworkError::TestFailed {
                reason: format!("{} tests failed", failed),
            })
        } else {
            Ok(())
        }
    }
}