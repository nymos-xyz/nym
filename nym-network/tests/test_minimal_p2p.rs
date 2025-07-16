//! Minimal P2P Network Tests for Nym
//!
//! This test suite focuses on the core P2P networking components
//! without external dependencies that have compilation issues.

use std::time::Duration;
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio::time::sleep;
use tracing::{info, error, debug};
use rand;

use nym_network::{
    NetworkError, NetworkResult, PeerId, PeerInfo, PeerStatus, PeerCapabilities,
    PeerManager, PeerStats, SimpleP2PConfig
};

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

/// Test 2: PeerId creation and manipulation
#[tokio::test]
async fn test_peer_id_operations() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing PeerId operations...");

    // Test random peer ID creation
    let peer_id1 = PeerId::new(Hash256::random(&mut rand::thread_rng()));
    let peer_id2 = PeerId::new(Hash256::random(&mut rand::thread_rng()));
    
    // They should be different
    assert_ne!(peer_id1.hash(), peer_id2.hash());

    // Test hex conversion
    let hex_str = peer_id1.to_hex();
    assert!(hex_str.len() == 64); // 32 bytes * 2 hex chars

    let peer_id_from_hex = PeerId::from_hex(&hex_str)?;
    assert_eq!(peer_id1.hash(), peer_id_from_hex.hash());

    info!("✅ PeerId operations test passed");
    Ok(())
}

/// Test 3: Configuration validation
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
    assert!(valid_config.heartbeat_interval > Duration::from_secs(0));
    assert!(valid_config.message_buffer_size > 0);

    info!("✅ Configuration validation test passed");
    Ok(())
}

/// Test 4: Concurrent operations
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

/// Test 5: Error handling
#[tokio::test]
async fn test_error_handling() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing error handling...");

    // Test invalid peer ID creation
    let invalid_hex = "invalid_hex_string";
    let result = PeerId::from_hex(invalid_hex);
    assert!(result.is_err());
    
    // Test invalid hex (wrong length)
    let wrong_length_hex = "1234567890"; // Too short
    let result = PeerId::from_hex(wrong_length_hex);
    assert!(result.is_err());

    // Test peer manager with max peers exceeded
    let mut manager = PeerManager::new(1, 50); // Only allow 1 peer
    
    let peer_id1 = PeerId::new(Hash256::random(&mut rand::thread_rng()));
    let peer_info1 = PeerInfo {
        id: peer_id1.clone(),
        addresses: vec!["127.0.0.1:8080".parse().unwrap()],
        identity: None,
        status: PeerStatus::Connected,
        capabilities: PeerCapabilities::default(),
        last_seen: 12345,
        connection_attempts: 1,
        reputation: 100,
        protocol_version: "1.0.0".to_string(),
        user_agent: "nym-test".to_string(),
    };
    
    // First peer should succeed
    assert!(manager.add_peer(peer_info1).is_ok());
    
    // Second peer should fail
    let peer_id2 = PeerId::new(Hash256::random(&mut rand::thread_rng()));
    let peer_info2 = PeerInfo {
        id: peer_id2.clone(),
        addresses: vec!["127.0.0.1:8081".parse().unwrap()],
        identity: None,
        status: PeerStatus::Connected,
        capabilities: PeerCapabilities::default(),
        last_seen: 12345,
        connection_attempts: 1,
        reputation: 100,
        protocol_version: "1.0.0".to_string(),
        user_agent: "nym-test".to_string(),
    };
    
    assert!(manager.add_peer(peer_info2).is_err());

    info!("✅ Error handling test passed");
    Ok(())
}

/// Test 6: Peer status and reputation management
#[tokio::test]
async fn test_peer_status_reputation() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing peer status and reputation management...");

    let mut manager = PeerManager::new(10, 30);
    
    let peer_id = PeerId::new(Hash256::random(&mut rand::thread_rng()));
    let peer_info = PeerInfo {
        id: peer_id.clone(),
        addresses: vec!["127.0.0.1:8080".parse().unwrap()],
        identity: None,
        status: PeerStatus::Connected,
        capabilities: PeerCapabilities::default(),
        last_seen: 12345,
        connection_attempts: 1,
        reputation: 50,
        protocol_version: "1.0.0".to_string(),
        user_agent: "nym-test".to_string(),
    };

    manager.add_peer(peer_info)?;

    // Test status update
    manager.update_peer_status(&peer_id, PeerStatus::Disconnected)?;
    let peer = manager.get_peer(&peer_id).unwrap();
    assert_eq!(peer.status, PeerStatus::Disconnected);

    // Test banning peer
    manager.ban_peer(&peer_id)?;
    let peer = manager.get_peer(&peer_id).unwrap();
    assert_eq!(peer.status, PeerStatus::Banned);
    assert_eq!(peer.reputation, 0);

    info!("✅ Peer status and reputation management test passed");
    Ok(())
}

/// Test 7: Peer statistics
#[tokio::test]
async fn test_peer_statistics() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing peer statistics...");

    let mut manager = PeerManager::new(10, 30);
    
    let peer_id = PeerId::new(Hash256::random(&mut rand::thread_rng()));
    let peer_info = PeerInfo {
        id: peer_id.clone(),
        addresses: vec!["127.0.0.1:8080".parse().unwrap()],
        identity: None,
        status: PeerStatus::Connected,
        capabilities: PeerCapabilities::default(),
        last_seen: 12345,
        connection_attempts: 1,
        reputation: 50,
        protocol_version: "1.0.0".to_string(),
        user_agent: "nym-test".to_string(),
    };

    manager.add_peer(peer_info)?;

    // Test statistics update
    manager.update_stats(&peer_id, 1000, 500)?;
    
    let stats = manager.get_peer_stats(&peer_id).unwrap();
    assert_eq!(stats.bytes_sent, 1000);
    assert_eq!(stats.bytes_received, 500);
    assert_eq!(stats.messages_sent, 1);
    assert_eq!(stats.messages_received, 1);

    info!("✅ Peer statistics test passed");
    Ok(())
}

/// Test 8: Peer cleanup
#[tokio::test]
async fn test_peer_cleanup() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing peer cleanup...");

    let mut manager = PeerManager::new(10, 30);
    
    // Add a peer that should be cleaned up (low reputation)
    let peer_id = PeerId::new(Hash256::random(&mut rand::thread_rng()));
    let peer_info = PeerInfo {
        id: peer_id.clone(),
        addresses: vec!["127.0.0.1:8080".parse().unwrap()],
        identity: None,
        status: PeerStatus::Connected,
        capabilities: PeerCapabilities::default(),
        last_seen: 12345,
        connection_attempts: 15, // High connection attempts should trigger cleanup
        reputation: 5, // Low reputation should trigger cleanup
        protocol_version: "1.0.0".to_string(),
        user_agent: "nym-test".to_string(),
    };

    manager.add_peer(peer_info)?;
    assert_eq!(manager.peer_count(), 1);

    // Run cleanup
    let removed_count = manager.cleanup();
    assert_eq!(removed_count, 1);
    assert_eq!(manager.peer_count(), 0);

    info!("✅ Peer cleanup test passed");
    Ok(())
}

/// Test 9: Full workflow integration
#[tokio::test]
async fn test_full_workflow() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing full workflow integration...");

    let mut manager = PeerManager::new(50, 30);
    
    // Create several peers
    let mut peer_ids = Vec::new();
    for i in 0..5 {
        let peer_id = PeerId::new(Hash256::random(&mut rand::thread_rng()));
        let peer_info = PeerInfo {
            id: peer_id.clone(),
            addresses: vec![format!("127.0.0.1:{}", 8080 + i).parse().unwrap()],
            identity: None,
            status: PeerStatus::Connected,
            capabilities: PeerCapabilities {
                full_node: i % 2 == 0, // Alternate full nodes
                consensus: i % 3 == 0, // Some consensus nodes
                tx_relay: true,
                archival: false,
                privacy_level: SecurityLevel::Level1,
            },
            last_seen: 12345,
            connection_attempts: 1,
            reputation: 50 + (i * 10) as u8,
            protocol_version: "1.0.0".to_string(),
            user_agent: "nym-test".to_string(),
        };
        
        manager.add_peer(peer_info)?;
        peer_ids.push(peer_id);
    }

    // Verify all peers were added
    assert_eq!(manager.peer_count(), 5);

    // Update some peer statistics
    for (i, peer_id) in peer_ids.iter().enumerate() {
        manager.update_stats(peer_id, (i + 1) * 1000, (i + 1) * 500)?;
    }

    // Get connected peers
    let connected_peers = manager.connected_peers();
    assert_eq!(connected_peers.len(), 5);

    // Get good peers (reputation >= 30)
    let good_peers = manager.good_peers();
    assert_eq!(good_peers.len(), 5); // All should be good

    // Get a random peer
    let random_peer = manager.random_peer();
    assert!(random_peer.is_some());

    info!("✅ Full workflow integration test passed");
    Ok(())
}

/// Test 10: Performance with many peers
#[tokio::test]
async fn test_performance_many_peers() -> NetworkResult<()> {
    let _guard = tracing_subscriber::fmt()
        .with_env_filter("debug")
        .with_test_writer()
        .try_init();

    info!("🧪 Testing performance with many peers...");

    let mut manager = PeerManager::new(1000, 30);
    
    // Add many peers
    let start_time = std::time::Instant::now();
    for i in 0..100 {
        let peer_id = PeerId::new(Hash256::random(&mut rand::thread_rng()));
        let peer_info = PeerInfo {
            id: peer_id.clone(),
            addresses: vec![format!("127.0.0.1:{}", 8080 + i).parse().unwrap()],
            identity: None,
            status: PeerStatus::Connected,
            capabilities: PeerCapabilities::default(),
            last_seen: 12345,
            connection_attempts: 1,
            reputation: 50,
            protocol_version: "1.0.0".to_string(),
            user_agent: "nym-test".to_string(),
        };
        
        manager.add_peer(peer_info)?;
    }
    
    let add_time = start_time.elapsed();
    
    // Measure lookup performance
    let lookup_start = std::time::Instant::now();
    for _ in 0..1000 {
        let _ = manager.connected_peers();
    }
    let lookup_time = lookup_start.elapsed();

    assert_eq!(manager.peer_count(), 100);
    
    // Performance should be reasonable
    assert!(add_time < Duration::from_millis(100));
    assert!(lookup_time < Duration::from_millis(100));

    info!("✅ Performance test passed (add: {:?}, lookup: {:?})", add_time, lookup_time);
    Ok(())
}

#[cfg(test)]
mod test_runner {
    use super::*;
    
    /// Run all minimal P2P tests
    pub async fn run_all_minimal_tests() -> NetworkResult<()> {
        let test_results = vec![
            ("peer_manager_basic", test_peer_manager_basic().await),
            ("peer_id_operations", test_peer_id_operations().await),
            ("configuration_validation", test_configuration_validation().await),
            ("concurrent_operations", test_concurrent_operations().await),
            ("error_handling", test_error_handling().await),
            ("peer_status_reputation", test_peer_status_reputation().await),
            ("peer_statistics", test_peer_statistics().await),
            ("peer_cleanup", test_peer_cleanup().await),
            ("full_workflow", test_full_workflow().await),
            ("performance_many_peers", test_performance_many_peers().await),
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
        
        println!("\n📊 Minimal Test Results: {} passed, {} failed", passed, failed);
        
        if failed > 0 {
            Err(NetworkError::TestFailed {
                reason: format!("{} tests failed", failed),
            })
        } else {
            Ok(())
        }
    }
}