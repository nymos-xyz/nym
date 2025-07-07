use nym_network::performance_optimizer::*;
use nym_network::{NetworkResult, PeerId};
use std::time::Duration;

#[tokio::test]
async fn test_performance_optimizer_basic() -> NetworkResult<()> {
    let config = PerformanceConfig::default();
    let optimizer = NetworkPerformanceOptimizer::new(config);
    
    // Test startup
    optimizer.start().await?;
    
    // Test metrics
    let metrics = optimizer.get_performance_metrics().await?;
    assert!(metrics.timestamp.elapsed() < Duration::from_secs(1));
    
    println!("✅ Performance optimizer basic test passed");
    Ok(())
}

#[tokio::test] 
async fn test_peer_optimization() -> NetworkResult<()> {
    let config = PerformanceConfig {
        enable_auto_optimization: true,
        optimization_aggressiveness: 0.8,
        ..Default::default()
    };
    let optimizer = NetworkPerformanceOptimizer::new(config);
    
    optimizer.start().await?;
    
    // Test peer optimization
    let peer_id = PeerId::random();
    let result = optimizer.optimize_peer_connection(&peer_id).await?;
    
    assert!(result.timestamp.elapsed() < Duration::from_secs(1));
    
    println!("✅ Peer optimization test passed");
    Ok(())
}

#[tokio::test]
async fn test_performance_prediction() -> NetworkResult<()> {
    let config = PerformanceConfig::default();
    let optimizer = NetworkPerformanceOptimizer::new(config);
    
    optimizer.start().await?;
    
    // Test performance prediction
    let predictions = optimizer.predict_performance(Duration::from_secs(300)).await?;
    
    println!("✅ Performance prediction test passed with {} predictions", predictions.len());
    Ok(())
}

#[tokio::test]
async fn test_force_optimization() -> NetworkResult<()> {
    let config = PerformanceConfig {
        enable_connection_pooling: true,
        enable_load_balancing: true,
        enable_adaptive_bandwidth: true,
        ..Default::default()
    };
    let optimizer = NetworkPerformanceOptimizer::new(config);
    
    optimizer.start().await?;
    
    // Test forced optimization
    let results = optimizer.force_optimization().await?;
    
    println!("✅ Force optimization test completed with {} optimizations", results.len());
    Ok(())
}

fn main() {
    println!("Performance optimizer tests ready to run with:");
    println!("cargo test --package nym-network --test test_performance");
}