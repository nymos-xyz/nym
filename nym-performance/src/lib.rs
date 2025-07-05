//! # Nym Performance Optimization and Monitoring
//!
//! This crate provides comprehensive performance optimization and monitoring
//! capabilities for the Nym blockchain ecosystem, including:
//!
//! - zk-STARK proof generation optimization
//! - Memory usage optimization and profiling
//! - Network protocol efficiency improvements
//! - Real-time performance monitoring
//! - Benchmarking and profiling tools
//!
//! ## Key Features
//!
//! - **Proof Optimization**: Batch processing, caching, and parallelization
//! - **Memory Management**: Pool allocators and optimized data structures
//! - **Network Efficiency**: Message batching, compression, connection pooling
//! - **Performance Monitoring**: Real-time metrics and alerting
//! - **Benchmarking**: Comprehensive performance testing framework

pub mod zkstark_optimizer;
pub mod memory_optimizer;
pub mod network_optimizer;
pub mod profiling;
pub mod benchmarking;
pub mod monitoring;
pub mod allocators;
pub mod compression;
pub mod caching;
pub mod parallelization;
pub mod error;
pub mod metrics;
pub mod config;

pub use error::{PerformanceError, Result};
pub use config::PerformanceConfig;
pub use metrics::PerformanceMetrics;

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};

/// Main performance optimization manager
pub struct PerformanceManager {
    config: PerformanceConfig,
    zkstark_optimizer: Arc<zkstark_optimizer::ZkStarkOptimizer>,
    memory_optimizer: Arc<memory_optimizer::MemoryOptimizer>,
    network_optimizer: Arc<network_optimizer::NetworkOptimizer>,
    profiler: Arc<profiling::Profiler>,
    benchmarker: Arc<benchmarking::Benchmarker>,
    monitor: Arc<monitoring::Monitor>,
    metrics: Arc<RwLock<PerformanceMetrics>>,
}

impl PerformanceManager {
    /// Create a new performance manager with default configuration
    pub fn new() -> Result<Self> {
        Self::with_config(PerformanceConfig::default())
    }

    /// Create a new performance manager with custom configuration
    pub fn with_config(config: PerformanceConfig) -> Result<Self> {
        info!("Initializing Nym Performance Manager");

        let zkstark_optimizer = Arc::new(zkstark_optimizer::ZkStarkOptimizer::new(&config)?);
        let memory_optimizer = Arc::new(memory_optimizer::MemoryOptimizer::new(&config)?);
        let network_optimizer = Arc::new(network_optimizer::NetworkOptimizer::new(&config)?);
        let profiler = Arc::new(profiling::Profiler::new(&config)?);
        let benchmarker = Arc::new(benchmarking::Benchmarker::new(&config)?);
        let monitor = Arc::new(monitoring::Monitor::new(&config)?);
        let metrics = Arc::new(RwLock::new(PerformanceMetrics::new()));

        Ok(Self {
            config,
            zkstark_optimizer,
            memory_optimizer,
            network_optimizer,
            profiler,
            benchmarker,
            monitor,
            metrics,
        })
    }

    /// Start all optimization services
    pub async fn start(&self) -> Result<()> {
        info!("Starting performance optimization services");

        // Start monitoring
        self.monitor.start().await?;

        // Initialize optimizers
        self.zkstark_optimizer.initialize().await?;
        self.memory_optimizer.initialize().await?;
        self.network_optimizer.initialize().await?;

        // Start profiling if enabled
        if self.config.profiling.enabled {
            self.profiler.start().await?;
        }

        // Start benchmarking if enabled
        if self.config.benchmarking.enabled {
            self.benchmarker.start().await?;
        }

        info!("Performance optimization services started successfully");
        Ok(())
    }

    /// Stop all optimization services
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping performance optimization services");

        // Stop services in reverse order
        if self.config.benchmarking.enabled {
            self.benchmarker.stop().await?;
        }

        if self.config.profiling.enabled {
            self.profiler.stop().await?;
        }

        self.network_optimizer.shutdown().await?;
        self.memory_optimizer.shutdown().await?;
        self.zkstark_optimizer.shutdown().await?;
        self.monitor.stop().await?;

        info!("Performance optimization services stopped successfully");
        Ok(())
    }

    /// Get current performance metrics
    pub async fn get_metrics(&self) -> PerformanceMetrics {
        self.metrics.read().await.clone()
    }

    /// Run comprehensive performance optimization
    pub async fn optimize(&self) -> Result<()> {
        info!("Running comprehensive performance optimization");

        // Update metrics
        let mut metrics = self.metrics.write().await;
        metrics.optimization_runs += 1;
        metrics.last_optimization = chrono::Utc::now();
        drop(metrics);

        // Run optimizations in parallel
        let zkstark_task = self.zkstark_optimizer.optimize();
        let memory_task = self.memory_optimizer.optimize();
        let network_task = self.network_optimizer.optimize();

        let (zkstark_result, memory_result, network_result) = 
            tokio::join!(zkstark_task, memory_task, network_task);

        zkstark_result?;
        memory_result?;
        network_result?;

        info!("Comprehensive performance optimization completed");
        Ok(())
    }

    /// Run performance benchmarks
    pub async fn benchmark(&self) -> Result<benchmarking::BenchmarkResults> {
        self.benchmarker.run_all().await
    }

    /// Get current performance profile
    pub async fn profile(&self) -> Result<profiling::ProfileReport> {
        self.profiler.generate_report().await
    }

    /// Get zkSTARK optimizer
    pub fn zkstark_optimizer(&self) -> &Arc<zkstark_optimizer::ZkStarkOptimizer> {
        &self.zkstark_optimizer
    }

    /// Get memory optimizer
    pub fn memory_optimizer(&self) -> &Arc<memory_optimizer::MemoryOptimizer> {
        &self.memory_optimizer
    }

    /// Get network optimizer
    pub fn network_optimizer(&self) -> &Arc<network_optimizer::NetworkOptimizer> {
        &self.network_optimizer
    }

    /// Get profiler
    pub fn profiler(&self) -> &Arc<profiling::Profiler> {
        &self.profiler
    }

    /// Get benchmarker
    pub fn benchmarker(&self) -> &Arc<benchmarking::Benchmarker> {
        &self.benchmarker
    }

    /// Get monitor
    pub fn monitor(&self) -> &Arc<monitoring::Monitor> {
        &self.monitor
    }
}

impl Default for PerformanceManager {
    fn default() -> Self {
        Self::new().expect("Failed to create default PerformanceManager")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use test_case::test_case;

    #[tokio::test]
    async fn test_performance_manager_creation() {
        let manager = PerformanceManager::new().unwrap();
        assert!(manager.config.zkstark_optimization.enabled);
        assert!(manager.config.memory_optimization.enabled);
        assert!(manager.config.network_optimization.enabled);
    }

    #[tokio::test]
    async fn test_performance_manager_start_stop() {
        let manager = PerformanceManager::new().unwrap();
        
        // Start services
        manager.start().await.unwrap();
        
        // Check initial metrics
        let metrics = manager.get_metrics().await;
        assert_eq!(metrics.optimization_runs, 0);
        
        // Stop services
        manager.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_performance_optimization() {
        let manager = PerformanceManager::new().unwrap();
        manager.start().await.unwrap();
        
        // Run optimization
        manager.optimize().await.unwrap();
        
        // Check metrics were updated
        let metrics = manager.get_metrics().await;
        assert_eq!(metrics.optimization_runs, 1);
        
        manager.stop().await.unwrap();
    }

    #[test_case(true, true, true; "all features enabled")]
    #[test_case(false, false, false; "all features disabled")]
    #[tokio::test]
    async fn test_performance_manager_configuration(
        zkstark_enabled: bool,
        memory_enabled: bool,
        network_enabled: bool,
    ) {
        let mut config = PerformanceConfig::default();
        config.zkstark_optimization.enabled = zkstark_enabled;
        config.memory_optimization.enabled = memory_enabled;
        config.network_optimization.enabled = network_enabled;
        
        let manager = PerformanceManager::with_config(config).unwrap();
        assert_eq!(manager.config.zkstark_optimization.enabled, zkstark_enabled);
        assert_eq!(manager.config.memory_optimization.enabled, memory_enabled);
        assert_eq!(manager.config.network_optimization.enabled, network_enabled);
    }
}