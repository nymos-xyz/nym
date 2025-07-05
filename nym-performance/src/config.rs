//! Performance optimization configuration

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// Performance optimization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceConfig {
    /// zk-STARK optimization configuration
    pub zkstark_optimization: ZkStarkOptimizationConfig,
    /// Memory optimization configuration
    pub memory_optimization: MemoryOptimizationConfig,
    /// Network optimization configuration
    pub network_optimization: NetworkOptimizationConfig,
    /// Profiling configuration
    pub profiling: ProfilingConfig,
    /// Benchmarking configuration
    pub benchmarking: BenchmarkingConfig,
    /// Monitoring configuration
    pub monitoring: MonitoringConfig,
    /// General performance configuration
    pub general: GeneralConfig,
}

/// zk-STARK optimization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkStarkOptimizationConfig {
    /// Enable zk-STARK optimization
    pub enabled: bool,
    /// Batch size for proof generation
    pub batch_size: usize,
    /// Number of worker threads for parallel processing
    pub worker_threads: usize,
    /// Cache size for proof caching (in MB)
    pub cache_size_mb: usize,
    /// Enable proof caching
    pub enable_caching: bool,
    /// Enable batch processing
    pub enable_batching: bool,
    /// Enable parallel processing
    pub enable_parallel: bool,
    /// Maximum proof generation time (seconds)
    pub max_proof_time_secs: u64,
    /// Proof verification timeout (seconds)
    pub verification_timeout_secs: u64,
    /// Memory limit for proof generation (MB)
    pub memory_limit_mb: usize,
    /// Enable proof compression
    pub enable_compression: bool,
    /// Compression level (0-9)
    pub compression_level: u32,
}

/// Memory optimization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryOptimizationConfig {
    /// Enable memory optimization
    pub enabled: bool,
    /// Enable custom allocators
    pub enable_custom_allocators: bool,
    /// Pool allocator configuration
    pub pool_allocator: PoolAllocatorConfig,
    /// Garbage collection configuration
    pub garbage_collection: GcConfig,
    /// Memory monitoring configuration
    pub monitoring: MemoryMonitoringConfig,
    /// Maximum memory usage (MB)
    pub max_memory_mb: usize,
    /// Memory usage warning threshold (%)
    pub warning_threshold_percent: u8,
    /// Memory usage critical threshold (%)
    pub critical_threshold_percent: u8,
    /// Enable memory profiling
    pub enable_profiling: bool,
}

/// Pool allocator configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PoolAllocatorConfig {
    /// Enable pool allocator
    pub enabled: bool,
    /// Small object pool size
    pub small_pool_size: usize,
    /// Medium object pool size
    pub medium_pool_size: usize,
    /// Large object pool size
    pub large_pool_size: usize,
    /// Small object threshold (bytes)
    pub small_threshold: usize,
    /// Medium object threshold (bytes)
    pub medium_threshold: usize,
}

/// Garbage collection configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GcConfig {
    /// Enable garbage collection
    pub enabled: bool,
    /// GC interval (seconds)
    pub interval_secs: u64,
    /// GC threshold (MB)
    pub threshold_mb: usize,
    /// Force GC on memory pressure
    pub force_on_pressure: bool,
}

/// Memory monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMonitoringConfig {
    /// Enable memory monitoring
    pub enabled: bool,
    /// Monitoring interval (seconds)
    pub interval_secs: u64,
    /// Enable memory leak detection
    pub enable_leak_detection: bool,
    /// Memory leak threshold (MB)
    pub leak_threshold_mb: usize,
}

/// Network optimization configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkOptimizationConfig {
    /// Enable network optimization
    pub enabled: bool,
    /// Message batching configuration
    pub batching: NetworkBatchingConfig,
    /// Compression configuration
    pub compression: NetworkCompressionConfig,
    /// Connection pooling configuration
    pub connection_pooling: ConnectionPoolingConfig,
    /// Network monitoring configuration
    pub monitoring: NetworkMonitoringConfig,
    /// Maximum connections
    pub max_connections: usize,
    /// Connection timeout (seconds)
    pub connection_timeout_secs: u64,
    /// Read timeout (seconds)
    pub read_timeout_secs: u64,
    /// Write timeout (seconds)
    pub write_timeout_secs: u64,
}

/// Network batching configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkBatchingConfig {
    /// Enable message batching
    pub enabled: bool,
    /// Maximum batch size
    pub max_batch_size: usize,
    /// Batch timeout (milliseconds)
    pub batch_timeout_ms: u64,
    /// Minimum batch size
    pub min_batch_size: usize,
}

/// Network compression configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkCompressionConfig {
    /// Enable compression
    pub enabled: bool,
    /// Compression algorithm
    pub algorithm: CompressionAlgorithm,
    /// Compression level (0-9)
    pub level: u32,
    /// Minimum size for compression (bytes)
    pub min_size: usize,
}

/// Connection pooling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectionPoolingConfig {
    /// Enable connection pooling
    pub enabled: bool,
    /// Maximum pool size
    pub max_pool_size: usize,
    /// Minimum pool size
    pub min_pool_size: usize,
    /// Connection idle timeout (seconds)
    pub idle_timeout_secs: u64,
    /// Connection max lifetime (seconds)
    pub max_lifetime_secs: u64,
}

/// Network monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMonitoringConfig {
    /// Enable network monitoring
    pub enabled: bool,
    /// Monitoring interval (seconds)
    pub interval_secs: u64,
    /// Enable latency monitoring
    pub enable_latency_monitoring: bool,
    /// Enable bandwidth monitoring
    pub enable_bandwidth_monitoring: bool,
    /// Enable connection monitoring
    pub enable_connection_monitoring: bool,
}

/// Profiling configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfilingConfig {
    /// Enable profiling
    pub enabled: bool,
    /// Profiling interval (seconds)
    pub interval_secs: u64,
    /// Enable CPU profiling
    pub enable_cpu_profiling: bool,
    /// Enable memory profiling
    pub enable_memory_profiling: bool,
    /// Enable network profiling
    pub enable_network_profiling: bool,
    /// Enable flamegraph generation
    pub enable_flamegraph: bool,
    /// Profiling output directory
    pub output_dir: String,
    /// Maximum profile file size (MB)
    pub max_file_size_mb: usize,
}

/// Benchmarking configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkingConfig {
    /// Enable benchmarking
    pub enabled: bool,
    /// Benchmark interval (seconds)
    pub interval_secs: u64,
    /// Enable transaction benchmarks
    pub enable_transaction_benchmarks: bool,
    /// Enable proof benchmarks
    pub enable_proof_benchmarks: bool,
    /// Enable network benchmarks
    pub enable_network_benchmarks: bool,
    /// Enable storage benchmarks
    pub enable_storage_benchmarks: bool,
    /// Benchmark output directory
    pub output_dir: String,
    /// Number of iterations per benchmark
    pub iterations: usize,
    /// Warmup iterations
    pub warmup_iterations: usize,
}

/// Monitoring configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitoringConfig {
    /// Enable monitoring
    pub enabled: bool,
    /// Monitoring interval (seconds)
    pub interval_secs: u64,
    /// Enable Prometheus metrics
    pub enable_prometheus: bool,
    /// Prometheus port
    pub prometheus_port: u16,
    /// Enable real-time alerts
    pub enable_alerts: bool,
    /// Alert configuration
    pub alerts: AlertConfig,
    /// Metrics retention period (hours)
    pub retention_hours: u64,
}

/// Alert configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertConfig {
    /// Enable CPU usage alerts
    pub cpu_usage_enabled: bool,
    /// CPU usage threshold (%)
    pub cpu_usage_threshold: f32,
    /// Enable memory usage alerts
    pub memory_usage_enabled: bool,
    /// Memory usage threshold (%)
    pub memory_usage_threshold: f32,
    /// Enable network latency alerts
    pub network_latency_enabled: bool,
    /// Network latency threshold (ms)
    pub network_latency_threshold_ms: u64,
    /// Enable disk usage alerts
    pub disk_usage_enabled: bool,
    /// Disk usage threshold (%)
    pub disk_usage_threshold: f32,
}

/// General configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GeneralConfig {
    /// Number of worker threads
    pub worker_threads: usize,
    /// Enable debug logging
    pub debug_logging: bool,
    /// Log level
    pub log_level: String,
    /// Enable performance logging
    pub performance_logging: bool,
    /// Performance log interval (seconds)
    pub performance_log_interval_secs: u64,
    /// Enable metrics collection
    pub metrics_enabled: bool,
    /// Metrics collection interval (seconds)
    pub metrics_interval_secs: u64,
}

/// Compression algorithm
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub enum CompressionAlgorithm {
    /// LZ4 compression
    Lz4,
    /// ZSTD compression
    Zstd,
    /// Gzip compression
    Gzip,
    /// No compression
    None,
}

impl Default for PerformanceConfig {
    fn default() -> Self {
        Self {
            zkstark_optimization: ZkStarkOptimizationConfig::default(),
            memory_optimization: MemoryOptimizationConfig::default(),
            network_optimization: NetworkOptimizationConfig::default(),
            profiling: ProfilingConfig::default(),
            benchmarking: BenchmarkingConfig::default(),
            monitoring: MonitoringConfig::default(),
            general: GeneralConfig::default(),
        }
    }
}

impl Default for ZkStarkOptimizationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            batch_size: 100,
            worker_threads: num_cpus::get(),
            cache_size_mb: 256,
            enable_caching: true,
            enable_batching: true,
            enable_parallel: true,
            max_proof_time_secs: 30,
            verification_timeout_secs: 10,
            memory_limit_mb: 1024,
            enable_compression: true,
            compression_level: 6,
        }
    }
}

impl Default for MemoryOptimizationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            enable_custom_allocators: true,
            pool_allocator: PoolAllocatorConfig::default(),
            garbage_collection: GcConfig::default(),
            monitoring: MemoryMonitoringConfig::default(),
            max_memory_mb: 4096,
            warning_threshold_percent: 80,
            critical_threshold_percent: 95,
            enable_profiling: true,
        }
    }
}

impl Default for PoolAllocatorConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            small_pool_size: 1000,
            medium_pool_size: 500,
            large_pool_size: 100,
            small_threshold: 1024,
            medium_threshold: 8192,
        }
    }
}

impl Default for GcConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 60,
            threshold_mb: 512,
            force_on_pressure: true,
        }
    }
}

impl Default for MemoryMonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 30,
            enable_leak_detection: true,
            leak_threshold_mb: 100,
        }
    }
}

impl Default for NetworkOptimizationConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            batching: NetworkBatchingConfig::default(),
            compression: NetworkCompressionConfig::default(),
            connection_pooling: ConnectionPoolingConfig::default(),
            monitoring: NetworkMonitoringConfig::default(),
            max_connections: 1000,
            connection_timeout_secs: 30,
            read_timeout_secs: 30,
            write_timeout_secs: 30,
        }
    }
}

impl Default for NetworkBatchingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_batch_size: 100,
            batch_timeout_ms: 100,
            min_batch_size: 10,
        }
    }
}

impl Default for NetworkCompressionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            algorithm: CompressionAlgorithm::Lz4,
            level: 4,
            min_size: 1024,
        }
    }
}

impl Default for ConnectionPoolingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            max_pool_size: 100,
            min_pool_size: 10,
            idle_timeout_secs: 300,
            max_lifetime_secs: 3600,
        }
    }
}

impl Default for NetworkMonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 30,
            enable_latency_monitoring: true,
            enable_bandwidth_monitoring: true,
            enable_connection_monitoring: true,
        }
    }
}

impl Default for ProfilingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 300,
            enable_cpu_profiling: true,
            enable_memory_profiling: true,
            enable_network_profiling: true,
            enable_flamegraph: true,
            output_dir: "./profiles".to_string(),
            max_file_size_mb: 100,
        }
    }
}

impl Default for BenchmarkingConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            interval_secs: 3600,
            enable_transaction_benchmarks: true,
            enable_proof_benchmarks: true,
            enable_network_benchmarks: true,
            enable_storage_benchmarks: true,
            output_dir: "./benchmarks".to_string(),
            iterations: 1000,
            warmup_iterations: 100,
        }
    }
}

impl Default for MonitoringConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            interval_secs: 60,
            enable_prometheus: true,
            prometheus_port: 9090,
            enable_alerts: true,
            alerts: AlertConfig::default(),
            retention_hours: 24,
        }
    }
}

impl Default for AlertConfig {
    fn default() -> Self {
        Self {
            cpu_usage_enabled: true,
            cpu_usage_threshold: 80.0,
            memory_usage_enabled: true,
            memory_usage_threshold: 80.0,
            network_latency_enabled: true,
            network_latency_threshold_ms: 100,
            disk_usage_enabled: true,
            disk_usage_threshold: 80.0,
        }
    }
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            worker_threads: num_cpus::get(),
            debug_logging: false,
            log_level: "info".to_string(),
            performance_logging: true,
            performance_log_interval_secs: 60,
            metrics_enabled: true,
            metrics_interval_secs: 30,
        }
    }
}

impl PerformanceConfig {
    /// Load configuration from file
    pub fn load_from_file(path: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let content = std::fs::read_to_string(path)?;
        let config: Self = serde_json::from_str(&content)?;
        Ok(config)
    }

    /// Save configuration to file
    pub fn save_to_file(&self, path: &str) -> Result<(), Box<dyn std::error::Error>> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::write(path, content)?;
        Ok(())
    }

    /// Validate configuration
    pub fn validate(&self) -> Result<(), String> {
        // Validate ZkSTARK configuration
        if self.zkstark_optimization.enabled {
            if self.zkstark_optimization.batch_size == 0 {
                return Err("ZkSTARK batch size must be greater than 0".to_string());
            }
            if self.zkstark_optimization.worker_threads == 0 {
                return Err("ZkSTARK worker threads must be greater than 0".to_string());
            }
        }

        // Validate memory configuration
        if self.memory_optimization.enabled {
            if self.memory_optimization.max_memory_mb == 0 {
                return Err("Maximum memory must be greater than 0".to_string());
            }
            if self.memory_optimization.warning_threshold_percent >= 100 {
                return Err("Memory warning threshold must be less than 100%".to_string());
            }
            if self.memory_optimization.critical_threshold_percent >= 100 {
                return Err("Memory critical threshold must be less than 100%".to_string());
            }
        }

        // Validate network configuration
        if self.network_optimization.enabled {
            if self.network_optimization.max_connections == 0 {
                return Err("Maximum connections must be greater than 0".to_string());
            }
            if self.network_optimization.batching.enabled {
                if self.network_optimization.batching.max_batch_size == 0 {
                    return Err("Network batch size must be greater than 0".to_string());
                }
                if self.network_optimization.batching.min_batch_size > self.network_optimization.batching.max_batch_size {
                    return Err("Network min batch size must be less than or equal to max batch size".to_string());
                }
            }
        }

        // Validate general configuration
        if self.general.worker_threads == 0 {
            return Err("Worker threads must be greater than 0".to_string());
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = PerformanceConfig::default();
        assert!(config.zkstark_optimization.enabled);
        assert!(config.memory_optimization.enabled);
        assert!(config.network_optimization.enabled);
        assert!(config.monitoring.enabled);
        assert!(!config.profiling.enabled);
        assert!(!config.benchmarking.enabled);
    }

    #[test]
    fn test_config_validation() {
        let mut config = PerformanceConfig::default();
        assert!(config.validate().is_ok());

        // Test invalid batch size
        config.zkstark_optimization.batch_size = 0;
        assert!(config.validate().is_err());

        // Reset and test invalid memory threshold
        config = PerformanceConfig::default();
        config.memory_optimization.warning_threshold_percent = 100;
        assert!(config.validate().is_err());

        // Reset and test invalid network configuration
        config = PerformanceConfig::default();
        config.network_optimization.max_connections = 0;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_config_serialization() {
        let config = PerformanceConfig::default();
        let serialized = serde_json::to_string(&config).unwrap();
        let deserialized: PerformanceConfig = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(config.zkstark_optimization.enabled, deserialized.zkstark_optimization.enabled);
        assert_eq!(config.memory_optimization.enabled, deserialized.memory_optimization.enabled);
        assert_eq!(config.network_optimization.enabled, deserialized.network_optimization.enabled);
    }

    #[test]
    fn test_config_file_operations() {
        let config = PerformanceConfig::default();
        let temp_file = NamedTempFile::new().unwrap();
        let path = temp_file.path().to_str().unwrap();

        // Save config
        config.save_to_file(path).unwrap();

        // Load config
        let loaded_config = PerformanceConfig::load_from_file(path).unwrap();

        assert_eq!(config.zkstark_optimization.enabled, loaded_config.zkstark_optimization.enabled);
        assert_eq!(config.memory_optimization.enabled, loaded_config.memory_optimization.enabled);
        assert_eq!(config.network_optimization.enabled, loaded_config.network_optimization.enabled);
    }
}