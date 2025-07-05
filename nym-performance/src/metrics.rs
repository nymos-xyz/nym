//! Performance metrics collection and reporting

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::Duration;
use chrono::{DateTime, Utc};
use hdrhistogram::Histogram;

/// Performance metrics aggregation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Timestamp of last update
    pub timestamp: DateTime<Utc>,
    /// Number of optimization runs
    pub optimization_runs: u64,
    /// Last optimization timestamp
    pub last_optimization: DateTime<Utc>,
    /// zk-STARK metrics
    pub zkstark: ZkStarkMetrics,
    /// Memory metrics
    pub memory: MemoryMetrics,
    /// Network metrics
    pub network: NetworkMetrics,
    /// System metrics
    pub system: SystemMetrics,
    /// Transaction metrics
    pub transactions: TransactionMetrics,
    /// Custom metrics
    pub custom: HashMap<String, f64>,
}

/// zk-STARK performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZkStarkMetrics {
    /// Total proofs generated
    pub total_proofs_generated: u64,
    /// Total proofs verified
    pub total_proofs_verified: u64,
    /// Average proof generation time (ms)
    pub avg_proof_gen_time_ms: f64,
    /// Average proof verification time (ms)
    pub avg_proof_verify_time_ms: f64,
    /// Proof generation failures
    pub proof_gen_failures: u64,
    /// Proof verification failures
    pub proof_verify_failures: u64,
    /// Cache hit rate (%)
    pub cache_hit_rate: f64,
    /// Batch processing rate (%)
    pub batch_processing_rate: f64,
    /// Parallel processing efficiency (%)
    pub parallel_efficiency: f64,
    /// Memory usage for proof generation (MB)
    pub proof_memory_usage_mb: f64,
    /// Compression ratio
    pub compression_ratio: f64,
}

/// Memory performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryMetrics {
    /// Total memory allocated (MB)
    pub total_allocated_mb: f64,
    /// Current memory usage (MB)
    pub current_usage_mb: f64,
    /// Peak memory usage (MB)
    pub peak_usage_mb: f64,
    /// Memory usage percentage
    pub usage_percentage: f64,
    /// Pool allocator hit rate (%)
    pub pool_hit_rate: f64,
    /// Garbage collection runs
    pub gc_runs: u64,
    /// Average GC time (ms)
    pub avg_gc_time_ms: f64,
    /// Memory leaks detected
    pub memory_leaks: u64,
    /// Fragmentation ratio
    pub fragmentation_ratio: f64,
    /// Allocation rate (allocations/sec)
    pub allocation_rate: f64,
    /// Deallocation rate (deallocations/sec)
    pub deallocation_rate: f64,
}

/// Network performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    /// Total messages sent
    pub total_messages_sent: u64,
    /// Total messages received
    pub total_messages_received: u64,
    /// Total bytes sent
    pub total_bytes_sent: u64,
    /// Total bytes received
    pub total_bytes_received: u64,
    /// Average message latency (ms)
    pub avg_message_latency_ms: f64,
    /// Average bandwidth utilization (%)
    pub avg_bandwidth_utilization: f64,
    /// Connection pool utilization (%)
    pub connection_pool_utilization: f64,
    /// Batch processing rate (%)
    pub batch_processing_rate: f64,
    /// Compression ratio
    pub compression_ratio: f64,
    /// Network errors
    pub network_errors: u64,
    /// Connection failures
    pub connection_failures: u64,
    /// Timeout errors
    pub timeout_errors: u64,
}

/// System performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetrics {
    /// CPU usage percentage
    pub cpu_usage_percent: f64,
    /// Memory usage percentage
    pub memory_usage_percent: f64,
    /// Disk usage percentage
    pub disk_usage_percent: f64,
    /// Network I/O rate (bytes/sec)
    pub network_io_rate: f64,
    /// Disk I/O rate (bytes/sec)
    pub disk_io_rate: f64,
    /// System load average
    pub load_average: f64,
    /// Number of threads
    pub thread_count: u64,
    /// Number of file descriptors
    pub fd_count: u64,
    /// System uptime (seconds)
    pub uptime_seconds: u64,
}

/// Transaction performance metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionMetrics {
    /// Total transactions processed
    pub total_transactions: u64,
    /// Transactions per second
    pub transactions_per_second: f64,
    /// Average transaction processing time (ms)
    pub avg_processing_time_ms: f64,
    /// Transaction validation failures
    pub validation_failures: u64,
    /// Transaction verification failures
    pub verification_failures: u64,
    /// Average transaction size (bytes)
    pub avg_transaction_size_bytes: f64,
    /// Transaction throughput (bytes/sec)
    pub transaction_throughput: f64,
}

/// Metrics collector for performance data
pub struct MetricsCollector {
    zkstark_metrics: ZkStarkMetrics,
    memory_metrics: MemoryMetrics,
    network_metrics: NetworkMetrics,
    system_metrics: SystemMetrics,
    transaction_metrics: TransactionMetrics,
    custom_metrics: HashMap<String, f64>,
    
    // Histograms for detailed statistics
    proof_gen_histogram: Histogram<u64>,
    proof_verify_histogram: Histogram<u64>,
    message_latency_histogram: Histogram<u64>,
    transaction_time_histogram: Histogram<u64>,
    
    // Counters
    zkstark_counters: ZkStarkCounters,
    memory_counters: MemoryCounters,
    network_counters: NetworkCounters,
    transaction_counters: TransactionCounters,
    
    last_update: DateTime<Utc>,
}

/// zk-STARK counters
#[derive(Debug, Default)]
struct ZkStarkCounters {
    proofs_generated: u64,
    proofs_verified: u64,
    proof_gen_failures: u64,
    proof_verify_failures: u64,
    cache_hits: u64,
    cache_misses: u64,
    batch_operations: u64,
    single_operations: u64,
}

/// Memory counters
#[derive(Debug, Default)]
struct MemoryCounters {
    allocations: u64,
    deallocations: u64,
    gc_runs: u64,
    memory_leaks: u64,
    pool_hits: u64,
    pool_misses: u64,
}

/// Network counters
#[derive(Debug, Default)]
struct NetworkCounters {
    messages_sent: u64,
    messages_received: u64,
    bytes_sent: u64,
    bytes_received: u64,
    network_errors: u64,
    connection_failures: u64,
    timeout_errors: u64,
    batch_operations: u64,
}

/// Transaction counters
#[derive(Debug, Default)]
struct TransactionCounters {
    transactions_processed: u64,
    validation_failures: u64,
    verification_failures: u64,
    total_processing_time_ms: u64,
    total_transaction_bytes: u64,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Self {
        Self {
            zkstark_metrics: ZkStarkMetrics::default(),
            memory_metrics: MemoryMetrics::default(),
            network_metrics: NetworkMetrics::default(),
            system_metrics: SystemMetrics::default(),
            transaction_metrics: TransactionMetrics::default(),
            custom_metrics: HashMap::new(),
            
            proof_gen_histogram: Histogram::new(3).unwrap(),
            proof_verify_histogram: Histogram::new(3).unwrap(),
            message_latency_histogram: Histogram::new(3).unwrap(),
            transaction_time_histogram: Histogram::new(3).unwrap(),
            
            zkstark_counters: ZkStarkCounters::default(),
            memory_counters: MemoryCounters::default(),
            network_counters: NetworkCounters::default(),
            transaction_counters: TransactionCounters::default(),
            
            last_update: Utc::now(),
        }
    }

    /// Record proof generation time
    pub fn record_proof_generation(&mut self, duration: Duration, success: bool) {
        let duration_ms = duration.as_millis() as u64;
        
        if success {
            self.zkstark_counters.proofs_generated += 1;
            self.proof_gen_histogram.record(duration_ms).ok();
        } else {
            self.zkstark_counters.proof_gen_failures += 1;
        }
    }

    /// Record proof verification time
    pub fn record_proof_verification(&mut self, duration: Duration, success: bool) {
        let duration_ms = duration.as_millis() as u64;
        
        if success {
            self.zkstark_counters.proofs_verified += 1;
            self.proof_verify_histogram.record(duration_ms).ok();
        } else {
            self.zkstark_counters.proof_verify_failures += 1;
        }
    }

    /// Record cache hit/miss
    pub fn record_cache_access(&mut self, hit: bool) {
        if hit {
            self.zkstark_counters.cache_hits += 1;
        } else {
            self.zkstark_counters.cache_misses += 1;
        }
    }

    /// Record batch operation
    pub fn record_batch_operation(&mut self, batch_size: usize) {
        if batch_size > 1 {
            self.zkstark_counters.batch_operations += 1;
        } else {
            self.zkstark_counters.single_operations += 1;
        }
    }

    /// Record memory allocation
    pub fn record_memory_allocation(&mut self, size: usize, from_pool: bool) {
        self.memory_counters.allocations += 1;
        if from_pool {
            self.memory_counters.pool_hits += 1;
        } else {
            self.memory_counters.pool_misses += 1;
        }
    }

    /// Record memory deallocation
    pub fn record_memory_deallocation(&mut self, _size: usize) {
        self.memory_counters.deallocations += 1;
    }

    /// Record garbage collection
    pub fn record_gc_run(&mut self, _duration: Duration) {
        self.memory_counters.gc_runs += 1;
    }

    /// Record memory leak
    pub fn record_memory_leak(&mut self, _size: usize) {
        self.memory_counters.memory_leaks += 1;
    }

    /// Record network message
    pub fn record_network_message(&mut self, direction: MessageDirection, size: usize, latency: Option<Duration>) {
        match direction {
            MessageDirection::Sent => {
                self.network_counters.messages_sent += 1;
                self.network_counters.bytes_sent += size as u64;
            }
            MessageDirection::Received => {
                self.network_counters.messages_received += 1;
                self.network_counters.bytes_received += size as u64;
            }
        }

        if let Some(latency) = latency {
            let latency_ms = latency.as_millis() as u64;
            self.message_latency_histogram.record(latency_ms).ok();
        }
    }

    /// Record network error
    pub fn record_network_error(&mut self, error_type: NetworkErrorType) {
        match error_type {
            NetworkErrorType::General => self.network_counters.network_errors += 1,
            NetworkErrorType::ConnectionFailure => self.network_counters.connection_failures += 1,
            NetworkErrorType::Timeout => self.network_counters.timeout_errors += 1,
        }
    }

    /// Record network batch operation
    pub fn record_network_batch(&mut self, batch_size: usize) {
        if batch_size > 1 {
            self.network_counters.batch_operations += 1;
        }
    }

    /// Record transaction processing
    pub fn record_transaction_processing(&mut self, duration: Duration, size: usize, success: bool) {
        let duration_ms = duration.as_millis() as u64;
        
        if success {
            self.transaction_counters.transactions_processed += 1;
            self.transaction_counters.total_processing_time_ms += duration_ms;
            self.transaction_counters.total_transaction_bytes += size as u64;
            self.transaction_time_histogram.record(duration_ms).ok();
        }
    }

    /// Record transaction validation failure
    pub fn record_transaction_validation_failure(&mut self) {
        self.transaction_counters.validation_failures += 1;
    }

    /// Record transaction verification failure
    pub fn record_transaction_verification_failure(&mut self) {
        self.transaction_counters.verification_failures += 1;
    }

    /// Record custom metric
    pub fn record_custom_metric(&mut self, name: String, value: f64) {
        self.custom_metrics.insert(name, value);
    }

    /// Update system metrics
    pub fn update_system_metrics(&mut self, system_info: &SystemInfo) {
        self.system_metrics.cpu_usage_percent = system_info.cpu_usage_percent;
        self.system_metrics.memory_usage_percent = system_info.memory_usage_percent;
        self.system_metrics.disk_usage_percent = system_info.disk_usage_percent;
        self.system_metrics.network_io_rate = system_info.network_io_rate;
        self.system_metrics.disk_io_rate = system_info.disk_io_rate;
        self.system_metrics.load_average = system_info.load_average;
        self.system_metrics.thread_count = system_info.thread_count;
        self.system_metrics.fd_count = system_info.fd_count;
        self.system_metrics.uptime_seconds = system_info.uptime_seconds;
    }

    /// Generate performance metrics snapshot
    pub fn generate_metrics(&mut self) -> PerformanceMetrics {
        let now = Utc::now();
        let duration_since_last = (now - self.last_update).num_seconds() as f64;
        
        // Update zk-STARK metrics
        self.zkstark_metrics.total_proofs_generated = self.zkstark_counters.proofs_generated;
        self.zkstark_metrics.total_proofs_verified = self.zkstark_counters.proofs_verified;
        self.zkstark_metrics.proof_gen_failures = self.zkstark_counters.proof_gen_failures;
        self.zkstark_metrics.proof_verify_failures = self.zkstark_counters.proof_verify_failures;
        
        if self.proof_gen_histogram.len() > 0 {
            self.zkstark_metrics.avg_proof_gen_time_ms = self.proof_gen_histogram.mean();
        }
        
        if self.proof_verify_histogram.len() > 0 {
            self.zkstark_metrics.avg_proof_verify_time_ms = self.proof_verify_histogram.mean();
        }
        
        let total_cache_accesses = self.zkstark_counters.cache_hits + self.zkstark_counters.cache_misses;
        if total_cache_accesses > 0 {
            self.zkstark_metrics.cache_hit_rate = (self.zkstark_counters.cache_hits as f64 / total_cache_accesses as f64) * 100.0;
        }
        
        let total_operations = self.zkstark_counters.batch_operations + self.zkstark_counters.single_operations;
        if total_operations > 0 {
            self.zkstark_metrics.batch_processing_rate = (self.zkstark_counters.batch_operations as f64 / total_operations as f64) * 100.0;
        }
        
        // Update memory metrics
        self.memory_metrics.gc_runs = self.memory_counters.gc_runs;
        self.memory_metrics.memory_leaks = self.memory_counters.memory_leaks;
        
        let total_pool_accesses = self.memory_counters.pool_hits + self.memory_counters.pool_misses;
        if total_pool_accesses > 0 {
            self.memory_metrics.pool_hit_rate = (self.memory_counters.pool_hits as f64 / total_pool_accesses as f64) * 100.0;
        }
        
        if duration_since_last > 0.0 {
            self.memory_metrics.allocation_rate = self.memory_counters.allocations as f64 / duration_since_last;
            self.memory_metrics.deallocation_rate = self.memory_counters.deallocations as f64 / duration_since_last;
        }
        
        // Update network metrics
        self.network_metrics.total_messages_sent = self.network_counters.messages_sent;
        self.network_metrics.total_messages_received = self.network_counters.messages_received;
        self.network_metrics.total_bytes_sent = self.network_counters.bytes_sent;
        self.network_metrics.total_bytes_received = self.network_counters.bytes_received;
        self.network_metrics.network_errors = self.network_counters.network_errors;
        self.network_metrics.connection_failures = self.network_counters.connection_failures;
        self.network_metrics.timeout_errors = self.network_counters.timeout_errors;
        
        if self.message_latency_histogram.len() > 0 {
            self.network_metrics.avg_message_latency_ms = self.message_latency_histogram.mean();
        }
        
        let total_network_operations = self.network_counters.batch_operations + (self.network_counters.messages_sent - self.network_counters.batch_operations);
        if total_network_operations > 0 {
            self.network_metrics.batch_processing_rate = (self.network_counters.batch_operations as f64 / total_network_operations as f64) * 100.0;
        }
        
        // Update transaction metrics
        self.transaction_metrics.total_transactions = self.transaction_counters.transactions_processed;
        self.transaction_metrics.validation_failures = self.transaction_counters.validation_failures;
        self.transaction_metrics.verification_failures = self.transaction_counters.verification_failures;
        
        if self.transaction_counters.transactions_processed > 0 {
            self.transaction_metrics.avg_processing_time_ms = self.transaction_counters.total_processing_time_ms as f64 / self.transaction_counters.transactions_processed as f64;
            self.transaction_metrics.avg_transaction_size_bytes = self.transaction_counters.total_transaction_bytes as f64 / self.transaction_counters.transactions_processed as f64;
        }
        
        if duration_since_last > 0.0 {
            self.transaction_metrics.transactions_per_second = self.transaction_counters.transactions_processed as f64 / duration_since_last;
            self.transaction_metrics.transaction_throughput = self.transaction_counters.total_transaction_bytes as f64 / duration_since_last;
        }
        
        self.last_update = now;
        
        PerformanceMetrics {
            timestamp: now,
            optimization_runs: 0,
            last_optimization: now,
            zkstark: self.zkstark_metrics.clone(),
            memory: self.memory_metrics.clone(),
            network: self.network_metrics.clone(),
            system: self.system_metrics.clone(),
            transactions: self.transaction_metrics.clone(),
            custom: self.custom_metrics.clone(),
        }
    }

    /// Reset all metrics
    pub fn reset(&mut self) {
        self.zkstark_counters = ZkStarkCounters::default();
        self.memory_counters = MemoryCounters::default();
        self.network_counters = NetworkCounters::default();
        self.transaction_counters = TransactionCounters::default();
        self.custom_metrics.clear();
        
        self.proof_gen_histogram.clear();
        self.proof_verify_histogram.clear();
        self.message_latency_histogram.clear();
        self.transaction_time_histogram.clear();
        
        self.last_update = Utc::now();
    }
}

/// Message direction for network metrics
#[derive(Debug, Clone, Copy)]
pub enum MessageDirection {
    Sent,
    Received,
}

/// Network error type
#[derive(Debug, Clone, Copy)]
pub enum NetworkErrorType {
    General,
    ConnectionFailure,
    Timeout,
}

/// System information for metrics
#[derive(Debug, Clone)]
pub struct SystemInfo {
    pub cpu_usage_percent: f64,
    pub memory_usage_percent: f64,
    pub disk_usage_percent: f64,
    pub network_io_rate: f64,
    pub disk_io_rate: f64,
    pub load_average: f64,
    pub thread_count: u64,
    pub fd_count: u64,
    pub uptime_seconds: u64,
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self::new()
    }
}

impl PerformanceMetrics {
    /// Create new performance metrics
    pub fn new() -> Self {
        Self {
            timestamp: Utc::now(),
            optimization_runs: 0,
            last_optimization: Utc::now(),
            zkstark: ZkStarkMetrics::default(),
            memory: MemoryMetrics::default(),
            network: NetworkMetrics::default(),
            system: SystemMetrics::default(),
            transactions: TransactionMetrics::default(),
            custom: HashMap::new(),
        }
    }

    /// Export metrics to JSON
    pub fn to_json(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }

    /// Import metrics from JSON
    pub fn from_json(json: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json)
    }
}

// Default implementations for metrics structs
impl Default for ZkStarkMetrics {
    fn default() -> Self {
        Self {
            total_proofs_generated: 0,
            total_proofs_verified: 0,
            avg_proof_gen_time_ms: 0.0,
            avg_proof_verify_time_ms: 0.0,
            proof_gen_failures: 0,
            proof_verify_failures: 0,
            cache_hit_rate: 0.0,
            batch_processing_rate: 0.0,
            parallel_efficiency: 0.0,
            proof_memory_usage_mb: 0.0,
            compression_ratio: 0.0,
        }
    }
}

impl Default for MemoryMetrics {
    fn default() -> Self {
        Self {
            total_allocated_mb: 0.0,
            current_usage_mb: 0.0,
            peak_usage_mb: 0.0,
            usage_percentage: 0.0,
            pool_hit_rate: 0.0,
            gc_runs: 0,
            avg_gc_time_ms: 0.0,
            memory_leaks: 0,
            fragmentation_ratio: 0.0,
            allocation_rate: 0.0,
            deallocation_rate: 0.0,
        }
    }
}

impl Default for NetworkMetrics {
    fn default() -> Self {
        Self {
            total_messages_sent: 0,
            total_messages_received: 0,
            total_bytes_sent: 0,
            total_bytes_received: 0,
            avg_message_latency_ms: 0.0,
            avg_bandwidth_utilization: 0.0,
            connection_pool_utilization: 0.0,
            batch_processing_rate: 0.0,
            compression_ratio: 0.0,
            network_errors: 0,
            connection_failures: 0,
            timeout_errors: 0,
        }
    }
}

impl Default for SystemMetrics {
    fn default() -> Self {
        Self {
            cpu_usage_percent: 0.0,
            memory_usage_percent: 0.0,
            disk_usage_percent: 0.0,
            network_io_rate: 0.0,
            disk_io_rate: 0.0,
            load_average: 0.0,
            thread_count: 0,
            fd_count: 0,
            uptime_seconds: 0,
        }
    }
}

impl Default for TransactionMetrics {
    fn default() -> Self {
        Self {
            total_transactions: 0,
            transactions_per_second: 0.0,
            avg_processing_time_ms: 0.0,
            validation_failures: 0,
            verification_failures: 0,
            avg_transaction_size_bytes: 0.0,
            transaction_throughput: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new();
        assert_eq!(collector.zkstark_counters.proofs_generated, 0);
        assert_eq!(collector.memory_counters.allocations, 0);
        assert_eq!(collector.network_counters.messages_sent, 0);
        assert_eq!(collector.transaction_counters.transactions_processed, 0);
    }

    #[test]
    fn test_proof_generation_recording() {
        let mut collector = MetricsCollector::new();
        
        collector.record_proof_generation(Duration::from_millis(100), true);
        collector.record_proof_generation(Duration::from_millis(200), false);
        
        assert_eq!(collector.zkstark_counters.proofs_generated, 1);
        assert_eq!(collector.zkstark_counters.proof_gen_failures, 1);
    }

    #[test]
    fn test_memory_recording() {
        let mut collector = MetricsCollector::new();
        
        collector.record_memory_allocation(1024, true);
        collector.record_memory_allocation(2048, false);
        collector.record_memory_deallocation(1024);
        
        assert_eq!(collector.memory_counters.allocations, 2);
        assert_eq!(collector.memory_counters.deallocations, 1);
        assert_eq!(collector.memory_counters.pool_hits, 1);
        assert_eq!(collector.memory_counters.pool_misses, 1);
    }

    #[test]
    fn test_network_recording() {
        let mut collector = MetricsCollector::new();
        
        collector.record_network_message(MessageDirection::Sent, 1024, Some(Duration::from_millis(50)));
        collector.record_network_message(MessageDirection::Received, 2048, None);
        collector.record_network_error(NetworkErrorType::Timeout);
        
        assert_eq!(collector.network_counters.messages_sent, 1);
        assert_eq!(collector.network_counters.messages_received, 1);
        assert_eq!(collector.network_counters.bytes_sent, 1024);
        assert_eq!(collector.network_counters.bytes_received, 2048);
        assert_eq!(collector.network_counters.timeout_errors, 1);
    }

    #[test]
    fn test_transaction_recording() {
        let mut collector = MetricsCollector::new();
        
        collector.record_transaction_processing(Duration::from_millis(100), 1024, true);
        collector.record_transaction_validation_failure();
        collector.record_transaction_verification_failure();
        
        assert_eq!(collector.transaction_counters.transactions_processed, 1);
        assert_eq!(collector.transaction_counters.validation_failures, 1);
        assert_eq!(collector.transaction_counters.verification_failures, 1);
    }

    #[test]
    fn test_metrics_generation() {
        let mut collector = MetricsCollector::new();
        
        // Record some data
        collector.record_proof_generation(Duration::from_millis(100), true);
        collector.record_memory_allocation(1024, true);
        collector.record_network_message(MessageDirection::Sent, 1024, Some(Duration::from_millis(50)));
        collector.record_transaction_processing(Duration::from_millis(100), 1024, true);
        
        let metrics = collector.generate_metrics();
        
        assert_eq!(metrics.zkstark.total_proofs_generated, 1);
        assert_eq!(metrics.memory.pool_hit_rate, 100.0);
        assert_eq!(metrics.network.total_messages_sent, 1);
        assert_eq!(metrics.transactions.total_transactions, 1);
    }

    #[test]
    fn test_metrics_serialization() {
        let metrics = PerformanceMetrics::new();
        let json = metrics.to_json().unwrap();
        let deserialized = PerformanceMetrics::from_json(&json).unwrap();
        
        assert_eq!(metrics.zkstark.total_proofs_generated, deserialized.zkstark.total_proofs_generated);
        assert_eq!(metrics.memory.total_allocated_mb, deserialized.memory.total_allocated_mb);
        assert_eq!(metrics.network.total_messages_sent, deserialized.network.total_messages_sent);
        assert_eq!(metrics.transactions.total_transactions, deserialized.transactions.total_transactions);
    }

    #[test]
    fn test_custom_metrics() {
        let mut collector = MetricsCollector::new();
        
        collector.record_custom_metric("custom_metric_1".to_string(), 42.5);
        collector.record_custom_metric("custom_metric_2".to_string(), 100.0);
        
        let metrics = collector.generate_metrics();
        
        assert_eq!(metrics.custom.get("custom_metric_1"), Some(&42.5));
        assert_eq!(metrics.custom.get("custom_metric_2"), Some(&100.0));
    }

    #[test]
    fn test_collector_reset() {
        let mut collector = MetricsCollector::new();
        
        collector.record_proof_generation(Duration::from_millis(100), true);
        collector.record_memory_allocation(1024, true);
        collector.record_custom_metric("test".to_string(), 42.0);
        
        collector.reset();
        
        assert_eq!(collector.zkstark_counters.proofs_generated, 0);
        assert_eq!(collector.memory_counters.allocations, 0);
        assert!(collector.custom_metrics.is_empty());
    }
}