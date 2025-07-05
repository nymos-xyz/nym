//! Comprehensive benchmarking tools for performance analysis

use crate::{PerformanceError, Result, PerformanceConfig};
use std::collections::HashMap;
use std::time::{Duration, Instant};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Deserialize, Serialize};
use hdrhistogram::Histogram;
use criterion::{Criterion, BenchmarkId, Throughput};
use tracing::{info, warn, debug};

/// Comprehensive benchmarking suite
pub struct Benchmarker {
    config: PerformanceConfig,
    benchmark_registry: Arc<RwLock<HashMap<String, BenchmarkDefinition>>>,
    results_history: Arc<RwLock<Vec<BenchmarkResult>>>,
    active_benchmarks: Arc<RwLock<HashMap<String, RunningBenchmark>>>,
    criterion: Option<Criterion>,
}

/// Individual benchmark definition
#[derive(Debug, Clone)]
pub struct BenchmarkDefinition {
    pub name: String,
    pub description: String,
    pub benchmark_type: BenchmarkType,
    pub iterations: usize,
    pub warmup_iterations: usize,
    pub timeout: Duration,
    pub parameters: BenchmarkParameters,
}

/// Running benchmark state
#[derive(Debug)]
struct RunningBenchmark {
    definition: BenchmarkDefinition,
    started_at: Instant,
    current_iteration: usize,
    results: Vec<IterationResult>,
}

/// Benchmark result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkResult {
    pub name: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub duration: Duration,
    pub iterations: usize,
    pub throughput: f64,
    pub latency_stats: LatencyStatistics,
    pub memory_stats: MemoryStatistics,
    pub success_rate: f64,
    pub error_count: u64,
    pub metadata: HashMap<String, String>,
}

/// Benchmark suite results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSuiteResults {
    pub suite_name: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub total_duration: Duration,
    pub benchmarks: Vec<BenchmarkResult>,
    pub summary: BenchmarkSummary,
}

/// Iteration result
#[derive(Debug, Clone)]
struct IterationResult {
    iteration: usize,
    duration: Duration,
    success: bool,
    memory_used: usize,
    error: Option<String>,
}

/// Benchmark type enumeration
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum BenchmarkType {
    Transaction,
    ProofGeneration,
    ProofVerification,
    NetworkThroughput,
    NetworkLatency,
    StorageRead,
    StorageWrite,
    MemoryAllocation,
    Custom,
}

/// Benchmark parameters
#[derive(Debug, Clone)]
pub struct BenchmarkParameters {
    pub transaction_count: Option<usize>,
    pub data_size: Option<usize>,
    pub batch_size: Option<usize>,
    pub concurrent_operations: Option<usize>,
    pub custom_params: HashMap<String, String>,
}

/// Latency statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencyStatistics {
    pub min: Duration,
    pub max: Duration,
    pub mean: Duration,
    pub median: Duration,
    pub p95: Duration,
    pub p99: Duration,
    pub p99_9: Duration,
    pub std_dev: Duration,
}

/// Memory statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStatistics {
    pub peak_usage_mb: f64,
    pub average_usage_mb: f64,
    pub allocations: u64,
    pub deallocations: u64,
    pub gc_runs: u64,
}

/// Benchmark summary
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BenchmarkSummary {
    pub total_benchmarks: usize,
    pub successful_benchmarks: usize,
    pub failed_benchmarks: usize,
    pub total_operations: u64,
    pub overall_throughput: f64,
    pub average_latency: Duration,
    pub performance_score: f64,
}

/// Transaction benchmark configuration
#[derive(Debug, Clone)]
pub struct TransactionBenchmarkConfig {
    pub transaction_count: usize,
    pub concurrent_senders: usize,
    pub transaction_size: usize,
    pub use_batching: bool,
    pub enable_verification: bool,
}

/// Network benchmark configuration
#[derive(Debug, Clone)]
pub struct NetworkBenchmarkConfig {
    pub message_count: usize,
    pub message_size: usize,
    pub concurrent_connections: usize,
    pub enable_compression: bool,
    pub enable_batching: bool,
}

/// Storage benchmark configuration
#[derive(Debug, Clone)]
pub struct StorageBenchmarkConfig {
    pub operation_count: usize,
    pub data_size: usize,
    pub concurrent_operations: usize,
    pub use_encryption: bool,
    pub sync_writes: bool,
}

impl Benchmarker {
    /// Create a new benchmarker
    pub fn new(config: &PerformanceConfig) -> Result<Self> {
        let benchmark_registry = Arc::new(RwLock::new(HashMap::new()));
        let results_history = Arc::new(RwLock::new(Vec::new()));
        let active_benchmarks = Arc::new(RwLock::new(HashMap::new()));
        
        // Initialize Criterion if HTML reports are enabled
        let criterion = if config.benchmarking.enabled {
            Some(Criterion::default()
                .sample_size(config.benchmarking.iterations.min(100))
                .warm_up_time(Duration::from_millis(
                    config.benchmarking.warmup_iterations as u64 * 10
                )))
        } else {
            None
        };

        Ok(Self {
            config: config.clone(),
            benchmark_registry,
            results_history,
            active_benchmarks,
            criterion,
        })
    }

    /// Start benchmarking service
    pub async fn start(&self) -> Result<()> {
        info!("Starting benchmarking service");
        
        // Register default benchmarks
        self.register_default_benchmarks().await?;
        
        // Start periodic benchmarking if enabled
        if self.config.benchmarking.enabled {
            self.start_periodic_benchmarking().await?;
        }
        
        info!("Benchmarking service started");
        Ok(())
    }

    /// Stop benchmarking service
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping benchmarking service");
        
        // Stop any running benchmarks
        let mut active = self.active_benchmarks.write().await;
        active.clear();
        
        info!("Benchmarking service stopped");
        Ok(())
    }

    /// Register a benchmark
    pub async fn register_benchmark(&self, definition: BenchmarkDefinition) -> Result<()> {
        let mut registry = self.benchmark_registry.write().await;
        registry.insert(definition.name.clone(), definition);
        Ok(())
    }

    /// Run a single benchmark
    pub async fn run_benchmark(&self, name: &str) -> Result<BenchmarkResult> {
        let definition = {
            let registry = self.benchmark_registry.read().await;
            registry.get(name).cloned()
                .ok_or_else(|| PerformanceError::benchmarking(format!("Benchmark '{}' not found", name)))?
        };

        info!("Running benchmark: {}", name);
        
        let start_time = Instant::now();
        let mut iterations_results = Vec::new();
        let mut histogram = Histogram::<u64>::new(3).unwrap();
        
        // Warmup iterations
        for i in 0..definition.warmup_iterations {
            debug!("Warmup iteration {}/{}", i + 1, definition.warmup_iterations);
            self.run_benchmark_iteration(&definition, i, true).await?;
        }
        
        // Actual benchmark iterations
        for i in 0..definition.iterations {
            debug!("Benchmark iteration {}/{}", i + 1, definition.iterations);
            
            let result = self.run_benchmark_iteration(&definition, i, false).await?;
            histogram.record(result.duration.as_nanos() as u64).unwrap();
            iterations_results.push(result);
        }
        
        let total_duration = start_time.elapsed();
        
        // Calculate statistics
        let latency_stats = self.calculate_latency_stats(&iterations_results, &histogram)?;
        let memory_stats = self.calculate_memory_stats(&iterations_results)?;
        let success_rate = iterations_results.iter()
            .filter(|r| r.success)
            .count() as f64 / iterations_results.len() as f64;
        let error_count = iterations_results.iter()
            .filter(|r| !r.success)
            .count() as u64;
        let throughput = iterations_results.len() as f64 / total_duration.as_secs_f64();
        
        let result = BenchmarkResult {
            name: name.to_string(),
            timestamp: chrono::Utc::now(),
            duration: total_duration,
            iterations: definition.iterations,
            throughput,
            latency_stats,
            memory_stats,
            success_rate,
            error_count,
            metadata: HashMap::new(),
        };
        
        // Store result
        self.results_history.write().await.push(result.clone());
        
        info!("Benchmark '{}' completed: {:.2} ops/sec, {:.2}% success rate", 
              name, throughput, success_rate * 100.0);
        
        Ok(result)
    }

    /// Run all registered benchmarks
    pub async fn run_all(&self) -> Result<BenchmarkSuiteResults> {
        info!("Running complete benchmark suite");
        
        let start_time = Instant::now();
        let mut benchmark_results = Vec::new();
        
        let benchmark_names: Vec<String> = {
            let registry = self.benchmark_registry.read().await;
            registry.keys().cloned().collect()
        };
        
        for name in benchmark_names {
            match self.run_benchmark(&name).await {
                Ok(result) => benchmark_results.push(result),
                Err(e) => {
                    warn!("Benchmark '{}' failed: {}", name, e);
                    // Continue with other benchmarks
                }
            }
        }
        
        let total_duration = start_time.elapsed();
        let summary = self.calculate_suite_summary(&benchmark_results, total_duration);
        
        let suite_results = BenchmarkSuiteResults {
            suite_name: "Performance Benchmark Suite".to_string(),
            timestamp: chrono::Utc::now(),
            total_duration,
            benchmarks: benchmark_results,
            summary,
        };
        
        info!("Benchmark suite completed in {:?}: {} benchmarks, {:.2} overall score",
              total_duration, suite_results.benchmarks.len(), suite_results.summary.performance_score);
        
        Ok(suite_results)
    }

    /// Run transaction benchmarks
    pub async fn run_transaction_benchmarks(&self, config: TransactionBenchmarkConfig) -> Result<BenchmarkResult> {
        let definition = BenchmarkDefinition {
            name: "transaction_throughput".to_string(),
            description: "Transaction processing throughput benchmark".to_string(),
            benchmark_type: BenchmarkType::Transaction,
            iterations: config.transaction_count,
            warmup_iterations: config.transaction_count / 10,
            timeout: Duration::from_secs(300),
            parameters: BenchmarkParameters {
                transaction_count: Some(config.transaction_count),
                data_size: Some(config.transaction_size),
                concurrent_operations: Some(config.concurrent_senders),
                batch_size: if config.use_batching { Some(100) } else { None },
                custom_params: HashMap::new(),
            },
        };

        self.register_benchmark(definition).await?;
        self.run_benchmark("transaction_throughput").await
    }

    /// Run network benchmarks
    pub async fn run_network_benchmarks(&self, config: NetworkBenchmarkConfig) -> Result<BenchmarkResult> {
        let definition = BenchmarkDefinition {
            name: "network_throughput".to_string(),
            description: "Network message throughput benchmark".to_string(),
            benchmark_type: BenchmarkType::NetworkThroughput,
            iterations: config.message_count,
            warmup_iterations: config.message_count / 10,
            timeout: Duration::from_secs(300),
            parameters: BenchmarkParameters {
                transaction_count: Some(config.message_count),
                data_size: Some(config.message_size),
                concurrent_operations: Some(config.concurrent_connections),
                batch_size: if config.enable_batching { Some(50) } else { None },
                custom_params: HashMap::new(),
            },
        };

        self.register_benchmark(definition).await?;
        self.run_benchmark("network_throughput").await
    }

    /// Run storage benchmarks
    pub async fn run_storage_benchmarks(&self, config: StorageBenchmarkConfig) -> Result<BenchmarkResult> {
        let definition = BenchmarkDefinition {
            name: "storage_throughput".to_string(),
            description: "Storage I/O throughput benchmark".to_string(),
            benchmark_type: BenchmarkType::StorageWrite,
            iterations: config.operation_count,
            warmup_iterations: config.operation_count / 10,
            timeout: Duration::from_secs(300),
            parameters: BenchmarkParameters {
                transaction_count: Some(config.operation_count),
                data_size: Some(config.data_size),
                concurrent_operations: Some(config.concurrent_operations),
                batch_size: None,
                custom_params: HashMap::new(),
            },
        };

        self.register_benchmark(definition).await?;
        self.run_benchmark("storage_throughput").await
    }

    /// Get benchmark results history
    pub async fn get_results_history(&self) -> Vec<BenchmarkResult> {
        self.results_history.read().await.clone()
    }

    /// Export results to JSON
    pub async fn export_results(&self, path: &str) -> Result<()> {
        let results = self.get_results_history().await;
        let json = serde_json::to_string_pretty(&results)
            .map_err(|e| PerformanceError::benchmarking(format!("Failed to serialize results: {}", e)))?;
        
        tokio::fs::write(path, json).await
            .map_err(|e| PerformanceError::benchmarking(format!("Failed to write results file: {}", e)))?;
        
        info!("Benchmark results exported to {}", path);
        Ok(())
    }

    /// Generate benchmark report
    pub async fn generate_report(&self) -> Result<String> {
        let results = self.get_results_history().await;
        
        let mut report = String::new();
        report.push_str("# Performance Benchmark Report\n\n");
        report.push_str(&format!("Generated: {}\n\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
        
        if results.is_empty() {
            report.push_str("No benchmark results available.\n");
            return Ok(report);
        }
        
        report.push_str("## Summary\n\n");
        report.push_str(&format!("Total benchmarks: {}\n", results.len()));
        
        let avg_throughput = results.iter()
            .map(|r| r.throughput)
            .sum::<f64>() / results.len() as f64;
        report.push_str(&format!("Average throughput: {:.2} ops/sec\n", avg_throughput));
        
        let avg_success_rate = results.iter()
            .map(|r| r.success_rate)
            .sum::<f64>() / results.len() as f64;
        report.push_str(&format!("Average success rate: {:.2}%\n\n", avg_success_rate * 100.0));
        
        report.push_str("## Individual Benchmark Results\n\n");
        
        for result in &results {
            report.push_str(&format!("### {}\n\n", result.name));
            report.push_str(&format!("- Duration: {:?}\n", result.duration));
            report.push_str(&format!("- Iterations: {}\n", result.iterations));
            report.push_str(&format!("- Throughput: {:.2} ops/sec\n", result.throughput));
            report.push_str(&format!("- Success rate: {:.2}%\n", result.success_rate * 100.0));
            report.push_str(&format!("- Average latency: {:?}\n", result.latency_stats.mean));
            report.push_str(&format!("- P95 latency: {:?}\n", result.latency_stats.p95));
            report.push_str(&format!("- P99 latency: {:?}\n", result.latency_stats.p99));
            report.push_str(&format!("- Peak memory: {:.2} MB\n\n", result.memory_stats.peak_usage_mb));
        }
        
        Ok(report)
    }

    // Private helper methods

    async fn register_default_benchmarks(&self) -> Result<()> {
        // Transaction benchmark
        let tx_benchmark = BenchmarkDefinition {
            name: "default_transaction".to_string(),
            description: "Default transaction processing benchmark".to_string(),
            benchmark_type: BenchmarkType::Transaction,
            iterations: 1000,
            warmup_iterations: 100,
            timeout: Duration::from_secs(60),
            parameters: BenchmarkParameters::default(),
        };
        self.register_benchmark(tx_benchmark).await?;

        // Proof generation benchmark
        let proof_benchmark = BenchmarkDefinition {
            name: "default_proof_generation".to_string(),
            description: "Default proof generation benchmark".to_string(),
            benchmark_type: BenchmarkType::ProofGeneration,
            iterations: 100,
            warmup_iterations: 10,
            timeout: Duration::from_secs(300),
            parameters: BenchmarkParameters::default(),
        };
        self.register_benchmark(proof_benchmark).await?;

        // Network benchmark
        let network_benchmark = BenchmarkDefinition {
            name: "default_network".to_string(),
            description: "Default network throughput benchmark".to_string(),
            benchmark_type: BenchmarkType::NetworkThroughput,
            iterations: 1000,
            warmup_iterations: 100,
            timeout: Duration::from_secs(60),
            parameters: BenchmarkParameters::default(),
        };
        self.register_benchmark(network_benchmark).await?;

        Ok(())
    }

    async fn start_periodic_benchmarking(&self) -> Result<()> {
        let interval = Duration::from_secs(self.config.benchmarking.interval_secs);
        
        tokio::spawn(async move {
            let mut interval_timer = tokio::time::interval(interval);
            
            loop {
                interval_timer.tick().await;
                
                // This would run periodic benchmarks
                // For now, just log
                debug!("Periodic benchmark check");
            }
        });
        
        Ok(())
    }

    async fn run_benchmark_iteration(
        &self,
        definition: &BenchmarkDefinition,
        iteration: usize,
        is_warmup: bool,
    ) -> Result<IterationResult> {
        let start_time = Instant::now();
        let mut success = true;
        let mut error = None;
        let memory_before = self.get_memory_usage().await;

        // Simulate benchmark work based on type
        match definition.benchmark_type {
            BenchmarkType::Transaction => {
                // Simulate transaction processing
                self.simulate_transaction_processing(definition).await?;
            }
            BenchmarkType::ProofGeneration => {
                // Simulate proof generation
                self.simulate_proof_generation(definition).await?;
            }
            BenchmarkType::NetworkThroughput => {
                // Simulate network operations
                self.simulate_network_operations(definition).await?;
            }
            BenchmarkType::StorageWrite => {
                // Simulate storage operations
                self.simulate_storage_operations(definition).await?;
            }
            _ => {
                // Generic simulation
                tokio::time::sleep(Duration::from_millis(1)).await;
            }
        }

        let duration = start_time.elapsed();
        let memory_after = self.get_memory_usage().await;
        let memory_used = memory_after.saturating_sub(memory_before);

        // Check for timeout
        if duration > definition.timeout {
            success = false;
            error = Some("Benchmark iteration timed out".to_string());
        }

        Ok(IterationResult {
            iteration,
            duration,
            success,
            memory_used,
            error,
        })
    }

    async fn simulate_transaction_processing(&self, definition: &BenchmarkDefinition) -> Result<()> {
        let tx_count = definition.parameters.transaction_count.unwrap_or(1);
        let tx_size = definition.parameters.data_size.unwrap_or(1024);
        
        // Simulate transaction creation and processing
        for _ in 0..tx_count {
            let _tx_data = vec![0u8; tx_size];
            // Simulate processing time
            tokio::time::sleep(Duration::from_micros(100)).await;
        }
        
        Ok(())
    }

    async fn simulate_proof_generation(&self, definition: &BenchmarkDefinition) -> Result<()> {
        let proof_size = definition.parameters.data_size.unwrap_or(4096);
        
        // Simulate computationally intensive proof generation
        let _proof_data = vec![0u8; proof_size];
        
        // Simulate proof generation time
        tokio::time::sleep(Duration::from_millis(50)).await;
        
        Ok(())
    }

    async fn simulate_network_operations(&self, definition: &BenchmarkDefinition) -> Result<()> {
        let message_count = definition.parameters.transaction_count.unwrap_or(10);
        let message_size = definition.parameters.data_size.unwrap_or(1024);
        
        for _ in 0..message_count {
            let _message_data = vec![0u8; message_size];
            // Simulate network latency
            tokio::time::sleep(Duration::from_micros(10)).await;
        }
        
        Ok(())
    }

    async fn simulate_storage_operations(&self, definition: &BenchmarkDefinition) -> Result<()> {
        let op_count = definition.parameters.transaction_count.unwrap_or(10);
        let data_size = definition.parameters.data_size.unwrap_or(4096);
        
        for _ in 0..op_count {
            let _data = vec![0u8; data_size];
            // Simulate storage I/O
            tokio::time::sleep(Duration::from_micros(50)).await;
        }
        
        Ok(())
    }

    async fn get_memory_usage(&self) -> usize {
        // This would implement actual memory usage tracking
        // For now, return a placeholder
        1024 * 1024 // 1MB
    }

    fn calculate_latency_stats(
        &self,
        results: &[IterationResult],
        histogram: &Histogram<u64>,
    ) -> Result<LatencyStatistics> {
        let successful_results: Vec<&IterationResult> = results.iter()
            .filter(|r| r.success)
            .collect();

        if successful_results.is_empty() {
            return Ok(LatencyStatistics {
                min: Duration::from_nanos(0),
                max: Duration::from_nanos(0),
                mean: Duration::from_nanos(0),
                median: Duration::from_nanos(0),
                p95: Duration::from_nanos(0),
                p99: Duration::from_nanos(0),
                p99_9: Duration::from_nanos(0),
                std_dev: Duration::from_nanos(0),
            });
        }

        Ok(LatencyStatistics {
            min: Duration::from_nanos(histogram.min()),
            max: Duration::from_nanos(histogram.max()),
            mean: Duration::from_nanos(histogram.mean() as u64),
            median: Duration::from_nanos(histogram.value_at_quantile(0.5)),
            p95: Duration::from_nanos(histogram.value_at_quantile(0.95)),
            p99: Duration::from_nanos(histogram.value_at_quantile(0.99)),
            p99_9: Duration::from_nanos(histogram.value_at_quantile(0.999)),
            std_dev: Duration::from_nanos(histogram.stdev() as u64),
        })
    }

    fn calculate_memory_stats(&self, results: &[IterationResult]) -> Result<MemoryStatistics> {
        let successful_results: Vec<&IterationResult> = results.iter()
            .filter(|r| r.success)
            .collect();

        if successful_results.is_empty() {
            return Ok(MemoryStatistics {
                peak_usage_mb: 0.0,
                average_usage_mb: 0.0,
                allocations: 0,
                deallocations: 0,
                gc_runs: 0,
            });
        }

        let peak_usage = successful_results.iter()
            .map(|r| r.memory_used)
            .max()
            .unwrap_or(0) as f64 / (1024.0 * 1024.0);

        let avg_usage = successful_results.iter()
            .map(|r| r.memory_used)
            .sum::<usize>() as f64 / successful_results.len() as f64 / (1024.0 * 1024.0);

        Ok(MemoryStatistics {
            peak_usage_mb: peak_usage,
            average_usage_mb: avg_usage,
            allocations: successful_results.len() as u64,
            deallocations: successful_results.len() as u64,
            gc_runs: 0,
        })
    }

    fn calculate_suite_summary(&self, results: &[BenchmarkResult], total_duration: Duration) -> BenchmarkSummary {
        let total_benchmarks = results.len();
        let successful_benchmarks = results.iter()
            .filter(|r| r.success_rate > 0.95)
            .count();
        let failed_benchmarks = total_benchmarks - successful_benchmarks;

        let total_operations = results.iter()
            .map(|r| r.iterations as u64)
            .sum();

        let overall_throughput = total_operations as f64 / total_duration.as_secs_f64();

        let average_latency = if !results.is_empty() {
            let total_nanos: u64 = results.iter()
                .map(|r| r.latency_stats.mean.as_nanos() as u64)
                .sum();
            Duration::from_nanos(total_nanos / results.len() as u64)
        } else {
            Duration::from_nanos(0)
        };

        // Calculate performance score (0-100 based on throughput and success rate)
        let avg_throughput = if !results.is_empty() {
            results.iter().map(|r| r.throughput).sum::<f64>() / results.len() as f64
        } else {
            0.0
        };

        let avg_success_rate = if !results.is_empty() {
            results.iter().map(|r| r.success_rate).sum::<f64>() / results.len() as f64
        } else {
            0.0
        };

        let performance_score = (avg_throughput.log10().max(0.0) * 20.0 + avg_success_rate * 80.0).min(100.0);

        BenchmarkSummary {
            total_benchmarks,
            successful_benchmarks,
            failed_benchmarks,
            total_operations,
            overall_throughput,
            average_latency,
            performance_score,
        }
    }
}

impl Default for BenchmarkParameters {
    fn default() -> Self {
        Self {
            transaction_count: Some(100),
            data_size: Some(1024),
            batch_size: Some(10),
            concurrent_operations: Some(1),
            custom_params: HashMap::new(),
        }
    }
}

impl Default for TransactionBenchmarkConfig {
    fn default() -> Self {
        Self {
            transaction_count: 1000,
            concurrent_senders: 10,
            transaction_size: 1024,
            use_batching: true,
            enable_verification: true,
        }
    }
}

impl Default for NetworkBenchmarkConfig {
    fn default() -> Self {
        Self {
            message_count: 1000,
            message_size: 1024,
            concurrent_connections: 10,
            enable_compression: true,
            enable_batching: true,
        }
    }
}

impl Default for StorageBenchmarkConfig {
    fn default() -> Self {
        Self {
            operation_count: 1000,
            data_size: 4096,
            concurrent_operations: 10,
            use_encryption: true,
            sync_writes: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PerformanceConfig;

    #[tokio::test]
    async fn test_benchmarker_creation() {
        let config = PerformanceConfig::default();
        let benchmarker = Benchmarker::new(&config).unwrap();
        
        benchmarker.start().await.unwrap();
        
        // Check that default benchmarks are registered
        let registry = benchmarker.benchmark_registry.read().await;
        assert!(registry.contains_key("default_transaction"));
        assert!(registry.contains_key("default_proof_generation"));
        assert!(registry.contains_key("default_network"));
        
        benchmarker.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_benchmark_registration() {
        let config = PerformanceConfig::default();
        let benchmarker = Benchmarker::new(&config).unwrap();
        
        let definition = BenchmarkDefinition {
            name: "test_benchmark".to_string(),
            description: "Test benchmark".to_string(),
            benchmark_type: BenchmarkType::Custom,
            iterations: 10,
            warmup_iterations: 2,
            timeout: Duration::from_secs(10),
            parameters: BenchmarkParameters::default(),
        };
        
        benchmarker.register_benchmark(definition).await.unwrap();
        
        let registry = benchmarker.benchmark_registry.read().await;
        assert!(registry.contains_key("test_benchmark"));
    }

    #[tokio::test]
    async fn test_benchmark_execution() {
        let config = PerformanceConfig::default();
        let benchmarker = Benchmarker::new(&config).unwrap();
        benchmarker.start().await.unwrap();
        
        let result = benchmarker.run_benchmark("default_transaction").await.unwrap();
        
        assert_eq!(result.name, "default_transaction");
        assert!(result.iterations > 0);
        assert!(result.throughput > 0.0);
        assert!(result.success_rate >= 0.0 && result.success_rate <= 1.0);
        
        benchmarker.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_transaction_benchmark() {
        let config = PerformanceConfig::default();
        let benchmarker = Benchmarker::new(&config).unwrap();
        benchmarker.start().await.unwrap();
        
        let tx_config = TransactionBenchmarkConfig {
            transaction_count: 10,
            concurrent_senders: 2,
            transaction_size: 512,
            use_batching: true,
            enable_verification: true,
        };
        
        let result = benchmarker.run_transaction_benchmarks(tx_config).await.unwrap();
        
        assert_eq!(result.name, "transaction_throughput");
        assert!(result.throughput > 0.0);
        
        benchmarker.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_network_benchmark() {
        let config = PerformanceConfig::default();
        let benchmarker = Benchmarker::new(&config).unwrap();
        benchmarker.start().await.unwrap();
        
        let net_config = NetworkBenchmarkConfig {
            message_count: 10,
            message_size: 1024,
            concurrent_connections: 2,
            enable_compression: true,
            enable_batching: true,
        };
        
        let result = benchmarker.run_network_benchmarks(net_config).await.unwrap();
        
        assert_eq!(result.name, "network_throughput");
        assert!(result.throughput > 0.0);
        
        benchmarker.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_benchmark_suite() {
        let config = PerformanceConfig::default();
        let benchmarker = Benchmarker::new(&config).unwrap();
        benchmarker.start().await.unwrap();
        
        let suite_results = benchmarker.run_all().await.unwrap();
        
        assert!(!suite_results.benchmarks.is_empty());
        assert_eq!(suite_results.summary.total_benchmarks, suite_results.benchmarks.len());
        assert!(suite_results.summary.performance_score >= 0.0);
        assert!(suite_results.summary.performance_score <= 100.0);
        
        benchmarker.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_results_history() {
        let config = PerformanceConfig::default();
        let benchmarker = Benchmarker::new(&config).unwrap();
        benchmarker.start().await.unwrap();
        
        // Run a benchmark
        benchmarker.run_benchmark("default_transaction").await.unwrap();
        
        // Check results history
        let history = benchmarker.get_results_history().await;
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].name, "default_transaction");
        
        benchmarker.stop().await.unwrap();
    }

    #[tokio::test]
    async fn test_report_generation() {
        let config = PerformanceConfig::default();
        let benchmarker = Benchmarker::new(&config).unwrap();
        benchmarker.start().await.unwrap();
        
        // Run a benchmark to have some results
        benchmarker.run_benchmark("default_transaction").await.unwrap();
        
        let report = benchmarker.generate_report().await.unwrap();
        
        assert!(report.contains("Performance Benchmark Report"));
        assert!(report.contains("default_transaction"));
        assert!(report.contains("Throughput"));
        assert!(report.contains("Success rate"));
        
        benchmarker.stop().await.unwrap();
    }

    #[test]
    fn test_benchmark_parameters() {
        let params = BenchmarkParameters::default();
        
        assert_eq!(params.transaction_count, Some(100));
        assert_eq!(params.data_size, Some(1024));
        assert_eq!(params.batch_size, Some(10));
        assert_eq!(params.concurrent_operations, Some(1));
    }

    #[test]
    fn test_benchmark_configs() {
        let tx_config = TransactionBenchmarkConfig::default();
        assert_eq!(tx_config.transaction_count, 1000);
        assert_eq!(tx_config.concurrent_senders, 10);
        assert!(tx_config.use_batching);
        
        let net_config = NetworkBenchmarkConfig::default();
        assert_eq!(net_config.message_count, 1000);
        assert_eq!(net_config.message_size, 1024);
        assert!(net_config.enable_compression);
        
        let storage_config = StorageBenchmarkConfig::default();
        assert_eq!(storage_config.operation_count, 1000);
        assert_eq!(storage_config.data_size, 4096);
        assert!(storage_config.use_encryption);
    }
}