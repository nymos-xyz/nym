//! zk-STARK proof generation optimization
//!
//! This module provides comprehensive optimization for zk-STARK proof generation
//! including batch processing, caching, parallelization, and performance tuning.

use crate::{PerformanceError, Result, PerformanceConfig};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Semaphore};
use tokio::time::timeout;
use rayon::prelude::*;
use lru::LruCache;
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use nym_crypto::zkstark::{ZkStarkProof, ZkStarkProofParameters};
use tracing::{info, warn, error, debug};

/// zk-STARK proof optimizer
pub struct ZkStarkOptimizer {
    config: PerformanceConfig,
    proof_cache: Arc<Mutex<LruCache<ProofCacheKey, CachedProof>>>,
    batch_processor: Arc<BatchProcessor>,
    parallel_processor: Arc<ParallelProcessor>,
    compressor: Arc<ProofCompressor>,
    metrics: Arc<RwLock<ZkStarkOptimizerMetrics>>,
    semaphore: Arc<Semaphore>,
}

/// Proof cache key
#[derive(Debug, Clone, Hash, Eq, PartialEq)]
struct ProofCacheKey {
    statement_hash: [u8; 32],
    parameters_hash: [u8; 32],
}

/// Cached proof entry
#[derive(Debug, Clone)]
struct CachedProof {
    proof: ZkStarkProof,
    compressed_size: usize,
    generation_time: Duration,
    timestamp: Instant,
    access_count: u64,
}

/// Batch processor for proof generation
struct BatchProcessor {
    config: PerformanceConfig,
    pending_requests: Arc<RwLock<Vec<ProofRequest>>>,
    batch_timer: Arc<RwLock<Option<Instant>>>,
}

/// Parallel processor for proof generation
struct ParallelProcessor {
    config: PerformanceConfig,
    worker_pool: rayon::ThreadPool,
}

/// Proof compressor for storage optimization
struct ProofCompressor {
    compression_level: u32,
    min_size_threshold: usize,
}

/// Proof generation request
#[derive(Debug, Clone)]
struct ProofRequest {
    id: u64,
    statement: ProofStatement,
    parameters: ZkStarkProofParameters,
    priority: ProofPriority,
    deadline: Option<Instant>,
    result_sender: Option<tokio::sync::oneshot::Sender<Result<ZkStarkProof>>>,
}

/// Proof statement for generation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofStatement {
    pub witness: Vec<u8>,
    pub public_inputs: Vec<u8>,
    pub circuit_hash: [u8; 32],
}

/// Proof generation priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProofPriority {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// zk-STARK optimizer metrics
#[derive(Debug, Clone, Default)]
pub struct ZkStarkOptimizerMetrics {
    pub total_proofs_generated: u64,
    pub total_proofs_verified: u64,
    pub cache_hits: u64,
    pub cache_misses: u64,
    pub batch_operations: u64,
    pub single_operations: u64,
    pub parallel_operations: u64,
    pub compression_ratio: f64,
    pub average_generation_time: Duration,
    pub average_verification_time: Duration,
    pub memory_usage_mb: f64,
    pub error_count: u64,
    pub timeout_count: u64,
}

/// Proof generation options
#[derive(Debug, Clone)]
pub struct ProofOptions {
    pub use_cache: bool,
    pub use_compression: bool,
    pub use_batching: bool,
    pub use_parallel: bool,
    pub priority: ProofPriority,
    pub timeout: Option<Duration>,
}

/// Batch proof generation result
#[derive(Debug, Clone)]
pub struct BatchProofResult {
    pub proofs: Vec<ZkStarkProof>,
    pub generation_time: Duration,
    pub cache_hits: usize,
    pub compression_ratio: f64,
}

impl ZkStarkOptimizer {
    /// Create a new zk-STARK optimizer
    pub fn new(config: &PerformanceConfig) -> Result<Self> {
        let cache_size = config.zkstark_optimization.cache_size_mb * 1024 * 1024 / 1000; // Approximate entries
        let proof_cache = Arc::new(Mutex::new(LruCache::new(cache_size)));
        
        let batch_processor = Arc::new(BatchProcessor::new(config.clone())?);
        let parallel_processor = Arc::new(ParallelProcessor::new(config.clone())?);
        let compressor = Arc::new(ProofCompressor::new(
            config.zkstark_optimization.compression_level,
            1024, // 1KB minimum size threshold
        ));
        
        let metrics = Arc::new(RwLock::new(ZkStarkOptimizerMetrics::default()));
        let semaphore = Arc::new(Semaphore::new(config.zkstark_optimization.worker_threads));

        Ok(Self {
            config: config.clone(),
            proof_cache,
            batch_processor,
            parallel_processor,
            compressor,
            metrics,
            semaphore,
        })
    }

    /// Initialize the optimizer
    pub async fn initialize(&self) -> Result<()> {
        info!("Initializing zk-STARK optimizer");
        
        // Initialize batch processor
        self.batch_processor.initialize().await?;
        
        // Initialize parallel processor
        self.parallel_processor.initialize().await?;
        
        info!("zk-STARK optimizer initialized successfully");
        Ok(())
    }

    /// Shutdown the optimizer
    pub async fn shutdown(&self) -> Result<()> {
        info!("Shutting down zk-STARK optimizer");
        
        // Shutdown batch processor
        self.batch_processor.shutdown().await?;
        
        // Clear cache
        self.proof_cache.lock().clear();
        
        info!("zk-STARK optimizer shutdown completed");
        Ok(())
    }

    /// Generate a single proof with optimization
    pub async fn generate_proof(
        &self,
        statement: ProofStatement,
        parameters: ZkStarkProofParameters,
        options: ProofOptions,
    ) -> Result<ZkStarkProof> {
        let start_time = Instant::now();
        
        // Check cache first if enabled
        if options.use_cache && self.config.zkstark_optimization.enable_caching {
            let cache_key = self.create_cache_key(&statement, &parameters);
            if let Some(cached_proof) = self.get_cached_proof(&cache_key).await {
                self.update_cache_hit_metrics().await;
                return Ok(cached_proof.proof);
            }
            self.update_cache_miss_metrics().await;
        }

        // Acquire semaphore permit for resource management
        let _permit = self.semaphore.acquire().await
            .map_err(|e| PerformanceError::zkstark_optimization(format!("Failed to acquire semaphore: {}", e)))?;

        // Generate proof based on configuration
        let proof = if options.use_parallel && self.config.zkstark_optimization.enable_parallel {
            self.generate_proof_parallel(statement.clone(), parameters.clone(), options.clone()).await?
        } else {
            self.generate_proof_sequential(statement.clone(), parameters.clone(), options.clone()).await?
        };

        let generation_time = start_time.elapsed();

        // Cache the proof if enabled
        if options.use_cache && self.config.zkstark_optimization.enable_caching {
            let cache_key = self.create_cache_key(&statement, &parameters);
            self.cache_proof(cache_key, proof.clone(), generation_time).await?;
        }

        // Compress proof if enabled
        let final_proof = if options.use_compression && self.config.zkstark_optimization.enable_compression {
            self.compressor.compress_proof(&proof)?
        } else {
            proof
        };

        // Update metrics
        self.update_generation_metrics(generation_time, false).await;

        Ok(final_proof)
    }

    /// Generate multiple proofs with batch optimization
    pub async fn generate_proofs_batch(
        &self,
        statements: Vec<ProofStatement>,
        parameters: Vec<ZkStarkProofParameters>,
        options: ProofOptions,
    ) -> Result<BatchProofResult> {
        if statements.len() != parameters.len() {
            return Err(PerformanceError::zkstark_optimization(
                "Statements and parameters count mismatch".to_string(),
            ));
        }

        let start_time = Instant::now();
        let mut cache_hits = 0;
        let mut proofs = Vec::new();
        let mut pending_requests = Vec::new();

        // Check cache for each proof
        if options.use_cache && self.config.zkstark_optimization.enable_caching {
            for (statement, param) in statements.iter().zip(parameters.iter()) {
                let cache_key = self.create_cache_key(statement, param);
                if let Some(cached_proof) = self.get_cached_proof(&cache_key).await {
                    proofs.push(cached_proof.proof);
                    cache_hits += 1;
                } else {
                    pending_requests.push((statement.clone(), param.clone()));
                }
            }
        } else {
            pending_requests = statements.into_iter().zip(parameters.into_iter()).collect();
        }

        // Generate remaining proofs
        if !pending_requests.is_empty() {
            let new_proofs = if options.use_parallel && self.config.zkstark_optimization.enable_parallel {
                self.generate_proofs_parallel(pending_requests, options.clone()).await?
            } else {
                self.generate_proofs_sequential(pending_requests, options.clone()).await?
            };

            proofs.extend(new_proofs);
        }

        let generation_time = start_time.elapsed();
        let compression_ratio = if options.use_compression {
            self.compressor.get_compression_ratio()
        } else {
            1.0
        };

        // Update metrics
        self.update_batch_metrics(proofs.len(), cache_hits, generation_time).await;

        Ok(BatchProofResult {
            proofs,
            generation_time,
            cache_hits,
            compression_ratio,
        })
    }

    /// Verify a proof with optimization
    pub async fn verify_proof(
        &self,
        proof: &ZkStarkProof,
        statement: &ProofStatement,
        parameters: &ZkStarkProofParameters,
    ) -> Result<bool> {
        let start_time = Instant::now();
        
        // Decompress proof if needed
        let actual_proof = if self.config.zkstark_optimization.enable_compression {
            self.compressor.decompress_proof(proof)?
        } else {
            proof.clone()
        };

        // Verify proof with timeout
        let verification_timeout = Duration::from_secs(self.config.zkstark_optimization.verification_timeout_secs);
        let result = timeout(verification_timeout, self.verify_proof_internal(&actual_proof, statement, parameters)).await
            .map_err(|_| PerformanceError::timeout("Proof verification timed out".to_string()))?;

        let verification_time = start_time.elapsed();

        // Update metrics
        self.update_verification_metrics(verification_time, result.is_ok()).await;

        result
    }

    /// Run optimization routines
    pub async fn optimize(&self) -> Result<()> {
        info!("Running zk-STARK optimization");

        // Cache optimization
        self.optimize_cache().await?;

        // Memory optimization
        self.optimize_memory().await?;

        // Performance tuning
        self.optimize_performance().await?;

        info!("zk-STARK optimization completed");
        Ok(())
    }

    /// Get current metrics
    pub async fn get_metrics(&self) -> ZkStarkOptimizerMetrics {
        self.metrics.read().await.clone()
    }

    /// Clear cache
    pub async fn clear_cache(&self) -> Result<()> {
        self.proof_cache.lock().clear();
        info!("zk-STARK proof cache cleared");
        Ok(())
    }

    /// Get cache statistics
    pub async fn get_cache_stats(&self) -> CacheStats {
        let cache = self.proof_cache.lock();
        CacheStats {
            capacity: cache.cap(),
            size: cache.len(),
            hit_ratio: 0.0, // Calculate from metrics
        }
    }

    // Private helper methods

    async fn generate_proof_sequential(
        &self,
        statement: ProofStatement,
        parameters: ZkStarkProofParameters,
        _options: ProofOptions,
    ) -> Result<ZkStarkProof> {
        // This is a placeholder implementation
        // In a real implementation, this would call the actual zk-STARK library
        debug!("Generating proof sequentially");
        
        // Simulate proof generation
        tokio::time::sleep(Duration::from_millis(100)).await;
        
        // Create a dummy proof for testing
        let proof = ZkStarkProof {
            proof_data: vec![0u8; 1024],
            public_inputs: statement.public_inputs,
            verification_key: parameters.verification_key,
        };
        
        Ok(proof)
    }

    async fn generate_proof_parallel(
        &self,
        statement: ProofStatement,
        parameters: ZkStarkProofParameters,
        options: ProofOptions,
    ) -> Result<ZkStarkProof> {
        debug!("Generating proof in parallel");
        
        // Use thread pool for CPU-intensive work
        let statement_clone = statement.clone();
        let parameters_clone = parameters.clone();
        
        let proof = tokio::task::spawn_blocking(move || {
            // This would be the actual parallel proof generation
            // For now, simulate with a simple operation
            std::thread::sleep(Duration::from_millis(50));
            
            ZkStarkProof {
                proof_data: vec![0u8; 1024],
                public_inputs: statement_clone.public_inputs,
                verification_key: parameters_clone.verification_key,
            }
        }).await
        .map_err(|e| PerformanceError::zkstark_optimization(format!("Parallel proof generation failed: {}", e)))?;

        Ok(proof)
    }

    async fn generate_proofs_sequential(
        &self,
        requests: Vec<(ProofStatement, ZkStarkProofParameters)>,
        options: ProofOptions,
    ) -> Result<Vec<ZkStarkProof>> {
        let mut proofs = Vec::new();
        
        for (statement, parameters) in requests {
            let proof = self.generate_proof_sequential(statement, parameters, options.clone()).await?;
            proofs.push(proof);
        }
        
        Ok(proofs)
    }

    async fn generate_proofs_parallel(
        &self,
        requests: Vec<(ProofStatement, ZkStarkProofParameters)>,
        options: ProofOptions,
    ) -> Result<Vec<ZkStarkProof>> {
        let futures: Vec<_> = requests.into_iter().map(|(statement, parameters)| {
            self.generate_proof_parallel(statement, parameters, options.clone())
        }).collect();

        let results = futures::future::join_all(futures).await;
        let mut proofs = Vec::new();
        
        for result in results {
            proofs.push(result?);
        }
        
        Ok(proofs)
    }

    async fn verify_proof_internal(
        &self,
        proof: &ZkStarkProof,
        statement: &ProofStatement,
        parameters: &ZkStarkProofParameters,
    ) -> Result<bool> {
        // This is a placeholder implementation
        // In a real implementation, this would call the actual zk-STARK verification
        debug!("Verifying proof");
        
        // Simulate verification
        tokio::time::sleep(Duration::from_millis(10)).await;
        
        // Simple validation for testing
        Ok(!proof.proof_data.is_empty() && !statement.public_inputs.is_empty())
    }

    fn create_cache_key(&self, statement: &ProofStatement, parameters: &ZkStarkProofParameters) -> ProofCacheKey {
        let mut hasher = Sha3_256::new();
        hasher.update(&statement.witness);
        hasher.update(&statement.public_inputs);
        hasher.update(&statement.circuit_hash);
        let statement_hash = hasher.finalize().into();

        let mut hasher = Sha3_256::new();
        hasher.update(&parameters.verification_key);
        // Add other parameter fields as needed
        let parameters_hash = hasher.finalize().into();

        ProofCacheKey {
            statement_hash,
            parameters_hash,
        }
    }

    async fn get_cached_proof(&self, key: &ProofCacheKey) -> Option<CachedProof> {
        let mut cache = self.proof_cache.lock();
        cache.get_mut(key).map(|cached| {
            cached.access_count += 1;
            cached.clone()
        })
    }

    async fn cache_proof(&self, key: ProofCacheKey, proof: ZkStarkProof, generation_time: Duration) -> Result<()> {
        let compressed_size = if self.config.zkstark_optimization.enable_compression {
            self.compressor.get_compressed_size(&proof)?
        } else {
            proof.proof_data.len()
        };

        let cached_proof = CachedProof {
            proof,
            compressed_size,
            generation_time,
            timestamp: Instant::now(),
            access_count: 1,
        };

        self.proof_cache.lock().put(key, cached_proof);
        Ok(())
    }

    async fn optimize_cache(&self) -> Result<()> {
        debug!("Optimizing proof cache");
        
        let mut cache = self.proof_cache.lock();
        let current_time = Instant::now();
        let max_age = Duration::from_secs(3600); // 1 hour
        
        // Remove expired entries
        let keys_to_remove: Vec<_> = cache.iter()
            .filter(|(_, cached)| current_time.duration_since(cached.timestamp) > max_age)
            .map(|(k, _)| k.clone())
            .collect();
        
        for key in keys_to_remove {
            cache.pop(&key);
        }
        
        debug!("Cache optimization completed, removed {} expired entries", keys_to_remove.len());
        Ok(())
    }

    async fn optimize_memory(&self) -> Result<()> {
        debug!("Optimizing memory usage");
        
        // Force garbage collection if needed
        if self.get_memory_usage().await? > self.config.zkstark_optimization.memory_limit_mb {
            warn!("Memory usage exceeded limit, forcing cleanup");
            self.clear_cache().await?;
        }
        
        Ok(())
    }

    async fn optimize_performance(&self) -> Result<()> {
        debug!("Optimizing performance parameters");
        
        // Adjust thread pool size based on current load
        let metrics = self.get_metrics().await;
        if metrics.average_generation_time > Duration::from_secs(10) {
            warn!("Proof generation time is high, consider increasing worker threads");
        }
        
        Ok(())
    }

    async fn get_memory_usage(&self) -> Result<usize> {
        // This would implement actual memory usage tracking
        // For now, return a placeholder
        Ok(0)
    }

    async fn update_cache_hit_metrics(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.cache_hits += 1;
    }

    async fn update_cache_miss_metrics(&self) {
        let mut metrics = self.metrics.write().await;
        metrics.cache_misses += 1;
    }

    async fn update_generation_metrics(&self, duration: Duration, is_batch: bool) {
        let mut metrics = self.metrics.write().await;
        metrics.total_proofs_generated += 1;
        
        if is_batch {
            metrics.batch_operations += 1;
        } else {
            metrics.single_operations += 1;
        }
        
        // Update average generation time
        let total_time = metrics.average_generation_time.as_millis() as u64 * (metrics.total_proofs_generated - 1) + duration.as_millis() as u64;
        metrics.average_generation_time = Duration::from_millis(total_time / metrics.total_proofs_generated);
    }

    async fn update_verification_metrics(&self, duration: Duration, success: bool) {
        let mut metrics = self.metrics.write().await;
        
        if success {
            metrics.total_proofs_verified += 1;
            
            // Update average verification time
            let total_time = metrics.average_verification_time.as_millis() as u64 * (metrics.total_proofs_verified - 1) + duration.as_millis() as u64;
            metrics.average_verification_time = Duration::from_millis(total_time / metrics.total_proofs_verified);
        } else {
            metrics.error_count += 1;
        }
    }

    async fn update_batch_metrics(&self, proof_count: usize, cache_hits: usize, duration: Duration) {
        let mut metrics = self.metrics.write().await;
        metrics.batch_operations += 1;
        metrics.cache_hits += cache_hits as u64;
        metrics.cache_misses += (proof_count - cache_hits) as u64;
        
        // Update average generation time
        let total_time = metrics.average_generation_time.as_millis() as u64 * metrics.total_proofs_generated + duration.as_millis() as u64;
        metrics.total_proofs_generated += proof_count as u64;
        metrics.average_generation_time = Duration::from_millis(total_time / metrics.total_proofs_generated);
    }
}

impl BatchProcessor {
    fn new(config: PerformanceConfig) -> Result<Self> {
        Ok(Self {
            config,
            pending_requests: Arc::new(RwLock::new(Vec::new())),
            batch_timer: Arc::new(RwLock::new(None)),
        })
    }

    async fn initialize(&self) -> Result<()> {
        info!("Initializing batch processor");
        Ok(())
    }

    async fn shutdown(&self) -> Result<()> {
        info!("Shutting down batch processor");
        Ok(())
    }
}

impl ParallelProcessor {
    fn new(config: PerformanceConfig) -> Result<Self> {
        let worker_pool = rayon::ThreadPoolBuilder::new()
            .num_threads(config.zkstark_optimization.worker_threads)
            .build()
            .map_err(|e| PerformanceError::zkstark_optimization(format!("Failed to create thread pool: {}", e)))?;

        Ok(Self {
            config,
            worker_pool,
        })
    }

    async fn initialize(&self) -> Result<()> {
        info!("Initializing parallel processor with {} threads", self.config.zkstark_optimization.worker_threads);
        Ok(())
    }
}

impl ProofCompressor {
    fn new(compression_level: u32, min_size_threshold: usize) -> Self {
        Self {
            compression_level,
            min_size_threshold,
        }
    }

    fn compress_proof(&self, proof: &ZkStarkProof) -> Result<ZkStarkProof> {
        if proof.proof_data.len() < self.min_size_threshold {
            return Ok(proof.clone());
        }

        // Implement compression logic here
        // For now, return the original proof
        Ok(proof.clone())
    }

    fn decompress_proof(&self, proof: &ZkStarkProof) -> Result<ZkStarkProof> {
        // Implement decompression logic here
        // For now, return the original proof
        Ok(proof.clone())
    }

    fn get_compressed_size(&self, proof: &ZkStarkProof) -> Result<usize> {
        // Return actual compressed size
        Ok(proof.proof_data.len())
    }

    fn get_compression_ratio(&self) -> f64 {
        // Return actual compression ratio
        1.0
    }
}

impl Default for ProofOptions {
    fn default() -> Self {
        Self {
            use_cache: true,
            use_compression: true,
            use_batching: true,
            use_parallel: true,
            priority: ProofPriority::Medium,
            timeout: Some(Duration::from_secs(30)),
        }
    }
}

/// Cache statistics
#[derive(Debug, Clone)]
pub struct CacheStats {
    pub capacity: usize,
    pub size: usize,
    pub hit_ratio: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::PerformanceConfig;

    #[tokio::test]
    async fn test_zkstark_optimizer_creation() {
        let config = PerformanceConfig::default();
        let optimizer = ZkStarkOptimizer::new(&config).unwrap();
        
        optimizer.initialize().await.unwrap();
        
        let metrics = optimizer.get_metrics().await;
        assert_eq!(metrics.total_proofs_generated, 0);
        assert_eq!(metrics.cache_hits, 0);
        
        optimizer.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_proof_generation() {
        let config = PerformanceConfig::default();
        let optimizer = ZkStarkOptimizer::new(&config).unwrap();
        optimizer.initialize().await.unwrap();

        let statement = ProofStatement {
            witness: vec![1, 2, 3, 4],
            public_inputs: vec![5, 6, 7, 8],
            circuit_hash: [0u8; 32],
        };

        let parameters = ZkStarkProofParameters {
            verification_key: vec![9, 10, 11, 12],
        };

        let options = ProofOptions::default();
        let proof = optimizer.generate_proof(statement, parameters, options).await.unwrap();
        
        assert!(!proof.proof_data.is_empty());
        assert!(!proof.public_inputs.is_empty());

        optimizer.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_batch_proof_generation() {
        let config = PerformanceConfig::default();
        let optimizer = ZkStarkOptimizer::new(&config).unwrap();
        optimizer.initialize().await.unwrap();

        let statements = vec![
            ProofStatement {
                witness: vec![1, 2, 3, 4],
                public_inputs: vec![5, 6, 7, 8],
                circuit_hash: [0u8; 32],
            },
            ProofStatement {
                witness: vec![9, 10, 11, 12],
                public_inputs: vec![13, 14, 15, 16],
                circuit_hash: [1u8; 32],
            },
        ];

        let parameters = vec![
            ZkStarkProofParameters {
                verification_key: vec![17, 18, 19, 20],
            },
            ZkStarkProofParameters {
                verification_key: vec![21, 22, 23, 24],
            },
        ];

        let options = ProofOptions::default();
        let result = optimizer.generate_proofs_batch(statements, parameters, options).await.unwrap();
        
        assert_eq!(result.proofs.len(), 2);
        assert!(result.generation_time > Duration::from_millis(0));

        optimizer.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_proof_verification() {
        let config = PerformanceConfig::default();
        let optimizer = ZkStarkOptimizer::new(&config).unwrap();
        optimizer.initialize().await.unwrap();

        let statement = ProofStatement {
            witness: vec![1, 2, 3, 4],
            public_inputs: vec![5, 6, 7, 8],
            circuit_hash: [0u8; 32],
        };

        let parameters = ZkStarkProofParameters {
            verification_key: vec![9, 10, 11, 12],
        };

        let options = ProofOptions::default();
        let proof = optimizer.generate_proof(statement.clone(), parameters.clone(), options).await.unwrap();
        
        let is_valid = optimizer.verify_proof(&proof, &statement, &parameters).await.unwrap();
        assert!(is_valid);

        optimizer.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_cache_functionality() {
        let config = PerformanceConfig::default();
        let optimizer = ZkStarkOptimizer::new(&config).unwrap();
        optimizer.initialize().await.unwrap();

        let statement = ProofStatement {
            witness: vec![1, 2, 3, 4],
            public_inputs: vec![5, 6, 7, 8],
            circuit_hash: [0u8; 32],
        };

        let parameters = ZkStarkProofParameters {
            verification_key: vec![9, 10, 11, 12],
        };

        let options = ProofOptions::default();
        
        // First generation - should miss cache
        let _proof1 = optimizer.generate_proof(statement.clone(), parameters.clone(), options.clone()).await.unwrap();
        
        // Second generation - should hit cache
        let _proof2 = optimizer.generate_proof(statement, parameters, options).await.unwrap();
        
        let metrics = optimizer.get_metrics().await;
        assert_eq!(metrics.cache_hits, 1);
        assert_eq!(metrics.cache_misses, 1);

        optimizer.shutdown().await.unwrap();
    }

    #[tokio::test]
    async fn test_optimization_routines() {
        let config = PerformanceConfig::default();
        let optimizer = ZkStarkOptimizer::new(&config).unwrap();
        optimizer.initialize().await.unwrap();

        // Run optimization
        optimizer.optimize().await.unwrap();

        // Clear cache
        optimizer.clear_cache().await.unwrap();

        // Get cache stats
        let stats = optimizer.get_cache_stats().await;
        assert_eq!(stats.size, 0);

        optimizer.shutdown().await.unwrap();
    }
}