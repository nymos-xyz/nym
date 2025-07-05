//! Intelligent caching system for performance optimization
//!
//! This module provides multiple caching strategies optimized for different
//! access patterns and data types in the Nym blockchain.

use crate::{PerformanceError, Result};
use std::collections::{HashMap, VecDeque, BTreeMap};
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{RwLock, Mutex};
use parking_lot::RwLock as ParkingLot;
use lru::LruCache;
use ahash::AHashMap;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use tracing::{debug, trace, warn};

/// Multi-level cache manager
pub struct CacheManager {
    l1_cache: Arc<L1Cache>,
    l2_cache: Arc<L2Cache>,
    l3_cache: Arc<L3Cache>,
    adaptive_cache: Arc<AdaptiveCache>,
    write_through_cache: Arc<WriteThroughCache>,
    cache_stats: Arc<RwLock<CacheStats>>,
}

/// Level 1 cache (fastest, smallest)
struct L1Cache {
    data: Arc<ParkingLot<AHashMap<CacheKey, CacheEntry>>>,
    capacity: usize,
    hit_count: std::sync::atomic::AtomicU64,
    miss_count: std::sync::atomic::AtomicU64,
}

/// Level 2 cache (medium speed, medium size)
struct L2Cache {
    data: Arc<RwLock<LruCache<CacheKey, CacheEntry>>>,
    capacity: usize,
    hit_count: std::sync::atomic::AtomicU64,
    miss_count: std::sync::atomic::AtomicU64,
}

/// Level 3 cache (slowest, largest)
struct L3Cache {
    data: Arc<DashMap<CacheKey, CacheEntry>>,
    capacity: usize,
    eviction_queue: Arc<RwLock<VecDeque<CacheKey>>>,
    hit_count: std::sync::atomic::AtomicU64,
    miss_count: std::sync::atomic::AtomicU64,
}

/// Adaptive cache with machine learning
struct AdaptiveCache {
    cache: Arc<RwLock<HashMap<CacheKey, CacheEntry>>>,
    access_predictor: Arc<AccessPredictor>,
    eviction_policy: Arc<Mutex<Box<dyn EvictionPolicy>>>,
    capacity: usize,
}

/// Write-through cache for persistent data
struct WriteThroughCache {
    cache: Arc<RwLock<HashMap<CacheKey, CacheEntry>>>,
    backend: Arc<dyn CacheBackend>,
    write_queue: Arc<RwLock<VecDeque<WriteOperation>>>,
    flush_interval: Duration,
}

/// Access pattern predictor
struct AccessPredictor {
    history: Arc<RwLock<HashMap<CacheKey, AccessHistory>>>,
    prediction_model: Arc<RwLock<PredictionModel>>,
}

/// Cache key
#[derive(Debug, Clone, Hash, Eq, PartialEq, Serialize, Deserialize)]
pub struct CacheKey {
    pub namespace: String,
    pub key: String,
    pub version: u64,
}

/// Cache entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    pub value: Vec<u8>,
    pub metadata: CacheMetadata,
    pub created_at: Instant,
    pub accessed_at: Instant,
    pub access_count: u64,
    pub size: usize,
}

/// Cache metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheMetadata {
    pub ttl: Option<Duration>,
    pub priority: CachePriority,
    pub tags: Vec<String>,
    pub compressed: bool,
    pub checksum: u64,
}

/// Cache priority
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum CachePriority {
    Low = 0,
    Medium = 1,
    High = 2,
    Critical = 3,
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub l1_hits: u64,
    pub l1_misses: u64,
    pub l2_hits: u64,
    pub l2_misses: u64,
    pub l3_hits: u64,
    pub l3_misses: u64,
    pub total_entries: usize,
    pub memory_usage: usize,
    pub hit_ratio: f64,
    pub evictions: u64,
    pub prefetch_hits: u64,
    pub prefetch_misses: u64,
}

/// Access history for prediction
#[derive(Debug, Clone)]
struct AccessHistory {
    timestamps: VecDeque<Instant>,
    access_pattern: AccessPattern,
    frequency: f64,
    recency: f64,
}

/// Access pattern
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AccessPattern {
    Sequential,
    Random,
    Temporal,
    Spatial,
    Burst,
}

/// Prediction model
#[derive(Debug, Clone)]
struct PredictionModel {
    weights: HashMap<String, f64>,
    bias: f64,
    learning_rate: f64,
    accuracy: f64,
}

/// Eviction policy trait
trait EvictionPolicy: Send + Sync {
    fn should_evict(&self, entry: &CacheEntry, stats: &CacheStats) -> bool;
    fn eviction_priority(&self, entry: &CacheEntry) -> f64;
    fn name(&self) -> &'static str;
}

/// Least Recently Used eviction policy
struct LRUPolicy;

/// Least Frequently Used eviction policy
struct LFUPolicy;

/// Time-based eviction policy
struct TTLPolicy;

/// Adaptive Replacement Cache policy
struct ARCPolicy {
    t1: VecDeque<CacheKey>,
    t2: VecDeque<CacheKey>,
    b1: VecDeque<CacheKey>,
    b2: VecDeque<CacheKey>,
    p: usize,
}

/// Cache backend trait
#[async_trait::async_trait]
pub trait CacheBackend: Send + Sync {
    async fn get(&self, key: &CacheKey) -> Result<Option<Vec<u8>>>;
    async fn set(&self, key: &CacheKey, value: &[u8]) -> Result<()>;
    async fn delete(&self, key: &CacheKey) -> Result<()>;
    async fn flush(&self) -> Result<()>;
}

/// Write operation for write-through cache
#[derive(Debug, Clone)]
struct WriteOperation {
    key: CacheKey,
    value: Vec<u8>,
    operation_type: WriteOperationType,
    timestamp: Instant,
}

/// Write operation type
#[derive(Debug, Clone, Copy)]
enum WriteOperationType {
    Set,
    Delete,
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    pub l1_capacity: usize,
    pub l2_capacity: usize,
    pub l3_capacity: usize,
    pub default_ttl: Duration,
    pub max_entry_size: usize,
    pub compression_threshold: usize,
    pub prefetch_enabled: bool,
    pub adaptive_enabled: bool,
    pub write_through_enabled: bool,
    pub flush_interval: Duration,
}

impl CacheManager {
    /// Create a new cache manager
    pub fn new(config: CacheConfig) -> Result<Self> {
        let l1_cache = Arc::new(L1Cache::new(config.l1_capacity));
        let l2_cache = Arc::new(L2Cache::new(config.l2_capacity));
        let l3_cache = Arc::new(L3Cache::new(config.l3_capacity));
        let adaptive_cache = Arc::new(AdaptiveCache::new(config.l2_capacity / 2)?);
        let write_through_cache = Arc::new(WriteThroughCache::new(config.flush_interval)?);

        Ok(Self {
            l1_cache,
            l2_cache,
            l3_cache,
            adaptive_cache,
            write_through_cache,
            cache_stats: Arc::new(RwLock::new(CacheStats::default())),
        })
    }

    /// Get a value from cache
    pub async fn get(&self, key: &CacheKey) -> Result<Option<Vec<u8>>> {
        // Try L1 cache first
        if let Some(entry) = self.l1_cache.get(key).await {
            self.update_hit_stats(1).await;
            return Ok(Some(entry.value));
        }

        // Try L2 cache
        if let Some(entry) = self.l2_cache.get(key).await {
            // Promote to L1
            self.l1_cache.set(key.clone(), entry.clone()).await?;
            self.update_hit_stats(2).await;
            return Ok(Some(entry.value));
        }

        // Try L3 cache
        if let Some(entry) = self.l3_cache.get(key).await {
            // Promote to L2
            self.l2_cache.set(key.clone(), entry.clone()).await?;
            self.update_hit_stats(3).await;
            return Ok(Some(entry.value));
        }

        // Try adaptive cache
        if let Some(entry) = self.adaptive_cache.get(key).await {
            // Promote to L2
            self.l2_cache.set(key.clone(), entry.clone()).await?;
            self.update_hit_stats(3).await;
            return Ok(Some(entry.value));
        }

        // Try write-through cache
        if let Some(entry) = self.write_through_cache.get(key).await {
            // Promote to L3
            self.l3_cache.set(key.clone(), entry.clone()).await?;
            self.update_hit_stats(3).await;
            return Ok(Some(entry.value));
        }

        self.update_miss_stats().await;
        Ok(None)
    }

    /// Set a value in cache
    pub async fn set(&self, key: CacheKey, value: Vec<u8>, metadata: CacheMetadata) -> Result<()> {
        let entry = CacheEntry {
            value: value.clone(),
            metadata: metadata.clone(),
            created_at: Instant::now(),
            accessed_at: Instant::now(),
            access_count: 1,
            size: value.len(),
        };

        // Always set in L1 for fast access
        self.l1_cache.set(key.clone(), entry.clone()).await?;

        // Set in appropriate level based on priority
        match metadata.priority {
            CachePriority::Critical => {
                self.l1_cache.set(key.clone(), entry.clone()).await?;
                self.l2_cache.set(key.clone(), entry.clone()).await?;
            }
            CachePriority::High => {
                self.l2_cache.set(key.clone(), entry.clone()).await?;
            }
            CachePriority::Medium => {
                self.l3_cache.set(key.clone(), entry.clone()).await?;
            }
            CachePriority::Low => {
                self.adaptive_cache.set(key.clone(), entry.clone()).await?;
            }
        }

        // Set in write-through cache if enabled
        if metadata.tags.contains(&"persistent".to_string()) {
            self.write_through_cache.set(key, entry).await?;
        }

        Ok(())
    }

    /// Delete a value from cache
    pub async fn delete(&self, key: &CacheKey) -> Result<()> {
        self.l1_cache.delete(key).await?;
        self.l2_cache.delete(key).await?;
        self.l3_cache.delete(key).await?;
        self.adaptive_cache.delete(key).await?;
        self.write_through_cache.delete(key).await?;

        Ok(())
    }

    /// Clear all caches
    pub async fn clear(&self) -> Result<()> {
        self.l1_cache.clear().await?;
        self.l2_cache.clear().await?;
        self.l3_cache.clear().await?;
        self.adaptive_cache.clear().await?;
        self.write_through_cache.clear().await?;

        *self.cache_stats.write().await = CacheStats::default();
        debug!("All caches cleared");
        Ok(())
    }

    /// Get cache statistics
    pub async fn get_stats(&self) -> CacheStats {
        let mut stats = self.cache_stats.read().await.clone();
        
        // Update with current values
        stats.l1_hits = self.l1_cache.hit_count.load(std::sync::atomic::Ordering::Relaxed);
        stats.l1_misses = self.l1_cache.miss_count.load(std::sync::atomic::Ordering::Relaxed);
        stats.l2_hits = self.l2_cache.hit_count.load(std::sync::atomic::Ordering::Relaxed);
        stats.l2_misses = self.l2_cache.miss_count.load(std::sync::atomic::Ordering::Relaxed);
        stats.l3_hits = self.l3_cache.hit_count.load(std::sync::atomic::Ordering::Relaxed);
        stats.l3_misses = self.l3_cache.miss_count.load(std::sync::atomic::Ordering::Relaxed);
        
        let total_hits = stats.l1_hits + stats.l2_hits + stats.l3_hits;
        let total_misses = stats.l1_misses + stats.l2_misses + stats.l3_misses;
        let total_requests = total_hits + total_misses;
        
        stats.hit_ratio = if total_requests > 0 {
            total_hits as f64 / total_requests as f64
        } else {
            0.0
        };
        
        stats
    }

    /// Prefetch values based on access patterns
    pub async fn prefetch(&self, keys: Vec<CacheKey>) -> Result<()> {
        for key in keys {
            if self.get(&key).await?.is_none() {
                // Predict if this key will be accessed soon
                if self.adaptive_cache.should_prefetch(&key).await {
                    // Simulate loading from backend
                    trace!("Prefetching key: {:?}", key);
                }
            }
        }
        Ok(())
    }

    /// Optimize cache based on access patterns
    pub async fn optimize(&self) -> Result<()> {
        debug!("Starting cache optimization");

        // Adaptive cache optimization
        self.adaptive_cache.optimize().await?;

        // Remove expired entries
        self.evict_expired().await?;

        // Rebalance cache levels
        self.rebalance_levels().await?;

        debug!("Cache optimization completed");
        Ok(())
    }

    // Private helper methods

    async fn update_hit_stats(&self, level: u8) {
        match level {
            1 => self.l1_cache.hit_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            2 => self.l2_cache.hit_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            3 => self.l3_cache.hit_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed),
            _ => 0,
        };
    }

    async fn update_miss_stats(&self) {
        self.l1_cache.miss_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.l2_cache.miss_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.l3_cache.miss_count.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    }

    async fn evict_expired(&self) -> Result<()> {
        let now = Instant::now();
        
        // This would implement TTL-based eviction
        // For now, just log the operation
        trace!("Evicting expired entries at: {:?}", now);
        
        Ok(())
    }

    async fn rebalance_levels(&self) -> Result<()> {
        // This would implement intelligent rebalancing between cache levels
        // based on access patterns and hit rates
        trace!("Rebalancing cache levels");
        
        Ok(())
    }
}

impl L1Cache {
    fn new(capacity: usize) -> Self {
        Self {
            data: Arc::new(ParkingLot::new(AHashMap::with_capacity(capacity))),
            capacity,
            hit_count: std::sync::atomic::AtomicU64::new(0),
            miss_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    async fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        let data = self.data.read();
        if let Some(entry) = data.get(key) {
            let mut entry = entry.clone();
            entry.accessed_at = Instant::now();
            entry.access_count += 1;
            Some(entry)
        } else {
            None
        }
    }

    async fn set(&self, key: CacheKey, entry: CacheEntry) -> Result<()> {
        let mut data = self.data.write();
        
        // Evict if at capacity
        if data.len() >= self.capacity && !data.contains_key(&key) {
            self.evict_one(&mut data);
        }
        
        data.insert(key, entry);
        Ok(())
    }

    async fn delete(&self, key: &CacheKey) -> Result<()> {
        self.data.write().remove(key);
        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        self.data.write().clear();
        Ok(())
    }

    fn evict_one(&self, data: &mut AHashMap<CacheKey, CacheEntry>) {
        // Simple LRU eviction - remove least recently accessed
        if let Some((key, _)) = data.iter()
            .min_by_key(|(_, entry)| entry.accessed_at)
            .map(|(k, v)| (k.clone(), v.clone()))
        {
            data.remove(&key);
        }
    }
}

impl L2Cache {
    fn new(capacity: usize) -> Self {
        Self {
            data: Arc::new(RwLock::new(LruCache::new(capacity))),
            capacity,
            hit_count: std::sync::atomic::AtomicU64::new(0),
            miss_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    async fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        let mut data = self.data.write().await;
        if let Some(entry) = data.get_mut(key) {
            entry.accessed_at = Instant::now();
            entry.access_count += 1;
            Some(entry.clone())
        } else {
            None
        }
    }

    async fn set(&self, key: CacheKey, entry: CacheEntry) -> Result<()> {
        self.data.write().await.put(key, entry);
        Ok(())
    }

    async fn delete(&self, key: &CacheKey) -> Result<()> {
        self.data.write().await.pop(key);
        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        self.data.write().await.clear();
        Ok(())
    }
}

impl L3Cache {
    fn new(capacity: usize) -> Self {
        Self {
            data: Arc::new(DashMap::with_capacity(capacity)),
            capacity,
            eviction_queue: Arc::new(RwLock::new(VecDeque::new())),
            hit_count: std::sync::atomic::AtomicU64::new(0),
            miss_count: std::sync::atomic::AtomicU64::new(0),
        }
    }

    async fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        if let Some(mut entry) = self.data.get_mut(key) {
            entry.accessed_at = Instant::now();
            entry.access_count += 1;
            Some(entry.clone())
        } else {
            None
        }
    }

    async fn set(&self, key: CacheKey, entry: CacheEntry) -> Result<()> {
        // Evict if at capacity
        if self.data.len() >= self.capacity && !self.data.contains_key(&key) {
            self.evict_one().await;
        }
        
        self.data.insert(key.clone(), entry);
        self.eviction_queue.write().await.push_back(key);
        Ok(())
    }

    async fn delete(&self, key: &CacheKey) -> Result<()> {
        self.data.remove(key);
        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        self.data.clear();
        self.eviction_queue.write().await.clear();
        Ok(())
    }

    async fn evict_one(&self) {
        if let Some(key) = self.eviction_queue.write().await.pop_front() {
            self.data.remove(&key);
        }
    }
}

impl AdaptiveCache {
    fn new(capacity: usize) -> Result<Self> {
        Ok(Self {
            cache: Arc::new(RwLock::new(HashMap::with_capacity(capacity))),
            access_predictor: Arc::new(AccessPredictor::new()),
            eviction_policy: Arc::new(Mutex::new(Box::new(ARCPolicy::new(capacity)))),
            capacity,
        })
    }

    async fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        let mut cache = self.cache.write().await;
        if let Some(entry) = cache.get_mut(key) {
            entry.accessed_at = Instant::now();
            entry.access_count += 1;
            
            // Update access predictor
            self.access_predictor.record_access(key.clone()).await;
            
            Some(entry.clone())
        } else {
            None
        }
    }

    async fn set(&self, key: CacheKey, entry: CacheEntry) -> Result<()> {
        let mut cache = self.cache.write().await;
        
        // Evict if at capacity
        if cache.len() >= self.capacity && !cache.contains_key(&key) {
            self.evict_adaptive(&mut cache).await;
        }
        
        cache.insert(key, entry);
        Ok(())
    }

    async fn delete(&self, key: &CacheKey) -> Result<()> {
        self.cache.write().await.remove(key);
        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        self.cache.write().await.clear();
        Ok(())
    }

    async fn should_prefetch(&self, key: &CacheKey) -> bool {
        self.access_predictor.predict_access(key).await
    }

    async fn optimize(&self) -> Result<()> {
        // Train the prediction model
        self.access_predictor.train().await?;
        
        // Optimize eviction policy
        self.optimize_eviction_policy().await?;
        
        Ok(())
    }

    async fn evict_adaptive(&self, cache: &mut HashMap<CacheKey, CacheEntry>) {
        let policy = self.eviction_policy.lock().await;
        
        // Find entry with lowest priority
        if let Some((key, _)) = cache.iter()
            .min_by_key(|(_, entry)| policy.eviction_priority(entry) as i64)
            .map(|(k, v)| (k.clone(), v.clone()))
        {
            cache.remove(&key);
        }
    }

    async fn optimize_eviction_policy(&self) -> Result<()> {
        // This would implement policy optimization based on recent performance
        Ok(())
    }
}

impl WriteThroughCache {
    fn new(flush_interval: Duration) -> Result<Self> {
        Ok(Self {
            cache: Arc::new(RwLock::new(HashMap::new())),
            backend: Arc::new(MemoryBackend::new()),
            write_queue: Arc::new(RwLock::new(VecDeque::new())),
            flush_interval,
        })
    }

    async fn get(&self, key: &CacheKey) -> Option<CacheEntry> {
        // Try cache first
        if let Some(entry) = self.cache.read().await.get(key) {
            return Some(entry.clone());
        }
        
        // Try backend
        if let Ok(Some(value)) = self.backend.get(key).await {
            let entry = CacheEntry {
                value,
                metadata: CacheMetadata {
                    ttl: None,
                    priority: CachePriority::Medium,
                    tags: vec!["persistent".to_string()],
                    compressed: false,
                    checksum: 0,
                },
                created_at: Instant::now(),
                accessed_at: Instant::now(),
                access_count: 1,
                size: 0,
            };
            
            // Cache it
            self.cache.write().await.insert(key.clone(), entry.clone());
            return Some(entry);
        }
        
        None
    }

    async fn set(&self, key: CacheKey, entry: CacheEntry) -> Result<()> {
        // Set in cache
        self.cache.write().await.insert(key.clone(), entry.clone());
        
        // Queue for backend write
        let write_op = WriteOperation {
            key,
            value: entry.value,
            operation_type: WriteOperationType::Set,
            timestamp: Instant::now(),
        };
        
        self.write_queue.write().await.push_back(write_op);
        Ok(())
    }

    async fn delete(&self, key: &CacheKey) -> Result<()> {
        // Remove from cache
        self.cache.write().await.remove(key);
        
        // Queue for backend delete
        let write_op = WriteOperation {
            key: key.clone(),
            value: Vec::new(),
            operation_type: WriteOperationType::Delete,
            timestamp: Instant::now(),
        };
        
        self.write_queue.write().await.push_back(write_op);
        Ok(())
    }

    async fn clear(&self) -> Result<()> {
        self.cache.write().await.clear();
        self.write_queue.write().await.clear();
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        let mut queue = self.write_queue.write().await;
        
        while let Some(op) = queue.pop_front() {
            match op.operation_type {
                WriteOperationType::Set => {
                    self.backend.set(&op.key, &op.value).await?;
                }
                WriteOperationType::Delete => {
                    self.backend.delete(&op.key).await?;
                }
            }
        }
        
        Ok(())
    }
}

impl AccessPredictor {
    fn new() -> Self {
        Self {
            history: Arc::new(RwLock::new(HashMap::new())),
            prediction_model: Arc::new(RwLock::new(PredictionModel::new())),
        }
    }

    async fn record_access(&self, key: CacheKey) {
        let mut history = self.history.write().await;
        let entry = history.entry(key).or_insert_with(|| AccessHistory::new());
        entry.record_access();
    }

    async fn predict_access(&self, key: &CacheKey) -> bool {
        let history = self.history.read().await;
        if let Some(access_history) = history.get(key) {
            let model = self.prediction_model.read().await;
            model.predict(access_history) > 0.5
        } else {
            false
        }
    }

    async fn train(&self) -> Result<()> {
        let history = self.history.read().await;
        let mut model = self.prediction_model.write().await;
        
        // Simple training based on access patterns
        model.train(&history);
        
        Ok(())
    }
}

impl AccessHistory {
    fn new() -> Self {
        Self {
            timestamps: VecDeque::new(),
            access_pattern: AccessPattern::Random,
            frequency: 0.0,
            recency: 0.0,
        }
    }

    fn record_access(&mut self) {
        let now = Instant::now();
        self.timestamps.push_back(now);
        
        // Keep only recent history
        while self.timestamps.len() > 100 {
            self.timestamps.pop_front();
        }
        
        self.update_metrics();
    }

    fn update_metrics(&mut self) {
        if self.timestamps.len() < 2 {
            return;
        }
        
        // Calculate frequency
        let duration = self.timestamps.back().unwrap().duration_since(*self.timestamps.front().unwrap());
        self.frequency = self.timestamps.len() as f64 / duration.as_secs_f64();
        
        // Calculate recency
        let last_access = self.timestamps.back().unwrap().elapsed();
        self.recency = 1.0 / (1.0 + last_access.as_secs_f64());
        
        // Detect access pattern
        self.access_pattern = self.detect_pattern();
    }

    fn detect_pattern(&self) -> AccessPattern {
        if self.timestamps.len() < 3 {
            return AccessPattern::Random;
        }
        
        // Simple pattern detection
        let intervals: Vec<Duration> = self.timestamps.windows(2)
            .map(|w| w[1].duration_since(w[0]))
            .collect();
        
        let avg_interval = intervals.iter().sum::<Duration>() / intervals.len() as u32;
        let variance = intervals.iter()
            .map(|d| (d.as_secs_f64() - avg_interval.as_secs_f64()).powi(2))
            .sum::<f64>() / intervals.len() as f64;
        
        if variance < 0.1 {
            AccessPattern::Temporal
        } else if variance > 10.0 {
            AccessPattern::Burst
        } else {
            AccessPattern::Random
        }
    }
}

impl PredictionModel {
    fn new() -> Self {
        Self {
            weights: HashMap::new(),
            bias: 0.0,
            learning_rate: 0.01,
            accuracy: 0.0,
        }
    }

    fn predict(&self, history: &AccessHistory) -> f64 {
        let features = self.extract_features(history);
        let mut prediction = self.bias;
        
        for (feature, value) in features {
            if let Some(weight) = self.weights.get(&feature) {
                prediction += weight * value;
            }
        }
        
        1.0 / (1.0 + (-prediction).exp()) // Sigmoid activation
    }

    fn train(&mut self, history: &HashMap<CacheKey, AccessHistory>) {
        // Simple gradient descent training
        for (_, access_history) in history.iter() {
            let prediction = self.predict(access_history);
            let actual = if access_history.recency > 0.5 { 1.0 } else { 0.0 };
            let error = actual - prediction;
            
            // Update weights
            let features = self.extract_features(access_history);
            for (feature, value) in features {
                let weight = self.weights.entry(feature).or_insert(0.0);
                *weight += self.learning_rate * error * value;
            }
            
            // Update bias
            self.bias += self.learning_rate * error;
        }
    }

    fn extract_features(&self, history: &AccessHistory) -> HashMap<String, f64> {
        let mut features = HashMap::new();
        
        features.insert("frequency".to_string(), history.frequency);
        features.insert("recency".to_string(), history.recency);
        features.insert("access_count".to_string(), history.timestamps.len() as f64);
        
        // Pattern features
        match history.access_pattern {
            AccessPattern::Sequential => features.insert("sequential".to_string(), 1.0),
            AccessPattern::Random => features.insert("random".to_string(), 1.0),
            AccessPattern::Temporal => features.insert("temporal".to_string(), 1.0),
            AccessPattern::Spatial => features.insert("spatial".to_string(), 1.0),
            AccessPattern::Burst => features.insert("burst".to_string(), 1.0),
        };
        
        features
    }
}

impl ARCPolicy {
    fn new(capacity: usize) -> Self {
        Self {
            t1: VecDeque::new(),
            t2: VecDeque::new(),
            b1: VecDeque::new(),
            b2: VecDeque::new(),
            p: 0,
        }
    }
}

impl EvictionPolicy for ARCPolicy {
    fn should_evict(&self, entry: &CacheEntry, _stats: &CacheStats) -> bool {
        // Simple TTL check
        if let Some(ttl) = entry.metadata.ttl {
            entry.created_at.elapsed() > ttl
        } else {
            false
        }
    }

    fn eviction_priority(&self, entry: &CacheEntry) -> f64 {
        // Lower values = higher priority for eviction
        let recency_score = 1.0 / (1.0 + entry.accessed_at.elapsed().as_secs_f64());
        let frequency_score = entry.access_count as f64;
        let priority_score = entry.metadata.priority as u8 as f64;
        
        recency_score * frequency_score * priority_score
    }

    fn name(&self) -> &'static str {
        "ARC"
    }
}

impl EvictionPolicy for LRUPolicy {
    fn should_evict(&self, entry: &CacheEntry, _stats: &CacheStats) -> bool {
        entry.accessed_at.elapsed() > Duration::from_secs(3600)
    }

    fn eviction_priority(&self, entry: &CacheEntry) -> f64 {
        entry.accessed_at.elapsed().as_secs_f64()
    }

    fn name(&self) -> &'static str {
        "LRU"
    }
}

impl EvictionPolicy for LFUPolicy {
    fn should_evict(&self, entry: &CacheEntry, _stats: &CacheStats) -> bool {
        entry.access_count < 2
    }

    fn eviction_priority(&self, entry: &CacheEntry) -> f64 {
        1.0 / (1.0 + entry.access_count as f64)
    }

    fn name(&self) -> &'static str {
        "LFU"
    }
}

impl EvictionPolicy for TTLPolicy {
    fn should_evict(&self, entry: &CacheEntry, _stats: &CacheStats) -> bool {
        if let Some(ttl) = entry.metadata.ttl {
            entry.created_at.elapsed() > ttl
        } else {
            false
        }
    }

    fn eviction_priority(&self, entry: &CacheEntry) -> f64 {
        if let Some(ttl) = entry.metadata.ttl {
            let remaining = ttl.saturating_sub(entry.created_at.elapsed());
            remaining.as_secs_f64()
        } else {
            f64::INFINITY
        }
    }

    fn name(&self) -> &'static str {
        "TTL"
    }
}

/// Simple in-memory backend for testing
struct MemoryBackend {
    data: Arc<RwLock<HashMap<CacheKey, Vec<u8>>>>,
}

impl MemoryBackend {
    fn new() -> Self {
        Self {
            data: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

#[async_trait::async_trait]
impl CacheBackend for MemoryBackend {
    async fn get(&self, key: &CacheKey) -> Result<Option<Vec<u8>>> {
        Ok(self.data.read().await.get(key).cloned())
    }

    async fn set(&self, key: &CacheKey, value: &[u8]) -> Result<()> {
        self.data.write().await.insert(key.clone(), value.to_vec());
        Ok(())
    }

    async fn delete(&self, key: &CacheKey) -> Result<()> {
        self.data.write().await.remove(key);
        Ok(())
    }

    async fn flush(&self) -> Result<()> {
        // No-op for memory backend
        Ok(())
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            l1_capacity: 1000,
            l2_capacity: 10000,
            l3_capacity: 100000,
            default_ttl: Duration::from_secs(3600),
            max_entry_size: 1024 * 1024, // 1MB
            compression_threshold: 1024, // 1KB
            prefetch_enabled: true,
            adaptive_enabled: true,
            write_through_enabled: false,
            flush_interval: Duration::from_secs(300),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_cache_manager_basic_operations() {
        let config = CacheConfig::default();
        let cache = CacheManager::new(config).unwrap();

        let key = CacheKey {
            namespace: "test".to_string(),
            key: "key1".to_string(),
            version: 1,
        };

        let metadata = CacheMetadata {
            ttl: None,
            priority: CachePriority::Medium,
            tags: vec!["test".to_string()],
            compressed: false,
            checksum: 0,
        };

        // Test set and get
        cache.set(key.clone(), b"value1".to_vec(), metadata).await.unwrap();
        let value = cache.get(&key).await.unwrap();
        assert_eq!(value, Some(b"value1".to_vec()));

        // Test delete
        cache.delete(&key).await.unwrap();
        let value = cache.get(&key).await.unwrap();
        assert_eq!(value, None);
    }

    #[tokio::test]
    async fn test_cache_levels() {
        let config = CacheConfig::default();
        let cache = CacheManager::new(config).unwrap();

        let key = CacheKey {
            namespace: "test".to_string(),
            key: "key1".to_string(),
            version: 1,
        };

        let metadata = CacheMetadata {
            ttl: None,
            priority: CachePriority::Critical,
            tags: vec!["test".to_string()],
            compressed: false,
            checksum: 0,
        };

        // Set with critical priority (should be in L1 and L2)
        cache.set(key.clone(), b"value1".to_vec(), metadata).await.unwrap();
        
        // Should find in L1
        let value = cache.get(&key).await.unwrap();
        assert_eq!(value, Some(b"value1".to_vec()));

        let stats = cache.get_stats().await;
        assert!(stats.l1_hits > 0);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let config = CacheConfig::default();
        let cache = CacheManager::new(config).unwrap();

        let key = CacheKey {
            namespace: "test".to_string(),
            key: "key1".to_string(),
            version: 1,
        };

        let metadata = CacheMetadata {
            ttl: None,
            priority: CachePriority::Medium,
            tags: vec!["test".to_string()],
            compressed: false,
            checksum: 0,
        };

        // Test miss
        let _ = cache.get(&key).await.unwrap();
        
        // Test hit
        cache.set(key.clone(), b"value1".to_vec(), metadata).await.unwrap();
        let _ = cache.get(&key).await.unwrap();

        let stats = cache.get_stats().await;
        assert!(stats.l1_hits > 0);
        assert!(stats.l1_misses > 0);
        assert!(stats.hit_ratio > 0.0);
    }

    #[tokio::test]
    async fn test_adaptive_cache() {
        let adaptive = AdaptiveCache::new(10).unwrap();

        let key = CacheKey {
            namespace: "test".to_string(),
            key: "key1".to_string(),
            version: 1,
        };

        let entry = CacheEntry {
            value: b"value1".to_vec(),
            metadata: CacheMetadata {
                ttl: None,
                priority: CachePriority::Medium,
                tags: vec!["test".to_string()],
                compressed: false,
                checksum: 0,
            },
            created_at: Instant::now(),
            accessed_at: Instant::now(),
            access_count: 1,
            size: 6,
        };

        adaptive.set(key.clone(), entry).await.unwrap();
        let result = adaptive.get(&key).await;
        assert!(result.is_some());
    }
}