//! Dynamic Economic Allocation System
//! 
//! This module implements sophisticated dynamic allocation of economic rewards
//! across different network participants based on real-time network needs,
//! performance metrics, and strategic priorities.

use crate::error::{EconomicsError, EconomicsResult};
use crate::adaptive_emissions::NetworkHealthMetrics;
use nym_core::NymIdentity;

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, debug, warn, error};
use serde::{Deserialize, Serialize};

/// Configuration for dynamic economic allocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicAllocationConfig {
    /// Base allocation percentages for different categories
    pub base_allocations: AllocationDistribution,
    /// Enable dynamic adjustments based on network conditions
    pub enable_dynamic_adjustment: bool,
    /// Adjustment sensitivity (0.0 to 1.0)
    pub adjustment_sensitivity: f64,
    /// Maximum deviation from base allocation (percentage)
    pub max_deviation: f64,
    /// Rebalancing frequency (blocks)
    pub rebalancing_frequency: u64,
    /// Priority weights for different network functions
    pub priority_weights: PriorityWeights,
    /// Emergency allocation mode threshold
    pub emergency_threshold: f64,
}

impl Default for DynamicAllocationConfig {
    fn default() -> Self {
        Self {
            base_allocations: AllocationDistribution::default(),
            enable_dynamic_adjustment: true,
            adjustment_sensitivity: 0.5,
            max_deviation: 0.25, // Max 25% deviation from base
            rebalancing_frequency: 720, // ~1 day at 2 min blocks
            priority_weights: PriorityWeights::default(),
            emergency_threshold: 0.33, // 33% security participation triggers emergency
        }
    }
}

/// Distribution of allocations across categories
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationDistribution {
    pub pow_mining: f64,
    pub pos_validation: f64,
    pub privacy_infrastructure: f64,
    pub development_fund: f64,
    pub ecosystem_growth: f64,
    pub creator_rewards: f64,
    pub burn_allocation: f64,
}

impl Default for AllocationDistribution {
    fn default() -> Self {
        Self {
            pow_mining: 0.35,           // 35% to PoW miners
            pos_validation: 0.25,       // 25% to PoS validators
            privacy_infrastructure: 0.10, // 10% to privacy nodes (mix, storage)
            development_fund: 0.10,     // 10% to development
            ecosystem_growth: 0.10,     // 10% to ecosystem
            creator_rewards: 0.05,      // 5% to content creators
            burn_allocation: 0.05,      // 5% burn by default
        }
    }
}

/// Priority weights for different network functions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PriorityWeights {
    pub security: f64,
    pub decentralization: f64,
    pub privacy: f64,
    pub scalability: f64,
    pub sustainability: f64,
}

impl Default for PriorityWeights {
    fn default() -> Self {
        Self {
            security: 0.35,          // 35% weight on security
            decentralization: 0.25,  // 25% weight on decentralization
            privacy: 0.20,          // 20% weight on privacy
            scalability: 0.10,      // 10% weight on scalability
            sustainability: 0.10,   // 10% weight on sustainability
        }
    }
}

/// Network performance metrics for allocation decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkPerformanceMetrics {
    /// Mining hash rate growth rate
    pub hash_rate_growth: f64,
    /// Validator participation rate
    pub validator_participation: f64,
    /// Privacy node availability
    pub privacy_node_availability: f64,
    /// Developer activity score
    pub developer_activity: f64,
    /// Ecosystem growth rate
    pub ecosystem_growth: f64,
    /// Creator engagement rate
    pub creator_engagement: f64,
    /// Network utilization rate
    pub network_utilization: f64,
}

/// Allocation strategy types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum AllocationStrategy {
    /// Fixed allocations based on configuration
    Fixed,
    /// Dynamic adjustments based on network conditions
    Dynamic,
    /// Emergency mode with security-focused allocation
    Emergency,
    /// Growth mode with ecosystem-focused allocation
    Growth,
    /// Stability mode with balanced allocation
    Stability,
}

/// Allocation adjustment reason
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationAdjustment {
    pub category: String,
    pub base_percentage: f64,
    pub adjusted_percentage: f64,
    pub reason: String,
    pub impact_score: f64,
}

/// Complete allocation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DynamicAllocationResult {
    /// Final allocation amounts per category
    pub allocations: HashMap<String, u64>,
    /// Percentage allocations
    pub percentages: AllocationDistribution,
    /// Strategy used for this allocation
    pub strategy: AllocationStrategy,
    /// Total amount allocated
    pub total_allocated: u64,
    /// Adjustments made from base allocation
    pub adjustments: Vec<AllocationAdjustment>,
    /// Efficiency score of allocation
    pub efficiency_score: f64,
    /// Timestamp of allocation
    pub timestamp: SystemTime,
}

/// Historical allocation data
#[derive(Debug, Clone)]
struct AllocationHistory {
    result: DynamicAllocationResult,
    network_metrics: NetworkHealthMetrics,
    performance_metrics: NetworkPerformanceMetrics,
    block_height: u64,
}

/// Allocation efficiency tracker
#[derive(Debug, Clone)]
struct EfficiencyTracker {
    category: String,
    allocations: VecDeque<(u64, f64)>, // (amount, performance_score)
    efficiency_score: f64,
    trend: f64,
}

/// Main dynamic allocation manager
pub struct DynamicAllocationManager {
    config: DynamicAllocationConfig,
    allocation_history: RwLock<VecDeque<AllocationHistory>>,
    efficiency_trackers: RwLock<HashMap<String, EfficiencyTracker>>,
    current_strategy: RwLock<AllocationStrategy>,
    last_rebalance: RwLock<u64>,
    emergency_mode: RwLock<bool>,
}

impl DynamicAllocationManager {
    pub fn new(config: DynamicAllocationConfig) -> Self {
        info!("Initializing dynamic allocation manager");
        
        let mut efficiency_trackers = HashMap::new();
        
        // Initialize efficiency trackers for each category
        for category in ["pow_mining", "pos_validation", "privacy_infrastructure", 
                        "development_fund", "ecosystem_growth", "creator_rewards"].iter() {
            efficiency_trackers.insert(
                category.to_string(),
                EfficiencyTracker {
                    category: category.to_string(),
                    allocations: VecDeque::new(),
                    efficiency_score: 0.5,
                    trend: 0.0,
                }
            );
        }
        
        Self {
            config,
            allocation_history: RwLock::new(VecDeque::new()),
            efficiency_trackers: RwLock::new(efficiency_trackers),
            current_strategy: RwLock::new(AllocationStrategy::Dynamic),
            last_rebalance: RwLock::new(0),
            emergency_mode: RwLock::new(false),
        }
    }

    /// Allocate rewards dynamically based on network conditions
    pub async fn allocate_rewards(
        &self,
        total_amount: u64,
        block_height: u64,
        network_metrics: &NetworkHealthMetrics,
        performance_metrics: &NetworkPerformanceMetrics,
    ) -> EconomicsResult<DynamicAllocationResult> {
        debug!("Allocating {} tokens at block {}", total_amount, block_height);
        
        // Determine allocation strategy
        let strategy = self.determine_strategy(network_metrics, performance_metrics).await?;
        
        // Check if rebalancing is needed
        let should_rebalance = self.should_rebalance(block_height).await;
        
        // Calculate allocations based on strategy
        let (percentages, adjustments) = if should_rebalance && self.config.enable_dynamic_adjustment {
            self.calculate_dynamic_allocations(
                &strategy,
                network_metrics,
                performance_metrics
            ).await?
        } else {
            (self.config.base_allocations.clone(), Vec::new())
        };
        
        // Convert percentages to actual amounts
        let allocations = self.percentages_to_amounts(total_amount, &percentages);
        
        // Calculate efficiency score
        let efficiency_score = self.calculate_allocation_efficiency(
            &allocations,
            network_metrics,
            performance_metrics
        ).await;
        
        // Update efficiency trackers
        self.update_efficiency_trackers(&allocations, performance_metrics).await;
        
        // Create result
        let result = DynamicAllocationResult {
            allocations,
            percentages,
            strategy,
            total_allocated: total_amount,
            adjustments,
            efficiency_score,
            timestamp: SystemTime::now(),
        };
        
        // Record allocation in history
        self.record_allocation(
            result.clone(),
            block_height,
            network_metrics.clone(),
            performance_metrics.clone()
        ).await;
        
        // Update last rebalance if needed
        if should_rebalance {
            let mut last_rebalance = self.last_rebalance.write().await;
            *last_rebalance = block_height;
        }
        
        info!("Allocation complete: strategy={:?}, efficiency={:.2}", 
              result.strategy, result.efficiency_score);
        
        Ok(result)
    }

    /// Set emergency mode
    pub async fn set_emergency_mode(&self, enabled: bool, reason: Option<String>) -> EconomicsResult<()> {
        let mut emergency = self.emergency_mode.write().await;
        *emergency = enabled;
        
        if enabled {
            warn!("Emergency allocation mode activated: {}", reason.unwrap_or_default());
            let mut strategy = self.current_strategy.write().await;
            *strategy = AllocationStrategy::Emergency;
        } else {
            info!("Emergency allocation mode deactivated");
        }
        
        Ok(())
    }

    /// Get allocation statistics
    pub async fn get_statistics(&self) -> AllocationStatistics {
        let history = self.allocation_history.read().await;
        let trackers = self.efficiency_trackers.read().await;
        let strategy = self.current_strategy.read().await;
        
        let recent_allocations = history.iter()
            .rev()
            .take(100)
            .map(|h| h.result.percentages.clone())
            .collect::<Vec<_>>();
        
        let average_efficiency = if recent_allocations.is_empty() {
            0.5
        } else {
            history.iter()
                .rev()
                .take(100)
                .map(|h| h.result.efficiency_score)
                .sum::<f64>() / recent_allocations.len() as f64
        };
        
        let category_performance: HashMap<String, f64> = trackers.iter()
            .map(|(k, v)| (k.clone(), v.efficiency_score))
            .collect();
        
        AllocationStatistics {
            current_strategy: strategy.clone(),
            average_efficiency,
            category_performance,
            rebalance_count: history.len(),
            emergency_activations: history.iter()
                .filter(|h| h.result.strategy == AllocationStrategy::Emergency)
                .count(),
        }
    }

    /// Determine allocation strategy based on network conditions
    async fn determine_strategy(
        &self,
        network_metrics: &NetworkHealthMetrics,
        performance_metrics: &NetworkPerformanceMetrics,
    ) -> EconomicsResult<AllocationStrategy> {
        let emergency = self.emergency_mode.read().await;
        
        if *emergency {
            return Ok(AllocationStrategy::Emergency);
        }
        
        // Check security participation
        let security_ratio = network_metrics.security_participation as f64 / network_metrics.total_supply as f64;
        if security_ratio < self.config.emergency_threshold {
            return Ok(AllocationStrategy::Emergency);
        }
        
        // Check network growth
        if performance_metrics.ecosystem_growth > 0.1 && 
           performance_metrics.developer_activity > 0.7 {
            return Ok(AllocationStrategy::Growth);
        }
        
        // Check stability indicators
        if network_metrics.congestion_level < 0.3 &&
           performance_metrics.validator_participation > 0.8 {
            return Ok(AllocationStrategy::Stability);
        }
        
        // Default to dynamic
        Ok(AllocationStrategy::Dynamic)
    }

    /// Calculate dynamic allocations based on network conditions
    async fn calculate_dynamic_allocations(
        &self,
        strategy: &AllocationStrategy,
        network_metrics: &NetworkHealthMetrics,
        performance_metrics: &NetworkPerformanceMetrics,
    ) -> EconomicsResult<(AllocationDistribution, Vec<AllocationAdjustment>)> {
        let mut allocations = self.config.base_allocations.clone();
        let mut adjustments = Vec::new();
        
        match strategy {
            AllocationStrategy::Emergency => {
                // Boost security allocations
                let security_boost = 0.15;
                allocations.pow_mining += security_boost * 0.6;
                allocations.pos_validation += security_boost * 0.4;
                allocations.ecosystem_growth -= security_boost * 0.5;
                allocations.creator_rewards -= security_boost * 0.5;
                
                adjustments.push(AllocationAdjustment {
                    category: "security".to_string(),
                    base_percentage: self.config.base_allocations.pow_mining + self.config.base_allocations.pos_validation,
                    adjusted_percentage: allocations.pow_mining + allocations.pos_validation,
                    reason: "Emergency security boost".to_string(),
                    impact_score: 0.9,
                });
            }
            
            AllocationStrategy::Growth => {
                // Boost ecosystem and developer allocations
                let growth_boost = 0.10;
                allocations.ecosystem_growth += growth_boost * 0.5;
                allocations.development_fund += growth_boost * 0.3;
                allocations.creator_rewards += growth_boost * 0.2;
                allocations.pow_mining -= growth_boost * 0.5;
                allocations.pos_validation -= growth_boost * 0.5;
                
                adjustments.push(AllocationAdjustment {
                    category: "ecosystem".to_string(),
                    base_percentage: self.config.base_allocations.ecosystem_growth,
                    adjusted_percentage: allocations.ecosystem_growth,
                    reason: "Growth mode allocation boost".to_string(),
                    impact_score: 0.7,
                });
            }
            
            AllocationStrategy::Dynamic => {
                // Dynamic adjustments based on performance
                let trackers = self.efficiency_trackers.read().await;
                
                // Adjust based on efficiency scores
                for (category, tracker) in trackers.iter() {
                    let adjustment = self.calculate_category_adjustment(
                        category,
                        tracker,
                        network_metrics,
                        performance_metrics
                    );
                    
                    if adjustment.abs() > 0.01 {
                        self.apply_allocation_adjustment(
                            &mut allocations,
                            category,
                            adjustment,
                            &mut adjustments
                        );
                    }
                }
            }
            
            _ => {} // Fixed or Stability - use base allocations
        }
        
        // Ensure allocations sum to 1.0
        self.normalize_allocations(&mut allocations);
        
        Ok((allocations, adjustments))
    }

    /// Calculate adjustment for a specific category
    fn calculate_category_adjustment(
        &self,
        category: &str,
        tracker: &EfficiencyTracker,
        network_metrics: &NetworkHealthMetrics,
        performance_metrics: &NetworkPerformanceMetrics,
    ) -> f64 {
        let mut adjustment = 0.0;
        
        // Base adjustment on efficiency score
        let efficiency_factor = (tracker.efficiency_score - 0.5) * self.config.adjustment_sensitivity;
        
        // Category-specific adjustments
        match category {
            "pow_mining" => {
                if performance_metrics.hash_rate_growth < -0.1 {
                    adjustment += 0.05; // Boost if hash rate declining
                }
            }
            "pos_validation" => {
                if performance_metrics.validator_participation < 0.7 {
                    adjustment += 0.05; // Boost if participation low
                }
            }
            "privacy_infrastructure" => {
                if performance_metrics.privacy_node_availability < 0.6 {
                    adjustment += 0.03; // Boost if privacy nodes insufficient
                }
            }
            "development_fund" => {
                if performance_metrics.developer_activity > 0.8 {
                    adjustment += 0.02; // Slight boost for high activity
                }
            }
            _ => {}
        }
        
        // Apply efficiency factor
        adjustment += efficiency_factor * 0.1;
        
        // Limit adjustment to max deviation
        adjustment.max(-self.config.max_deviation).min(self.config.max_deviation)
    }

    /// Apply allocation adjustment to distribution
    fn apply_allocation_adjustment(
        &self,
        allocations: &mut AllocationDistribution,
        category: &str,
        adjustment: f64,
        adjustments: &mut Vec<AllocationAdjustment>,
    ) {
        let base_value = match category {
            "pow_mining" => {
                let base = allocations.pow_mining;
                allocations.pow_mining += adjustment;
                base
            }
            "pos_validation" => {
                let base = allocations.pos_validation;
                allocations.pos_validation += adjustment;
                base
            }
            "privacy_infrastructure" => {
                let base = allocations.privacy_infrastructure;
                allocations.privacy_infrastructure += adjustment;
                base
            }
            "development_fund" => {
                let base = allocations.development_fund;
                allocations.development_fund += adjustment;
                base
            }
            "ecosystem_growth" => {
                let base = allocations.ecosystem_growth;
                allocations.ecosystem_growth += adjustment;
                base
            }
            "creator_rewards" => {
                let base = allocations.creator_rewards;
                allocations.creator_rewards += adjustment;
                base
            }
            _ => return,
        };
        
        adjustments.push(AllocationAdjustment {
            category: category.to_string(),
            base_percentage: base_value,
            adjusted_percentage: base_value + adjustment,
            reason: format!("Dynamic adjustment based on performance"),
            impact_score: adjustment.abs(),
        });
    }

    /// Normalize allocations to sum to 1.0
    fn normalize_allocations(&self, allocations: &mut AllocationDistribution) {
        let total = allocations.pow_mining + 
                   allocations.pos_validation + 
                   allocations.privacy_infrastructure +
                   allocations.development_fund +
                   allocations.ecosystem_growth +
                   allocations.creator_rewards +
                   allocations.burn_allocation;
        
        if total > 0.0 && (total - 1.0).abs() > 0.001 {
            allocations.pow_mining /= total;
            allocations.pos_validation /= total;
            allocations.privacy_infrastructure /= total;
            allocations.development_fund /= total;
            allocations.ecosystem_growth /= total;
            allocations.creator_rewards /= total;
            allocations.burn_allocation /= total;
        }
    }

    /// Convert percentage allocations to token amounts
    fn percentages_to_amounts(&self, total: u64, percentages: &AllocationDistribution) -> HashMap<String, u64> {
        let mut allocations = HashMap::new();
        
        allocations.insert("pow_mining".to_string(), 
                          (total as f64 * percentages.pow_mining) as u64);
        allocations.insert("pos_validation".to_string(), 
                          (total as f64 * percentages.pos_validation) as u64);
        allocations.insert("privacy_infrastructure".to_string(), 
                          (total as f64 * percentages.privacy_infrastructure) as u64);
        allocations.insert("development_fund".to_string(), 
                          (total as f64 * percentages.development_fund) as u64);
        allocations.insert("ecosystem_growth".to_string(), 
                          (total as f64 * percentages.ecosystem_growth) as u64);
        allocations.insert("creator_rewards".to_string(), 
                          (total as f64 * percentages.creator_rewards) as u64);
        allocations.insert("burn_allocation".to_string(), 
                          (total as f64 * percentages.burn_allocation) as u64);
        
        // Ensure total is preserved
        let allocated: u64 = allocations.values().sum();
        if allocated < total {
            let remainder = total - allocated;
            if let Some(mining) = allocations.get_mut("pow_mining") {
                *mining += remainder;
            }
        }
        
        allocations
    }

    /// Calculate allocation efficiency score
    async fn calculate_allocation_efficiency(
        &self,
        allocations: &HashMap<String, u64>,
        network_metrics: &NetworkHealthMetrics,
        performance_metrics: &NetworkPerformanceMetrics,
    ) -> f64 {
        let mut efficiency_score = 0.0;
        let weights = &self.config.priority_weights;
        
        // Security efficiency
        let security_allocation = allocations.get("pow_mining").unwrap_or(&0) + 
                                allocations.get("pos_validation").unwrap_or(&0);
        let security_ratio = security_allocation as f64 / network_metrics.total_supply as f64;
        let security_score = (security_ratio * 100.0).min(1.0);
        efficiency_score += security_score * weights.security;
        
        // Decentralization efficiency
        let decentralization_score = performance_metrics.validator_participation * 0.5 +
                                   (performance_metrics.privacy_node_availability * 0.5);
        efficiency_score += decentralization_score * weights.decentralization;
        
        // Privacy efficiency
        let privacy_allocation = allocations.get("privacy_infrastructure").unwrap_or(&0);
        let privacy_ratio = privacy_allocation as f64 / network_metrics.total_supply as f64;
        let privacy_score = (privacy_ratio * 50.0).min(1.0);
        efficiency_score += privacy_score * weights.privacy;
        
        // Scalability efficiency
        let scalability_score = 1.0 - network_metrics.congestion_level;
        efficiency_score += scalability_score * weights.scalability;
        
        // Sustainability efficiency
        let burn_amount = allocations.get("burn_allocation").unwrap_or(&0);
        let sustainability_score = (burn_amount as f64 / network_metrics.fee_revenue as f64).min(1.0);
        efficiency_score += sustainability_score * weights.sustainability;
        
        efficiency_score.max(0.0).min(1.0)
    }

    /// Update efficiency trackers with new allocation data
    async fn update_efficiency_trackers(
        &self,
        allocations: &HashMap<String, u64>,
        performance_metrics: &NetworkPerformanceMetrics,
    ) {
        let mut trackers = self.efficiency_trackers.write().await;
        
        for (category, amount) in allocations {
            if let Some(tracker) = trackers.get_mut(category) {
                // Calculate performance score for this category
                let performance_score = match category.as_str() {
                    "pow_mining" => (performance_metrics.hash_rate_growth + 1.0) / 2.0,
                    "pos_validation" => performance_metrics.validator_participation,
                    "privacy_infrastructure" => performance_metrics.privacy_node_availability,
                    "development_fund" => performance_metrics.developer_activity,
                    "ecosystem_growth" => performance_metrics.ecosystem_growth,
                    "creator_rewards" => performance_metrics.creator_engagement,
                    _ => 0.5,
                };
                
                // Add to history
                tracker.allocations.push_back((*amount, performance_score));
                if tracker.allocations.len() > 100 {
                    tracker.allocations.pop_front();
                }
                
                // Update efficiency score
                if !tracker.allocations.is_empty() {
                    let recent_scores: Vec<f64> = tracker.allocations.iter()
                        .rev()
                        .take(20)
                        .map(|(_, score)| *score)
                        .collect();
                    
                    tracker.efficiency_score = recent_scores.iter().sum::<f64>() / recent_scores.len() as f64;
                    
                    // Calculate trend
                    if tracker.allocations.len() >= 20 {
                        let old_avg = tracker.allocations.iter()
                            .take(10)
                            .map(|(_, score)| *score)
                            .sum::<f64>() / 10.0;
                        
                        tracker.trend = tracker.efficiency_score - old_avg;
                    }
                }
            }
        }
    }

    /// Check if rebalancing is needed
    async fn should_rebalance(&self, block_height: u64) -> bool {
        let last_rebalance = self.last_rebalance.read().await;
        block_height - *last_rebalance >= self.config.rebalancing_frequency
    }

    /// Record allocation in history
    async fn record_allocation(
        &self,
        result: DynamicAllocationResult,
        block_height: u64,
        network_metrics: NetworkHealthMetrics,
        performance_metrics: NetworkPerformanceMetrics,
    ) {
        let mut history = self.allocation_history.write().await;
        
        history.push_back(AllocationHistory {
            result,
            network_metrics,
            performance_metrics,
            block_height,
        });
        
        // Keep only recent history
        while history.len() > 1000 {
            history.pop_front();
        }
    }
}

/// Allocation system statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationStatistics {
    pub current_strategy: AllocationStrategy,
    pub average_efficiency: f64,
    pub category_performance: HashMap<String, f64>,
    pub rebalance_count: usize,
    pub emergency_activations: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_dynamic_allocation() {
        let config = DynamicAllocationConfig::default();
        let manager = DynamicAllocationManager::new(config);
        
        let network_metrics = NetworkHealthMetrics::default();
        let performance_metrics = NetworkPerformanceMetrics {
            hash_rate_growth: 0.05,
            validator_participation: 0.75,
            privacy_node_availability: 0.65,
            developer_activity: 0.6,
            ecosystem_growth: 0.08,
            creator_engagement: 0.4,
            network_utilization: 0.5,
        };
        
        let result = manager.allocate_rewards(
            1_000_000, // 1M tokens
            100,
            &network_metrics,
            &performance_metrics
        ).await.unwrap();
        
        // Verify total allocation
        let total: u64 = result.allocations.values().sum();
        assert_eq!(total, 1_000_000);
        
        // Verify all categories are allocated
        assert!(result.allocations.contains_key("pow_mining"));
        assert!(result.allocations.contains_key("pos_validation"));
        assert!(result.allocations.contains_key("development_fund"));
    }

    #[tokio::test]
    async fn test_emergency_allocation() {
        let config = DynamicAllocationConfig::default();
        let manager = DynamicAllocationManager::new(config);
        
        // Set emergency mode
        manager.set_emergency_mode(true, Some("Test emergency".to_string())).await.unwrap();
        
        let mut network_metrics = NetworkHealthMetrics::default();
        network_metrics.security_participation = network_metrics.total_supply / 4; // 25% - below threshold
        
        let performance_metrics = NetworkPerformanceMetrics {
            hash_rate_growth: -0.2, // Declining
            validator_participation: 0.4, // Low
            privacy_node_availability: 0.5,
            developer_activity: 0.5,
            ecosystem_growth: 0.0,
            creator_engagement: 0.3,
            network_utilization: 0.7,
        };
        
        let result = manager.allocate_rewards(
            1_000_000,
            100,
            &network_metrics,
            &performance_metrics
        ).await.unwrap();
        
        assert_eq!(result.strategy, AllocationStrategy::Emergency);
        
        // Verify security allocations are boosted
        let security_total = result.allocations.get("pow_mining").unwrap() +
                           result.allocations.get("pos_validation").unwrap();
        assert!(security_total > 600_000); // Should be > 60% in emergency
    }

    #[tokio::test]
    async fn test_allocation_normalization() {
        let manager = DynamicAllocationManager::new(DynamicAllocationConfig::default());
        
        let mut allocations = AllocationDistribution {
            pow_mining: 0.4,
            pos_validation: 0.3,
            privacy_infrastructure: 0.2,
            development_fund: 0.15,
            ecosystem_growth: 0.15,
            creator_rewards: 0.1,
            burn_allocation: 0.1,
        };
        
        // Total is 1.4, should normalize to 1.0
        manager.normalize_allocations(&mut allocations);
        
        let total = allocations.pow_mining + 
                   allocations.pos_validation + 
                   allocations.privacy_infrastructure +
                   allocations.development_fund +
                   allocations.ecosystem_growth +
                   allocations.creator_rewards +
                   allocations.burn_allocation;
        
        assert!((total - 1.0).abs() < 0.001);
    }
}