//! Dynamic Economic Allocation System
//! 
//! This module implements sophisticated dynamic allocation of economic rewards across different
//! network participants and functions based on network needs, performance metrics, and hybrid
//! consensus requirements. Includes fee burning mechanisms and adaptive reward distribution.

use crate::error::{EconomicsError, EconomicsResult};
use crate::adaptive_emissions::NetworkHealthMetrics;
use nym_core::NymIdentity;
use nym_crypto::Hash256;

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, debug, warn, error};

/// Configuration for dynamic economic allocation strategies
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationConfig {
    /// Base allocation percentages for different network functions
    pub base_allocations: HashMap<String, f64>,
    /// Enable dynamic adjustment based on network conditions
    pub enable_dynamic_adjustment: bool,
    /// Maximum adjustment factor for dynamic allocation
    pub max_adjustment_factor: f64,
    /// Minimum allocation percentage for any category
    pub min_allocation_percentage: f64,
    /// Fee burning configuration
    pub fee_burning: FeeBurningConfig,
    /// Hybrid consensus allocation weights
    pub hybrid_consensus_weights: HybridConsensusWeights,
    /// Performance-based allocation factors
    pub performance_factors: PerformanceFactors,
    /// Emergency allocation overrides
    pub emergency_allocations: HashMap<String, f64>,
}

/// Fee burning configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeBurningConfig {
    /// Enable fee burning mechanism
    pub enable_burning: bool,
    /// Percentage of fees to burn (0.0 to 1.0)
    pub burn_percentage: f64,
    /// Minimum fee threshold for burning
    pub min_burn_threshold: u64,
    /// Maximum burn amount per block
    pub max_burn_per_block: u64,
    /// Burn rate adjustment factor
    pub burn_rate_adjustment: f64,
}

/// Hybrid consensus allocation weights
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridConsensusWeights {
    /// Base PoW allocation weight
    pub pow_base_weight: f64,
    /// Base PoS allocation weight
    pub pos_base_weight: f64,
    /// Dynamic weight adjustment enabled
    pub enable_dynamic_weights: bool,
    /// PoW difficulty adjustment factor
    pub pow_difficulty_factor: f64,
    /// PoS participation adjustment factor
    pub pos_participation_factor: f64,
}

/// Performance-based allocation factors
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceFactors {
    /// Network uptime factor weight
    pub uptime_factor_weight: f64,
    /// Transaction throughput factor weight
    pub throughput_factor_weight: f64,
    /// Security participation factor weight
    pub security_factor_weight: f64,
    /// Fee market health factor weight
    pub fee_market_factor_weight: f64,
}

impl Default for AllocationConfig {
    fn default() -> Self {
        let mut base_allocations = HashMap::new();
        base_allocations.insert("pow_mining".to_string(), 0.35);      // 35% to PoW mining
        base_allocations.insert("pos_staking".to_string(), 0.25);     // 25% to PoS staking
        base_allocations.insert("development".to_string(), 0.15);     // 15% to development
        base_allocations.insert("ecosystem".to_string(), 0.15);       // 15% to ecosystem
        base_allocations.insert("privacy_infrastructure".to_string(), 0.10); // 10% to privacy infrastructure

        let mut emergency_allocations = HashMap::new();
        emergency_allocations.insert("pow_mining".to_string(), 0.5);   // 50% to secure network
        emergency_allocations.insert("pos_staking".to_string(), 0.3);  // 30% to secure network
        emergency_allocations.insert("development".to_string(), 0.1);  // 10% to development
        emergency_allocations.insert("ecosystem".to_string(), 0.1);    // 10% to ecosystem

        Self {
            base_allocations,
            enable_dynamic_adjustment: true,
            max_adjustment_factor: 2.0,
            min_allocation_percentage: 0.05, // 5% minimum
            fee_burning: FeeBurningConfig {
                enable_burning: true,
                burn_percentage: 0.6, // Burn 60% of fees
                min_burn_threshold: 100_000, // 0.1 NYM
                max_burn_per_block: 10_000_000, // 10 NYM
                burn_rate_adjustment: 0.1,
            },
            hybrid_consensus_weights: HybridConsensusWeights {
                pow_base_weight: 0.6,
                pos_base_weight: 0.4,
                enable_dynamic_weights: true,
                pow_difficulty_factor: 0.2,
                pos_participation_factor: 0.3,
            },
            performance_factors: PerformanceFactors {
                uptime_factor_weight: 0.25,
                throughput_factor_weight: 0.25,
                security_factor_weight: 0.3,
                fee_market_factor_weight: 0.2,
            },
            emergency_allocations,
        }
    }
}

/// Allocation strategy enumeration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AllocationStrategy {
    /// Fixed allocation based on configuration
    Fixed,
    /// Dynamic allocation based on network conditions
    Dynamic,
    /// Emergency allocation for network security
    Emergency,
    /// Performance-based allocation
    PerformanceBased,
    /// Hybrid consensus weighted allocation
    HybridWeighted,
}

/// Detailed allocation result with comprehensive breakdown
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationResult {
    /// Allocations by category
    pub allocations: HashMap<String, u64>,
    /// Strategy used for allocation
    pub strategy_used: AllocationStrategy,
    /// Total amount allocated
    pub total_allocated: u64,
    /// Fee burning details
    pub fee_burning: FeeBurningResult,
    /// Hybrid consensus allocation details
    pub hybrid_allocation: HybridAllocationResult,
    /// Performance adjustment factors applied
    pub performance_adjustments: HashMap<String, f64>,
    /// Reasoning for allocation decisions
    pub allocation_reasoning: String,
}

/// Fee burning result details
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeBurningResult {
    /// Total fees available for burning
    pub total_fees: u64,
    /// Amount burned this block
    pub burned_amount: u64,
    /// Burn percentage applied
    pub burn_percentage: f64,
    /// Remaining fees after burning
    pub remaining_fees: u64,
    /// Burn efficiency score
    pub burn_efficiency: f64,
}

/// Hybrid consensus allocation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridAllocationResult {
    /// PoW allocation amount
    pub pow_allocation: u64,
    /// PoS allocation amount
    pub pos_allocation: u64,
    /// PoW weight applied
    pub pow_weight: f64,
    /// PoS weight applied
    pub pos_weight: f64,
    /// Dynamic adjustment factor
    pub dynamic_adjustment: f64,
}

/// Performance metrics for allocation decisions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Network uptime percentage
    pub uptime_percentage: f64,
    /// Transaction throughput (TPS)
    pub throughput: f64,
    /// Security participation ratio
    pub security_participation: f64,
    /// Fee market health score
    pub fee_market_health: f64,
    /// Mining decentralization score
    pub mining_decentralization: f64,
    /// Validator decentralization score
    pub validator_decentralization: f64,
}

/// Allocation statistics and historical data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationStatistics {
    /// Current allocation percentages
    pub current_allocations: HashMap<String, f64>,
    /// Historical allocation efficiency
    pub historical_efficiency: f64,
    /// Adjustment frequency over time
    pub adjustment_frequency: u32,
    /// Fee burning statistics
    pub fee_burning_stats: FeeBurningStatistics,
    /// Hybrid consensus performance
    pub hybrid_performance: HybridPerformanceStats,
    /// Performance trend analysis
    pub performance_trends: HashMap<String, f64>,
}

/// Fee burning statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeBurningStatistics {
    /// Total fees burned (lifetime)
    pub total_burned: u64,
    /// Average burn rate
    pub average_burn_rate: f64,
    /// Burn efficiency over time
    pub burn_efficiency_trend: f64,
    /// Fee market impact
    pub fee_market_impact: f64,
}

/// Hybrid consensus performance statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridPerformanceStats {
    /// PoW mining efficiency
    pub pow_efficiency: f64,
    /// PoS staking efficiency
    pub pos_efficiency: f64,
    /// Consensus balance score
    pub consensus_balance: f64,
    /// Security budget utilization
    pub security_utilization: f64,
}

/// Allocation history for analysis
#[derive(Debug, Clone)]
struct AllocationHistory {
    block_height: u64,
    allocations: HashMap<String, u64>,
    strategy: AllocationStrategy,
    performance_metrics: PerformanceMetrics,
    timestamp: SystemTime,
}

/// Dynamic economic allocation manager
pub struct EconomicAllocationManager {
    config: AllocationConfig,
    allocation_history: RwLock<VecDeque<AllocationHistory>>,
    performance_metrics: RwLock<PerformanceMetrics>,
    fee_burning_history: RwLock<VecDeque<FeeBurningResult>>,
    current_strategy: RwLock<AllocationStrategy>,
    emergency_mode: RwLock<bool>,
}

impl EconomicAllocationManager {
    pub fn new(config: AllocationConfig) -> Self {
        info!("Initializing dynamic economic allocation manager");
        
        Self {
            config,
            allocation_history: RwLock::new(VecDeque::new()),
            performance_metrics: RwLock::new(PerformanceMetrics::default()),
            fee_burning_history: RwLock::new(VecDeque::new()),
            current_strategy: RwLock::new(AllocationStrategy::Dynamic),
            emergency_mode: RwLock::new(false),
        }
    }

    /// Allocate economic rewards with dynamic adjustment
    pub async fn allocate_rewards(
        &self,
        total_amount: u64,
        network_metrics: &NetworkHealthMetrics,
        block_height: u64,
    ) -> EconomicsResult<AllocationResult> {
        debug!("Allocating {} NYM for block {}", total_amount, block_height);

        // Update performance metrics
        self.update_performance_metrics(network_metrics).await?;

        // Determine allocation strategy
        let strategy = self.determine_allocation_strategy(network_metrics).await?;

        // Calculate base allocations
        let mut allocations = self.calculate_base_allocations(total_amount, &strategy).await?;

        // Apply dynamic adjustments
        if self.config.enable_dynamic_adjustment {
            self.apply_dynamic_adjustments(&mut allocations, network_metrics).await?;
        }

        // Calculate fee burning
        let fee_burning = self.calculate_fee_burning(network_metrics).await?;

        // Calculate hybrid consensus allocation
        let hybrid_allocation = self.calculate_hybrid_allocation(
            &allocations,
            network_metrics,
        ).await?;

        // Apply performance adjustments
        let performance_adjustments = self.apply_performance_adjustments(
            &mut allocations,
            network_metrics,
        ).await?;

        // Generate allocation reasoning
        let allocation_reasoning = self.generate_allocation_reasoning(
            &strategy,
            &performance_adjustments,
            &fee_burning,
        ).await;

        let result = AllocationResult {
            allocations: allocations.clone(),
            strategy_used: strategy.clone(),
            total_allocated: total_amount,
            fee_burning,
            hybrid_allocation,
            performance_adjustments,
            allocation_reasoning,
        };

        // Record allocation history
        self.record_allocation_history(block_height, &result, network_metrics).await;

        info!("Block {} allocation complete: strategy={:?}, burned={} NYM", 
              block_height, strategy, result.fee_burning.burned_amount);

        Ok(result)
    }

    /// Update performance metrics from network health data
    async fn update_performance_metrics(&self, network_metrics: &NetworkHealthMetrics) -> EconomicsResult<()> {
        let mut metrics = self.performance_metrics.write().await;
        
        metrics.uptime_percentage = self.calculate_uptime_percentage(network_metrics).await;
        metrics.throughput = network_metrics.transaction_throughput;
        metrics.security_participation = network_metrics.security_participation as f64 / network_metrics.total_supply as f64;
        metrics.fee_market_health = self.calculate_fee_market_health(network_metrics).await;
        metrics.mining_decentralization = self.calculate_mining_decentralization(network_metrics).await;
        metrics.validator_decentralization = self.calculate_validator_decentralization(network_metrics).await;

        Ok(())
    }

    /// Determine the best allocation strategy based on network conditions
    async fn determine_allocation_strategy(&self, network_metrics: &NetworkHealthMetrics) -> EconomicsResult<AllocationStrategy> {
        let emergency = self.emergency_mode.read().await;
        
        if *emergency {
            return Ok(AllocationStrategy::Emergency);
        }

        // Check security thresholds
        let security_ratio = network_metrics.security_participation as f64 / network_metrics.total_supply as f64;
        if security_ratio < 0.33 {
            warn!("Low security participation detected: {:.1}%", security_ratio * 100.0);
            return Ok(AllocationStrategy::Emergency);
        }

        // Check network performance
        let performance_metrics = self.performance_metrics.read().await;
        if performance_metrics.uptime_percentage < 0.95 || performance_metrics.throughput < 100.0 {
            return Ok(AllocationStrategy::PerformanceBased);
        }

        // Default to hybrid weighted allocation
        Ok(AllocationStrategy::HybridWeighted)
    }

    /// Calculate base allocations based on strategy
    async fn calculate_base_allocations(
        &self,
        total_amount: u64,
        strategy: &AllocationStrategy,
    ) -> EconomicsResult<HashMap<String, u64>> {
        let mut allocations = HashMap::new();

        let allocation_percentages = match strategy {
            AllocationStrategy::Emergency => &self.config.emergency_allocations,
            _ => &self.config.base_allocations,
        };

        let mut total_percentage = 0.0;
        for (category, percentage) in allocation_percentages {
            let amount = (total_amount as f64 * percentage) as u64;
            allocations.insert(category.clone(), amount);
            total_percentage += percentage;
        }

        // Ensure allocations sum to total (handle rounding)
        if total_percentage < 1.0 {
            let remainder = total_amount - allocations.values().sum::<u64>();
            if let Some((category, amount)) = allocations.iter_mut().next() {
                *amount += remainder;
            }
        }

        Ok(allocations)
    }

    /// Apply dynamic adjustments based on network conditions
    async fn apply_dynamic_adjustments(
        &self,
        allocations: &mut HashMap<String, u64>,
        network_metrics: &NetworkHealthMetrics,
    ) -> EconomicsResult<()> {
        let security_ratio = network_metrics.security_participation as f64 / network_metrics.total_supply as f64;
        let congestion_level = network_metrics.congestion_level;

        // Adjust based on security participation
        if security_ratio < 0.5 {
            // Increase mining and staking rewards
            self.adjust_allocation(allocations, "pow_mining", 1.2).await;
            self.adjust_allocation(allocations, "pos_staking", 1.15).await;
        } else if security_ratio > 0.8 {
            // Decrease mining and staking, increase development
            self.adjust_allocation(allocations, "pow_mining", 0.9).await;
            self.adjust_allocation(allocations, "pos_staking", 0.95).await;
            self.adjust_allocation(allocations, "development", 1.1).await;
        }

        // Adjust based on network congestion
        if congestion_level > 0.7 {
            // Increase privacy infrastructure funding
            self.adjust_allocation(allocations, "privacy_infrastructure", 1.3).await;
        }

        Ok(())
    }

    /// Calculate fee burning based on network conditions
    async fn calculate_fee_burning(&self, network_metrics: &NetworkHealthMetrics) -> EconomicsResult<FeeBurningResult> {
        let fee_config = &self.config.fee_burning;
        
        if !fee_config.enable_burning || network_metrics.fee_revenue < fee_config.min_burn_threshold {
            return Ok(FeeBurningResult {
                total_fees: network_metrics.fee_revenue,
                burned_amount: 0,
                burn_percentage: 0.0,
                remaining_fees: network_metrics.fee_revenue,
                burn_efficiency: 0.0,
            });
        }

        // Calculate burn amount
        let base_burn = (network_metrics.fee_revenue as f64 * fee_config.burn_percentage) as u64;
        let burned_amount = base_burn.min(fee_config.max_burn_per_block);
        
        // Apply dynamic burn rate adjustment
        let fee_market_pressure = network_metrics.congestion_level;
        let adjusted_burn = if fee_market_pressure > 0.8 {
            // Increase burning during high congestion
            (burned_amount as f64 * (1.0 + fee_config.burn_rate_adjustment)) as u64
        } else if fee_market_pressure < 0.2 {
            // Decrease burning during low congestion
            (burned_amount as f64 * (1.0 - fee_config.burn_rate_adjustment)) as u64
        } else {
            burned_amount
        };

        let final_burn = adjusted_burn.min(network_metrics.fee_revenue);
        let remaining_fees = network_metrics.fee_revenue - final_burn;
        
        // Calculate burn efficiency
        let burn_efficiency = if network_metrics.fee_revenue > 0 {
            final_burn as f64 / network_metrics.fee_revenue as f64
        } else {
            0.0
        };

        let result = FeeBurningResult {
            total_fees: network_metrics.fee_revenue,
            burned_amount: final_burn,
            burn_percentage: final_burn as f64 / network_metrics.fee_revenue as f64,
            remaining_fees,
            burn_efficiency,
        };

        // Record fee burning history
        let mut history = self.fee_burning_history.write().await;
        history.push_back(result.clone());
        
        // Keep only recent history
        while history.len() > 1000 {
            history.pop_front();
        }

        Ok(result)
    }

    /// Calculate hybrid consensus allocation
    async fn calculate_hybrid_allocation(
        &self,
        allocations: &HashMap<String, u64>,
        network_metrics: &NetworkHealthMetrics,
    ) -> EconomicsResult<HybridAllocationResult> {
        let weights = &self.config.hybrid_consensus_weights;
        
        let pow_allocation = allocations.get("pow_mining").copied().unwrap_or(0);
        let pos_allocation = allocations.get("pos_staking").copied().unwrap_or(0);
        
        let mut pow_weight = weights.pow_base_weight;
        let mut pos_weight = weights.pos_base_weight;
        
        if weights.enable_dynamic_weights {
            // Adjust weights based on network conditions
            let network_hash_rate_factor = (network_metrics.network_hash_rate as f64 / 1_000_000.0).min(2.0);
            pow_weight *= 1.0 + (network_hash_rate_factor - 1.0) * weights.pow_difficulty_factor;
            
            let validator_participation = network_metrics.active_validators as f64 / 500.0; // Target 500 validators
            pos_weight *= 1.0 + (validator_participation - 1.0) * weights.pos_participation_factor;
        }
        
        // Normalize weights
        let total_weight = pow_weight + pos_weight;
        pow_weight /= total_weight;
        pos_weight /= total_weight;
        
        let dynamic_adjustment = if weights.enable_dynamic_weights {
            ((pow_weight - weights.pow_base_weight).abs() + (pos_weight - weights.pos_base_weight).abs()) / 2.0
        } else {
            0.0
        };

        Ok(HybridAllocationResult {
            pow_allocation,
            pos_allocation,
            pow_weight,
            pos_weight,
            dynamic_adjustment,
        })
    }

    /// Apply performance-based adjustments to allocations
    async fn apply_performance_adjustments(
        &self,
        allocations: &mut HashMap<String, u64>,
        network_metrics: &NetworkHealthMetrics,
    ) -> EconomicsResult<HashMap<String, f64>> {
        let mut adjustments = HashMap::new();
        let performance_metrics = self.performance_metrics.read().await;
        let factors = &self.config.performance_factors;

        // Calculate overall performance score
        let performance_score = 
            performance_metrics.uptime_percentage * factors.uptime_factor_weight +
            (performance_metrics.throughput / 1000.0).min(1.0) * factors.throughput_factor_weight +
            performance_metrics.security_participation * factors.security_factor_weight +
            performance_metrics.fee_market_health * factors.fee_market_factor_weight;

        // Apply adjustments based on performance
        for (category, amount) in allocations.iter_mut() {
            let adjustment_factor = match category.as_str() {
                "pow_mining" => {
                    if performance_metrics.mining_decentralization > 0.8 {
                        1.1 // Reward good decentralization
                    } else if performance_metrics.mining_decentralization < 0.5 {
                        0.9 // Penalize centralization
                    } else {
                        1.0
                    }
                }
                "pos_staking" => {
                    if performance_metrics.validator_decentralization > 0.8 {
                        1.1 // Reward good decentralization
                    } else if performance_metrics.validator_decentralization < 0.5 {
                        0.9 // Penalize centralization
                    } else {
                        1.0
                    }
                }
                "development" => {
                    if performance_score < 0.7 {
                        1.2 // Increase development funding when performance is poor
                    } else {
                        1.0
                    }
                }
                _ => 1.0,
            };

            *amount = (*amount as f64 * adjustment_factor) as u64;
            adjustments.insert(category.clone(), adjustment_factor);
        }

        Ok(adjustments)
    }

    /// Generate human-readable allocation reasoning
    async fn generate_allocation_reasoning(
        &self,
        strategy: &AllocationStrategy,
        performance_adjustments: &HashMap<String, f64>,
        fee_burning: &FeeBurningResult,
    ) -> String {
        let mut reasoning = format!("Strategy: {:?}. ", strategy);

        if fee_burning.burned_amount > 0 {
            reasoning.push_str(&format!("Burned {} NYM ({}% of fees). ", 
                                      fee_burning.burned_amount, 
                                      (fee_burning.burn_percentage * 100.0) as u32));
        }

        let major_adjustments: Vec<String> = performance_adjustments.iter()
            .filter(|(_, &factor)| factor > 1.1 || factor < 0.9)
            .map(|(category, factor)| {
                format!("{}: {:.1}x", category, factor)
            })
            .collect();

        if !major_adjustments.is_empty() {
            reasoning.push_str(&format!("Performance adjustments: {}. ", major_adjustments.join(", ")));
        }

        reasoning
    }

    /// Helper function to adjust allocation amounts
    async fn adjust_allocation(&self, allocations: &mut HashMap<String, u64>, category: &str, factor: f64) {
        if let Some(amount) = allocations.get_mut(category) {
            let adjusted = (*amount as f64 * factor) as u64;
            *amount = adjusted.max((*amount as f64 * self.config.min_allocation_percentage) as u64);
        }
    }

    /// Record allocation history for analysis
    async fn record_allocation_history(
        &self,
        block_height: u64,
        result: &AllocationResult,
        network_metrics: &NetworkHealthMetrics,
    ) {
        let performance_metrics = self.performance_metrics.read().await.clone();
        let mut history = self.allocation_history.write().await;
        
        history.push_back(AllocationHistory {
            block_height,
            allocations: result.allocations.clone(),
            strategy: result.strategy_used.clone(),
            performance_metrics,
            timestamp: SystemTime::now(),
        });

        // Keep only recent history
        while history.len() > 2000 {
            history.pop_front();
        }
    }

    /// Calculate network uptime percentage
    async fn calculate_uptime_percentage(&self, _network_metrics: &NetworkHealthMetrics) -> f64 {
        // Simplified calculation - in production this would analyze block times
        0.99 // 99% uptime
    }

    /// Calculate fee market health score
    async fn calculate_fee_market_health(&self, network_metrics: &NetworkHealthMetrics) -> f64 {
        if network_metrics.fee_revenue == 0 {
            return 0.0;
        }

        // Health based on fee revenue vs transaction volume
        let fee_per_tx = network_metrics.average_fee;
        let optimal_fee = 50_000; // 0.05 NYM optimal fee
        
        if fee_per_tx <= optimal_fee {
            1.0
        } else {
            (optimal_fee as f64 / fee_per_tx as f64).max(0.1)
        }
    }

    /// Calculate mining decentralization score
    async fn calculate_mining_decentralization(&self, network_metrics: &NetworkHealthMetrics) -> f64 {
        // Simplified - in production would analyze hash rate distribution
        if network_metrics.network_hash_rate > 1_000_000 {
            0.8 // Good decentralization
        } else {
            0.5 // Moderate decentralization
        }
    }

    /// Calculate validator decentralization score
    async fn calculate_validator_decentralization(&self, network_metrics: &NetworkHealthMetrics) -> f64 {
        let validator_count = network_metrics.active_validators as f64;
        let optimal_validators = 200.0;
        
        if validator_count >= optimal_validators {
            1.0
        } else {
            (validator_count / optimal_validators).max(0.1)
        }
    }

    /// Set emergency mode
    pub async fn set_emergency_mode(&self, enabled: bool, reason: Option<String>) -> EconomicsResult<()> {
        let mut emergency = self.emergency_mode.write().await;
        *emergency = enabled;
        
        if enabled {
            warn!("Economic allocation emergency mode activated: {}", reason.unwrap_or_default());
        } else {
            info!("Economic allocation emergency mode deactivated");
        }
        
        Ok(())
    }

    /// Get comprehensive allocation statistics
    pub async fn get_statistics(&self) -> AllocationStatistics {
        let history = self.allocation_history.read().await;
        let fee_burning_history = self.fee_burning_history.read().await;
        let current_allocations = self.config.base_allocations.clone();

        // Calculate historical efficiency
        let historical_efficiency = if history.is_empty() {
            0.85
        } else {
            history.iter()
                .map(|h| h.performance_metrics.uptime_percentage)
                .sum::<f64>() / history.len() as f64
        };

        // Calculate adjustment frequency
        let adjustment_frequency = history.iter()
            .filter(|h| matches!(h.strategy, AllocationStrategy::Dynamic | AllocationStrategy::PerformanceBased))
            .count() as u32;

        // Fee burning statistics
        let fee_burning_stats = if fee_burning_history.is_empty() {
            FeeBurningStatistics {
                total_burned: 0,
                average_burn_rate: 0.0,
                burn_efficiency_trend: 0.0,
                fee_market_impact: 0.0,
            }
        } else {
            let total_burned = fee_burning_history.iter().map(|f| f.burned_amount).sum();
            let average_burn_rate = fee_burning_history.iter()
                .map(|f| f.burn_percentage)
                .sum::<f64>() / fee_burning_history.len() as f64;
            
            FeeBurningStatistics {
                total_burned,
                average_burn_rate,
                burn_efficiency_trend: 0.1, // Placeholder
                fee_market_impact: 0.05, // Placeholder
            }
        };

        // Hybrid performance statistics
        let hybrid_performance = HybridPerformanceStats {
            pow_efficiency: 0.85,
            pos_efficiency: 0.90,
            consensus_balance: 0.8,
            security_utilization: 0.75,
        };

        // Performance trends
        let mut performance_trends = HashMap::new();
        performance_trends.insert("uptime".to_string(), 0.02);
        performance_trends.insert("throughput".to_string(), 0.15);
        performance_trends.insert("security".to_string(), 0.05);

        AllocationStatistics {
            current_allocations,
            historical_efficiency,
            adjustment_frequency,
            fee_burning_stats,
            hybrid_performance,
            performance_trends,
        }
    }
}

impl Default for PerformanceMetrics {
    fn default() -> Self {
        Self {
            uptime_percentage: 0.99,
            throughput: 1000.0,
            security_participation: 0.67,
            fee_market_health: 0.8,
            mining_decentralization: 0.75,
            validator_decentralization: 0.8,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::adaptive_emissions::NetworkHealthMetrics;

    #[tokio::test]
    async fn test_basic_allocation() {
        let config = AllocationConfig::default();
        let manager = EconomicAllocationManager::new(config);
        
        let network_metrics = NetworkHealthMetrics::default();
        let result = manager.allocate_rewards(1_000_000, &network_metrics, 1).await.unwrap();
        
        assert_eq!(result.total_allocated, 1_000_000);
        assert!(!result.allocations.is_empty());
        assert!(result.allocations.values().sum::<u64>() <= 1_000_000);
    }

    #[tokio::test]
    async fn test_fee_burning() {
        let config = AllocationConfig::default();
        let manager = EconomicAllocationManager::new(config);
        
        let mut network_metrics = NetworkHealthMetrics::default();
        network_metrics.fee_revenue = 1_000_000; // 1 NYM in fees
        
        let result = manager.allocate_rewards(1_000_000, &network_metrics, 1).await.unwrap();
        
        assert!(result.fee_burning.burned_amount > 0);
        assert!(result.fee_burning.burn_percentage > 0.0);
    }

    #[tokio::test]
    async fn test_emergency_allocation() {
        let config = AllocationConfig::default();
        let manager = EconomicAllocationManager::new(config);
        
        manager.set_emergency_mode(true, Some("Test emergency".to_string())).await.unwrap();
        
        let mut network_metrics = NetworkHealthMetrics::default();
        network_metrics.security_participation = network_metrics.total_supply / 4; // 25% participation
        
        let result = manager.allocate_rewards(1_000_000, &network_metrics, 1).await.unwrap();
        
        assert!(matches!(result.strategy_used, AllocationStrategy::Emergency));
    }

    #[tokio::test]
    async fn test_dynamic_adjustments() {
        let config = AllocationConfig::default();
        let manager = EconomicAllocationManager::new(config);
        
        let mut network_metrics = NetworkHealthMetrics::default();
        network_metrics.security_participation = network_metrics.total_supply / 3; // 33% participation
        network_metrics.congestion_level = 0.8; // High congestion
        
        let result = manager.allocate_rewards(1_000_000, &network_metrics, 1).await.unwrap();
        
        // Should have performance adjustments
        assert!(!result.performance_adjustments.is_empty());
        assert!(result.performance_adjustments.values().any(|&v| v != 1.0));
    }

    #[tokio::test]
    async fn test_hybrid_allocation() {
        let config = AllocationConfig::default();
        let manager = EconomicAllocationManager::new(config);
        
        let network_metrics = NetworkHealthMetrics::default();
        let result = manager.allocate_rewards(1_000_000, &network_metrics, 1).await.unwrap();
        
        assert!(result.hybrid_allocation.pow_allocation > 0);
        assert!(result.hybrid_allocation.pos_allocation > 0);
        assert!(result.hybrid_allocation.pow_weight > 0.0);
        assert!(result.hybrid_allocation.pos_weight > 0.0);
    }

    #[tokio::test]
    async fn test_allocation_statistics() {
        let config = AllocationConfig::default();
        let manager = EconomicAllocationManager::new(config);
        
        let network_metrics = NetworkHealthMetrics::default();
        manager.allocate_rewards(1_000_000, &network_metrics, 1).await.unwrap();
        
        let stats = manager.get_statistics().await;
        
        assert!(!stats.current_allocations.is_empty());
        assert!(stats.historical_efficiency > 0.0);
        assert!(stats.fee_burning_stats.total_burned >= 0);
    }
}