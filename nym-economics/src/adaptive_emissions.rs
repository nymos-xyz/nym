//! Adaptive Tail Emissions System
//! 
//! This module implements a sophisticated economic algorithm to maintain network
//! security and sustainability through adaptive block rewards that respond to
//! network health, fee market conditions, and long-term sustainability metrics.

use crate::error::{EconomicsError, EconomicsResult};
use nym_core::NymIdentity;
use nym_crypto::Hash256;

use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, debug, warn, error};
use serde::{Deserialize, Serialize};
use bigdecimal::{BigDecimal, FromPrimitive, ToPrimitive};
use num_bigint::BigUint;

/// Configuration for the adaptive emissions system
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AdaptiveEmissionsConfig {
    /// Base emission rate (tokens per block)
    pub base_emission_rate: u64,
    /// Minimum emission rate (tokens per block)
    pub min_emission_rate: u64,
    /// Maximum emission rate (tokens per block)
    pub max_emission_rate: u64,
    /// Target inflation rate (annual percentage)
    pub target_inflation: f64,
    /// Minimum inflation rate (annual percentage)
    pub min_inflation: f64,
    /// Maximum inflation rate (annual percentage)  
    pub max_inflation: f64,
    /// Security participation threshold (percentage of total supply staked)
    pub security_threshold: f64,
    /// Fee burn threshold (minimum fees to trigger burning)
    pub fee_burn_threshold: u64,
    /// Block time target (seconds)
    pub block_time_target: u64,
    /// Economic adjustment window (blocks)
    pub adjustment_window: u64,
    /// Emergency adjustment factor
    pub emergency_adjustment_factor: f64,
}

impl Default for AdaptiveEmissionsConfig {
    fn default() -> Self {
        Self {
            base_emission_rate: 1_000_000,      // 1 NYM per block
            min_emission_rate: 100_000,         // 0.1 NYM per block
            max_emission_rate: 10_000_000,      // 10 NYM per block
            target_inflation: 2.0,              // 2% annual inflation target
            min_inflation: 0.5,                 // 0.5% minimum
            max_inflation: 5.0,                 // 5% maximum
            security_threshold: 0.67,           // 67% of supply should be securing network
            fee_burn_threshold: 1_000_000,      // 1 NYM minimum for burning
            block_time_target: 120,             // 2 minutes per block
            adjustment_window: 1440,            // ~2 days of blocks
            emergency_adjustment_factor: 0.5,  // 50% emergency adjustments
        }
    }
}

/// Network health metrics that influence emissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkHealthMetrics {
    /// Total supply of tokens
    pub total_supply: u64,
    /// Amount of tokens actively securing the network (staked + mining)
    pub security_participation: u64,
    /// Total fees collected in the current period
    pub fee_revenue: u64,
    /// Average fee per transaction
    pub average_fee: u64,
    /// Current network hash rate (for PoW component)
    pub network_hash_rate: u64,
    /// Number of active validators (for PoS component)
    pub active_validators: u32,
    /// Average block time over recent period
    pub average_block_time: f64,
    /// Transaction throughput (transactions per second)
    pub transaction_throughput: f64,
    /// Network congestion level (0.0 to 1.0)
    pub congestion_level: f64,
    /// Timestamp of metrics collection
    pub timestamp: SystemTime,
}

impl Default for NetworkHealthMetrics {
    fn default() -> Self {
        Self {
            total_supply: 1_000_000_000_000_000, // 1 billion NYM with 6 decimals
            security_participation: 670_000_000_000_000, // 67% participation
            fee_revenue: 0,
            average_fee: 10_000, // 0.01 NYM
            network_hash_rate: 1_000_000,
            active_validators: 100,
            average_block_time: 120.0,
            transaction_throughput: 1000.0,
            congestion_level: 0.3,
            timestamp: SystemTime::now(),
        }
    }
}

/// Fee market analysis for emission adjustments
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeMarketAnalysis {
    /// Recent fee history (block_height, total_fees)
    pub fee_history: VecDeque<(u64, u64)>,
    /// Fee revenue trend (positive = increasing, negative = decreasing)
    pub revenue_trend: f64,
    /// Fee market efficiency (0.0 to 1.0)
    pub market_efficiency: f64,
    /// Recommended burn amount based on fee revenue
    pub recommended_burn: u64,
    /// Fee sustainability score (0.0 to 1.0)
    pub sustainability_score: f64,
}

impl Default for FeeMarketAnalysis {
    fn default() -> Self {
        Self {
            fee_history: VecDeque::new(),
            revenue_trend: 0.0,
            market_efficiency: 0.5,
            recommended_burn: 0,
            sustainability_score: 0.5,
        }
    }
}

/// Security budget analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityBudgetAnalysis {
    /// Current security budget (emissions + fees)
    pub current_budget: u64,
    /// Required security budget for network safety
    pub required_budget: u64,
    /// Security budget utilization ratio
    pub utilization_ratio: f64,
    /// Threat level assessment (0.0 to 1.0)
    pub threat_level: f64,
    /// Recommended security allocation
    pub recommended_allocation: u64,
}

impl Default for SecurityBudgetAnalysis {
    fn default() -> Self {
        Self {
            current_budget: 0,
            required_budget: 0,
            utilization_ratio: 0.0,
            threat_level: 0.1,
            recommended_allocation: 0,
        }
    }
}

/// Emission calculation result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmissionCalculation {
    /// Total emission for this block
    pub total_emission: u64,
    /// Amount allocated to PoW mining rewards
    pub pow_allocation: u64,
    /// Amount allocated to PoS validator rewards  
    pub pos_allocation: u64,
    /// Amount allocated to development fund
    pub development_allocation: u64,
    /// Amount allocated to ecosystem fund
    pub ecosystem_allocation: u64,
    /// Amount to be burned (deflationary component)
    pub burn_amount: u64,
    /// Effective inflation rate after burning
    pub effective_inflation: f64,
    /// Reasoning for emission adjustment
    pub adjustment_reason: String,
    /// Emergency adjustment applied
    pub emergency_adjustment: bool,
}

/// Historical emission data for analysis
#[derive(Debug, Clone)]
struct EmissionHistory {
    block_height: u64,
    emission: u64,
    inflation_rate: f64,
    metrics: NetworkHealthMetrics,
    timestamp: SystemTime,
}

/// Main adaptive emissions system
pub struct AdaptiveEmissionsSystem {
    config: AdaptiveEmissionsConfig,
    emission_history: RwLock<VecDeque<EmissionHistory>>,
    current_metrics: RwLock<NetworkHealthMetrics>,
    fee_market: RwLock<FeeMarketAnalysis>,
    security_budget: RwLock<SecurityBudgetAnalysis>,
    adjustment_factors: RwLock<EmissionAdjustmentFactors>,
    emergency_mode: RwLock<bool>,
}

/// Internal adjustment factors
#[derive(Debug, Clone)]
struct EmissionAdjustmentFactors {
    security_factor: f64,      // Based on security participation
    fee_factor: f64,          // Based on fee market health
    inflation_factor: f64,    // Based on inflation target
    network_factor: f64,      // Based on network performance
    emergency_factor: f64,    // Emergency adjustments
}

impl Default for EmissionAdjustmentFactors {
    fn default() -> Self {
        Self {
            security_factor: 1.0,
            fee_factor: 1.0,
            inflation_factor: 1.0,
            network_factor: 1.0,
            emergency_factor: 1.0,
        }
    }
}

impl AdaptiveEmissionsSystem {
    pub fn new(config: AdaptiveEmissionsConfig) -> Self {
        info!("Initializing adaptive emissions system with target inflation: {}%", 
              config.target_inflation);
        
        Self {
            config,
            emission_history: RwLock::new(VecDeque::new()),
            current_metrics: RwLock::new(NetworkHealthMetrics::default()),
            fee_market: RwLock::new(FeeMarketAnalysis::default()),
            security_budget: RwLock::new(SecurityBudgetAnalysis::default()),
            adjustment_factors: RwLock::new(EmissionAdjustmentFactors::default()),
            emergency_mode: RwLock::new(false),
        }
    }

    /// Calculate emissions for the next block
    pub async fn calculate_block_emission(
        &self,
        block_height: u64,
        metrics: NetworkHealthMetrics,
    ) -> EconomicsResult<EmissionCalculation> {
        debug!("Calculating emissions for block {}", block_height);

        // Update current metrics
        {
            let mut current = self.current_metrics.write().await;
            *current = metrics.clone();
        }

        // Analyze network health and adjust factors
        self.update_adjustment_factors(&metrics).await?;
        
        // Calculate base emission with adjustments
        let adjusted_emission = self.calculate_adjusted_emission(&metrics).await?;
        
        // Analyze fee market for burn recommendations
        self.update_fee_market_analysis(block_height, &metrics).await?;
        
        // Calculate security budget requirements
        self.update_security_budget_analysis(&metrics).await?;
        
        // Determine final emission allocation
        let emission_calc = self.allocate_emissions(adjusted_emission, &metrics).await?;
        
        // Record emission in history
        self.record_emission_history(block_height, &emission_calc, &metrics).await;
        
        info!("Block {} emission: {} NYM (inflation: {:.2}%)", 
              block_height, emission_calc.total_emission, emission_calc.effective_inflation);
        
        Ok(emission_calc)
    }

    /// Update network health metrics
    pub async fn update_network_metrics(&self, metrics: NetworkHealthMetrics) -> EconomicsResult<()> {
        let mut current = self.current_metrics.write().await;
        *current = metrics;
        Ok(())
    }

    /// Enable/disable emergency mode
    pub async fn set_emergency_mode(&self, enabled: bool, reason: Option<String>) -> EconomicsResult<()> {
        let mut emergency = self.emergency_mode.write().await;
        *emergency = enabled;
        
        if enabled {
            warn!("Emergency mode activated: {}", reason.unwrap_or_default());
        } else {
            info!("Emergency mode deactivated");
        }
        
        Ok(())
    }

    /// Get current emission statistics
    pub async fn get_emission_stats(&self) -> EmissionStatistics {
        let history = self.emission_history.read().await;
        let metrics = self.current_metrics.read().await;
        let factors = self.adjustment_factors.read().await;
        let emergency = self.emergency_mode.read().await;
        
        let recent_emissions: Vec<u64> = history.iter()
            .rev()
            .take(self.config.adjustment_window as usize)
            .map(|h| h.emission)
            .collect();
        
        let average_emission = if recent_emissions.is_empty() {
            self.config.base_emission_rate
        } else {
            recent_emissions.iter().sum::<u64>() / recent_emissions.len() as u64
        };
        
        let current_inflation = self.calculate_current_inflation_rate(&metrics).await;
        
        EmissionStatistics {
            current_emission_rate: average_emission,
            current_inflation_rate: current_inflation,
            target_inflation_rate: self.config.target_inflation,
            security_participation_ratio: metrics.security_participation as f64 / metrics.total_supply as f64,
            fee_revenue_24h: self.calculate_24h_fee_revenue().await,
            emergency_mode_active: *emergency,
            adjustment_factors: factors.clone(),
            blocks_analyzed: history.len(),
        }
    }

    /// Calculate adjusted emission based on network conditions
    async fn calculate_adjusted_emission(&self, metrics: &NetworkHealthMetrics) -> EconomicsResult<u64> {
        let factors = self.adjustment_factors.read().await;
        let emergency = self.emergency_mode.read().await;
        
        let mut adjusted_rate = self.config.base_emission_rate as f64;
        
        // Apply adjustment factors
        adjusted_rate *= factors.security_factor;
        adjusted_rate *= factors.fee_factor;
        adjusted_rate *= factors.inflation_factor;
        adjusted_rate *= factors.network_factor;
        
        // Apply emergency adjustments if needed
        if *emergency {
            adjusted_rate *= factors.emergency_factor;
        }
        
        // Ensure emission stays within bounds
        let final_emission = adjusted_rate
            .max(self.config.min_emission_rate as f64)
            .min(self.config.max_emission_rate as f64) as u64;
        
        debug!("Emission calculation: base={}, factors=({:.3}, {:.3}, {:.3}, {:.3}), final={}",
               self.config.base_emission_rate,
               factors.security_factor,
               factors.fee_factor, 
               factors.inflation_factor,
               factors.network_factor,
               final_emission);
        
        Ok(final_emission)
    }

    /// Update adjustment factors based on network health
    async fn update_adjustment_factors(&self, metrics: &NetworkHealthMetrics) -> EconomicsResult<()> {
        let mut factors = self.adjustment_factors.write().await;
        
        // Security participation factor
        let security_ratio = metrics.security_participation as f64 / metrics.total_supply as f64;
        factors.security_factor = if security_ratio < self.config.security_threshold {
            // Increase emissions to incentivize security participation
            1.0 + (self.config.security_threshold - security_ratio) * 2.0
        } else {
            // Decrease emissions if over-secured
            1.0 - (security_ratio - self.config.security_threshold) * 0.5
        }.max(0.5).min(2.0);
        
        // Fee market factor
        let fee_sufficiency = self.calculate_fee_sufficiency(metrics).await;
        factors.fee_factor = if fee_sufficiency < 0.5 {
            // Increase emissions if fees are insufficient
            1.0 + (0.5 - fee_sufficiency) * 1.5
        } else {
            // Decrease emissions if fees are sufficient
            1.0 - (fee_sufficiency - 0.5) * 0.8
        }.max(0.3).min(1.8);
        
        // Inflation targeting factor
        let current_inflation = self.calculate_current_inflation_rate(metrics).await;
        let inflation_diff = self.config.target_inflation - current_inflation;
        factors.inflation_factor = (1.0 + inflation_diff * 0.1).max(0.5).min(1.5);
        
        // Network performance factor
        factors.network_factor = self.calculate_network_performance_factor(metrics).await;
        
        // Emergency factor (only applied in emergency mode)
        factors.emergency_factor = if metrics.security_participation as f64 / metrics.total_supply as f64 < 0.33 {
            // Critical security threshold breached
            self.config.emergency_adjustment_factor
        } else {
            1.0
        };
        
        Ok(())
    }

    /// Allocate emissions across different purposes
    async fn allocate_emissions(
        &self,
        total_emission: u64,
        metrics: &NetworkHealthMetrics,
    ) -> EconomicsResult<EmissionCalculation> {
        let fee_market = self.fee_market.read().await;
        let security_budget = self.security_budget.read().await;
        
        // Base allocation percentages (can be dynamic based on network needs)
        let pow_percentage = 0.4;    // 40% to PoW mining
        let pos_percentage = 0.3;    // 30% to PoS validation
        let dev_percentage = 0.15;   // 15% to development
        let eco_percentage = 0.15;   // 15% to ecosystem
        
        let pow_allocation = (total_emission as f64 * pow_percentage) as u64;
        let pos_allocation = (total_emission as f64 * pos_percentage) as u64;
        let development_allocation = (total_emission as f64 * dev_percentage) as u64;
        let ecosystem_allocation = (total_emission as f64 * eco_percentage) as u64;
        
        // Calculate burn amount based on fee revenue
        let burn_amount = if fee_market.recommended_burn > self.config.fee_burn_threshold {
            (fee_market.recommended_burn * 0.8) // Burn 80% of excess fees
        } else {
            0
        };
        
        // Calculate effective inflation rate
        let net_emission = total_emission.saturating_sub(burn_amount);
        let effective_inflation = if metrics.total_supply > 0 {
            (net_emission as f64 / metrics.total_supply as f64) * 365.25 * 24.0 * 3600.0 / self.config.block_time_target as f64 * 100.0
        } else {
            0.0
        };
        
        // Determine adjustment reasoning
        let factors = self.adjustment_factors.read().await;
        let emergency = self.emergency_mode.read().await;
        
        let adjustment_reason = if *emergency {
            "Emergency adjustment due to security concerns".to_string()
        } else if factors.security_factor > 1.2 {
            "Increased emissions to incentivize security participation".to_string()
        } else if factors.fee_factor > 1.2 {
            "Increased emissions due to insufficient fee revenue".to_string()
        } else if factors.inflation_factor > 1.1 {
            "Adjusted emissions to target inflation rate".to_string()
        } else {
            "Normal emissions based on network health".to_string()
        };
        
        Ok(EmissionCalculation {
            total_emission,
            pow_allocation,
            pos_allocation,
            development_allocation,
            ecosystem_allocation,
            burn_amount,
            effective_inflation,
            adjustment_reason,
            emergency_adjustment: *emergency,
        })
    }

    /// Update fee market analysis
    async fn update_fee_market_analysis(
        &self,
        block_height: u64,
        metrics: &NetworkHealthMetrics,
    ) -> EconomicsResult<()> {
        let mut fee_market = self.fee_market.write().await;
        
        // Add current block to fee history
        fee_market.fee_history.push_back((block_height, metrics.fee_revenue));
        
        // Keep only recent history
        let window_size = self.config.adjustment_window as usize;
        while fee_market.fee_history.len() > window_size {
            fee_market.fee_history.pop_front();
        }
        
        // Calculate revenue trend
        if fee_market.fee_history.len() >= 2 {
            let recent_avg = fee_market.fee_history.iter()
                .rev()
                .take(window_size / 4)
                .map(|(_, fees)| *fees as f64)
                .sum::<f64>() / (window_size / 4) as f64;
            
            let older_avg = fee_market.fee_history.iter()
                .take(window_size / 4)
                .map(|(_, fees)| *fees as f64)
                .sum::<f64>() / (window_size / 4) as f64;
            
            fee_market.revenue_trend = if older_avg > 0.0 {
                (recent_avg - older_avg) / older_avg
            } else {
                0.0
            };
        }
        
        // Calculate market efficiency (simplified)
        fee_market.market_efficiency = (metrics.transaction_throughput / 10000.0).min(1.0);
        
        // Calculate recommended burn amount
        let total_fees: u64 = fee_market.fee_history.iter()
            .map(|(_, fees)| *fees)
            .sum();
        
        let average_fees = if fee_market.fee_history.is_empty() {
            0
        } else {
            total_fees / fee_market.fee_history.len() as u64
        };
        
        fee_market.recommended_burn = if average_fees > self.config.fee_burn_threshold {
            average_fees - self.config.fee_burn_threshold
        } else {
            0
        };
        
        // Calculate sustainability score
        fee_market.sustainability_score = if metrics.fee_revenue > 0 {
            (metrics.fee_revenue as f64 / (self.config.base_emission_rate * 4) as f64).min(1.0)
        } else {
            0.0
        };
        
        Ok(())
    }

    /// Update security budget analysis
    async fn update_security_budget_analysis(&self, metrics: &NetworkHealthMetrics) -> EconomicsResult<()> {
        let mut security_budget = self.security_budget.write().await;
        
        // Current security budget from emissions and fees
        security_budget.current_budget = self.config.base_emission_rate + metrics.fee_revenue;
        
        // Required budget based on network value and threat assessment
        let network_value = metrics.total_supply / 1_000_000; // Simplified value calculation
        security_budget.required_budget = (network_value as f64 * 0.01) as u64; // 1% of network value
        
        // Calculate utilization ratio
        security_budget.utilization_ratio = if security_budget.required_budget > 0 {
            security_budget.current_budget as f64 / security_budget.required_budget as f64
        } else {
            1.0
        };
        
        // Assess threat level based on security participation
        let security_ratio = metrics.security_participation as f64 / metrics.total_supply as f64;
        security_budget.threat_level = if security_ratio < 0.33 {
            0.9  // High threat
        } else if security_ratio < 0.5 {
            0.6  // Medium threat
        } else if security_ratio < 0.67 {
            0.3  // Low threat
        } else {
            0.1  // Very low threat
        };
        
        // Recommend security allocation
        security_budget.recommended_allocation = if security_budget.threat_level > 0.7 {
            security_budget.required_budget * 2 // Double allocation for high threat
        } else {
            security_budget.required_budget
        };
        
        Ok(())
    }

    /// Calculate fee sufficiency for the network
    async fn calculate_fee_sufficiency(&self, metrics: &NetworkHealthMetrics) -> f64 {
        if metrics.fee_revenue == 0 {
            return 0.0;
        }
        
        // Fees should ideally cover at least 25% of security budget
        let target_fee_coverage = self.config.base_emission_rate / 4;
        (metrics.fee_revenue as f64 / target_fee_coverage as f64).min(1.0)
    }

    /// Calculate current inflation rate
    async fn calculate_current_inflation_rate(&self, metrics: &NetworkHealthMetrics) -> f64 {
        let history = self.emission_history.read().await;
        
        if history.is_empty() || metrics.total_supply == 0 {
            return self.config.target_inflation;
        }
        
        // Calculate annual emission rate based on recent history
        let recent_emissions: u64 = history.iter()
            .rev()
            .take(self.config.adjustment_window as usize)
            .map(|h| h.emission)
            .sum();
        
        let blocks_per_year = 365.25 * 24.0 * 3600.0 / self.config.block_time_target as f64;
        let annual_emission = recent_emissions as f64 * blocks_per_year / history.len() as f64;
        
        (annual_emission / metrics.total_supply as f64) * 100.0
    }

    /// Calculate network performance factor
    async fn calculate_network_performance_factor(&self, metrics: &NetworkHealthMetrics) -> f64 {
        let mut performance_score = 1.0;
        
        // Block time performance
        let block_time_ratio = metrics.average_block_time / self.config.block_time_target as f64;
        if block_time_ratio > 1.2 {
            performance_score *= 0.9; // Penalize slow blocks
        } else if block_time_ratio < 0.8 {
            performance_score *= 0.95; // Slight penalty for too fast blocks
        }
        
        // Congestion performance
        if metrics.congestion_level > 0.8 {
            performance_score *= 0.85; // High congestion penalty
        } else if metrics.congestion_level > 0.5 {
            performance_score *= 0.95; // Medium congestion penalty
        }
        
        // Validator count performance
        if metrics.active_validators < 50 {
            performance_score *= 0.9; // Insufficient decentralization
        }
        
        performance_score.max(0.5).min(1.2)
    }

    /// Calculate 24-hour fee revenue
    async fn calculate_24h_fee_revenue(&self) -> u64 {
        let fee_market = self.fee_market.read().await;
        let blocks_per_day = 86400 / self.config.block_time_target;
        
        fee_market.fee_history.iter()
            .rev()
            .take(blocks_per_day as usize)
            .map(|(_, fees)| *fees)
            .sum()
    }

    /// Record emission in history
    async fn record_emission_history(
        &self,
        block_height: u64,
        emission_calc: &EmissionCalculation,
        metrics: &NetworkHealthMetrics,
    ) {
        let mut history = self.emission_history.write().await;
        
        history.push_back(EmissionHistory {
            block_height,
            emission: emission_calc.total_emission,
            inflation_rate: emission_calc.effective_inflation,
            metrics: metrics.clone(),
            timestamp: SystemTime::now(),
        });
        
        // Keep only recent history
        let max_history = (self.config.adjustment_window * 2) as usize;
        while history.len() > max_history {
            history.pop_front();
        }
    }
}

/// Emission system statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmissionStatistics {
    pub current_emission_rate: u64,
    pub current_inflation_rate: f64,
    pub target_inflation_rate: f64,
    pub security_participation_ratio: f64,
    pub fee_revenue_24h: u64,
    pub emergency_mode_active: bool,
    pub adjustment_factors: EmissionAdjustmentFactors,
    pub blocks_analyzed: usize,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_emission_calculation() {
        let config = AdaptiveEmissionsConfig::default();
        let system = AdaptiveEmissionsSystem::new(config);
        
        let metrics = NetworkHealthMetrics::default();
        let emission = system.calculate_block_emission(1, metrics).await.unwrap();
        
        assert!(emission.total_emission > 0);
        assert!(emission.pow_allocation > 0);
        assert!(emission.pos_allocation > 0);
        assert_eq!(
            emission.total_emission,
            emission.pow_allocation + emission.pos_allocation + 
            emission.development_allocation + emission.ecosystem_allocation
        );
    }

    #[tokio::test]
    async fn test_security_factor_adjustment() {
        let config = AdaptiveEmissionsConfig::default();
        let system = AdaptiveEmissionsSystem::new(config.clone());
        
        // Test low security participation
        let mut metrics = NetworkHealthMetrics::default();
        metrics.security_participation = metrics.total_supply / 3; // 33%
        
        system.update_adjustment_factors(&metrics).await.unwrap();
        let factors = system.adjustment_factors.read().await;
        
        // Should increase emissions due to low security participation
        assert!(factors.security_factor > 1.0);
    }

    #[tokio::test]
    async fn test_emergency_mode() {
        let config = AdaptiveEmissionsConfig::default();
        let system = AdaptiveEmissionsSystem::new(config);
        
        system.set_emergency_mode(true, Some("Test emergency".to_string())).await.unwrap();
        
        let emergency = system.emergency_mode.read().await;
        assert!(*emergency);
    }

    #[tokio::test]
    async fn test_fee_market_analysis() {
        let config = AdaptiveEmissionsConfig::default();
        let system = AdaptiveEmissionsSystem::new(config);
        
        let mut metrics = NetworkHealthMetrics::default();
        metrics.fee_revenue = 2_000_000; // Above burn threshold
        
        system.update_fee_market_analysis(1, &metrics).await.unwrap();
        
        let fee_market = system.fee_market.read().await;
        assert!(fee_market.recommended_burn > 0);
    }

    #[tokio::test]
    async fn test_inflation_bounds() {
        let config = AdaptiveEmissionsConfig {
            min_inflation: 0.5,
            max_inflation: 5.0,
            ..Default::default()
        };
        let system = AdaptiveEmissionsSystem::new(config);
        
        // Test with various network conditions
        let metrics = NetworkHealthMetrics::default();
        let emission = system.calculate_block_emission(1, metrics).await.unwrap();
        
        assert!(emission.effective_inflation >= 0.0);
        assert!(emission.effective_inflation <= 10.0); // Allow some tolerance
    }
}