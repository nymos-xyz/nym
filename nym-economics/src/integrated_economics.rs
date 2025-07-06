//! Integrated Economics System
//! 
//! This module integrates the adaptive emissions and dynamic allocation systems
//! to provide a complete economic protocol for the Nym blockchain.

use crate::{
    error::{EconomicsError, EconomicsResult},
    adaptive_emissions::{
        AdaptiveEmissionsSystem, AdaptiveEmissionsConfig, NetworkHealthMetrics,
        EmissionCalculation,
    },
    dynamic_allocation::{
        DynamicAllocationManager, DynamicAllocationConfig, NetworkPerformanceMetrics,
        DynamicAllocationResult,
    },
    fee_market::{FeeMarketManager, FeeMarketConfig, FeeMarketMetrics},
    inflation_targeting::{InflationTargetingSystem, InflationConfig, InflationMetrics},
};

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, debug, warn, error};
use serde::{Deserialize, Serialize};

/// Integrated economics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegratedEconomicsConfig {
    pub emissions_config: AdaptiveEmissionsConfig,
    pub allocation_config: DynamicAllocationConfig,
    pub fee_market_config: FeeMarketConfig,
    pub inflation_config: InflationConfig,
    pub enable_automation: bool,
    pub reporting_frequency: u64, // blocks
}

impl Default for IntegratedEconomicsConfig {
    fn default() -> Self {
        Self {
            emissions_config: AdaptiveEmissionsConfig::default(),
            allocation_config: DynamicAllocationConfig::default(),
            fee_market_config: FeeMarketConfig::default(),
            inflation_config: InflationConfig::default(),
            enable_automation: true,
            reporting_frequency: 720, // ~1 day
        }
    }
}

/// Complete economic state for a block
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockEconomicState {
    pub block_height: u64,
    pub emission_calculation: EmissionCalculation,
    pub allocation_result: DynamicAllocationResult,
    pub fee_recommendations: Vec<(u8, u64)>, // (priority, fee)
    pub inflation_rate: f64,
    pub economic_health_score: f64,
}

/// Economic health assessment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicHealthAssessment {
    pub overall_score: f64,
    pub security_score: f64,
    pub sustainability_score: f64,
    pub efficiency_score: f64,
    pub growth_score: f64,
    pub warnings: Vec<String>,
    pub recommendations: Vec<String>,
}

/// Integrated economics system
pub struct IntegratedEconomicsSystem {
    config: IntegratedEconomicsConfig,
    emissions_system: Arc<AdaptiveEmissionsSystem>,
    allocation_manager: Arc<DynamicAllocationManager>,
    fee_market_manager: Arc<RwLock<FeeMarketManager>>,
    inflation_system: Arc<RwLock<InflationTargetingSystem>>,
    last_report_block: RwLock<u64>,
}

impl IntegratedEconomicsSystem {
    pub fn new(config: IntegratedEconomicsConfig) -> Self {
        info!("Initializing integrated economics system");
        
        Self {
            emissions_system: Arc::new(AdaptiveEmissionsSystem::new(config.emissions_config.clone())),
            allocation_manager: Arc::new(DynamicAllocationManager::new(config.allocation_config.clone())),
            fee_market_manager: Arc::new(RwLock::new(FeeMarketManager::new(config.fee_market_config.clone()))),
            inflation_system: Arc::new(RwLock::new(InflationTargetingSystem::new(config.inflation_config.clone()))),
            config,
            last_report_block: RwLock::new(0),
        }
    }

    /// Process economics for a new block
    pub async fn process_block(
        &self,
        block_height: u64,
        network_metrics: NetworkHealthMetrics,
        performance_metrics: NetworkPerformanceMetrics,
    ) -> EconomicsResult<BlockEconomicState> {
        info!("Processing economics for block {}", block_height);
        
        // Step 1: Calculate adaptive emissions
        let emission_calculation = self.emissions_system
            .calculate_block_emission(block_height, network_metrics.clone())
            .await?;
        
        // Step 2: Allocate emissions dynamically
        let allocation_result = self.allocation_manager
            .allocate_rewards(
                emission_calculation.total_emission,
                block_height,
                &network_metrics,
                &performance_metrics,
            )
            .await?;
        
        // Step 3: Update fee market analysis
        let fee_market_metrics = FeeMarketMetrics {
            current_base_fee: network_metrics.average_fee,
            congestion_level: network_metrics.congestion_level,
            transaction_throughput: network_metrics.transaction_throughput,
            average_wait_time: 120.0, // placeholder
        };
        
        let mut fee_market = self.fee_market_manager.write().await;
        fee_market.analyze_market(&fee_market_metrics).await?;
        
        // Step 4: Get fee recommendations for different priorities
        let mut fee_recommendations = Vec::new();
        for priority in 0..=3 {
            let recommendation = fee_market.recommend_fee(priority).await?;
            fee_recommendations.push((priority, recommendation.recommended_fee));
        }
        drop(fee_market);
        
        // Step 5: Update inflation tracking
        let inflation_metrics = InflationMetrics {
            current_rate: emission_calculation.effective_inflation,
            trend: 0.0, // calculated over time
            volatility: 0.1,
            deviation_from_target: emission_calculation.effective_inflation - self.config.inflation_config.target_rate,
        };
        
        let mut inflation_system = self.inflation_system.write().await;
        let inflation_adjustment = inflation_system.analyze_inflation(&inflation_metrics).await?;
        drop(inflation_system);
        
        // Step 6: Calculate economic health score
        let health_assessment = self.assess_economic_health(
            &network_metrics,
            &performance_metrics,
            &emission_calculation,
            &allocation_result,
        ).await;
        
        // Step 7: Generate report if needed
        if self.should_generate_report(block_height).await {
            self.generate_economic_report(
                block_height,
                &health_assessment,
            ).await;
        }
        
        // Step 8: Apply any automated adjustments
        if self.config.enable_automation {
            self.apply_automated_adjustments(
                &health_assessment,
                &inflation_adjustment,
            ).await?;
        }
        
        Ok(BlockEconomicState {
            block_height,
            emission_calculation,
            allocation_result,
            fee_recommendations,
            inflation_rate: inflation_metrics.current_rate,
            economic_health_score: health_assessment.overall_score,
        })
    }

    /// Assess overall economic health
    async fn assess_economic_health(
        &self,
        network_metrics: &NetworkHealthMetrics,
        performance_metrics: &NetworkPerformanceMetrics,
        emission_calculation: &EmissionCalculation,
        allocation_result: &DynamicAllocationResult,
    ) -> EconomicHealthAssessment {
        let mut warnings = Vec::new();
        let mut recommendations = Vec::new();
        
        // Security score
        let security_participation = network_metrics.security_participation as f64 / network_metrics.total_supply as f64;
        let security_score = if security_participation < 0.33 {
            warnings.push("Critical: Security participation below 33%".to_string());
            recommendations.push("Increase security rewards immediately".to_string());
            0.2
        } else if security_participation < 0.5 {
            warnings.push("Warning: Security participation below 50%".to_string());
            recommendations.push("Consider boosting security incentives".to_string());
            0.5
        } else if security_participation < 0.67 {
            0.75
        } else {
            0.9
        };
        
        // Sustainability score
        let fee_coverage = network_metrics.fee_revenue as f64 / emission_calculation.total_emission as f64;
        let sustainability_score = if fee_coverage < 0.1 {
            warnings.push("Low fee revenue relative to emissions".to_string());
            recommendations.push("Focus on increasing network usage".to_string());
            0.3
        } else if fee_coverage < 0.25 {
            0.6
        } else if fee_coverage < 0.5 {
            0.8
        } else {
            0.95
        };
        
        // Efficiency score
        let efficiency_score = allocation_result.efficiency_score;
        if efficiency_score < 0.5 {
            warnings.push("Low allocation efficiency detected".to_string());
            recommendations.push("Review allocation strategy".to_string());
        }
        
        // Growth score
        let growth_score = (performance_metrics.ecosystem_growth + 1.0) / 2.0 * 0.4 +
                          performance_metrics.developer_activity * 0.3 +
                          performance_metrics.creator_engagement * 0.3;
        
        if growth_score < 0.3 {
            warnings.push("Low ecosystem growth metrics".to_string());
            recommendations.push("Increase ecosystem and developer incentives".to_string());
        }
        
        // Overall score
        let overall_score = security_score * 0.4 +
                           sustainability_score * 0.3 +
                           efficiency_score * 0.2 +
                           growth_score * 0.1;
        
        EconomicHealthAssessment {
            overall_score,
            security_score,
            sustainability_score,
            efficiency_score,
            growth_score,
            warnings,
            recommendations,
        }
    }

    /// Apply automated economic adjustments
    async fn apply_automated_adjustments(
        &self,
        health_assessment: &EconomicHealthAssessment,
        inflation_adjustment: &crate::inflation_targeting::InflationAdjustment,
    ) -> EconomicsResult<()> {
        // Emergency mode activation
        if health_assessment.security_score < 0.3 {
            warn!("Activating emergency mode due to low security score");
            self.emissions_system.set_emergency_mode(
                true,
                Some("Security score critically low".to_string())
            ).await?;
            
            self.allocation_manager.set_emergency_mode(
                true,
                Some("Security emergency".to_string())
            ).await?;
        }
        
        // Apply inflation adjustments if needed
        if inflation_adjustment.emission_adjustment.abs() > 0.1 {
            debug!("Applying inflation adjustment: {}", inflation_adjustment.reasoning);
            // In a real implementation, this would adjust emission parameters
        }
        
        Ok(())
    }

    /// Check if economic report should be generated
    async fn should_generate_report(&self, block_height: u64) -> bool {
        let last_report = self.last_report_block.read().await;
        block_height - *last_report >= self.config.reporting_frequency
    }

    /// Generate economic report
    async fn generate_economic_report(
        &self,
        block_height: u64,
        health_assessment: &EconomicHealthAssessment,
    ) {
        info!("=== Economic Report - Block {} ===", block_height);
        info!("Overall Health Score: {:.2}", health_assessment.overall_score);
        info!("Security Score: {:.2}", health_assessment.security_score);
        info!("Sustainability Score: {:.2}", health_assessment.sustainability_score);
        info!("Efficiency Score: {:.2}", health_assessment.efficiency_score);
        info!("Growth Score: {:.2}", health_assessment.growth_score);
        
        if !health_assessment.warnings.is_empty() {
            warn!("Warnings:");
            for warning in &health_assessment.warnings {
                warn!("  - {}", warning);
            }
        }
        
        if !health_assessment.recommendations.is_empty() {
            info!("Recommendations:");
            for recommendation in &health_assessment.recommendations {
                info!("  - {}", recommendation);
            }
        }
        
        let mut last_report = self.last_report_block.write().await;
        *last_report = block_height;
    }

    /// Get comprehensive economic statistics
    pub async fn get_statistics(&self) -> IntegratedEconomicsStatistics {
        let emission_stats = self.emissions_system.get_emission_stats().await;
        let allocation_stats = self.allocation_manager.get_statistics().await;
        let fee_stats = self.fee_market_manager.read().await.get_statistics().await;
        let inflation_stats = self.inflation_system.read().await.get_statistics().await;
        
        IntegratedEconomicsStatistics {
            current_emission_rate: emission_stats.current_emission_rate,
            current_inflation_rate: emission_stats.current_inflation_rate,
            allocation_efficiency: allocation_stats.average_efficiency,
            fee_market_efficiency: fee_stats.market_efficiency,
            inflation_target_adherence: inflation_stats.target_adherence,
            emergency_mode_active: emission_stats.emergency_mode_active,
        }
    }
}

/// Integrated economics statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegratedEconomicsStatistics {
    pub current_emission_rate: u64,
    pub current_inflation_rate: f64,
    pub allocation_efficiency: f64,
    pub fee_market_efficiency: f64,
    pub inflation_target_adherence: f64,
    pub emergency_mode_active: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_integrated_economics() {
        let config = IntegratedEconomicsConfig::default();
        let system = IntegratedEconomicsSystem::new(config);
        
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
        
        let result = system.process_block(100, network_metrics, performance_metrics).await.unwrap();
        
        assert_eq!(result.block_height, 100);
        assert!(result.emission_calculation.total_emission > 0);
        assert!(!result.allocation_result.allocations.is_empty());
        assert!(!result.fee_recommendations.is_empty());
        assert!(result.economic_health_score > 0.0);
    }

    #[tokio::test]
    async fn test_economic_health_assessment() {
        let config = IntegratedEconomicsConfig::default();
        let system = IntegratedEconomicsSystem::new(config);
        
        // Test with poor network conditions
        let mut network_metrics = NetworkHealthMetrics::default();
        network_metrics.security_participation = network_metrics.total_supply / 4; // 25%
        network_metrics.fee_revenue = 100_000; // Low fees
        
        let performance_metrics = NetworkPerformanceMetrics {
            hash_rate_growth: -0.1,
            validator_participation: 0.3,
            privacy_node_availability: 0.4,
            developer_activity: 0.2,
            ecosystem_growth: -0.05,
            creator_engagement: 0.1,
            network_utilization: 0.2,
        };
        
        let result = system.process_block(100, network_metrics, performance_metrics).await.unwrap();
        
        // Should have low health score
        assert!(result.economic_health_score < 0.5);
        
        // Should activate emergency mode
        let stats = system.get_statistics().await;
        assert!(stats.emergency_mode_active);
    }
}