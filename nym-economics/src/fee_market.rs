//! Fee Market Management
//! 
//! This module implements fee market analysis, optimization, and recommendations
//! for maintaining healthy transaction economics.

use crate::error::{EconomicsError, EconomicsResult};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Fee market configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeMarketConfig {
    pub base_fee: u64,
    pub max_fee_multiplier: f64,
    pub congestion_threshold: f64,
    pub adjustment_speed: f64,
}

impl Default for FeeMarketConfig {
    fn default() -> Self {
        Self {
            base_fee: 10_000, // 0.01 NYM
            max_fee_multiplier: 10.0,
            congestion_threshold: 0.8,
            adjustment_speed: 0.1,
        }
    }
}

/// Fee market metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeMarketMetrics {
    pub current_base_fee: u64,
    pub congestion_level: f64,
    pub transaction_throughput: f64,
    pub average_wait_time: f64,
}

/// Fee recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeRecommendation {
    pub recommended_fee: u64,
    pub confidence_level: f64,
    pub expected_confirmation_time: u64,
}

/// Fee market statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FeeMarketStatistics {
    pub average_fee: u64,
    pub fee_volatility: f64,
    pub market_efficiency: f64,
}

/// Fee market manager
pub struct FeeMarketManager {
    config: FeeMarketConfig,
    fee_history: VecDeque<u64>,
}

impl FeeMarketManager {
    pub fn new(config: FeeMarketConfig) -> Self {
        Self {
            config,
            fee_history: VecDeque::new(),
        }
    }

    pub async fn analyze_market(&mut self, metrics: &FeeMarketMetrics) -> EconomicsResult<()> {
        self.fee_history.push_back(metrics.current_base_fee);
        if self.fee_history.len() > 1000 {
            self.fee_history.pop_front();
        }
        Ok(())
    }

    pub async fn recommend_fee(&self, priority: u8) -> EconomicsResult<FeeRecommendation> {
        let base_fee = self.config.base_fee;
        let multiplier = match priority {
            0 => 1.0,   // Low priority
            1 => 1.5,   // Normal priority
            2 => 2.0,   // High priority
            _ => 3.0,   // Urgent priority
        };

        Ok(FeeRecommendation {
            recommended_fee: (base_fee as f64 * multiplier) as u64,
            confidence_level: 0.85,
            expected_confirmation_time: 120, // 2 minutes
        })
    }

    pub async fn get_statistics(&self) -> FeeMarketStatistics {
        let average_fee = if self.fee_history.is_empty() {
            self.config.base_fee
        } else {
            self.fee_history.iter().sum::<u64>() / self.fee_history.len() as u64
        };

        FeeMarketStatistics {
            average_fee,
            fee_volatility: 0.15,
            market_efficiency: 0.78,
        }
    }
}