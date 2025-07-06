//! Inflation Targeting System
//! 
//! This module implements precise inflation rate targeting with adaptive mechanisms
//! to maintain price stability and economic predictability.

use crate::error::{EconomicsError, EconomicsResult};
use serde::{Deserialize, Serialize};
use std::collections::VecDeque;

/// Inflation targeting configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InflationConfig {
    pub target_rate: f64,
    pub tolerance_band: f64,
    pub adjustment_speed: f64,
    pub max_adjustment: f64,
}

impl Default for InflationConfig {
    fn default() -> Self {
        Self {
            target_rate: 2.0,      // 2% annual target
            tolerance_band: 0.5,   // ±0.5% tolerance
            adjustment_speed: 0.1, // 10% adjustment speed
            max_adjustment: 0.5,   // Max 50% adjustment per period
        }
    }
}

/// Inflation metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InflationMetrics {
    pub current_rate: f64,
    pub trend: f64,
    pub volatility: f64,
    pub deviation_from_target: f64,
}

/// Inflation adjustment recommendation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InflationAdjustment {
    pub emission_adjustment: f64,
    pub burn_adjustment: f64,
    pub confidence: f64,
    pub reasoning: String,
}

/// Inflation statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InflationStatistics {
    pub average_rate: f64,
    pub target_adherence: f64,
    pub adjustment_frequency: u32,
}

/// Inflation targeting system
pub struct InflationTargetingSystem {
    config: InflationConfig,
    inflation_history: VecDeque<f64>,
}

impl InflationTargetingSystem {
    pub fn new(config: InflationConfig) -> Self {
        Self {
            config,
            inflation_history: VecDeque::new(),
        }
    }

    pub async fn analyze_inflation(&mut self, metrics: &InflationMetrics) -> EconomicsResult<InflationAdjustment> {
        self.inflation_history.push_back(metrics.current_rate);
        if self.inflation_history.len() > 365 {
            self.inflation_history.pop_front();
        }

        let deviation = metrics.current_rate - self.config.target_rate;
        let adjustment_needed = deviation.abs() > self.config.tolerance_band;

        if adjustment_needed {
            let adjustment_magnitude = (deviation * self.config.adjustment_speed)
                .max(-self.config.max_adjustment)
                .min(self.config.max_adjustment);

            Ok(InflationAdjustment {
                emission_adjustment: -adjustment_magnitude,
                burn_adjustment: adjustment_magnitude.max(0.0),
                confidence: 0.8,
                reasoning: format!("Inflation rate {:.2}% deviates from target {:.2}%", 
                                  metrics.current_rate, self.config.target_rate),
            })
        } else {
            Ok(InflationAdjustment {
                emission_adjustment: 0.0,
                burn_adjustment: 0.0,
                confidence: 0.9,
                reasoning: "Inflation rate within target band".to_string(),
            })
        }
    }

    pub async fn get_statistics(&self) -> InflationStatistics {
        let average_rate = if self.inflation_history.is_empty() {
            self.config.target_rate
        } else {
            self.inflation_history.iter().sum::<f64>() / self.inflation_history.len() as f64
        };

        let target_adherence = if self.inflation_history.is_empty() {
            1.0
        } else {
            let in_band_count = self.inflation_history.iter()
                .filter(|&&rate| (rate - self.config.target_rate).abs() <= self.config.tolerance_band)
                .count();
            in_band_count as f64 / self.inflation_history.len() as f64
        };

        InflationStatistics {
            average_rate,
            target_adherence,
            adjustment_frequency: 0,
        }
    }
}