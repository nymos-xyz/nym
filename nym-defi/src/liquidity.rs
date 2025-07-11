//! Privacy-preserving liquidity provision

use serde::{Serialize, Deserialize};

/// Liquidity provider
#[derive(Debug, Clone)]
pub struct LiquidityProvider {
    pub provider_id: String,
}

/// Liquidity pool
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LiquidityPool {
    pub pool_id: String,
    pub assets: Vec<String>,
}

/// Private liquidity
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateLiquidity {
    pub position_id: String,
    pub pool_id: String,
}

impl LiquidityProvider {
    pub fn new(provider_id: String) -> Self {
        Self { provider_id }
    }
}

impl LiquidityPool {
    pub fn new(pool_id: String, assets: Vec<String>) -> Self {
        Self { pool_id, assets }
    }
}

impl PrivateLiquidity {
    pub fn new(position_id: String, pool_id: String) -> Self {
        Self { position_id, pool_id }
    }
}