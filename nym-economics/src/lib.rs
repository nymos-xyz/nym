//! # Nym Economics
//! 
//! Economic protocol implementation for the Nym blockchain including:
//! - Adaptive tail emissions system
//! - Dynamic economic allocation
//! - Fee market analysis and optimization
//! - Inflation targeting and economic sustainability

pub mod error;
pub mod adaptive_emissions;
pub mod economic_allocation;
pub mod dynamic_allocation;
pub mod fee_market;
pub mod inflation_targeting;
pub mod integrated_economics;

pub use error::{EconomicsError, EconomicsResult};
pub use adaptive_emissions::{
    AdaptiveEmissionsSystem, AdaptiveEmissionsConfig, NetworkHealthMetrics,
    EmissionCalculation, EmissionStatistics, FeeMarketAnalysis, SecurityBudgetAnalysis
};
pub use economic_allocation::{
    EconomicAllocationManager, AllocationConfig, AllocationStrategy,
    AllocationResult, AllocationStatistics
};
pub use dynamic_allocation::{
    DynamicAllocationManager, DynamicAllocationConfig, DynamicAllocationResult,
    AllocationDistribution, PriorityWeights, NetworkPerformanceMetrics,
    AllocationAdjustment, AllocationStatistics as DynamicAllocationStatistics
};
pub use fee_market::{
    FeeMarketManager, FeeMarketConfig, FeeMarketMetrics,
    FeeRecommendation, FeeMarketStatistics
};
pub use inflation_targeting::{
    InflationTargetingSystem, InflationConfig, InflationMetrics,
    InflationAdjustment, InflationStatistics
};
pub use integrated_economics::{
    IntegratedEconomicsSystem, IntegratedEconomicsConfig, BlockEconomicState,
    EconomicHealthAssessment, IntegratedEconomicsStatistics
};

/// Protocol version for compatibility
pub const ECONOMICS_PROTOCOL_VERSION: u32 = 1;

/// Maximum safe inflation rate (annual percentage)
pub const MAX_SAFE_INFLATION: f64 = 10.0;

/// Minimum safe inflation rate (annual percentage)  
pub const MIN_SAFE_INFLATION: f64 = -2.0; // Allow slight deflation

/// Default block time target (seconds)
pub const DEFAULT_BLOCK_TIME: u64 = 120;

/// Default adjustment window (blocks)
pub const DEFAULT_ADJUSTMENT_WINDOW: u64 = 1440;