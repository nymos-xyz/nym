//! Economics system error types

use thiserror::Error;

/// Result type for economics operations
pub type EconomicsResult<T> = Result<T, EconomicsError>;

/// Economics system errors
#[derive(Error, Debug, Clone)]
pub enum EconomicsError {
    #[error("Invalid configuration: {0}")]
    InvalidConfiguration(String),
    
    #[error("Calculation error: {0}")]
    CalculationError(String),
    
    #[error("Insufficient data for analysis: {0}")]
    InsufficientData(String),
    
    #[error("Network health critical: {0}")]
    NetworkHealthCritical(String),
    
    #[error("Emergency protocol activated: {0}")]
    EmergencyProtocol(String),
    
    #[error("Fee market dysfunction: {0}")]
    FeeMarketDysfunction(String),
    
    #[error("Inflation out of bounds: current={current}%, safe_range=({min}%, {max}%)")]
    InflationOutOfBounds { current: f64, min: f64, max: f64 },
    
    #[error("Security budget insufficient: required={required}, available={available}")]
    SecurityBudgetInsufficient { required: u64, available: u64 },
    
    #[error("Economic allocation failed: {reason}")]
    AllocationFailed { reason: String },
    
    #[error("Serialization error: {0}")]
    SerializationError(String),
    
    #[error("Internal error: {0}")]
    Internal(String),
}