//! Error types for DeFi operations

use thiserror::Error;

/// DeFi operation errors
#[derive(Error, Debug, Clone, PartialEq)]
pub enum DeFiError {
    #[error("Insufficient liquidity: {0}")]
    InsufficientLiquidity(String),
    
    #[error("Invalid swap parameters: {0}")]
    InvalidSwapParameters(String),
    
    #[error("Slippage tolerance exceeded: expected {expected}, got {actual}")]
    SlippageExceeded { expected: f64, actual: f64 },
    
    #[error("Insufficient collateral: required {required}, provided {provided}")]
    InsufficientCollateral { required: u64, provided: u64 },
    
    #[error("Liquidation threshold breached: ratio {ratio}")]
    LiquidationThreshold { ratio: f64 },
    
    #[error("Cross-chain bridge error: {0}")]
    CrossChainError(String),
    
    #[error("Privacy proof verification failed: {0}")]
    PrivacyProofFailed(String),
    
    #[error("Pool not found: {pool_id}")]
    PoolNotFound { pool_id: String },
    
    #[error("Unauthorized operation: {0}")]
    Unauthorized(String),
    
    #[error("Invalid price oracle data: {0}")]
    InvalidPriceOracle(String),
    
    #[error("Smart contract execution failed: {0}")]
    ContractExecutionFailed(String),
    
    #[error("Cryptographic error: {0}")]
    CryptoError(String),
    
    #[error("Network error: {0}")]
    NetworkError(String),
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
}

/// Result type for DeFi operations
pub type DeFiResult<T> = Result<T, DeFiError>;

impl From<nym_crypto::CryptoError> for DeFiError {
    fn from(err: nym_crypto::CryptoError) -> Self {
        DeFiError::CryptoError(err.to_string())
    }
}