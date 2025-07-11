//! Nym DeFi - Privacy-preserving DeFi infrastructure
//! 
//! This module provides DeFi protocols with privacy guarantees:
//! - Anonymous automated market makers (AMMs)
//! - Private lending and borrowing platforms
//! - Cross-chain privacy operations
//! - Privacy-preserving liquidity provision

pub mod error;
pub mod amm;
pub mod lending;
pub mod cross_chain;
pub mod liquidity;

pub use error::{DeFiError, DeFiResult};
pub use amm::{PrivacyAMM, AMMPool, PrivateSwap, SwapProof};
pub use lending::{PrivateLendingProtocol, LendingPool, CollateralManager};
pub use cross_chain::{CrossChainBridge, PrivacyBridge, AtomicSwap};
pub use liquidity::{LiquidityProvider, LiquidityPool, PrivateLiquidity};

/// DeFi protocol version
pub const DEFI_VERSION: &str = "0.1.0";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_version() {
        assert_eq!(DEFI_VERSION, "0.1.0");
    }
}