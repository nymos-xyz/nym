//! Cross-chain privacy operations

use serde::{Serialize, Deserialize};

/// Cross-chain bridge
#[derive(Debug, Clone)]
pub struct CrossChainBridge {
    pub bridge_id: String,
}

/// Privacy bridge
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyBridge {
    pub bridge_id: String,
    pub source_chain: String,
    pub target_chain: String,
}

/// Atomic swap
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AtomicSwap {
    pub swap_id: String,
    pub asset_a: String,
    pub asset_b: String,
}

impl CrossChainBridge {
    pub fn new(bridge_id: String) -> Self {
        Self { bridge_id }
    }
}

impl PrivacyBridge {
    pub fn new(bridge_id: String, source_chain: String, target_chain: String) -> Self {
        Self { bridge_id, source_chain, target_chain }
    }
}

impl AtomicSwap {
    pub fn new(swap_id: String, asset_a: String, asset_b: String) -> Self {
        Self { swap_id, asset_a, asset_b }
    }
}