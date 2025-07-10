pub mod cli;
pub mod config;
pub mod error;
pub mod genesis;
pub mod node;
pub mod rpc;
pub mod state;
pub mod light_client;
pub mod mobile_interface;
pub mod hardware_wallet;
pub mod security_audit;
pub mod vulnerability_scanner;
pub mod bug_bounty;
pub mod penetration_testing;
pub mod performance_optimizer;

pub use config::NodeConfig;
pub use error::{NodeError, Result};
pub use genesis::GenesisBlock;
pub use node::NymNode;
pub use light_client::LightClient;
pub use mobile_interface::MobileInterface;
pub use hardware_wallet::HardwareWallet;
pub use security_audit::SecurityAudit;
pub use vulnerability_scanner::VulnerabilityScanner;
pub use bug_bounty::BugBountyProgram;
pub use penetration_testing::PenetrationTestingFramework;
pub use performance_optimizer::PerformanceOptimizer;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_creation() {
        // Test will be implemented after node structure is complete
    }
}