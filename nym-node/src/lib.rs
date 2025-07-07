pub mod cli;
pub mod config;
pub mod error;
pub mod genesis;
pub mod node;
pub mod rpc;
pub mod state;

pub use config::NodeConfig;
pub use error::{NodeError, Result};
pub use genesis::GenesisBlock;
pub use node::NymNode;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_node_creation() {
        // Test will be implemented after node structure is complete
    }
}