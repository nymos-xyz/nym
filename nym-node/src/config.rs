use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::net::SocketAddr;
use crate::error::{NodeError, Result};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeConfig {
    // Node identity
    pub node_id: Option<String>,
    pub quid_identity_path: Option<PathBuf>,
    
    // Network configuration
    pub network: NetworkConfig,
    
    // Storage configuration
    pub storage: StorageConfig,
    
    // Consensus configuration
    pub consensus: ConsensusConfig,
    
    // RPC configuration
    pub rpc: RpcConfig,
    
    // Compute configuration
    pub compute: ComputeConfig,
    
    // Economics configuration
    pub economics: EconomicsConfig,
    
    // Logging configuration
    pub logging: LoggingConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub listen_addr: SocketAddr,
    pub bootstrap_peers: Vec<String>,
    pub max_peers: usize,
    pub enable_privacy_routing: bool,
    pub mix_strategy: String,
    pub cover_traffic_rate: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StorageConfig {
    pub data_dir: PathBuf,
    pub max_storage_gb: u64,
    pub enable_pruning: bool,
    pub pruning_interval_hours: u64,
    pub enable_archival: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub consensus_type: ConsensusType,
    pub pow_enabled: bool,
    pub pos_enabled: bool,
    pub pow_weight: f64,
    pub pos_weight: f64,
    pub block_time_seconds: u64,
    pub finality_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ConsensusType {
    PoW,
    PoS,
    Hybrid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RpcConfig {
    pub enabled: bool,
    pub listen_addr: SocketAddr,
    pub max_connections: usize,
    pub auth_enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeConfig {
    pub enabled: bool,
    pub max_jobs: usize,
    pub supported_runtimes: Vec<String>,
    pub resource_limits: ResourceLimits,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_mb: u64,
    pub max_cpu_cores: u32,
    pub max_execution_time_seconds: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EconomicsConfig {
    pub enable_adaptive_emissions: bool,
    pub enable_fee_burning: bool,
    pub min_stake_amount: u64,
    pub validator_reward_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    pub level: String,
    pub format: String,
    pub file_path: Option<PathBuf>,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            node_id: None,
            quid_identity_path: None,
            
            network: NetworkConfig {
                listen_addr: "0.0.0.0:30333".parse().unwrap(),
                bootstrap_peers: vec![],
                max_peers: 50,
                enable_privacy_routing: true,
                mix_strategy: "random_delay".to_string(),
                cover_traffic_rate: 0.1,
            },
            
            storage: StorageConfig {
                data_dir: dirs::data_dir()
                    .unwrap_or_else(|| PathBuf::from("."))
                    .join("nym-node"),
                max_storage_gb: 100,
                enable_pruning: true,
                pruning_interval_hours: 24,
                enable_archival: false,
            },
            
            consensus: ConsensusConfig {
                consensus_type: ConsensusType::Hybrid,
                pow_enabled: true,
                pos_enabled: true,
                pow_weight: 0.5,
                pos_weight: 0.5,
                block_time_seconds: 120,
                finality_threshold: 67,
            },
            
            rpc: RpcConfig {
                enabled: true,
                listen_addr: "127.0.0.1:9933".parse().unwrap(),
                max_connections: 100,
                auth_enabled: true,
            },
            
            compute: ComputeConfig {
                enabled: true,
                max_jobs: 10,
                supported_runtimes: vec!["wasm".to_string(), "docker".to_string()],
                resource_limits: ResourceLimits {
                    max_memory_mb: 4096,
                    max_cpu_cores: 2,
                    max_execution_time_seconds: 3600,
                },
            },
            
            economics: EconomicsConfig {
                enable_adaptive_emissions: true,
                enable_fee_burning: true,
                min_stake_amount: 1000,
                validator_reward_percentage: 0.05,
            },
            
            logging: LoggingConfig {
                level: "info".to_string(),
                format: "pretty".to_string(),
                file_path: None,
            },
        }
    }
}

impl NodeConfig {
    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let config: NodeConfig = toml::from_str(&content)?;
        config.validate()?;
        Ok(config)
    }
    
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let content = toml::to_string_pretty(self)?;
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(path, content)?;
        Ok(())
    }
    
    pub fn validate(&self) -> Result<()> {
        // Validate consensus weights
        if self.consensus.pow_weight + self.consensus.pos_weight != 1.0 {
            return Err(NodeError::Config(
                "PoW and PoS weights must sum to 1.0".to_string()
            ));
        }
        
        // Validate finality threshold
        if self.consensus.finality_threshold < 51 || self.consensus.finality_threshold > 100 {
            return Err(NodeError::Config(
                "Finality threshold must be between 51 and 100".to_string()
            ));
        }
        
        // Validate storage
        if self.storage.max_storage_gb < 10 {
            return Err(NodeError::Config(
                "Minimum storage requirement is 10GB".to_string()
            ));
        }
        
        Ok(())
    }
    
    pub fn set_test_config(&mut self) {
        self.consensus.block_time_seconds = 5; // Faster blocks for testing
        self.storage.max_storage_gb = 1; // Lower storage for testing
        self.network.max_peers = 10; // Fewer peers for testing
    }
}