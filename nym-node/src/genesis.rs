use crate::error::{NodeError, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use std::collections::HashMap;
use chrono::{DateTime, Utc};
use sha3::{Digest, Sha3_256};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisBlock {
    pub chain_id: String,
    pub genesis_time: DateTime<Utc>,
    pub initial_validators: Vec<GenesisValidator>,
    pub initial_balances: HashMap<String, u64>,
    pub consensus_params: GenesisConsensusParams,
    pub app_state: GenesisAppState,
    pub hash: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidator {
    pub address: String,
    pub public_key: String,
    pub voting_power: u64,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConsensusParams {
    pub block_time_seconds: u64,
    pub max_block_size: u64,
    pub max_transactions_per_block: u64,
    pub pow_weight: f64,
    pub pos_weight: f64,
    pub finality_threshold: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisAppState {
    pub total_supply: u64,
    pub initial_emission_rate: f64,
    pub min_stake_amount: u64,
    pub validator_reward_percentage: f64,
    pub network_version: u32,
}

impl Default for GenesisConsensusParams {
    fn default() -> Self {
        Self {
            block_time_seconds: 120,
            max_block_size: 1024 * 1024, // 1MB
            max_transactions_per_block: 1000,
            pow_weight: 0.5,
            pos_weight: 0.5,
            finality_threshold: 67,
        }
    }
}

impl Default for GenesisAppState {
    fn default() -> Self {
        Self {
            total_supply: 1_000_000_000, // 1 billion NYM tokens
            initial_emission_rate: 0.05, // 5% annual
            min_stake_amount: 1000,
            validator_reward_percentage: 0.05,
            network_version: 1,
        }
    }
}

impl GenesisBlock {
    pub fn new(
        chain_id: String,
        initial_validators: Vec<GenesisValidator>,
        initial_balances: HashMap<String, u64>,
    ) -> Self {
        let mut genesis = Self {
            chain_id,
            genesis_time: Utc::now(),
            initial_validators,
            initial_balances,
            consensus_params: GenesisConsensusParams::default(),
            app_state: GenesisAppState::default(),
            hash: String::new(),
        };
        
        // Calculate genesis hash
        genesis.hash = genesis.calculate_hash();
        genesis
    }
    
    pub fn create_testnet(chain_id: String) -> Self {
        // Create default test validators
        let validators = vec![
            GenesisValidator {
                address: "nym1test1validator000000000000000000000001".to_string(),
                public_key: "nympub1test1validator00000000000000000000001".to_string(),
                voting_power: 100,
                name: "Test Validator 1".to_string(),
            },
            GenesisValidator {
                address: "nym1test2validator000000000000000000000002".to_string(),
                public_key: "nympub1test2validator00000000000000000000002".to_string(),
                voting_power: 100,
                name: "Test Validator 2".to_string(),
            },
            GenesisValidator {
                address: "nym1test3validator000000000000000000000003".to_string(),
                public_key: "nympub1test3validator00000000000000000000003".to_string(),
                voting_power: 100,
                name: "Test Validator 3".to_string(),
            },
        ];
        
        // Create initial balances for validators and test accounts
        let mut balances = HashMap::new();
        
        // Give validators initial stakes
        for validator in &validators {
            balances.insert(validator.address.clone(), 1_000_000); // 1M NYM each
        }
        
        // Add some test accounts
        balances.insert("nym1testuser1000000000000000000000000001".to_string(), 100_000);
        balances.insert("nym1testuser2000000000000000000000000002".to_string(), 100_000);
        balances.insert("nym1testuser3000000000000000000000000003".to_string(), 100_000);
        
        Self::new(chain_id, validators, balances)
    }
    
    pub fn create_mainnet(chain_id: String) -> Self {
        // Initial mainnet validators (placeholder addresses)
        let validators = vec![
            GenesisValidator {
                address: "nym1mainnetvalidator1000000000000000001".to_string(),
                public_key: "nympubmainnetvalidator1000000000000000001".to_string(),
                voting_power: 1000,
                name: "Genesis Validator 1".to_string(),
            },
            GenesisValidator {
                address: "nym1mainnetvalidator1000000000000000002".to_string(),
                public_key: "nympubmainnetvalidator1000000000000000002".to_string(),
                voting_power: 1000,
                name: "Genesis Validator 2".to_string(),
            },
            GenesisValidator {
                address: "nym1mainnetvalidator1000000000000000003".to_string(),
                public_key: "nympubmainnetvalidator1000000000000000003".to_string(),
                voting_power: 1000,
                name: "Genesis Validator 3".to_string(),
            },
            GenesisValidator {
                address: "nym1mainnetvalidator1000000000000000004".to_string(),
                public_key: "nympubmainnetvalidator1000000000000000004".to_string(),
                voting_power: 1000,
                name: "Genesis Validator 4".to_string(),
            },
            GenesisValidator {
                address: "nym1mainnetvalidator1000000000000000005".to_string(),
                public_key: "nympubmainnetvalidator1000000000000000005".to_string(),
                voting_power: 1000,
                name: "Genesis Validator 5".to_string(),
            },
        ];
        
        // Initial token distribution for mainnet
        let mut balances = HashMap::new();
        
        // Genesis validators get initial stakes
        for validator in &validators {
            balances.insert(validator.address.clone(), 50_000_000); // 50M NYM each
        }
        
        // Foundation allocation
        balances.insert("nym1foundation00000000000000000000000001".to_string(), 2_000_000_000); // 2B NYM
        
        // Development fund
        balances.insert("nym1development0000000000000000000001".to_string(), 1_000_000_000); // 1B NYM
        
        // Ecosystem fund
        balances.insert("nym1ecosystem000000000000000000000001".to_string(), 500_000_000); // 500M NYM
        
        // Community treasury
        balances.insert("nym1treasury000000000000000000000001".to_string(), 300_000_000); // 300M NYM
        
        let mut genesis = Self::new(chain_id, validators, balances);
        
        // Mainnet-specific parameters
        genesis.consensus_params.block_time_seconds = 60; // 1 minute blocks
        genesis.consensus_params.max_block_size = 2 * 1024 * 1024; // 2MB blocks
        genesis.consensus_params.max_transactions_per_block = 5000; // Higher TPS
        genesis.app_state.total_supply = 10_000_000_000; // 10 billion NYM
        genesis.app_state.initial_emission_rate = 0.02; // 2% annual
        genesis.app_state.min_stake_amount = 10000; // Higher minimum stake
        genesis.app_state.validator_reward_percentage = 0.03; // 3% validator rewards
        
        // Recalculate hash after parameter changes
        genesis.hash = genesis.calculate_hash();
        genesis
    }
    
    pub fn parse_validators(validators_str: &str) -> Result<Vec<GenesisValidator>> {
        let mut validators = Vec::new();
        
        for (i, validator_info) in validators_str.split(',').enumerate() {
            let parts: Vec<&str> = validator_info.trim().split(':').collect();
            if parts.len() < 2 {
                return Err(NodeError::Config(
                    format!("Invalid validator format: {}", validator_info)
                ));
            }
            
            let address = parts[0].to_string();
            let voting_power: u64 = parts[1].parse()
                .map_err(|_| NodeError::Config(
                    format!("Invalid voting power: {}", parts[1])
                ))?;
            
            validators.push(GenesisValidator {
                address: address.clone(),
                public_key: format!("nympub{}", &address[4..]), // Derive pubkey from address
                voting_power,
                name: format!("Validator {}", i + 1),
            });
        }
        
        Ok(validators)
    }
    
    pub fn parse_balances(balances_str: &str) -> Result<HashMap<String, u64>> {
        let mut balances = HashMap::new();
        
        for balance_info in balances_str.split(',') {
            let parts: Vec<&str> = balance_info.trim().split(':').collect();
            if parts.len() != 2 {
                return Err(NodeError::Config(
                    format!("Invalid balance format: {}", balance_info)
                ));
            }
            
            let address = parts[0].to_string();
            let amount: u64 = parts[1].parse()
                .map_err(|_| NodeError::Config(
                    format!("Invalid balance amount: {}", parts[1])
                ))?;
            
            balances.insert(address, amount);
        }
        
        Ok(balances)
    }
    
    pub fn save(&self, path: &PathBuf) -> Result<()> {
        let content = serde_json::to_string_pretty(self)?;
        std::fs::create_dir_all(path.parent().unwrap())?;
        std::fs::write(path, content)?;
        Ok(())
    }
    
    pub fn load(path: &PathBuf) -> Result<Self> {
        let content = std::fs::read_to_string(path)?;
        let genesis: GenesisBlock = serde_json::from_str(&content)?;
        Ok(genesis)
    }
    
    pub fn validate(&self) -> Result<()> {
        // Validate chain ID
        if self.chain_id.is_empty() {
            return Err(NodeError::InvalidGenesis);
        }
        
        // Validate validators
        if self.initial_validators.is_empty() {
            return Err(NodeError::Config("Genesis must have at least one validator".to_string()));
        }
        
        // Validate consensus parameters
        if self.consensus_params.pow_weight + self.consensus_params.pos_weight != 1.0 {
            return Err(NodeError::Config("PoW and PoS weights must sum to 1.0".to_string()));
        }
        
        if self.consensus_params.finality_threshold < 51 || self.consensus_params.finality_threshold > 100 {
            return Err(NodeError::Config("Finality threshold must be between 51 and 100".to_string()));
        }
        
        // Validate total supply matches balances
        let total_balances: u64 = self.initial_balances.values().sum();
        if total_balances > self.app_state.total_supply {
            return Err(NodeError::Config("Initial balances exceed total supply".to_string()));
        }
        
        // Validate hash
        if self.hash != self.calculate_hash() {
            return Err(NodeError::InvalidGenesis);
        }
        
        Ok(())
    }
    
    fn calculate_hash(&self) -> String {
        let mut hasher = Sha3_256::new();
        
        // Hash all the essential genesis data
        hasher.update(self.chain_id.as_bytes());
        hasher.update(self.genesis_time.to_rfc3339().as_bytes());
        
        // Hash validators
        for validator in &self.initial_validators {
            hasher.update(validator.address.as_bytes());
            hasher.update(validator.public_key.as_bytes());
            hasher.update(&validator.voting_power.to_le_bytes());
        }
        
        // Hash balances
        let mut sorted_balances: Vec<_> = self.initial_balances.iter().collect();
        sorted_balances.sort_by_key(|(addr, _)| *addr);
        for (address, amount) in sorted_balances {
            hasher.update(address.as_bytes());
            hasher.update(&amount.to_le_bytes());
        }
        
        // Hash consensus params
        hasher.update(&self.consensus_params.block_time_seconds.to_le_bytes());
        hasher.update(&self.consensus_params.max_block_size.to_le_bytes());
        hasher.update(&self.consensus_params.pow_weight.to_le_bytes());
        hasher.update(&self.consensus_params.pos_weight.to_le_bytes());
        hasher.update(&self.consensus_params.finality_threshold.to_le_bytes());
        
        // Hash app state
        hasher.update(&self.app_state.total_supply.to_le_bytes());
        hasher.update(&self.app_state.initial_emission_rate.to_le_bytes());
        hasher.update(&self.app_state.min_stake_amount.to_le_bytes());
        hasher.update(&self.app_state.validator_reward_percentage.to_le_bytes());
        hasher.update(&self.app_state.network_version.to_le_bytes());
        
        hex::encode(hasher.finalize())
    }
    
    pub fn get_info(&self) -> String {
        format!(
            "Genesis Block Information:\n\
            Chain ID: {}\n\
            Genesis Time: {}\n\
            Validators: {}\n\
            Total Initial Supply: {} NYM\n\
            Total Allocated: {} NYM\n\
            Block Time: {} seconds\n\
            Consensus: {}% PoW, {}% PoS\n\
            Hash: {}",
            self.chain_id,
            self.genesis_time.format("%Y-%m-%d %H:%M:%S UTC"),
            self.initial_validators.len(),
            self.app_state.total_supply,
            self.initial_balances.values().sum::<u64>(),
            self.consensus_params.block_time_seconds,
            (self.consensus_params.pow_weight * 100.0) as u32,
            (self.consensus_params.pos_weight * 100.0) as u32,
            &self.hash[..16]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[test]
    fn test_genesis_creation() {
        let genesis = GenesisBlock::create_testnet("nym-test".to_string());
        assert_eq!(genesis.chain_id, "nym-test");
        assert_eq!(genesis.initial_validators.len(), 3);
        assert!(!genesis.hash.is_empty());
        assert!(genesis.validate().is_ok());
    }
    
    #[test]
    fn test_genesis_save_load() {
        let temp_dir = TempDir::new().unwrap();
        let genesis_path = temp_dir.path().join("genesis.json");
        
        let original = GenesisBlock::create_testnet("nym-test".to_string());
        original.save(&genesis_path).unwrap();
        
        let loaded = GenesisBlock::load(&genesis_path).unwrap();
        assert_eq!(original.chain_id, loaded.chain_id);
        assert_eq!(original.hash, loaded.hash);
    }
    
    #[test]
    fn test_validator_parsing() {
        let validators_str = "nym1addr1:100,nym1addr2:200,nym1addr3:150";
        let validators = GenesisBlock::parse_validators(validators_str).unwrap();
        
        assert_eq!(validators.len(), 3);
        assert_eq!(validators[0].address, "nym1addr1");
        assert_eq!(validators[0].voting_power, 100);
        assert_eq!(validators[1].voting_power, 200);
    }
    
    #[test]
    fn test_balance_parsing() {
        let balances_str = "nym1addr1:1000000,nym1addr2:2000000";
        let balances = GenesisBlock::parse_balances(balances_str).unwrap();
        
        assert_eq!(balances.len(), 2);
        assert_eq!(balances["nym1addr1"], 1000000);
        assert_eq!(balances["nym1addr2"], 2000000);
    }
}