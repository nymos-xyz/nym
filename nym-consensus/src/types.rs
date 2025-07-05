use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};
use nym_core::{NymIdentity, Transaction};
use nym_crypto::Hash256;
use std::collections::HashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
    pub consensus_data: ConsensusData,
    pub size: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BlockHeader {
    pub version: u32,
    pub height: u64,
    pub previous_hash: Hash256,
    pub merkle_root: Hash256,
    pub timestamp: DateTime<Utc>,
    pub difficulty_target: u64,
    pub nonce: u64,
    pub validator_signature: Option<Vec<u8>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusData {
    pub pow_proof: Option<ProofOfWorkData>,
    pub pos_proof: Option<ProofOfStakeData>,
    pub validator_votes: Vec<ValidatorVote>,
    pub finality_signatures: Vec<FinalitySignature>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfWorkData {
    pub algorithm: String,
    pub work_hash: Hash256,
    pub difficulty: u64,
    pub mining_time: u64,
    pub miner_identity: NymIdentity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProofOfStakeData {
    pub validator_id: NymIdentity,
    pub stake_amount: u64,
    pub selection_proof: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorVote {
    pub validator_id: NymIdentity,
    pub block_hash: Hash256,
    pub vote_type: VoteType,
    pub signature: Vec<u8>,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VoteType {
    Prevote,
    Precommit,
    Finalize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FinalitySignature {
    pub validator_id: NymIdentity,
    pub block_hash: Hash256,
    pub signature: Vec<u8>,
    pub stake_weight: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    pub is_valid: bool,
    pub pow_valid: bool,
    pub pos_valid: bool,
    pub validator_consensus: bool,
    pub finality_achieved: bool,
    pub error_message: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningResult {
    pub success: bool,
    pub block_hash: Option<Hash256>,
    pub nonce: u64,
    pub mining_time: u64,
    pub hash_rate: f64,
    pub difficulty_met: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StakeInfo {
    pub validator_id: NymIdentity,
    pub staked_amount: u64,
    pub delegation_count: u32,
    pub performance_score: f64,
    pub last_active: DateTime<Utc>,
    pub slashing_history: Vec<SlashingEvent>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlashingEvent {
    pub event_type: SlashingType,
    pub amount_slashed: u64,
    pub reason: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashingType {
    DoubleSign,
    Downtime,
    InvalidBehavior,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ValidatorInfo {
    pub identity: NymIdentity,
    pub stake_amount: u64,
    pub commission_rate: f64,
    pub uptime_percentage: f64,
    pub blocks_validated: u64,
    pub last_active: DateTime<Utc>,
    pub reputation_score: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusState {
    pub current_height: u64,
    pub latest_block_hash: Hash256,
    pub difficulty_target: u64,
    pub total_stake: u64,
    pub active_validators: u32,
    pub network_hash_rate: f64,
    pub finalized_height: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkMetrics {
    pub block_time: f64,
    pub transaction_throughput: f64,
    pub network_security: f64,
    pub decentralization_coefficient: f64,
    pub energy_efficiency: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsensusConfig {
    pub pow_weight: f64,
    pub pos_weight: f64,
    pub min_validators: u32,
    pub max_validators: u32,
    pub block_time_target: u64,
    pub difficulty_adjustment_period: u64,
    pub finality_threshold: f64,
}

impl Block {
    pub fn new(
        height: u64,
        previous_hash: Hash256,
        transactions: Vec<Transaction>,
        consensus_data: ConsensusData,
    ) -> Self {
        let merkle_root = Self::calculate_merkle_root(&transactions);
        let size = bincode::serialize(&transactions).unwrap_or_default().len();
        
        let header = BlockHeader {
            version: 1,
            height,
            previous_hash,
            merkle_root,
            timestamp: Utc::now(),
            difficulty_target: 0,
            nonce: 0,
            validator_signature: None,
        };

        Self {
            header,
            transactions,
            consensus_data,
            size,
        }
    }

    pub fn hash(&self) -> Hash256 {
        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        if let Ok(data) = bincode::serialize(&self.header) {
            hasher.update(&data);
        }
        Hash256::from_bytes(hasher.finalize().as_slice())
    }

    fn calculate_merkle_root(transactions: &[Transaction]) -> Hash256 {
        if transactions.is_empty() {
            return Hash256::default();
        }

        use sha3::{Digest, Sha3_256};
        let mut hasher = Sha3_256::new();
        for tx in transactions {
            if let Ok(tx_data) = bincode::serialize(tx) {
                hasher.update(&tx_data);
            }
        }
        Hash256::from_bytes(hasher.finalize().as_slice())
    }

    pub fn verify_merkle_root(&self) -> bool {
        let calculated_root = Self::calculate_merkle_root(&self.transactions);
        calculated_root == self.header.merkle_root
    }

    pub fn is_genesis(&self) -> bool {
        self.header.height == 0
    }

    pub fn transaction_count(&self) -> usize {
        self.transactions.len()
    }
}

impl ConsensusData {
    pub fn new() -> Self {
        Self {
            pow_proof: None,
            pos_proof: None,
            validator_votes: Vec::new(),
            finality_signatures: Vec::new(),
        }
    }

    pub fn has_pow_proof(&self) -> bool {
        self.pow_proof.is_some()
    }

    pub fn has_pos_proof(&self) -> bool {
        self.pos_proof.is_some()
    }

    pub fn validator_vote_count(&self) -> usize {
        self.validator_votes.len()
    }

    pub fn finality_signature_count(&self) -> usize {
        self.finality_signatures.len()
    }
}

impl Default for ConsensusData {
    fn default() -> Self {
        Self::new()
    }
}