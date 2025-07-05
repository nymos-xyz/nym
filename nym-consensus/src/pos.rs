use crate::{
    error::{ConsensusError, ConsensusResult},
    types::{
        Block, ProofOfStakeData, ValidationResult, StakeInfo, ValidatorInfo, 
        ValidatorVote, FinalitySignature, VoteType, SlashingEvent, SlashingType
    },
};
use nym_core::NymIdentity;
use nym_crypto::Hash256;

use std::collections::{HashMap, BTreeMap};
use std::sync::Arc;
use std::time::{Duration, SystemTime};
use tokio::sync::RwLock;
use tracing::{info, debug, warn, error};
use serde::{Deserialize, Serialize};
use rand::{thread_rng, Rng};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PosConfig {
    pub min_stake: u64,
    pub max_validators: u32,
    pub validator_rotation_period: u64,
    pub slashing_percentage: f64,
    pub reward_percentage: f64,
    pub finality_threshold: f64, // 2/3 supermajority
    pub validator_session_duration: Duration,
    pub unbonding_period: Duration,
}

impl Default for PosConfig {
    fn default() -> Self {
        Self {
            min_stake: 10_000_000, // 10M NYM tokens
            max_validators: 100,
            validator_rotation_period: 720, // ~1 day worth of blocks
            slashing_percentage: 0.05, // 5% slashing
            reward_percentage: 0.10, // 10% annual reward
            finality_threshold: 0.67, // 67% for finality
            validator_session_duration: Duration::from_secs(86400), // 1 day
            unbonding_period: Duration::from_secs(1814400), // 21 days
        }
    }
}

pub struct ProofOfStake {
    config: PosConfig,
    stake_manager: Arc<RwLock<StakeManager>>,
    validator_set: Arc<RwLock<ValidatorSet>>,
    voting_state: Arc<RwLock<VotingState>>,
}

#[derive(Debug)]
pub struct StakeManager {
    stakes: HashMap<NymIdentity, StakeInfo>,
    delegations: HashMap<NymIdentity, Vec<Delegation>>,
    total_stake: u64,
    pending_unbondings: Vec<UnbondingEntry>,
}

#[derive(Debug, Clone)]
pub struct Delegation {
    pub delegator: NymIdentity,
    pub validator: NymIdentity,
    pub amount: u64,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone)]
pub struct UnbondingEntry {
    pub delegator: NymIdentity,
    pub validator: NymIdentity,
    pub amount: u64,
    pub completion_time: DateTime<Utc>,
}

#[derive(Debug)]
pub struct ValidatorSet {
    active_validators: BTreeMap<NymIdentity, ValidatorInfo>,
    candidate_validators: HashMap<NymIdentity, ValidatorInfo>,
    proposer_schedule: Vec<NymIdentity>,
    current_proposer_index: usize,
}

#[derive(Debug)]
pub struct VotingState {
    current_round: u64,
    votes: HashMap<Hash256, Vec<ValidatorVote>>,
    finality_signatures: HashMap<Hash256, Vec<FinalitySignature>>,
    vote_deadlines: HashMap<Hash256, DateTime<Utc>>,
}

impl StakeManager {
    pub fn new() -> Self {
        Self {
            stakes: HashMap::new(),
            delegations: HashMap::new(),
            total_stake: 0,
            pending_unbondings: Vec::new(),
        }
    }

    pub fn add_stake(&mut self, validator: NymIdentity, amount: u64) -> ConsensusResult<()> {
        let stake_info = self.stakes.entry(validator.clone()).or_insert_with(|| StakeInfo {
            validator_id: validator.clone(),
            staked_amount: 0,
            delegation_count: 0,
            performance_score: 1.0,
            last_active: Utc::now(),
            slashing_history: Vec::new(),
        });

        stake_info.staked_amount += amount;
        self.total_stake += amount;

        info!("Added stake: validator={}, amount={}, total={}", 
              validator.to_string(), amount, stake_info.staked_amount);

        Ok(())
    }

    pub fn delegate_stake(
        &mut self,
        delegator: NymIdentity,
        validator: NymIdentity,
        amount: u64,
    ) -> ConsensusResult<()> {
        if !self.stakes.contains_key(&validator) {
            return Err(ConsensusError::StakeError(
                "Validator not found".to_string()
            ));
        }

        let delegation = Delegation {
            delegator: delegator.clone(),
            validator: validator.clone(),
            amount,
            timestamp: Utc::now(),
        };

        self.delegations.entry(validator.clone()).or_default().push(delegation);

        if let Some(stake_info) = self.stakes.get_mut(&validator) {
            stake_info.staked_amount += amount;
            stake_info.delegation_count += 1;
        }

        self.total_stake += amount;

        info!("Delegated stake: delegator={}, validator={}, amount={}", 
              delegator.to_string(), validator.to_string(), amount);

        Ok(())
    }

    pub fn slash_validator(&mut self, validator: &NymIdentity, reason: String, percentage: f64) -> ConsensusResult<u64> {
        let stake_info = self.stakes.get_mut(validator)
            .ok_or_else(|| ConsensusError::StakeError("Validator not found".to_string()))?;

        let slash_amount = (stake_info.staked_amount as f64 * percentage) as u64;
        
        if slash_amount > stake_info.staked_amount {
            return Err(ConsensusError::StakeError(
                "Slash amount exceeds stake".to_string()
            ));
        }

        stake_info.staked_amount -= slash_amount;
        stake_info.performance_score *= 0.9; // Reduce performance score
        
        let slashing_event = SlashingEvent {
            event_type: SlashingType::InvalidBehavior,
            amount_slashed: slash_amount,
            reason,
            timestamp: Utc::now(),
        };
        
        stake_info.slashing_history.push(slashing_event);
        self.total_stake -= slash_amount;

        warn!("Slashed validator: validator={}, amount={}, reason={}", 
              validator.to_string(), slash_amount, 
              stake_info.slashing_history.last().unwrap().reason);

        Ok(slash_amount)
    }

    pub fn get_stake(&self, validator: &NymIdentity) -> Option<&StakeInfo> {
        self.stakes.get(validator)
    }

    pub fn get_total_stake(&self) -> u64 {
        self.total_stake
    }

    pub fn get_top_validators(&self, count: usize) -> Vec<(NymIdentity, u64)> {
        let mut validators: Vec<_> = self.stakes.iter()
            .map(|(id, info)| (id.clone(), info.staked_amount))
            .collect();
        
        validators.sort_by(|a, b| b.1.cmp(&a.1));
        validators.truncate(count);
        validators
    }

    pub fn process_unbondings(&mut self) {
        let now = Utc::now();
        let mut completed_unbondings = Vec::new();

        for (i, unbonding) in self.pending_unbondings.iter().enumerate() {
            if unbonding.completion_time <= now {
                completed_unbondings.push(i);
            }
        }

        // Remove completed unbondings in reverse order to maintain indices
        for &i in completed_unbondings.iter().rev() {
            let unbonding = self.pending_unbondings.remove(i);
            info!("Completed unbonding: delegator={}, amount={}", 
                  unbonding.delegator.to_string(), unbonding.amount);
        }
    }
}

impl ValidatorSet {
    pub fn new() -> Self {
        Self {
            active_validators: BTreeMap::new(),
            candidate_validators: HashMap::new(),
            proposer_schedule: Vec::new(),
            current_proposer_index: 0,
        }
    }

    pub fn update_validator_set(&mut self, stake_manager: &StakeManager, config: &PosConfig) -> ConsensusResult<()> {
        let top_validators = stake_manager.get_top_validators(config.max_validators as usize);
        
        // Filter validators that meet minimum stake requirement
        let qualified_validators: Vec<_> = top_validators.into_iter()
            .filter(|(_, stake)| *stake >= config.min_stake)
            .collect();

        // Update active validator set
        self.active_validators.clear();
        for (validator_id, stake_amount) in qualified_validators {
            if let Some(stake_info) = stake_manager.get_stake(&validator_id) {
                let validator_info = ValidatorInfo {
                    identity: validator_id.clone(),
                    stake_amount,
                    commission_rate: 0.1, // Default 10% commission
                    uptime_percentage: 0.99,
                    blocks_validated: 0,
                    last_active: Utc::now(),
                    reputation_score: stake_info.performance_score,
                };
                
                self.active_validators.insert(validator_id, validator_info);
            }
        }

        // Rebuild proposer schedule
        self.rebuild_proposer_schedule();

        info!("Updated validator set: {} active validators", self.active_validators.len());
        Ok(())
    }

    fn rebuild_proposer_schedule(&mut self) {
        self.proposer_schedule.clear();
        
        // Weighted random selection based on stake
        let mut weighted_validators = Vec::new();
        for (validator_id, validator_info) in &self.active_validators {
            // Add validator multiple times based on stake weight
            let weight = (validator_info.stake_amount / 1_000_000).max(1) as usize;
            for _ in 0..weight {
                weighted_validators.push(validator_id.clone());
            }
        }

        // Shuffle for randomness
        use rand::seq::SliceRandom;
        weighted_validators.shuffle(&mut thread_rng());
        
        self.proposer_schedule = weighted_validators;
        self.current_proposer_index = 0;
    }

    pub fn get_next_proposer(&mut self) -> Option<NymIdentity> {
        if self.proposer_schedule.is_empty() {
            return None;
        }

        let proposer = self.proposer_schedule[self.current_proposer_index].clone();
        self.current_proposer_index = (self.current_proposer_index + 1) % self.proposer_schedule.len();
        
        Some(proposer)
    }

    pub fn is_active_validator(&self, validator: &NymIdentity) -> bool {
        self.active_validators.contains_key(validator)
    }

    pub fn get_active_validators(&self) -> Vec<&ValidatorInfo> {
        self.active_validators.values().collect()
    }

    pub fn get_validator_count(&self) -> usize {
        self.active_validators.len()
    }
}

impl ProofOfStake {
    pub fn new(config: PosConfig) -> Self {
        info!("Initializing Proof-of-Stake with {} max validators", config.max_validators);

        Self {
            config,
            stake_manager: Arc::new(RwLock::new(StakeManager::new())),
            validator_set: Arc::new(RwLock::new(ValidatorSet::new())),
            voting_state: Arc::new(RwLock::new(VotingState {
                current_round: 0,
                votes: HashMap::new(),
                finality_signatures: HashMap::new(),
                vote_deadlines: HashMap::new(),
            })),
        }
    }

    pub async fn select_validator(&self, block_height: u64) -> ConsensusResult<Option<NymIdentity>> {
        let mut validator_set = self.validator_set.write().await;
        
        if validator_set.get_validator_count() == 0 {
            return Ok(None);
        }

        // Deterministic selection based on block height and stake
        let proposer = validator_set.get_next_proposer();
        
        if let Some(ref proposer_id) = proposer {
            debug!("Selected validator for block {}: {}", block_height, proposer_id.to_string());
        }

        Ok(proposer)
    }

    pub async fn create_pos_proof(
        &self,
        validator: &NymIdentity,
        block: &Block,
    ) -> ConsensusResult<ProofOfStakeData> {
        let stake_manager = self.stake_manager.read().await;
        
        let stake_info = stake_manager.get_stake(validator)
            .ok_or_else(|| ConsensusError::InvalidProofOfStake(
                "Validator not found in stake registry".to_string()
            ))?;

        // Create selection proof (simplified - should use VRF in production)
        let selection_proof = self.create_selection_proof(validator, block).await?;
        
        // Sign the block
        let block_hash = block.hash();
        let signature = validator.sign_data(block_hash.as_bytes())
            .map_err(|e| ConsensusError::CryptoError(format!("Failed to sign block: {}", e)))?;

        Ok(ProofOfStakeData {
            validator_id: validator.clone(),
            stake_amount: stake_info.staked_amount,
            selection_proof,
            signature,
        })
    }

    async fn create_selection_proof(&self, validator: &NymIdentity, block: &Block) -> ConsensusResult<Vec<u8>> {
        // Simplified selection proof - in production, use Verifiable Random Function (VRF)
        use sha3::{Digest, Sha3_256};
        
        let mut hasher = Sha3_256::new();
        hasher.update(validator.public_key_bytes());
        hasher.update(&block.header.height.to_be_bytes());
        hasher.update(block.header.previous_hash.as_bytes());
        
        Ok(hasher.finalize().to_vec())
    }

    pub async fn validate_pos_proof(&self, block: &Block) -> ConsensusResult<ValidationResult> {
        let pos_proof = block.consensus_data.pos_proof.as_ref()
            .ok_or_else(|| ConsensusError::InvalidProofOfStake(
                "No PoS proof found in block".to_string()
            ))?;

        let validator_set = self.validator_set.read().await;
        
        // Verify validator is active
        if !validator_set.is_active_validator(&pos_proof.validator_id) {
            return Ok(ValidationResult {
                is_valid: false,
                pow_valid: false,
                pos_valid: false,
                validator_consensus: false,
                finality_achieved: false,
                error_message: Some("Validator not in active set".to_string()),
            });
        }

        // Verify signature
        let block_hash = block.hash();
        let signature_valid = pos_proof.validator_id.verify_signature(
            block_hash.as_bytes(),
            &pos_proof.signature,
        ).map_err(|e| ConsensusError::CryptoError(format!("Signature verification failed: {}", e)))?;

        if !signature_valid {
            return Ok(ValidationResult {
                is_valid: false,
                pow_valid: false,
                pos_valid: false,
                validator_consensus: false,
                finality_achieved: false,
                error_message: Some("Invalid validator signature".to_string()),
            });
        }

        // Verify stake amount matches
        let stake_manager = self.stake_manager.read().await;
        if let Some(stake_info) = stake_manager.get_stake(&pos_proof.validator_id) {
            if stake_info.staked_amount != pos_proof.stake_amount {
                return Ok(ValidationResult {
                    is_valid: false,
                    pow_valid: false,
                    pos_valid: false,
                    validator_consensus: false,
                    finality_achieved: false,
                    error_message: Some("Stake amount mismatch".to_string()),
                });
            }
        }

        Ok(ValidationResult {
            is_valid: true,
            pow_valid: false,
            pos_valid: true,
            validator_consensus: false,
            finality_achieved: false,
            error_message: None,
        })
    }

    pub async fn submit_vote(
        &self,
        validator: &NymIdentity,
        block_hash: Hash256,
        vote_type: VoteType,
    ) -> ConsensusResult<()> {
        let validator_set = self.validator_set.read().await;
        
        if !validator_set.is_active_validator(validator) {
            return Err(ConsensusError::ValidatorError(
                "Validator not in active set".to_string()
            ));
        }

        let signature = validator.sign_data(block_hash.as_bytes())
            .map_err(|e| ConsensusError::CryptoError(format!("Failed to sign vote: {}", e)))?;

        let vote = ValidatorVote {
            validator_id: validator.clone(),
            block_hash,
            vote_type,
            signature,
            timestamp: Utc::now(),
        };

        let mut voting_state = self.voting_state.write().await;
        voting_state.votes.entry(block_hash).or_default().push(vote);

        debug!("Received vote from validator: {}", validator.to_string());
        Ok(())
    }

    pub async fn check_finality(&self, block_hash: Hash256) -> ConsensusResult<bool> {
        let voting_state = self.voting_state.read().await;
        let validator_set = self.validator_set.read().await;
        
        let votes = voting_state.votes.get(&block_hash).unwrap_or(&Vec::new());
        
        // Count votes by type
        let mut precommit_stake = 0u64;
        let stake_manager = self.stake_manager.read().await;
        
        for vote in votes {
            if matches!(vote.vote_type, VoteType::Precommit) {
                if let Some(stake_info) = stake_manager.get_stake(&vote.validator_id) {
                    precommit_stake += stake_info.staked_amount;
                }
            }
        }

        let total_stake = stake_manager.get_total_stake();
        let finality_stake_threshold = (total_stake as f64 * self.config.finality_threshold) as u64;

        let finality_achieved = precommit_stake >= finality_stake_threshold;
        
        if finality_achieved {
            info!("Finality achieved for block: {}, stake: {}/{}", 
                  block_hash.to_hex(), precommit_stake, total_stake);
        }

        Ok(finality_achieved)
    }

    pub async fn add_validator_stake(&self, validator: NymIdentity, amount: u64) -> ConsensusResult<()> {
        self.stake_manager.write().await.add_stake(validator, amount)
    }

    pub async fn delegate_stake(
        &self,
        delegator: NymIdentity,
        validator: NymIdentity,
        amount: u64,
    ) -> ConsensusResult<()> {
        self.stake_manager.write().await.delegate_stake(delegator, validator, amount)
    }

    pub async fn update_validator_set(&self) -> ConsensusResult<()> {
        let stake_manager = self.stake_manager.read().await;
        self.validator_set.write().await.update_validator_set(&stake_manager, &self.config)
    }

    pub async fn slash_validator(&self, validator: &NymIdentity, reason: String) -> ConsensusResult<u64> {
        let slashed_amount = self.stake_manager.write().await
            .slash_validator(validator, reason, self.config.slashing_percentage)?;
        
        // Update validator set after slashing
        self.update_validator_set().await?;
        
        Ok(slashed_amount)
    }

    pub async fn get_active_validators(&self) -> Vec<ValidatorInfo> {
        self.validator_set.read().await.get_active_validators()
            .into_iter().cloned().collect()
    }

    pub async fn get_total_stake(&self) -> u64 {
        self.stake_manager.read().await.get_total_stake()
    }
}

pub struct PosValidator {
    pos: Arc<ProofOfStake>,
    validator_identity: NymIdentity,
}

impl PosValidator {
    pub fn new(pos: Arc<ProofOfStake>, validator_identity: NymIdentity) -> Self {
        Self {
            pos,
            validator_identity,
        }
    }

    pub async fn validate_block(&self, block: &Block) -> ConsensusResult<ValidationResult> {
        self.pos.validate_pos_proof(block).await
    }

    pub async fn vote_on_block(&self, block_hash: Hash256, vote_type: VoteType) -> ConsensusResult<()> {
        self.pos.submit_vote(&self.validator_identity, block_hash, vote_type).await
    }

    pub async fn create_block_proposal(&self, transactions: Vec<nym_core::Transaction>) -> ConsensusResult<Block> {
        use crate::types::ConsensusData;
        
        let mut block = Block::new(0, Hash256::default(), transactions, ConsensusData::new());
        
        let pos_proof = self.pos.create_pos_proof(&self.validator_identity, &block).await?;
        block.consensus_data.pos_proof = Some(pos_proof);
        
        Ok(block)
    }
}