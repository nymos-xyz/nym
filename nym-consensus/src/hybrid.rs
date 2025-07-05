use crate::{
    error::{ConsensusError, ConsensusResult},
    types::{Block, ValidationResult, ConsensusState, NetworkMetrics},
    pow::{ProofOfWork, PowConfig},
    pos::{ProofOfStake, PosConfig},
};
use nym_core::NymIdentity;
use nym_crypto::Hash256;

use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;
use tracing::{info, debug, warn, error};
use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HybridConsensusConfig {
    pub pow_config: PowConfig,
    pub pos_config: PosConfig,
    pub pow_weight: f64,          // Weight of PoW in consensus (0.0 to 1.0)
    pub pos_weight: f64,          // Weight of PoS in consensus (0.0 to 1.0)
    pub dual_consensus_required: bool, // Require both PoW and PoS for block acceptance
    pub finality_blocks: u64,     // Number of blocks for finality
    pub fork_resolution_mode: ForkResolutionMode,
    pub security_threshold: f64,  // Minimum security level required
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ForkResolutionMode {
    PowDominant,     // PoW chain wins in case of forks
    PosDominant,     // PoS finality decides forks
    HybridWeight,    // Combined weight of PoW and PoS
    AdaptiveSecurity, // Dynamic based on network conditions
}

impl Default for HybridConsensusConfig {
    fn default() -> Self {
        Self {
            pow_config: PowConfig::default(),
            pos_config: PosConfig::default(),
            pow_weight: 0.4,  // 40% PoW
            pos_weight: 0.6,  // 60% PoS
            dual_consensus_required: true,
            finality_blocks: 12, // ~24 minutes for finality
            fork_resolution_mode: ForkResolutionMode::HybridWeight,
            security_threshold: 0.75, // 75% minimum security
        }
    }
}

pub struct HybridConsensus {
    config: HybridConsensusConfig,
    pow_engine: Arc<ProofOfWork>,
    pos_engine: Arc<ProofOfStake>,
    consensus_state: Arc<RwLock<ConsensusState>>,
    finalized_blocks: Arc<RwLock<Vec<Hash256>>>,
    pending_blocks: Arc<RwLock<Vec<Block>>>,
    network_metrics: Arc<RwLock<NetworkMetrics>>,
}

impl HybridConsensus {
    pub async fn new(config: HybridConsensusConfig) -> ConsensusResult<Self> {
        info!("Initializing Hybrid PoW/PoS Consensus with weights: PoW={}, PoS={}", 
              config.pow_weight, config.pos_weight);

        // Validate configuration
        if (config.pow_weight + config.pos_weight - 1.0).abs() > f64::EPSILON {
            return Err(ConsensusError::ConfigError(
                "PoW and PoS weights must sum to 1.0".to_string()
            ));
        }

        let pow_engine = Arc::new(ProofOfWork::new(config.pow_config.clone())?);
        let pos_engine = Arc::new(ProofOfStake::new(config.pos_config.clone()));

        let initial_state = ConsensusState {
            current_height: 0,
            latest_block_hash: Hash256::default(),
            difficulty_target: config.pow_config.min_difficulty,
            total_stake: 0,
            active_validators: 0,
            network_hash_rate: 0.0,
            finalized_height: 0,
        };

        let initial_metrics = NetworkMetrics {
            block_time: config.pow_config.target_block_time.as_secs_f64(),
            transaction_throughput: 0.0,
            network_security: 1.0,
            decentralization_coefficient: 1.0,
            energy_efficiency: 0.8,
        };

        Ok(Self {
            config,
            pow_engine,
            pos_engine,
            consensus_state: Arc::new(RwLock::new(initial_state)),
            finalized_blocks: Arc::new(RwLock::new(Vec::new())),
            pending_blocks: Arc::new(RwLock::new(Vec::new())),
            network_metrics: Arc::new(RwLock::new(initial_metrics)),
        })
    }

    pub async fn validate_block(&self, block: &Block) -> ConsensusResult<ValidationResult> {
        debug!("Validating block with hybrid consensus: height={}", block.header.height);

        let start_time = Instant::now();

        // Validate PoW component
        let pow_result = if block.consensus_data.has_pow_proof() {
            self.pow_engine.validate_pow(block).await?
        } else if self.config.dual_consensus_required {
            return Ok(ValidationResult {
                is_valid: false,
                pow_valid: false,
                pos_valid: false,
                validator_consensus: false,
                finality_achieved: false,
                error_message: Some("PoW proof required but not found".to_string()),
            });
        } else {
            ValidationResult {
                is_valid: true,
                pow_valid: false,
                pos_valid: false,
                validator_consensus: false,
                finality_achieved: false,
                error_message: None,
            }
        };

        // Validate PoS component
        let pos_result = if block.consensus_data.has_pos_proof() {
            self.pos_engine.validate_pos_proof(block).await?
        } else if self.config.dual_consensus_required {
            return Ok(ValidationResult {
                is_valid: false,
                pow_valid: pow_result.pow_valid,
                pos_valid: false,
                validator_consensus: false,
                finality_achieved: false,
                error_message: Some("PoS proof required but not found".to_string()),
            });
        } else {
            ValidationResult {
                is_valid: true,
                pow_valid: false,
                pos_valid: false,
                validator_consensus: false,
                finality_achieved: false,
                error_message: None,
            }
        };

        // Check validator consensus
        let validator_consensus = self.check_validator_consensus(block).await?;

        // Check finality
        let finality_achieved = self.check_block_finality(block.hash()).await?;

        // Calculate overall validity based on hybrid rules
        let is_valid = self.evaluate_hybrid_validity(&pow_result, &pos_result, validator_consensus).await?;

        let validation_time = start_time.elapsed();
        debug!("Block validation completed in {:?}: valid={}, pow={}, pos={}, consensus={}, finality={}", 
               validation_time, is_valid, pow_result.pow_valid, pos_result.pos_valid, 
               validator_consensus, finality_achieved);

        Ok(ValidationResult {
            is_valid,
            pow_valid: pow_result.pow_valid,
            pos_valid: pos_result.pos_valid,
            validator_consensus,
            finality_achieved,
            error_message: if is_valid { None } else { Some("Hybrid consensus requirements not met".to_string()) },
        })
    }

    async fn evaluate_hybrid_validity(
        &self,
        pow_result: &ValidationResult,
        pos_result: &ValidationResult,
        validator_consensus: bool,
    ) -> ConsensusResult<bool> {
        if self.config.dual_consensus_required {
            // Both PoW and PoS must be valid
            return Ok(pow_result.pow_valid && pos_result.pos_valid && validator_consensus);
        }

        // Calculate weighted validity score
        let pow_score = if pow_result.pow_valid { self.config.pow_weight } else { 0.0 };
        let pos_score = if pos_result.pos_valid { self.config.pos_weight } else { 0.0 };
        let consensus_bonus = if validator_consensus { 0.1 } else { 0.0 };

        let total_score = pow_score + pos_score + consensus_bonus;
        let required_score = self.config.security_threshold;

        Ok(total_score >= required_score)
    }

    async fn check_validator_consensus(&self, block: &Block) -> ConsensusResult<bool> {
        let votes = &block.consensus_data.validator_votes;
        
        if votes.is_empty() {
            return Ok(false);
        }

        // Count valid votes
        let mut valid_votes = 0;
        let mut total_stake_voting = 0u64;

        for vote in votes {
            // Verify vote signature
            let signature_valid = vote.validator_id.verify_signature(
                vote.block_hash.as_bytes(),
                &vote.signature,
            ).map_err(|e| ConsensusError::CryptoError(format!("Vote signature verification failed: {}", e)))?;

            if signature_valid {
                valid_votes += 1;
                
                // Add stake weight if we can determine it
                // This would integrate with the PoS engine to get actual stake amounts
                total_stake_voting += 1; // Placeholder
            }
        }

        let total_validators = self.pos_engine.get_active_validators().await.len();
        let consensus_threshold = (total_validators as f64 * self.config.pos_config.finality_threshold) as usize;

        Ok(valid_votes >= consensus_threshold)
    }

    async fn check_block_finality(&self, block_hash: Hash256) -> ConsensusResult<bool> {
        // Check if block has achieved finality through PoS consensus
        self.pos_engine.check_finality(block_hash).await
    }

    pub async fn process_new_block(&self, block: Block) -> ConsensusResult<bool> {
        info!("Processing new block: height={}, hash={}", 
              block.header.height, block.hash().to_hex());

        // Validate the block
        let validation_result = self.validate_block(&block).await?;
        
        if !validation_result.is_valid {
            warn!("Block validation failed: {:?}", validation_result.error_message);
            return Ok(false);
        }

        // Add to pending blocks for finality processing
        self.pending_blocks.write().await.push(block.clone());

        // Update consensus state
        self.update_consensus_state(&block).await?;

        // Process finality
        self.process_finality().await?;

        // Update network metrics
        self.update_network_metrics(&block, &validation_result).await?;

        info!("Block processed successfully: height={}", block.header.height);
        Ok(true)
    }

    async fn update_consensus_state(&self, block: &Block) -> ConsensusResult<()> {
        let mut state = self.consensus_state.write().await;
        
        state.current_height = block.header.height;
        state.latest_block_hash = block.hash();
        
        // Update difficulty from PoW proof
        if let Some(pow_proof) = &block.consensus_data.pow_proof {
            state.difficulty_target = pow_proof.difficulty;
        }

        // Update stake information from PoS
        state.total_stake = self.pos_engine.get_total_stake().await;
        state.active_validators = self.pos_engine.get_active_validators().await.len() as u32;

        // Update hash rate (this would be calculated from recent PoW blocks)
        state.network_hash_rate = self.pow_engine.get_hash_rate().await;

        Ok(())
    }

    async fn process_finality(&self) -> ConsensusResult<()> {
        let mut pending_blocks = self.pending_blocks.write().await;
        let mut finalized_blocks = self.finalized_blocks.write().await;
        let mut consensus_state = self.consensus_state.write().await;

        // Process blocks that have achieved finality
        let mut finalized_count = 0;
        
        for (i, block) in pending_blocks.iter().enumerate() {
            let finality_achieved = self.check_block_finality(block.hash()).await?;
            
            if finality_achieved {
                finalized_blocks.push(block.hash());
                consensus_state.finalized_height = block.header.height;
                finalized_count = i + 1;
                
                info!("Block finalized: height={}, hash={}", 
                      block.header.height, block.hash().to_hex());
            } else {
                break; // Process finality in order
            }
        }

        // Remove finalized blocks from pending
        pending_blocks.drain(0..finalized_count);

        // Maintain finalized blocks list (keep last N blocks)
        if finalized_blocks.len() > self.config.finality_blocks as usize * 10 {
            let excess = finalized_blocks.len() - self.config.finality_blocks as usize * 10;
            finalized_blocks.drain(0..excess);
        }

        Ok(())
    }

    async fn update_network_metrics(&self, block: &Block, validation_result: &ValidationResult) -> ConsensusResult<()> {
        let mut metrics = self.network_metrics.write().await;
        
        // Update block time (moving average)
        let block_time = if block.header.height > 0 {
            // This would calculate based on previous block timestamp
            self.config.pow_config.target_block_time.as_secs_f64()
        } else {
            metrics.block_time
        };
        
        metrics.block_time = (metrics.block_time * 0.9) + (block_time * 0.1);

        // Update transaction throughput
        let tx_count = block.transaction_count() as f64;
        let throughput = tx_count / metrics.block_time;
        metrics.transaction_throughput = (metrics.transaction_throughput * 0.9) + (throughput * 0.1);

        // Calculate network security based on hybrid consensus
        let pow_security = if validation_result.pow_valid { self.config.pow_weight } else { 0.0 };
        let pos_security = if validation_result.pos_valid { self.config.pos_weight } else { 0.0 };
        let consensus_security = if validation_result.validator_consensus { 0.1 } else { 0.0 };
        
        let current_security = pow_security + pos_security + consensus_security;
        metrics.network_security = (metrics.network_security * 0.95) + (current_security * 0.05);

        // Update decentralization coefficient
        let active_validators = self.pos_engine.get_active_validators().await.len() as f64;
        let target_validators = self.config.pos_config.max_validators as f64;
        let validator_decentralization = (active_validators / target_validators).min(1.0);
        
        // PoW decentralization would be calculated from mining pool distribution
        let pow_decentralization = 0.8; // Placeholder
        
        let overall_decentralization = (validator_decentralization + pow_decentralization) / 2.0;
        metrics.decentralization_coefficient = (metrics.decentralization_coefficient * 0.9) + (overall_decentralization * 0.1);

        // Energy efficiency (higher for PoS, lower for PoW)
        let efficiency = self.config.pos_weight * 0.95 + self.config.pow_weight * 0.3;
        metrics.energy_efficiency = (metrics.energy_efficiency * 0.9) + (efficiency * 0.1);

        Ok(())
    }

    pub async fn resolve_fork(&self, competing_chains: Vec<Vec<Block>>) -> ConsensusResult<Vec<Block>> {
        info!("Resolving fork with {} competing chains", competing_chains.len());

        if competing_chains.is_empty() {
            return Err(ConsensusError::ProtocolError("No chains provided for fork resolution".to_string()));
        }

        if competing_chains.len() == 1 {
            return Ok(competing_chains.into_iter().next().unwrap());
        }

        let winning_chain = match self.config.fork_resolution_mode {
            ForkResolutionMode::PowDominant => self.resolve_by_pow_work(&competing_chains).await?,
            ForkResolutionMode::PosDominant => self.resolve_by_pos_finality(&competing_chains).await?,
            ForkResolutionMode::HybridWeight => self.resolve_by_hybrid_weight(&competing_chains).await?,
            ForkResolutionMode::AdaptiveSecurity => self.resolve_by_adaptive_security(&competing_chains).await?,
        };

        info!("Fork resolved: selected chain with {} blocks", winning_chain.len());
        Ok(winning_chain)
    }

    async fn resolve_by_pow_work(&self, chains: &[Vec<Block>]) -> ConsensusResult<Vec<Block>> {
        let mut best_chain = None;
        let mut highest_work = 0u64;

        for chain in chains {
            let mut total_work = 0u64;
            for block in chain {
                if let Some(pow_proof) = &block.consensus_data.pow_proof {
                    total_work += pow_proof.difficulty;
                }
            }

            if total_work > highest_work {
                highest_work = total_work;
                best_chain = Some(chain.clone());
            }
        }

        best_chain.ok_or_else(|| ConsensusError::ProtocolError("No valid PoW chain found".to_string()))
    }

    async fn resolve_by_pos_finality(&self, chains: &[Vec<Block>]) -> ConsensusResult<Vec<Block>> {
        let mut best_chain = None;
        let mut highest_finalized_height = 0u64;

        for chain in chains {
            let mut finalized_height = 0u64;
            for block in chain {
                let finality = self.check_block_finality(block.hash()).await?;
                if finality {
                    finalized_height = block.header.height;
                }
            }

            if finalized_height > highest_finalized_height {
                highest_finalized_height = finalized_height;
                best_chain = Some(chain.clone());
            }
        }

        best_chain.ok_or_else(|| ConsensusError::ProtocolError("No finalized PoS chain found".to_string()))
    }

    async fn resolve_by_hybrid_weight(&self, chains: &[Vec<Block>]) -> ConsensusResult<Vec<Block>> {
        let mut best_chain = None;
        let mut highest_score = 0.0f64;

        for chain in chains {
            let mut total_score = 0.0f64;
            
            for block in chain {
                let validation = self.validate_block(block).await?;
                
                let pow_score = if validation.pow_valid { self.config.pow_weight } else { 0.0 };
                let pos_score = if validation.pos_valid { self.config.pos_weight } else { 0.0 };
                let consensus_bonus = if validation.validator_consensus { 0.1 } else { 0.0 };
                let finality_bonus = if validation.finality_achieved { 0.2 } else { 0.0 };
                
                total_score += pow_score + pos_score + consensus_bonus + finality_bonus;
            }

            if total_score > highest_score {
                highest_score = total_score;
                best_chain = Some(chain.clone());
            }
        }

        best_chain.ok_or_else(|| ConsensusError::ProtocolError("No valid hybrid chain found".to_string()))
    }

    async fn resolve_by_adaptive_security(&self, chains: &[Vec<Block>]) -> ConsensusResult<Vec<Block>> {
        // Dynamic fork resolution based on current network conditions
        let metrics = self.network_metrics.read().await;
        
        if metrics.network_security > 0.9 {
            // High security: prefer finality
            self.resolve_by_pos_finality(chains).await
        } else if metrics.decentralization_coefficient > 0.8 {
            // High decentralization: prefer work
            self.resolve_by_pow_work(chains).await
        } else {
            // Balanced approach
            self.resolve_by_hybrid_weight(chains).await
        }
    }

    pub async fn get_consensus_state(&self) -> ConsensusState {
        self.consensus_state.read().await.clone()
    }

    pub async fn get_network_metrics(&self) -> NetworkMetrics {
        self.network_metrics.read().await.clone()
    }

    pub async fn get_finalized_height(&self) -> u64 {
        self.consensus_state.read().await.finalized_height
    }

    pub async fn is_block_finalized(&self, block_hash: Hash256) -> bool {
        let finalized_blocks = self.finalized_blocks.read().await;
        finalized_blocks.contains(&block_hash)
    }
}

pub struct ConsensusEngine {
    hybrid_consensus: Arc<HybridConsensus>,
    is_running: Arc<tokio::sync::RwLock<bool>>,
}

impl ConsensusEngine {
    pub async fn new(config: HybridConsensusConfig) -> ConsensusResult<Self> {
        let hybrid_consensus = Arc::new(HybridConsensus::new(config).await?);
        
        Ok(Self {
            hybrid_consensus,
            is_running: Arc::new(tokio::sync::RwLock::new(false)),
        })
    }

    pub async fn start(&self) -> ConsensusResult<()> {
        let mut running = self.is_running.write().await;
        if *running {
            return Err(ConsensusError::ProtocolError("Consensus engine already running".to_string()));
        }

        *running = true;
        info!("Hybrid consensus engine started");

        // Start background tasks for consensus maintenance
        self.start_finality_processor().await;
        self.start_metrics_updater().await;

        Ok(())
    }

    pub async fn stop(&self) -> ConsensusResult<()> {
        let mut running = self.is_running.write().await;
        if !*running {
            return Ok(());
        }

        *running = false;
        info!("Hybrid consensus engine stopped");
        Ok(())
    }

    async fn start_finality_processor(&self) {
        let consensus = self.hybrid_consensus.clone();
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                if !*is_running.read().await {
                    break;
                }

                if let Err(e) = consensus.process_finality().await {
                    error!("Finality processing error: {}", e);
                }
            }
        });
    }

    async fn start_metrics_updater(&self) {
        let is_running = self.is_running.clone();

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                if !*is_running.read().await {
                    break;
                }

                // Periodic metrics updates would go here
                debug!("Consensus metrics updated");
            }
        });
    }

    pub async fn process_block(&self, block: Block) -> ConsensusResult<bool> {
        self.hybrid_consensus.process_new_block(block).await
    }

    pub async fn validate_block(&self, block: &Block) -> ConsensusResult<ValidationResult> {
        self.hybrid_consensus.validate_block(block).await
    }

    pub async fn resolve_fork(&self, competing_chains: Vec<Vec<Block>>) -> ConsensusResult<Vec<Block>> {
        self.hybrid_consensus.resolve_fork(competing_chains).await
    }

    pub async fn get_consensus_state(&self) -> ConsensusState {
        self.hybrid_consensus.get_consensus_state().await
    }

    pub async fn get_network_metrics(&self) -> NetworkMetrics {
        self.hybrid_consensus.get_network_metrics().await
    }
}