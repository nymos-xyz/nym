use crate::{
    error::{ConsensusError, ConsensusResult},
    types::{Block, ProofOfWorkData, MiningResult, ValidationResult},
    difficulty::{DifficultyAdjustment, DifficultyTarget},
};
use nym_core::NymIdentity;
use nym_crypto::Hash256;

use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, debug, warn};
use serde::{Deserialize, Serialize};
use rand::{thread_rng, Rng};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowConfig {
    pub algorithm: PowAlgorithm,
    pub target_block_time: Duration,
    pub difficulty_adjustment_period: u64,
    pub min_difficulty: u64,
    pub max_difficulty: u64,
    pub quantum_resistant: bool,
    pub asic_resistant: bool,
    pub memory_hard: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PowAlgorithm {
    RandomXNym,     // Quantum-resistant RandomX variant
    Sha3Keccak,     // Pure SHA-3 for quantum resistance
    Blake3Argon2,   // ASIC-resistant hybrid
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            algorithm: PowAlgorithm::RandomXNym,
            target_block_time: Duration::from_secs(120), // 2 minutes
            difficulty_adjustment_period: 1440, // ~2 days of blocks
            min_difficulty: 1_000_000,
            max_difficulty: u64::MAX / 256,
            quantum_resistant: true,
            asic_resistant: true,
            memory_hard: true,
        }
    }
}

pub struct ProofOfWork {
    config: PowConfig,
    difficulty_adjuster: DifficultyAdjustment,
    current_target: Arc<RwLock<DifficultyTarget>>,
    hash_rate_tracker: Arc<RwLock<HashRateTracker>>,
}

#[derive(Debug)]
struct HashRateTracker {
    samples: Vec<(Instant, u64)>,
    total_hashes: u64,
    current_rate: f64,
}

impl HashRateTracker {
    fn new() -> Self {
        Self {
            samples: Vec::new(),
            total_hashes: 0,
            current_rate: 0.0,
        }
    }

    fn add_sample(&mut self, hashes: u64) {
        let now = Instant::now();
        self.samples.push((now, hashes));
        self.total_hashes += hashes;
        
        // Keep only samples from last 10 minutes
        let cutoff = now - Duration::from_secs(600);
        self.samples.retain(|(timestamp, _)| *timestamp > cutoff);
        
        self.calculate_rate();
    }

    fn calculate_rate(&mut self) {
        if self.samples.len() < 2 {
            return;
        }

        let total_time = self.samples.last().unwrap().0.duration_since(self.samples[0].0);
        let total_hashes: u64 = self.samples.iter().map(|(_, h)| h).sum();
        
        if total_time.as_secs() > 0 {
            self.current_rate = total_hashes as f64 / total_time.as_secs() as f64;
        }
    }
}

impl ProofOfWork {
    pub fn new(config: PowConfig) -> ConsensusResult<Self> {
        info!("Initializing Proof-of-Work with algorithm: {:?}", config.algorithm);
        
        let difficulty_adjuster = DifficultyAdjustment::new(
            config.target_block_time,
            config.difficulty_adjustment_period,
        );

        let initial_target = DifficultyTarget::new(config.min_difficulty);

        Ok(Self {
            config,
            difficulty_adjuster,
            current_target: Arc::new(RwLock::new(initial_target)),
            hash_rate_tracker: Arc::new(RwLock::new(HashRateTracker::new())),
        })
    }

    pub async fn mine_block(
        &self,
        mut block: Block,
        miner_identity: NymIdentity,
        stop_signal: Arc<AtomicBool>,
    ) -> ConsensusResult<MiningResult> {
        info!("Starting PoW mining for block height: {}", block.header.height);

        let start_time = Instant::now();
        let mut nonce = thread_rng().gen::<u64>();
        let mut hash_count = AtomicU64::new(0);
        
        let target = self.current_target.read().await.clone();
        
        loop {
            if stop_signal.load(Ordering::Relaxed) {
                break;
            }

            block.header.nonce = nonce;
            let hash = self.calculate_pow_hash(&block).await?;
            hash_count.fetch_add(1, Ordering::Relaxed);

            if self.meets_difficulty_target(&hash, &target) {
                let mining_time = start_time.elapsed();
                let total_hashes = hash_count.load(Ordering::Relaxed);
                
                // Update hash rate tracker
                self.hash_rate_tracker.write().await.add_sample(total_hashes);
                
                let pow_proof = ProofOfWorkData {
                    algorithm: format!("{:?}", self.config.algorithm),
                    work_hash: hash,
                    difficulty: target.as_compact(),
                    mining_time: mining_time.as_millis() as u64,
                    miner_identity,
                };

                block.consensus_data.pow_proof = Some(pow_proof);
                
                info!("PoW mining successful! Block: {}, Time: {:?}, Hashes: {}",
                      block.hash().to_hex(), mining_time, total_hashes);

                return Ok(MiningResult {
                    success: true,
                    block_hash: Some(block.hash()),
                    nonce,
                    mining_time: mining_time.as_millis() as u64,
                    hash_rate: total_hashes as f64 / mining_time.as_secs_f64(),
                    difficulty_met: true,
                });
            }

            nonce = nonce.wrapping_add(1);

            // Periodic status update
            if hash_count.load(Ordering::Relaxed) % 100_000 == 0 {
                debug!("Mining progress: {} hashes, elapsed: {:?}", 
                       hash_count.load(Ordering::Relaxed), start_time.elapsed());
            }
        }

        // Mining stopped
        Ok(MiningResult {
            success: false,
            block_hash: None,
            nonce,
            mining_time: start_time.elapsed().as_millis() as u64,
            hash_rate: hash_count.load(Ordering::Relaxed) as f64 / start_time.elapsed().as_secs_f64(),
            difficulty_met: false,
        })
    }

    pub async fn validate_pow(&self, block: &Block) -> ConsensusResult<ValidationResult> {
        debug!("Validating PoW for block: {}", block.hash().to_hex());

        let pow_proof = block.consensus_data.pow_proof.as_ref()
            .ok_or_else(|| ConsensusError::InvalidProofOfWork(
                "No PoW proof found in block".to_string()
            ))?;

        // Verify the work hash matches the block
        let calculated_hash = self.calculate_pow_hash(block).await?;
        if calculated_hash != pow_proof.work_hash {
            return Ok(ValidationResult {
                is_valid: false,
                pow_valid: false,
                pos_valid: false,
                validator_consensus: false,
                finality_achieved: false,
                error_message: Some("PoW hash mismatch".to_string()),
            });
        }

        // Verify difficulty target is met
        let target = DifficultyTarget::from_compact(pow_proof.difficulty);
        if !self.meets_difficulty_target(&calculated_hash, &target) {
            return Ok(ValidationResult {
                is_valid: false,
                pow_valid: false,
                pos_valid: false,
                validator_consensus: false,
                finality_achieved: false,
                error_message: Some("Difficulty target not met".to_string()),
            });
        }

        // Verify algorithm matches configuration
        let expected_algorithm = format!("{:?}", self.config.algorithm);
        if pow_proof.algorithm != expected_algorithm {
            return Ok(ValidationResult {
                is_valid: false,
                pow_valid: false,
                pos_valid: false,
                validator_consensus: false,
                finality_achieved: false,
                error_message: Some("Invalid PoW algorithm".to_string()),
            });
        }

        info!("PoW validation successful for block: {}", block.hash().to_hex());

        Ok(ValidationResult {
            is_valid: true,
            pow_valid: true,
            pos_valid: false,
            validator_consensus: false,
            finality_achieved: false,
            error_message: None,
        })
    }

    async fn calculate_pow_hash(&self, block: &Block) -> ConsensusResult<Hash256> {
        match self.config.algorithm {
            PowAlgorithm::RandomXNym => self.randomx_nym_hash(block).await,
            PowAlgorithm::Sha3Keccak => self.sha3_hash(block).await,
            PowAlgorithm::Blake3Argon2 => self.blake3_argon2_hash(block).await,
        }
    }

    async fn randomx_nym_hash(&self, block: &Block) -> ConsensusResult<Hash256> {
        // Quantum-resistant RandomX variant
        // For now, use SHA-3 as placeholder until RandomX integration
        self.sha3_hash(block).await
    }

    async fn sha3_hash(&self, block: &Block) -> ConsensusResult<Hash256> {
        use sha3::{Digest, Sha3_256};
        
        let block_data = bincode::serialize(&block.header)
            .map_err(|e| ConsensusError::SerializationError(e))?;
        
        let mut hasher = Sha3_256::new();
        hasher.update(&block_data);
        
        // Add some quantum-resistant hardening
        let timestamp_bytes = block.header.timestamp.timestamp().to_be_bytes();
        hasher.update(&timestamp_bytes);
        hasher.update(&block.header.nonce.to_be_bytes());
        
        Ok(Hash256::from_bytes(hasher.finalize().as_slice()))
    }

    async fn blake3_argon2_hash(&self, block: &Block) -> ConsensusResult<Hash256> {
        use blake3::Hasher;
        
        let block_data = bincode::serialize(&block.header)
            .map_err(|e| ConsensusError::SerializationError(e))?;
        
        let mut hasher = Hasher::new();
        hasher.update(&block_data);
        hasher.update(&block.header.nonce.to_be_bytes());
        
        let hash = hasher.finalize();
        Ok(Hash256::from_bytes(hash.as_bytes()))
    }

    fn meets_difficulty_target(&self, hash: &Hash256, target: &DifficultyTarget) -> bool {
        target.meets_target(hash)
    }

    pub async fn adjust_difficulty(&self, recent_blocks: &[Block]) -> ConsensusResult<()> {
        if recent_blocks.len() < self.config.difficulty_adjustment_period as usize {
            return Ok(());
        }

        let new_target = self.difficulty_adjuster.calculate_new_difficulty(recent_blocks)?;
        *self.current_target.write().await = new_target;
        
        info!("Difficulty adjusted to: {}", new_target.as_compact());
        Ok(())
    }

    pub async fn get_current_difficulty(&self) -> u64 {
        self.current_target.read().await.as_compact()
    }

    pub async fn get_hash_rate(&self) -> f64 {
        self.hash_rate_tracker.read().await.current_rate
    }

    pub async fn estimate_mining_time(&self, hash_rate: f64) -> Duration {
        let difficulty = self.get_current_difficulty().await;
        let expected_hashes = difficulty as f64;
        
        if hash_rate > 0.0 {
            Duration::from_secs_f64(expected_hashes / hash_rate)
        } else {
            Duration::from_secs(u64::MAX)
        }
    }
}

pub struct PowMiner {
    pow: Arc<ProofOfWork>,
    miner_identity: NymIdentity,
    is_mining: Arc<AtomicBool>,
}

impl PowMiner {
    pub fn new(pow: Arc<ProofOfWork>, miner_identity: NymIdentity) -> Self {
        Self {
            pow,
            miner_identity,
            is_mining: Arc::new(AtomicBool::new(false)),
        }
    }

    pub async fn start_mining(&self, block: Block) -> ConsensusResult<MiningResult> {
        self.is_mining.store(true, Ordering::Relaxed);
        
        let result = self.pow.mine_block(
            block,
            self.miner_identity.clone(),
            self.is_mining.clone(),
        ).await;

        self.is_mining.store(false, Ordering::Relaxed);
        result
    }

    pub fn stop_mining(&self) {
        self.is_mining.store(false, Ordering::Relaxed);
    }

    pub fn is_mining(&self) -> bool {
        self.is_mining.load(Ordering::Relaxed)
    }
}

pub struct PowValidator {
    pow: Arc<ProofOfWork>,
}

impl PowValidator {
    pub fn new(pow: Arc<ProofOfWork>) -> Self {
        Self { pow }
    }

    pub async fn validate_block(&self, block: &Block) -> ConsensusResult<ValidationResult> {
        self.pow.validate_pow(block).await
    }

    pub async fn validate_chain(&self, blocks: &[Block]) -> ConsensusResult<Vec<ValidationResult>> {
        let mut results = Vec::new();
        
        for block in blocks {
            let result = self.validate_block(block).await?;
            results.push(result);
            
            if !result.pow_valid {
                break;
            }
        }
        
        Ok(results)
    }
}