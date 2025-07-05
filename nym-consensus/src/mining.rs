use crate::{
    error::{ConsensusError, ConsensusResult},
    types::{Block, MiningResult},
    pow::ProofOfWork,
};
use nym_core::NymIdentity;

use std::sync::{Arc, atomic::{AtomicBool, AtomicU64, Ordering}};
use std::collections::HashMap;
use tokio::sync::{RwLock, mpsc};
use tracing::{info, debug, warn, error};
use serde::{Deserialize, Serialize};
use rand::{thread_rng, Rng};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningJob {
    pub job_id: String,
    pub block_template: Block,
    pub difficulty_target: u64,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
}

pub struct MiningPool {
    miners: Arc<RwLock<HashMap<String, MiningWorker>>>,
    active_jobs: Arc<RwLock<HashMap<String, MiningJob>>>,
    pow_engine: Arc<ProofOfWork>,
    job_counter: AtomicU64,
    is_running: AtomicBool,
}

pub struct MiningWorker {
    worker_id: String,
    miner_identity: NymIdentity,
    is_mining: Arc<AtomicBool>,
    hash_rate: AtomicU64,
    blocks_mined: AtomicU64,
    current_job: Arc<RwLock<Option<String>>>,
    result_sender: mpsc::UnboundedSender<MiningResult>,
}

impl MiningPool {
    pub fn new(pow_engine: Arc<ProofOfWork>) -> Self {
        info!("Initializing mining pool");
        
        Self {
            miners: Arc::new(RwLock::new(HashMap::new())),
            active_jobs: Arc::new(RwLock::new(HashMap::new())),
            pow_engine,
            job_counter: AtomicU64::new(0),
            is_running: AtomicBool::new(false),
        }
    }

    pub async fn start(&self) -> ConsensusResult<()> {
        if self.is_running.load(Ordering::Relaxed) {
            return Err(ConsensusError::MiningError("Mining pool already running".to_string()));
        }

        self.is_running.store(true, Ordering::Relaxed);
        info!("Mining pool started");

        // Start job cleanup task
        self.start_job_cleanup().await;

        Ok(())
    }

    pub async fn stop(&self) -> ConsensusResult<()> {
        if !self.is_running.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.is_running.store(false, Ordering::Relaxed);

        // Stop all miners
        let miners = self.miners.read().await;
        for miner in miners.values() {
            miner.stop_mining();
        }

        info!("Mining pool stopped");
        Ok(())
    }

    pub async fn add_miner(&self, miner_identity: NymIdentity) -> ConsensusResult<String> {
        let worker_id = format!("miner_{}", thread_rng().gen::<u32>());
        let (result_sender, mut result_receiver) = mpsc::unbounded_channel();

        let worker = MiningWorker {
            worker_id: worker_id.clone(),
            miner_identity: miner_identity.clone(),
            is_mining: Arc::new(AtomicBool::new(false)),
            hash_rate: AtomicU64::new(0),
            blocks_mined: AtomicU64::new(0),
            current_job: Arc::new(RwLock::new(None)),
            result_sender,
        };

        self.miners.write().await.insert(worker_id.clone(), worker);

        // Start result processing for this miner
        let pool_miners = self.miners.clone();
        let pool_jobs = self.active_jobs.clone();
        let worker_id_clone = worker_id.clone();

        tokio::spawn(async move {
            while let Some(result) = result_receiver.recv().await {
                if let Err(e) = Self::process_mining_result(
                    &pool_miners,
                    &pool_jobs,
                    &worker_id_clone,
                    result,
                ).await {
                    error!("Failed to process mining result: {}", e);
                }
            }
        });

        info!("Added miner to pool: {} ({})", worker_id, miner_identity.to_string());
        Ok(worker_id)
    }

    pub async fn remove_miner(&self, worker_id: &str) -> ConsensusResult<()> {
        let mut miners = self.miners.write().await;
        
        if let Some(miner) = miners.remove(worker_id) {
            miner.stop_mining();
            info!("Removed miner from pool: {}", worker_id);
        }

        Ok(())
    }

    pub async fn create_mining_job(&self, block_template: Block) -> ConsensusResult<String> {
        let job_id = format!("job_{}", self.job_counter.fetch_add(1, Ordering::Relaxed));
        let difficulty_target = self.pow_engine.get_current_difficulty().await;
        
        let job = MiningJob {
            job_id: job_id.clone(),
            block_template,
            difficulty_target,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::minutes(10),
        };

        self.active_jobs.write().await.insert(job_id.clone(), job);

        // Distribute job to all miners
        self.distribute_job_to_miners(&job_id).await?;

        info!("Created mining job: {}", job_id);
        Ok(job_id)
    }

    async fn distribute_job_to_miners(&self, job_id: &str) -> ConsensusResult<()> {
        let miners = self.miners.read().await;
        let jobs = self.active_jobs.read().await;
        
        let job = jobs.get(job_id)
            .ok_or_else(|| ConsensusError::MiningError("Job not found".to_string()))?;

        for miner in miners.values() {
            miner.assign_job(job_id.to_string()).await;
        }

        debug!("Distributed job {} to {} miners", job_id, miners.len());
        Ok(())
    }

    async fn process_mining_result(
        miners: &Arc<RwLock<HashMap<String, MiningWorker>>>,
        jobs: &Arc<RwLock<HashMap<String, MiningJob>>>,
        worker_id: &str,
        result: MiningResult,
    ) -> ConsensusResult<()> {
        if result.success {
            info!("Mining success from worker {}: block_hash={:?}, time={}ms", 
                  worker_id, result.block_hash, result.mining_time);

            // Update miner statistics
            if let Some(miner) = miners.read().await.get(worker_id) {
                miner.blocks_mined.fetch_add(1, Ordering::Relaxed);
                miner.hash_rate.store(result.hash_rate as u64, Ordering::Relaxed);
            }

            // Stop all other miners working on this job
            let miners_guard = miners.read().await;
            for miner in miners_guard.values() {
                if miner.worker_id != worker_id {
                    miner.stop_current_job().await;
                }
            }
        }

        Ok(())
    }

    async fn start_job_cleanup(&self) {
        let jobs = self.active_jobs.clone();
        let is_running = &self.is_running;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            
            loop {
                interval.tick().await;
                
                if !is_running.load(Ordering::Relaxed) {
                    break;
                }

                let mut jobs_guard = jobs.write().await;
                let now = chrono::Utc::now();
                
                let expired_jobs: Vec<String> = jobs_guard.iter()
                    .filter(|(_, job)| job.expires_at < now)
                    .map(|(id, _)| id.clone())
                    .collect();

                for job_id in expired_jobs {
                    jobs_guard.remove(&job_id);
                    debug!("Cleaned up expired job: {}", job_id);
                }
            }
        });
    }

    pub async fn get_pool_statistics(&self) -> MiningPoolStatistics {
        let miners = self.miners.read().await;
        let jobs = self.active_jobs.read().await;

        let total_miners = miners.len();
        let active_miners = miners.values().filter(|m| m.is_mining()).count();
        let total_hash_rate: u64 = miners.values()
            .map(|m| m.hash_rate.load(Ordering::Relaxed))
            .sum();
        let total_blocks_mined: u64 = miners.values()
            .map(|m| m.blocks_mined.load(Ordering::Relaxed))
            .sum();

        MiningPoolStatistics {
            total_miners,
            active_miners,
            total_hash_rate,
            total_blocks_mined,
            active_jobs: jobs.len(),
        }
    }
}

impl MiningWorker {
    pub async fn assign_job(&self, job_id: String) {
        *self.current_job.write().await = Some(job_id);
        debug!("Assigned job to miner {}: {}", self.worker_id, 
               self.current_job.read().await.as_ref().unwrap());
    }

    pub async fn start_mining(&self, pow_engine: Arc<ProofOfWork>, job: MiningJob) -> ConsensusResult<()> {
        if self.is_mining.load(Ordering::Relaxed) {
            return Ok(());
        }

        self.is_mining.store(true, Ordering::Relaxed);
        
        let miner_identity = self.miner_identity.clone();
        let stop_signal = self.is_mining.clone();
        let result_sender = self.result_sender.clone();

        tokio::spawn(async move {
            let result = pow_engine.mine_block(
                job.block_template,
                miner_identity,
                stop_signal,
            ).await;

            match result {
                Ok(mining_result) => {
                    if let Err(_) = result_sender.send(mining_result) {
                        error!("Failed to send mining result");
                    }
                }
                Err(e) => {
                    error!("Mining error: {}", e);
                }
            }
        });

        Ok(())
    }

    pub fn stop_mining(&self) {
        self.is_mining.store(false, Ordering::Relaxed);
    }

    pub async fn stop_current_job(&self) {
        self.stop_mining();
        *self.current_job.write().await = None;
    }

    pub fn is_mining(&self) -> bool {
        self.is_mining.load(Ordering::Relaxed)
    }

    pub fn get_hash_rate(&self) -> u64 {
        self.hash_rate.load(Ordering::Relaxed)
    }

    pub fn get_blocks_mined(&self) -> u64 {
        self.blocks_mined.load(Ordering::Relaxed)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MiningPoolStatistics {
    pub total_miners: usize,
    pub active_miners: usize,
    pub total_hash_rate: u64,
    pub total_blocks_mined: u64,
    pub active_jobs: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pow::{PowConfig, ProofOfWork};
    use nym_core::NymIdentity;

    #[tokio::test]
    async fn test_mining_pool_creation() {
        let pow_config = PowConfig::default();
        let pow_engine = Arc::new(ProofOfWork::new(pow_config).unwrap());
        let pool = MiningPool::new(pow_engine);

        assert!(!pool.is_running.load(Ordering::Relaxed));
    }

    #[tokio::test]
    async fn test_add_remove_miner() {
        let pow_config = PowConfig::default();
        let pow_engine = Arc::new(ProofOfWork::new(pow_config).unwrap());
        let pool = MiningPool::new(pow_engine);

        let miner_identity = NymIdentity::default();
        let worker_id = pool.add_miner(miner_identity).await.unwrap();

        assert_eq!(pool.miners.read().await.len(), 1);

        pool.remove_miner(&worker_id).await.unwrap();
        assert_eq!(pool.miners.read().await.len(), 0);
    }
}