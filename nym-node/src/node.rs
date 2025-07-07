use std::sync::Arc;
use std::path::PathBuf;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio::time::{interval, Duration};
use tracing::{info, warn, error, debug};

use crate::{
    config::NodeConfig,
    error::{NodeError, Result},
    state::{StateManager, NodeStatus},
};

use nym_network::{
    Libp2pNetwork, Libp2pNetworkConfig, Libp2pNetworkEvent,
    AdvancedSecurityManager, AdvancedSecurityConfig
};
use nym_storage::{ChainStore, AccountStore, EncryptedStore, EncryptionConfig};
use nym_consensus::{HybridConsensus, HybridConsensusConfig};
use nym_compute::{NymComputePlatform, ComputePlatformConfig};
use nym_economics::{IntegratedEconomicsSystem, IntegratedEconomicsConfig};
use nym_transparency::{TransparencyVerificationSystem, AuditReportingSystem};
use nym_core::NymIdentity;
use quid_core::Identity;
use tokio::sync::mpsc;

pub struct NymNode {
    config: NodeConfig,
    state: Arc<StateManager>,
    network: Option<Arc<Libp2pNetwork>>,
    network_events: Option<mpsc::UnboundedReceiver<Libp2pNetworkEvent>>,
    storage: Option<NodeStorage>,
    consensus: Option<Arc<HybridConsensus>>,
    compute: Option<Arc<NymComputePlatform>>,
    economics: Option<Arc<IntegratedEconomicsSystem>>,
    transparency: Option<Arc<TransparencyVerificationSystem>>,
    security_manager: Option<Arc<AdvancedSecurityManager>>,
    quid_identity: Option<Identity>,
    nym_identity: Option<NymIdentity>,
    shutdown_signal: Arc<RwLock<bool>>,
    tasks: Vec<JoinHandle<()>>,
}

pub struct NodeStorage {
    chain_store: Arc<ChainStore>,
    account_store: Arc<AccountStore>,
    encrypted_store: Arc<EncryptedStore>,
}

impl NymNode {
    pub fn new(config: NodeConfig) -> Result<Self> {
        Ok(Self {
            config,
            state: Arc::new(StateManager::new()),
            network: None,
            network_events: None,
            storage: None,
            consensus: None,
            compute: None,
            economics: None,
            transparency: None,
            security_manager: None,
            quid_identity: None,
            nym_identity: None,
            shutdown_signal: Arc::new(RwLock::new(false)),
            tasks: Vec::new(),
        })
    }
    
    pub async fn initialize(&mut self) -> Result<()> {
        info!("Initializing Nym node...");
        
        self.state.update_status(NodeStatus::Starting).await?;
        
        // Load QuID identity if specified
        if let Some(ref identity_path) = self.config.quid_identity_path {
            info!("Loading QuID identity from {:?}", identity_path);
            self.quid_identity = Some(self.load_quid_identity(identity_path)?);
        }
        
        // Initialize storage
        info!("Initializing storage...");
        let storage = self.initialize_storage().await?;
        self.storage = Some(storage);
        
        // Initialize network
        info!("Initializing network...");
        let (network, network_events) = self.initialize_network().await?;
        self.network = Some(network.clone());
        self.network_events = Some(network_events);
        
        // Initialize consensus
        info!("Initializing consensus engine...");
        let consensus = Arc::new(self.initialize_consensus(self.storage.as_ref().unwrap()).await?);
        self.consensus = Some(consensus.clone());
        
        // Initialize compute if enabled
        if self.config.compute.enabled {
            info!("Initializing compute engine...");
            let compute = Arc::new(self.initialize_compute().await?);
            self.compute = Some(compute.clone());
        }
        
        // Initialize economics
        info!("Initializing economics engine...");
        let economics = Arc::new(self.initialize_economics().await?);
        self.economics = Some(economics.clone());
        
        // Initialize transparency service
        info!("Initializing transparency service...");
        let transparency = Arc::new(self.initialize_transparency().await?);
        self.transparency = Some(transparency.clone());
        
        // Initialize security manager
        info!("Initializing network security manager...");
        let security_manager = Arc::new(self.initialize_security_manager().await?);
        self.security_manager = Some(security_manager.clone());
        
        info!("Node initialization complete");
        Ok(())
    }
    
    pub async fn start(&mut self) -> Result<()> {
        if matches!(self.state.get_state().await.status, NodeStatus::Running) {
            return Err(NodeError::AlreadyRunning);
        }
        
        info!("Starting Nym node...");
        
        // Start network
        if let Some(ref network) = self.network {
            network.start().await?;
            self.spawn_network_monitor(network.clone());
        }
        
        // Start consensus
        if let Some(ref consensus) = self.consensus {
            consensus.start().await?;
            self.spawn_consensus_monitor(consensus.clone());
        }
        
        // Start compute if enabled
        if let Some(ref compute) = self.compute {
            compute.start().await?;
            self.spawn_compute_monitor(compute.clone());
        }
        
        // Start main synchronization loop
        self.spawn_sync_loop();
        
        // Start metrics collector
        self.spawn_metrics_collector();
        
        self.state.update_status(NodeStatus::Running).await?;
        
        info!("Nym node started successfully");
        Ok(())
    }
    
    pub async fn stop(&mut self) -> Result<()> {
        info!("Stopping Nym node...");
        
        self.state.update_status(NodeStatus::Stopping).await?;
        
        // Signal shutdown to all tasks
        *self.shutdown_signal.write().await = true;
        
        // Stop components in reverse order
        if let Some(ref compute) = self.compute {
            compute.stop().await?;
        }
        
        if let Some(ref consensus) = self.consensus {
            consensus.stop().await?;
        }
        
        if let Some(ref network) = self.network {
            network.stop().await?;
        }
        
        // Wait for all tasks to complete
        for task in self.tasks.drain(..) {
            let _ = task.await;
        }
        
        self.state.update_status(NodeStatus::Stopped).await?;
        
        info!("Nym node stopped");
        Ok(())
    }
    
    pub async fn get_state(&self) -> Result<crate::state::NodeState> {
        Ok(self.state.get_state().await)
    }
    
    // Private initialization methods
    
    fn load_quid_identity(&self, path: &PathBuf) -> Result<Identity> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| NodeError::Config(format!("Failed to read QuID identity: {}", e)))?;
        let identity: Identity = serde_json::from_str(&content)
            .map_err(|e| NodeError::Config(format!("Failed to parse QuID identity: {}", e)))?;
        Ok(identity)
    }
    
    async fn initialize_storage(&self) -> Result<NodeStorage> {
        let data_dir = &self.config.storage.data_dir;
        std::fs::create_dir_all(data_dir)?;
        
        // Initialize encryption config
        let encryption_config = EncryptionConfig {
            key_derivation_rounds: 100_000,
            encryption_algorithm: "AES-256-GCM".to_string(),
        };
        
        // Create store instances
        let chain_store = Arc::new(ChainStore::new(data_dir.join("chain")).await?);
        let account_store = Arc::new(AccountStore::new(data_dir.join("accounts")).await?);
        let encrypted_store = Arc::new(EncryptedStore::new(data_dir.join("encrypted"), encryption_config).await?);
        
        Ok(NodeStorage {
            chain_store,
            account_store,
            encrypted_store,
        })
    }
    
    async fn initialize_network(&self) -> Result<(Arc<Libp2pNetwork>, mpsc::UnboundedReceiver<Libp2pNetworkEvent>)> {
        // Create NymIdentity from QuID identity if available
        let nym_identity = if let Some(quid_id) = &self.quid_identity {
            NymIdentity::from_quid(quid_id)?
        } else {
            // Generate a new identity
            NymIdentity::generate()?
        };
        
        let net_config = Libp2pNetworkConfig {
            listen_addr: self.config.network.listen_addr,
            bootstrap_peers: self.config.network.bootstrap_peers.clone(),
            max_peers: self.config.network.max_peers,
            enable_privacy_routing: self.config.network.enable_privacy_routing,
        };
        
        let (network, events) = Libp2pNetwork::new(net_config, nym_identity).await?;
        
        Ok((Arc::new(network), events))
    }
    
    async fn initialize_consensus(&self, storage: &NodeStorage) -> Result<HybridConsensus> {
        let consensus_config = HybridConsensusConfig {
            pow_enabled: self.config.consensus.pow_enabled,
            pos_enabled: self.config.consensus.pos_enabled,
            pow_weight: self.config.consensus.pow_weight,
            pos_weight: self.config.consensus.pos_weight,
            block_time: Duration::from_secs(self.config.consensus.block_time_seconds),
            finality_threshold: self.config.consensus.finality_threshold,
        };
        
        HybridConsensus::new(consensus_config, storage.chain_store.clone()).await
    }
    
    async fn initialize_compute(&self) -> Result<NymComputePlatform> {
        let compute_config = ComputePlatformConfig {
            is_compute_provider: true,
            is_client: true,
            is_scheduler: false,
            max_concurrent_jobs: self.config.compute.max_jobs,
            supported_runtimes: self.config.compute.supported_runtimes.clone(),
            ..Default::default()
        };
        
        let quid_identity = self.quid_identity.as_ref()
            .ok_or_else(|| NodeError::Config("QuID identity required for compute platform".to_string()))?;
        
        NymComputePlatform::new(compute_config, quid_identity.clone()).await
    }
    
    async fn initialize_economics(&self) -> Result<IntegratedEconomicsSystem> {
        let economics_config = IntegratedEconomicsConfig::default();
        IntegratedEconomicsSystem::new(economics_config).await
    }
    
    async fn initialize_transparency(&self) -> Result<TransparencyVerificationSystem> {
        TransparencyVerificationSystem::new().await
    }
    
    async fn initialize_security_manager(&self) -> Result<AdvancedSecurityManager> {
        let security_config = AdvancedSecurityConfig {
            max_connections_per_ip: 3,
            rate_limit_window: 60,
            max_connection_attempts: 10,
            min_peer_diversity: 20,
            max_subnet_concentration: 0.3,
            sybil_detection_threshold: 0.8,
            ban_duration_seconds: 3600,
            enable_reputation_scoring: true,
            min_reputation_score: 0.3,
        };
        
        Ok(AdvancedSecurityManager::new(security_config))
    }
    
    // Task spawning methods
    
    fn spawn_network_monitor(&mut self, network: Arc<Libp2pNetwork>) {
        let state = self.state.clone();
        let shutdown = self.shutdown_signal.clone();
        
        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5));
            
            loop {
                interval.tick().await;
                
                if *shutdown.read().await {
                    break;
                }
                
                let peer_count = network.get_peer_count().await;
                if let Err(e) = state.update_peer_count(peer_count).await {
                    error!("Failed to update peer count: {}", e);
                }
            }
        });
        
        self.tasks.push(task);
    }
    
    fn spawn_consensus_monitor(&mut self, consensus: Arc<HybridConsensus>) {
        let state = self.state.clone();
        let shutdown = self.shutdown_signal.clone();
        
        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(1));
            
            loop {
                interval.tick().await;
                
                if *shutdown.read().await {
                    break;
                }
                
                // Update block height and mining status
                if let Ok(chain_state) = consensus.get_chain_state().await {
                    let _ = state.update_block_info(
                        chain_state.height,
                        chain_state.last_block_hash.to_string()
                    ).await;
                    
                    let _ = state.update_mining_status(
                        chain_state.is_mining,
                        chain_state.hash_rate
                    ).await;
                    
                    let _ = state.update_validator_status(
                        chain_state.is_validator,
                        chain_state.staked_amount
                    ).await;
                }
            }
        });
        
        self.tasks.push(task);
    }
    
    fn spawn_compute_monitor(&mut self, compute: Arc<NymComputePlatform>) {
        let state = self.state.clone();
        let shutdown = self.shutdown_signal.clone();
        
        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(10));
            
            loop {
                interval.tick().await;
                
                if *shutdown.read().await {
                    break;
                }
                
                if let Ok(stats) = compute.get_platform_stats().await {
                    let current_state = state.get_state().await;
                    let _ = state.increment_compute_jobs(
                        stats.active_jobs as i32 - current_state.compute_jobs_active as i32,
                        stats.total_jobs_completed - current_state.compute_jobs_completed
                    ).await;
                }
            }
        });
        
        self.tasks.push(task);
    }
    
    fn spawn_sync_loop(&mut self) {
        let state = self.state.clone();
        let network = self.network.clone();
        let consensus = self.consensus.clone();
        let shutdown = self.shutdown_signal.clone();
        
        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(5));
            
            loop {
                interval.tick().await;
                
                if *shutdown.read().await {
                    break;
                }
                
                // Sync logic would go here
                // For now, just update sync progress
                if let (Some(network), Some(consensus)) = (network.as_ref(), consensus.as_ref()) {
                    // Check if we need to sync
                    if let Ok(needs_sync) = consensus.needs_sync().await {
                        if needs_sync {
                            let _ = state.update_sync_progress(true, 50.0).await;
                            // Actual sync logic would be implemented here
                        } else {
                            let _ = state.update_sync_progress(false, 100.0).await;
                        }
                    }
                }
            }
        });
        
        self.tasks.push(task);
    }
    
    fn spawn_metrics_collector(&mut self) {
        let state = self.state.clone();
        let shutdown = self.shutdown_signal.clone();
        
        let task = tokio::spawn(async move {
            let mut interval = interval(Duration::from_secs(30));
            
            loop {
                interval.tick().await;
                
                if *shutdown.read().await {
                    break;
                }
                
                let summary = state.get_summary().await;
                debug!("Node metrics:\n{}", summary);
            }
        });
        
        self.tasks.push(task);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    #[tokio::test]
    async fn test_node_lifecycle() {
        let temp_dir = TempDir::new().unwrap();
        let mut config = NodeConfig::default();
        config.storage.data_dir = temp_dir.path().to_path_buf();
        config.set_test_config();
        
        let mut node = NymNode::new(config).unwrap();
        
        // Test initialization
        node.initialize().await.unwrap();
        
        // Test starting
        node.start().await.unwrap();
        let state = node.get_state().await.unwrap();
        assert_eq!(state.status, NodeStatus::Running);
        
        // Test stopping
        node.stop().await.unwrap();
        let state = node.get_state().await.unwrap();
        assert_eq!(state.status, NodeStatus::Stopped);
    }
}