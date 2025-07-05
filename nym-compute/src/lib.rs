//! # Nym Decentralized Compute Platform
//!
//! NymCompute provides a privacy-first decentralized cloud computing platform
//! built on the Nymverse ecosystem, enabling secure, anonymous, and verifiable
//! distributed computation.
//!
//! ## Architecture
//!
//! The platform consists of four main layers:
//! 1. **Compute Chain**: Blockchain layer for compute transactions (extends Nym)
//! 2. **Resource Management**: QuID-authenticated compute node registry
//! 3. **Job Execution**: Privacy-preserving execution environments
//! 4. **Content Distribution**: Axon-based code and data distribution
//!
//! ## Key Features
//!
//! - **Privacy-First**: Zero-knowledge proofs for computation verification
//! - **Quantum-Resistant**: Post-quantum cryptography throughout
//! - **Economic Incentives**: Nym token-based payment and staking system
//! - **Decentralized**: No central points of failure
//! - **Verifiable**: Cryptographic proofs of computation correctness

pub mod compute_chain;
pub mod resource_manager;
pub mod execution_engine;
pub mod privacy_engine;
pub mod node_registry;
pub mod job_scheduler;
pub mod economic_engine;
pub mod networking;
pub mod error;
pub mod types;

pub use error::{ComputeError, Result};
pub use types::{
    ComputeJob, ComputeJobId, ComputeTransaction, ResourceSpec, ExecutionResult,
    PrivacyLevel, Runtime, NodeCapabilities, JobStatus,
};

use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error};
use quid_core::identity::QuIDIdentity;
use nym_core::transaction::Transaction;

/// Main compute platform manager
pub struct NymComputePlatform {
    /// Node registry for managing compute providers
    node_registry: Arc<node_registry::NodeRegistry>,
    /// Job scheduler for managing compute jobs
    job_scheduler: Arc<job_scheduler::JobScheduler>,
    /// Execution engine for running jobs
    execution_engine: Arc<execution_engine::ExecutionEngine>,
    /// Privacy engine for zero-knowledge proofs
    privacy_engine: Arc<privacy_engine::PrivacyEngine>,
    /// Resource manager for allocation and discovery
    resource_manager: Arc<resource_manager::ResourceManager>,
    /// Economic engine for payments and incentives
    economic_engine: Arc<economic_engine::EconomicEngine>,
    /// Networking layer for P2P communication
    networking: Arc<networking::NetworkManager>,
    /// Platform configuration
    config: ComputePlatformConfig,
}

/// Configuration for the compute platform
#[derive(Debug, Clone)]
pub struct ComputePlatformConfig {
    /// Whether this node provides compute resources
    pub is_compute_provider: bool,
    /// Whether this node can submit jobs
    pub is_client: bool,
    /// Whether this node acts as a scheduler
    pub is_scheduler: bool,
    /// Maximum number of concurrent jobs
    pub max_concurrent_jobs: u32,
    /// Supported runtime environments
    pub supported_runtimes: Vec<Runtime>,
    /// Network configuration
    pub network_config: networking::NetworkConfig,
    /// Economic configuration
    pub economic_config: economic_engine::EconomicConfig,
    /// Privacy configuration
    pub privacy_config: privacy_engine::PrivacyConfig,
}

impl Default for ComputePlatformConfig {
    fn default() -> Self {
        Self {
            is_compute_provider: false,
            is_client: true,
            is_scheduler: false,
            max_concurrent_jobs: 10,
            supported_runtimes: vec![Runtime::WASM, Runtime::Docker],
            network_config: networking::NetworkConfig::default(),
            economic_config: economic_engine::EconomicConfig::default(),
            privacy_config: privacy_engine::PrivacyConfig::default(),
        }
    }
}

impl NymComputePlatform {
    /// Create a new compute platform instance
    pub async fn new(
        config: ComputePlatformConfig,
        node_identity: QuIDIdentity,
    ) -> Result<Self> {
        info!("Initializing NymCompute platform");

        // Initialize networking first
        let networking = Arc::new(
            networking::NetworkManager::new(config.network_config.clone(), node_identity.clone()).await?
        );

        // Initialize core engines
        let node_registry = Arc::new(
            node_registry::NodeRegistry::new(node_identity.clone()).await?
        );
        
        let privacy_engine = Arc::new(
            privacy_engine::PrivacyEngine::new(config.privacy_config.clone()).await?
        );

        let economic_engine = Arc::new(
            economic_engine::EconomicEngine::new(config.economic_config.clone()).await?
        );

        let resource_manager = Arc::new(
            resource_manager::ResourceManager::new(
                node_registry.clone(),
                economic_engine.clone(),
            ).await?
        );

        let execution_engine = Arc::new(
            execution_engine::ExecutionEngine::new(
                config.supported_runtimes.clone(),
                privacy_engine.clone(),
            ).await?
        );

        let job_scheduler = Arc::new(
            job_scheduler::JobScheduler::new(
                resource_manager.clone(),
                execution_engine.clone(),
                economic_engine.clone(),
            ).await?
        );

        Ok(Self {
            node_registry,
            job_scheduler,
            execution_engine,
            privacy_engine,
            resource_manager,
            economic_engine,
            networking,
            config,
        })
    }

    /// Start the compute platform
    pub async fn start(&self) -> Result<()> {
        info!("Starting NymCompute platform");

        // Start networking layer
        self.networking.start().await?;

        // Start core engines
        self.node_registry.start().await?;
        self.economic_engine.start().await?;
        self.resource_manager.start().await?;
        
        if self.config.is_compute_provider {
            self.execution_engine.start().await?;
        }
        
        if self.config.is_scheduler {
            self.job_scheduler.start().await?;
        }

        info!("NymCompute platform started successfully");
        Ok(())
    }

    /// Stop the compute platform
    pub async fn stop(&self) -> Result<()> {
        info!("Stopping NymCompute platform");

        // Stop in reverse order
        if self.config.is_scheduler {
            self.job_scheduler.stop().await?;
        }
        
        if self.config.is_compute_provider {
            self.execution_engine.stop().await?;
        }

        self.resource_manager.stop().await?;
        self.economic_engine.stop().await?;
        self.node_registry.stop().await?;
        self.networking.stop().await?;

        info!("NymCompute platform stopped successfully");
        Ok(())
    }

    /// Submit a compute job
    pub async fn submit_job(&self, job: ComputeJob) -> Result<ComputeJobId> {
        if !self.config.is_client {
            return Err(ComputeError::NotConfiguredAsClient);
        }

        info!("Submitting compute job: {:?}", job.job_id);

        // Validate job requirements
        self.validate_job(&job).await?;

        // Submit to scheduler
        let job_id = self.job_scheduler.submit_job(job).await?;

        info!("Job submitted successfully: {:?}", job_id);
        Ok(job_id)
    }

    /// Get job status
    pub async fn get_job_status(&self, job_id: ComputeJobId) -> Result<JobStatus> {
        self.job_scheduler.get_job_status(job_id).await
    }

    /// Get job result
    pub async fn get_job_result(&self, job_id: ComputeJobId) -> Result<ExecutionResult> {
        self.job_scheduler.get_job_result(job_id).await
    }

    /// Cancel a job
    pub async fn cancel_job(&self, job_id: ComputeJobId) -> Result<()> {
        self.job_scheduler.cancel_job(job_id).await
    }

    /// Register as a compute provider
    pub async fn register_as_provider(
        &self,
        capabilities: NodeCapabilities,
        stake_amount: u64,
    ) -> Result<()> {
        if !self.config.is_compute_provider {
            return Err(ComputeError::NotConfiguredAsProvider);
        }

        info!("Registering as compute provider");

        // Register with the node registry
        self.node_registry.register_node(capabilities, stake_amount).await?;

        // Start accepting jobs
        self.execution_engine.start_accepting_jobs().await?;

        info!("Successfully registered as compute provider");
        Ok(())
    }

    /// Get available compute resources
    pub async fn get_available_resources(&self) -> Result<Vec<resource_manager::AvailableResource>> {
        self.resource_manager.get_available_resources().await
    }

    /// Get platform statistics
    pub async fn get_platform_stats(&self) -> Result<PlatformStatistics> {
        Ok(PlatformStatistics {
            total_nodes: self.node_registry.get_node_count().await?,
            active_jobs: self.job_scheduler.get_active_job_count().await?,
            total_jobs_completed: self.job_scheduler.get_completed_job_count().await?,
            total_compute_hours: self.economic_engine.get_total_compute_hours().await?,
            network_health: self.networking.get_health_status().await?,
        })
    }

    /// Private helper to validate job requirements
    async fn validate_job(&self, job: &ComputeJob) -> Result<()> {
        // Validate resource requirements
        if job.resource_spec.cpu_cores == 0 {
            return Err(ComputeError::InvalidResourceSpec("CPU cores must be > 0".to_string()));
        }

        if job.resource_spec.memory_gb == 0 {
            return Err(ComputeError::InvalidResourceSpec("Memory must be > 0".to_string()));
        }

        // Validate runtime support
        if !self.config.supported_runtimes.contains(&job.runtime) {
            return Err(ComputeError::UnsupportedRuntime(job.runtime.clone()));
        }

        // Validate payment
        if job.payment_amount == 0 {
            return Err(ComputeError::InsufficientPayment);
        }

        Ok(())
    }
}

/// Platform statistics
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct PlatformStatistics {
    pub total_nodes: u64,
    pub active_jobs: u64,
    pub total_jobs_completed: u64,
    pub total_compute_hours: f64,
    pub network_health: f64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use quid_core::identity::QuIDIdentity;

    #[tokio::test]
    async fn test_platform_creation() {
        let config = ComputePlatformConfig::default();
        let identity = QuIDIdentity::generate_test_identity();
        
        let platform = NymComputePlatform::new(config, identity).await;
        assert!(platform.is_ok());
    }

    #[tokio::test]
    async fn test_platform_start_stop() {
        let config = ComputePlatformConfig::default();
        let identity = QuIDIdentity::generate_test_identity();
        
        let platform = NymComputePlatform::new(config, identity).await.unwrap();
        
        // Test start
        assert!(platform.start().await.is_ok());
        
        // Test stop
        assert!(platform.stop().await.is_ok());
    }
}