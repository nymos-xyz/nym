//! Core types for the Nym decentralized compute platform

use std::time::{Duration, SystemTime};
use serde::{Deserialize, Serialize};
use quid_core::identity::QuIDIdentity;
use nym_crypto::zkstark::ZkStarkProof;
use nym_core::balance::Balance;

/// Unique identifier for compute jobs
pub type ComputeJobId = [u8; 32];

/// Unique identifier for compute nodes
pub type ComputeNodeId = [u8; 32];

/// Content hash for code and data (compatible with Axon content addressing)
pub type ContentHash = [u8; 32];

/// Nym token amount
pub type NymToken = u64;

/// Geographic region for compute node placement
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Region {
    NorthAmerica,
    Europe,
    Asia,
    Australia,
    SouthAmerica,
    Africa,
    Any,
}

/// Privacy level for compute jobs
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum PrivacyLevel {
    /// Results visible to all
    Public,
    /// Results only visible to job submitter
    Private,
    /// Only zero-knowledge proof of correctness
    ZeroKnowledge,
    /// Anonymous execution with zk-proofs
    Anonymous,
}

/// Runtime environment for job execution
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum Runtime {
    /// WebAssembly runtime
    WASM,
    /// Docker container
    Docker,
    /// Trusted Execution Environment
    TEE,
    /// GPU compute
    GPU,
    /// Native Linux execution
    Native,
}

/// Job execution status
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum JobStatus {
    /// Job submitted and queued
    Queued,
    /// Resources being allocated
    Allocating,
    /// Job currently running
    Running,
    /// Job completed successfully
    Completed,
    /// Job failed with error
    Failed(String),
    /// Job cancelled by user
    Cancelled,
    /// Job timed out
    TimedOut,
}

/// Resource specification for compute jobs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceSpec {
    /// Number of CPU cores required
    pub cpu_cores: u32,
    /// Memory in GB required
    pub memory_gb: u32,
    /// Storage in GB required
    pub storage_gb: u32,
    /// Network bandwidth in Mbps
    pub network_bandwidth: u32,
    /// GPU units required (optional)
    pub gpu_units: Option<u32>,
    /// Maximum execution time
    pub execution_time_limit: Duration,
    /// Geographic preferences
    pub geographic_preferences: Vec<Region>,
    /// Minimum node reputation required
    pub min_reputation: f64,
}

impl Default for ResourceSpec {
    fn default() -> Self {
        Self {
            cpu_cores: 1,
            memory_gb: 1,
            storage_gb: 1,
            network_bandwidth: 10,
            gpu_units: None,
            execution_time_limit: Duration::from_secs(3600), // 1 hour
            geographic_preferences: vec![Region::Any],
            min_reputation: 0.5,
        }
    }
}

/// Compute node capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCapabilities {
    /// Maximum CPU cores available
    pub max_cpu_cores: u32,
    /// Maximum memory in GB
    pub max_memory_gb: u32,
    /// Maximum storage in GB
    pub max_storage_gb: u32,
    /// Network bandwidth in Mbps
    pub network_bandwidth: u32,
    /// GPU units available
    pub gpu_units: Option<u32>,
    /// Supported runtime environments
    pub supported_runtimes: Vec<Runtime>,
    /// Privacy features supported
    pub privacy_features: PrivacyFeatures,
    /// Geographic location
    pub region: Region,
    /// Hardware attestation support
    pub attestation_support: bool,
}

/// Privacy features supported by compute nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyFeatures {
    /// Secure enclaves available
    pub secure_enclaves: bool,
    /// Memory encryption support
    pub memory_encryption: bool,
    /// Hardware attestation type
    pub attestation_hardware: Option<AttestationType>,
    /// Zero-knowledge proof generation
    pub zk_proof_generation: bool,
    /// Confidential computing support
    pub confidential_computing: bool,
}

/// Hardware attestation types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AttestationType {
    IntelSGX,
    AMDTEE,
    ArmTrustZone,
    RISCVTEE,
}

/// Code bundle for execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeBundle {
    /// Content hash of the code (stored via Axon)
    pub content_hash: ContentHash,
    /// Runtime type required
    pub runtime_type: Runtime,
    /// Entry point for execution
    pub entry_point: String,
    /// Dependencies required
    pub dependencies: Vec<ContentHash>,
    /// Resource limits
    pub resource_limits: ResourceSpec,
    /// Code signature for verification
    pub signature: Vec<u8>,
}

/// Encrypted input data for jobs
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedData {
    /// Content hash of encrypted data
    pub content_hash: ContentHash,
    /// Encryption algorithm used
    pub encryption_algorithm: EncryptionAlgorithm,
    /// Encrypted symmetric key (encrypted with node's public key)
    pub encrypted_key: Vec<u8>,
    /// Data size in bytes
    pub size_bytes: u64,
    /// Data integrity hash
    pub integrity_hash: [u8; 32],
}

/// Encryption algorithms supported
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum EncryptionAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
    Kyber1024, // Post-quantum
}

/// Complete compute job specification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeJob {
    /// Unique job identifier
    pub job_id: ComputeJobId,
    /// Job submitter identity
    pub submitter: QuIDIdentity,
    /// Code to execute
    pub code_bundle: CodeBundle,
    /// Input data (encrypted)
    pub input_data: Option<EncryptedData>,
    /// Resource requirements
    pub resource_spec: ResourceSpec,
    /// Runtime environment
    pub runtime: Runtime,
    /// Privacy level required
    pub privacy_level: PrivacyLevel,
    /// Payment amount in Nym tokens
    pub payment_amount: NymToken,
    /// Job submission timestamp
    pub submitted_at: SystemTime,
    /// Job deadline
    pub deadline: Option<SystemTime>,
    /// Result callback specification
    pub result_callback: Option<CallbackSpec>,
}

/// Callback specification for job results
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CallbackSpec {
    /// Callback URL or identifier
    pub callback_target: String,
    /// Authentication for callback
    pub auth_token: Option<String>,
    /// Include execution proof in callback
    pub include_proof: bool,
}

/// Job execution result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionResult {
    /// Job identifier
    pub job_id: ComputeJobId,
    /// Execution status
    pub status: JobStatus,
    /// Result data (encrypted)
    pub result_data: Option<EncryptedData>,
    /// Execution proof
    pub execution_proof: Option<ZkStarkProof>,
    /// Resource usage during execution
    pub resource_usage: ResourceUsage,
    /// Execution logs (encrypted)
    pub execution_logs: Option<EncryptedData>,
    /// Start time
    pub started_at: Option<SystemTime>,
    /// Completion time
    pub completed_at: Option<SystemTime>,
    /// Error message if failed
    pub error_message: Option<String>,
    /// Node that executed the job
    pub executor_node: ComputeNodeId,
}

/// Resource usage during job execution
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    /// CPU time used in seconds
    pub cpu_time_seconds: f64,
    /// Peak memory usage in MB
    pub peak_memory_mb: u64,
    /// Storage used in MB
    pub storage_used_mb: u64,
    /// Network bytes transferred
    pub network_bytes: u64,
    /// GPU time used in seconds (if applicable)
    pub gpu_time_seconds: Option<f64>,
    /// Total execution time
    pub execution_duration: Duration,
}

/// Compute transaction for blockchain storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputeTransaction {
    /// Transaction type
    pub transaction_type: ComputeTransactionType,
    /// Transaction data
    pub data: ComputeTransactionData,
    /// Transaction fee
    pub fee: NymToken,
    /// Timestamp
    pub timestamp: SystemTime,
    /// Submitter signature
    pub signature: Vec<u8>,
}

/// Types of compute transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComputeTransactionType {
    /// Job submission transaction
    JobSubmission,
    /// Node registration transaction
    NodeRegistration,
    /// Job completion transaction
    JobCompletion,
    /// Payment transaction
    Payment,
    /// Stake transaction
    Stake,
    /// Slash transaction
    Slash,
}

/// Transaction data payload
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComputeTransactionData {
    JobSubmission {
        job: ComputeJob,
    },
    NodeRegistration {
        node_id: ComputeNodeId,
        identity: QuIDIdentity,
        capabilities: NodeCapabilities,
        stake_amount: NymToken,
    },
    JobCompletion {
        job_id: ComputeJobId,
        result: ExecutionResult,
    },
    Payment {
        from: QuIDIdentity,
        to: ComputeNodeId,
        amount: NymToken,
        job_id: ComputeJobId,
    },
    Stake {
        node_id: ComputeNodeId,
        amount: NymToken,
    },
    Slash {
        node_id: ComputeNodeId,
        amount: NymToken,
        reason: SlashReason,
    },
}

/// Reasons for slashing node stakes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SlashReason {
    /// Failed to complete assigned job
    JobFailure,
    /// Provided incorrect computation result
    IncorrectResult,
    /// Node was offline when needed
    Unavailability,
    /// Malicious behavior detected
    MaliciousBehavior,
    /// Privacy violation
    PrivacyViolation,
}

/// Node reputation score
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReputationScore {
    /// Overall reputation (0.0 to 1.0)
    pub overall: f64,
    /// Success rate for job completion
    pub success_rate: f64,
    /// Average response time
    pub response_time_score: f64,
    /// Privacy compliance score
    pub privacy_score: f64,
    /// Uptime score
    pub uptime_score: f64,
    /// Total jobs completed
    pub jobs_completed: u64,
    /// Last updated timestamp
    pub last_updated: SystemTime,
}

impl Default for ReputationScore {
    fn default() -> Self {
        Self {
            overall: 0.5,
            success_rate: 0.0,
            response_time_score: 0.0,
            privacy_score: 1.0,
            uptime_score: 0.0,
            jobs_completed: 0,
            last_updated: SystemTime::now(),
        }
    }
}

/// Compute marketplace pricing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComputePricing {
    /// Price per CPU core per hour
    pub cpu_core_hour_price: NymToken,
    /// Price per GB memory per hour
    pub memory_gb_hour_price: NymToken,
    /// Price per GB storage
    pub storage_gb_price: NymToken,
    /// Price per GB network transfer
    pub network_gb_price: NymToken,
    /// Price per GPU hour (if available)
    pub gpu_hour_price: Option<NymToken>,
    /// Base price for job submission
    pub base_job_price: NymToken,
    /// Privacy premium multiplier
    pub privacy_premium: f64,
}

impl Default for ComputePricing {
    fn default() -> Self {
        Self {
            cpu_core_hour_price: 1000,      // 0.001 Nym per core-hour
            memory_gb_hour_price: 500,      // 0.0005 Nym per GB-hour
            storage_gb_price: 100,          // 0.0001 Nym per GB
            network_gb_price: 50,           // 0.00005 Nym per GB
            gpu_hour_price: Some(10000),    // 0.01 Nym per GPU-hour
            base_job_price: 100,            // 0.0001 Nym base fee
            privacy_premium: 1.5,           // 50% premium for private jobs
        }
    }
}