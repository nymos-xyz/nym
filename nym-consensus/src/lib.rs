pub mod error;
pub mod pow;
pub mod pos;
pub mod hybrid;
pub mod types;
pub mod difficulty;
pub mod validator;
pub mod mining;

pub use error::{ConsensusError, ConsensusResult};
pub use pow::{ProofOfWork, PowMiner, PowValidator, PowConfig};
pub use pos::{ProofOfStake, PosValidator, PosConfig, StakeManager};
pub use hybrid::{HybridConsensus, HybridConsensusConfig, ConsensusEngine};
pub use types::{
    Block, BlockHeader, ConsensusData, ValidationResult, 
    MiningResult, StakeInfo, ValidatorInfo, ConsensusState
};
pub use difficulty::{DifficultyAdjustment, DifficultyTarget};
pub use validator::{ValidatorSet, ValidatorManager};
pub use mining::{MiningPool, MiningJob, MiningWorker};