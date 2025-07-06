//! Nym Virtual Machine - Privacy-preserving smart contract execution
//! 
//! This module provides:
//! - Privacy-Preserving Virtual Machine (PPVM)
//! - Core VM implementation with enhanced features
//! - Encrypted memory management
//! - Zero-knowledge proof generation
//! - Gas metering for privacy operations

pub mod error;
pub mod ppvm;
pub mod core_vm;
pub mod crypto_instructions;
pub mod integrated_vm;

pub use error::{VMError, VMResult};
pub use ppvm::{
    PPVM, PPVMConfig, PPVMInstruction, ExecutionContext, ExecutionResult,
    Register, MemoryAddress, ExitCode
};
pub use core_vm::{
    CoreVM, CoreVMConfig, MemoryManager, StackManager, ContractStateManager,
    InstructionEngine, CoreVMStats, MemoryStats, StackStats, StateManagerStats,
    ExecutionStats, InstructionResult
};
pub use crypto_instructions::{
    CryptoInstructionProcessor, CryptoInstruction, CryptoInstructionResult,
    StarkProofSystem, HomomorphicEngine, CommitmentHandler, ZKPredicateEvaluator,
    StarkProof, EncryptedValue, Commitment, FieldOperation, CryptoMetrics
};
pub use integrated_vm::{
    IntegratedVM, IntegratedVMConfig, IntegratedExecutionResult, IntegratedVMMetrics,
    IntegratedVMStats, ExecutionTrace, PerformanceMetrics
};