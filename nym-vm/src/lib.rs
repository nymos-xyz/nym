//! Nym Virtual Machine - Privacy-preserving smart contract execution
//! 
//! This module provides:
//! - Privacy-Preserving Virtual Machine (PPVM)
//! - Core VM implementation with enhanced features
//! - Encrypted memory management
//! - Zero-knowledge proof generation
//! - Gas metering for privacy operations
//! - VM Security and Optimization

pub mod error;
pub mod ppvm;
pub mod core_vm;
pub mod crypto_instructions;
pub mod integrated_vm;
pub mod security;
pub mod optimization;
pub mod secure_vm;

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
pub use security::{
    SecurityManager, SandboxConfig, ResourceLimits, SecurityPolicies, SecurityMonitor,
    SecurityViolation, SecurityMetrics, IsolationContext, MemoryOperation
};
pub use optimization::{
    OptimizationEngine, OptimizationConfig, OptimizationMetrics, OptimizationOpportunity,
    InstructionCache, MemoryOptimizer, GasOptimizer, CryptoOptimizer, ExecutionProfiler
};
pub use secure_vm::{
    SecureVM, SecureVMConfig, SecureVMMetrics, SecureExecutionResult, VulnerabilityScanResult,
    ExecutionAuditTrail, SecurityStatus, SecureVMReport
};