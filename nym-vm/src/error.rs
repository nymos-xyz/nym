//! VM error types

use std::fmt;

/// Virtual machine execution errors
#[derive(Debug, Clone)]
pub enum VMError {
    /// Memory access violation
    MemoryAccessViolation(String),
    /// Stack overflow
    StackOverflow,
    /// Stack underflow
    StackUnderflow,
    /// Out of gas
    OutOfGas,
    /// Execution limit exceeded
    ExecutionLimitExceeded,
    /// Invalid instruction
    InvalidInstruction(String),
    /// Privacy features not enabled
    PrivacyNotEnabled,
    /// Zero-knowledge proofs not enabled
    ZkProofsNotEnabled,
    /// Cryptographic error
    CryptographicError(String),
    /// Invalid bytecode
    InvalidBytecode(String),
    /// Contract not found
    ContractNotFound(String),
    /// Call stack overflow
    CallStackOverflow,
    /// Division by zero
    DivisionByZero,
    /// Out of memory
    OutOfMemory,
    /// Invalid page ID
    InvalidPageId,
    /// Page not allocated
    PageNotAllocated,
    /// Contract already exists
    ContractAlreadyExists,
    /// Unsupported instruction
    UnsupportedInstruction,
    /// Generic error with message
    Other(String),
}

impl fmt::Display for VMError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            VMError::MemoryAccessViolation(msg) => write!(f, "Memory access violation: {}", msg),
            VMError::StackOverflow => write!(f, "Stack overflow"),
            VMError::StackUnderflow => write!(f, "Stack underflow"),
            VMError::OutOfGas => write!(f, "Out of gas"),
            VMError::ExecutionLimitExceeded => write!(f, "Execution limit exceeded"),
            VMError::InvalidInstruction(msg) => write!(f, "Invalid instruction: {}", msg),
            VMError::PrivacyNotEnabled => write!(f, "Privacy features not enabled"),
            VMError::ZkProofsNotEnabled => write!(f, "Zero-knowledge proofs not enabled"),
            VMError::CryptographicError(msg) => write!(f, "Cryptographic error: {}", msg),
            VMError::InvalidBytecode(msg) => write!(f, "Invalid bytecode: {}", msg),
            VMError::ContractNotFound(msg) => write!(f, "Contract not found: {}", msg),
            VMError::CallStackOverflow => write!(f, "Call stack overflow"),
            VMError::DivisionByZero => write!(f, "Division by zero"),
            VMError::OutOfMemory => write!(f, "Out of memory"),
            VMError::InvalidPageId => write!(f, "Invalid page ID"),
            VMError::PageNotAllocated => write!(f, "Page not allocated"),
            VMError::ContractAlreadyExists => write!(f, "Contract already exists"),
            VMError::UnsupportedInstruction => write!(f, "Unsupported instruction"),
            VMError::Other(msg) => write!(f, "VM error: {}", msg),
        }
    }
}

impl std::error::Error for VMError {}

/// Result type for VM operations
pub type VMResult<T> = Result<T, VMError>;