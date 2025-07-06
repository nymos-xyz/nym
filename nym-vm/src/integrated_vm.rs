//! Integrated VM - Combines Core VM with Cryptographic Instructions
//! 
//! This module provides a unified interface that integrates the Core VM
//! with the advanced cryptographic instruction set for complete functionality.

use crate::error::{VMError, VMResult};
use crate::ppvm::{PPVMInstruction, ExecutionContext, ExecutionResult, Register, MemoryAddress, ExitCode};
use crate::core_vm::{CoreVM, CoreVMConfig, InstructionResult};
use crate::crypto_instructions::{CryptoInstructionProcessor, CryptoInstruction, CryptoInstructionResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Integrated Virtual Machine combining core and cryptographic capabilities
pub struct IntegratedVM {
    /// Core VM for basic operations
    core_vm: CoreVM,
    /// Cryptographic instruction processor
    crypto_processor: CryptoInstructionProcessor,
    /// VM configuration
    config: IntegratedVMConfig,
    /// Execution metrics
    metrics: IntegratedVMMetrics,
    /// Instruction dispatch table
    instruction_handlers: HashMap<String, InstructionHandler>,
}

/// Configuration for the integrated VM
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegratedVMConfig {
    /// Core VM configuration
    pub core_config: CoreVMConfig,
    /// Enable cryptographic instructions
    pub enable_crypto_instructions: bool,
    /// Enable advanced privacy features
    pub enable_advanced_privacy: bool,
    /// Maximum execution time (milliseconds)
    pub max_execution_time: u64,
    /// Enable instruction tracing
    pub enable_tracing: bool,
    /// Gas cost multiplier for crypto operations
    pub crypto_gas_multiplier: f64,
}

impl Default for IntegratedVMConfig {
    fn default() -> Self {
        Self {
            core_config: CoreVMConfig::default(),
            enable_crypto_instructions: true,
            enable_advanced_privacy: true,
            max_execution_time: 30000, // 30 seconds
            enable_tracing: false,
            crypto_gas_multiplier: 2.0,
        }
    }
}

/// Combined execution metrics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegratedVMMetrics {
    /// Core VM metrics
    pub core_metrics: crate::core_vm::ExecutionMetrics,
    /// Cryptographic operation metrics
    pub crypto_metrics: crate::crypto_instructions::CryptoMetrics,
    /// Total instructions executed
    pub total_instructions: u64,
    /// Total execution time
    pub total_execution_time: u64,
    /// Gas efficiency (instructions per gas unit)
    pub gas_efficiency: f64,
    /// Cryptographic operation ratio
    pub crypto_operation_ratio: f64,
}

/// Instruction handler types
#[derive(Debug, Clone)]
enum InstructionHandler {
    Core,
    Cryptographic,
    Hybrid,
}

/// Enhanced execution result
#[derive(Debug, Clone)]
pub struct IntegratedExecutionResult {
    /// Basic execution result
    pub base_result: ExecutionResult,
    /// Cryptographic operation results
    pub crypto_results: Vec<CryptoInstructionResult>,
    /// Total gas consumed
    pub total_gas_consumed: u64,
    /// Execution trace (if enabled)
    pub execution_trace: Option<ExecutionTrace>,
    /// Performance metrics
    pub performance_metrics: PerformanceMetrics,
}

/// Execution trace for debugging and analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionTrace {
    /// Trace entries
    pub entries: Vec<TraceEntry>,
    /// Total trace size
    pub total_entries: usize,
    /// Trace generation time
    pub generated_at: u64,
}

/// Individual trace entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceEntry {
    /// Instruction index
    pub instruction_index: u64,
    /// Instruction type
    pub instruction_type: String,
    /// Gas consumed for this instruction
    pub gas_consumed: u64,
    /// Execution time (microseconds)
    pub execution_time: u64,
    /// Memory state snapshot (optional)
    pub memory_snapshot: Option<MemorySnapshot>,
    /// Stack state snapshot (optional)
    pub stack_snapshot: Option<StackSnapshot>,
}

/// Memory state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemorySnapshot {
    /// Allocated pages
    pub allocated_pages: usize,
    /// Total memory usage
    pub memory_usage: usize,
    /// Encrypted pages count
    pub encrypted_pages: usize,
}

/// Stack state snapshot
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StackSnapshot {
    /// Current stack depth
    pub depth: usize,
    /// Encrypted entries count
    pub encrypted_entries: usize,
}

/// Performance metrics for execution analysis
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    /// Instructions per second
    pub instructions_per_second: f64,
    /// Memory access efficiency
    pub memory_efficiency: f64,
    /// Cryptographic operation efficiency
    pub crypto_efficiency: f64,
    /// Overall performance score
    pub performance_score: f64,
}

impl IntegratedVM {
    /// Create a new integrated VM
    pub fn new(config: IntegratedVMConfig) -> Self {
        let mut vm = Self {
            core_vm: CoreVM::new(config.core_config.clone()),
            crypto_processor: CryptoInstructionProcessor::new(),
            config,
            metrics: IntegratedVMMetrics::new(),
            instruction_handlers: HashMap::new(),
        };
        
        vm.initialize_instruction_handlers();
        vm
    }

    /// Initialize instruction dispatch table
    fn initialize_instruction_handlers(&mut self) {
        // Map instruction types to handlers
        let core_instructions = vec![
            "Nop", "Load", "Store", "Move", "Add", "Sub", "Mul", "Push", "Pop",
            "Jump", "JumpIf", "Call", "Return", "StateRead", "StateWrite", "Halt"
        ];

        let crypto_instructions = vec![
            "GenerateStarkProof", "VerifyStarkProof", "HomomorphicEncrypt", "HomomorphicAdd",
            "PedersenCommit", "RevealCommitment", "EvaluateZKPredicate", "RangeProof",
            "GenerateRandomness", "HashToField", "FieldArithmetic"
        ];

        for instruction in core_instructions {
            self.instruction_handlers.insert(instruction.to_string(), InstructionHandler::Core);
        }

        for instruction in crypto_instructions {
            self.instruction_handlers.insert(instruction.to_string(), InstructionHandler::Cryptographic);
        }
    }

    /// Execute a contract with enhanced capabilities
    pub fn execute_contract(
        &mut self,
        bytecode: &[u8],
        context: ExecutionContext,
    ) -> VMResult<IntegratedExecutionResult> {
        let start_time = current_timestamp();
        
        // Parse bytecode into instructions
        let instructions = self.parse_enhanced_bytecode(bytecode)?;
        
        // Initialize execution state
        let mut execution_trace = if self.config.enable_tracing {
            Some(ExecutionTrace {
                entries: Vec::new(),
                total_entries: 0,
                generated_at: start_time,
            })
        } else {
            None
        };

        let mut crypto_results = Vec::new();
        let mut total_gas_consumed = 0u64;
        let mut instruction_index = 0u64;

        // Execute instructions
        for (idx, instruction) in instructions.iter().enumerate() {
            let instruction_start = current_timestamp();
            
            // Check execution timeout
            if current_timestamp() - start_time > self.config.max_execution_time {
                return Err(VMError::ExecutionLimitExceeded);
            }

            let (instruction_result, gas_consumed) = match instruction {
                EnhancedInstruction::Core(core_inst) => {
                    let result = self.core_vm.execute_instruction(core_inst, &context)?;
                    let gas = self.calculate_core_instruction_gas(core_inst);
                    (InstructionExecutionResult::Core(result), gas)
                }
                
                EnhancedInstruction::Crypto(crypto_inst) => {
                    if !self.config.enable_crypto_instructions {
                        return Err(VMError::CryptographicError("Crypto instructions disabled".to_string()));
                    }
                    
                    let result = self.crypto_processor.execute_crypto_instruction(
                        crypto_inst,
                        &mut self.core_vm.memory_manager,
                        &mut self.core_vm.stack_manager,
                        &mut self.core_vm.state_manager,
                        &context,
                    )?;
                    
                    let gas = self.calculate_crypto_instruction_gas(&result);
                    crypto_results.push(result.clone());
                    (InstructionExecutionResult::Crypto(result), gas)
                }
            };

            total_gas_consumed += gas_consumed;
            let instruction_time = current_timestamp() - instruction_start;

            // Record trace entry if tracing is enabled
            if let Some(ref mut trace) = execution_trace {
                let entry = TraceEntry {
                    instruction_index,
                    instruction_type: self.get_instruction_type_name(instruction),
                    gas_consumed,
                    execution_time: instruction_time,
                    memory_snapshot: self.capture_memory_snapshot(),
                    stack_snapshot: self.capture_stack_snapshot(),
                };
                trace.entries.push(entry);
                trace.total_entries += 1;
            }

            // Check for halt conditions
            if let InstructionExecutionResult::Core(InstructionResult::Halt(exit_code)) = instruction_result {
                break;
            }

            instruction_index += 1;
        }

        let total_execution_time = current_timestamp() - start_time;
        
        // Generate base execution result
        let base_result = ExecutionResult {
            success: true,
            gas_used: total_gas_consumed,
            exit_code: ExitCode::Success,
            events: Vec::new(),
            state_changes: HashMap::new(),
            privacy_proofs: Vec::new(),
            execution_trace: None,
        };

        // Calculate performance metrics
        let performance_metrics = self.calculate_performance_metrics(
            instruction_index,
            total_execution_time,
            total_gas_consumed,
            &crypto_results,
        );

        // Update VM metrics
        self.update_integrated_metrics(instruction_index, total_execution_time, &crypto_results);

        Ok(IntegratedExecutionResult {
            base_result,
            crypto_results,
            total_gas_consumed,
            execution_trace,
            performance_metrics,
        })
    }

    /// Parse bytecode into enhanced instruction set
    fn parse_enhanced_bytecode(&self, bytecode: &[u8]) -> VMResult<Vec<EnhancedInstruction>> {
        let mut instructions = Vec::new();
        let mut offset = 0;

        while offset < bytecode.len() {
            if offset + 1 >= bytecode.len() {
                break;
            }

            let opcode = bytecode[offset];
            let instruction = match opcode {
                // Core instructions (0x00-0x7F)
                0x00 => EnhancedInstruction::Core(PPVMInstruction::Nop),
                0x01 => {
                    if offset + 8 < bytecode.len() {
                        let addr = u64::from_le_bytes(bytecode[offset+1..offset+9].try_into().unwrap());
                        offset += 8;
                        EnhancedInstruction::Core(PPVMInstruction::Load(MemoryAddress(addr)))
                    } else {
                        return Err(VMError::InvalidBytecode("Incomplete Load instruction".to_string()));
                    }
                }
                0x10 => {
                    if offset + 4 < bytecode.len() {
                        let reg = u32::from_le_bytes(bytecode[offset+1..offset+5].try_into().unwrap());
                        offset += 4;
                        EnhancedInstruction::Core(PPVMInstruction::Push(Register(reg)))
                    } else {
                        return Err(VMError::InvalidBytecode("Incomplete Push instruction".to_string()));
                    }
                }
                
                // Cryptographic instructions (0x80-0xFF)
                0x80 => {
                    // GenerateStarkProof instruction
                    if offset + 32 < bytecode.len() {
                        let circuit_id = String::from_utf8_lossy(&bytecode[offset+1..offset+17]).to_string();
                        let witness_addr = u64::from_le_bytes(bytecode[offset+17..offset+25].try_into().unwrap());
                        let public_inputs_addr = u64::from_le_bytes(bytecode[offset+25..offset+33].try_into().unwrap());
                        let proof_output_addr = u64::from_le_bytes(bytecode[offset+33..offset+41].try_into().unwrap());
                        offset += 40;
                        
                        EnhancedInstruction::Crypto(CryptoInstruction::GenerateStarkProof {
                            circuit_id,
                            witness_addr: MemoryAddress(witness_addr),
                            public_inputs_addr: MemoryAddress(public_inputs_addr),
                            proof_output_addr: MemoryAddress(proof_output_addr),
                        })
                    } else {
                        return Err(VMError::InvalidBytecode("Incomplete GenerateStarkProof instruction".to_string()));
                    }
                }
                
                0x90 => {
                    // PedersenCommit instruction
                    if offset + 20 < bytecode.len() {
                        let value_reg = u32::from_le_bytes(bytecode[offset+1..offset+5].try_into().unwrap());
                        let randomness_addr = u64::from_le_bytes(bytecode[offset+5..offset+13].try_into().unwrap());
                        let commitment_output_addr = u64::from_le_bytes(bytecode[offset+13..offset+21].try_into().unwrap());
                        offset += 20;
                        
                        EnhancedInstruction::Crypto(CryptoInstruction::PedersenCommit {
                            value_reg: Register(value_reg),
                            randomness_addr: MemoryAddress(randomness_addr),
                            commitment_output_addr: MemoryAddress(commitment_output_addr),
                        })
                    } else {
                        return Err(VMError::InvalidBytecode("Incomplete PedersenCommit instruction".to_string()));
                    }
                }

                _ => {
                    return Err(VMError::InvalidBytecode(format!("Unknown opcode: 0x{:02X}", opcode)));
                }
            };

            instructions.push(instruction);
            offset += 1;
        }

        Ok(instructions)
    }

    fn calculate_core_instruction_gas(&self, instruction: &PPVMInstruction) -> u64 {
        match instruction {
            PPVMInstruction::Nop => 1,
            PPVMInstruction::Load(_) | PPVMInstruction::Store(_) => self.config.core_config.memory_gas_cost,
            PPVMInstruction::Push(_) | PPVMInstruction::Pop(_) => 2,
            PPVMInstruction::Add(_, _, _) | PPVMInstruction::Sub(_, _, _) | PPVMInstruction::Mul(_, _, _) => 3,
            PPVMInstruction::StateRead(_) | PPVMInstruction::StateWrite(_, _) => self.config.core_config.state_gas_cost,
            PPVMInstruction::Halt(_) => 0,
            _ => self.config.core_config.base_gas_cost,
        }
    }

    fn calculate_crypto_instruction_gas(&self, result: &CryptoInstructionResult) -> u64 {
        let base_gas = match result {
            CryptoInstructionResult::ProofGenerated { gas_consumed, .. } |
            CryptoInstructionResult::ProofVerified { gas_consumed, .. } |
            CryptoInstructionResult::ValueEncrypted { gas_consumed, .. } |
            CryptoInstructionResult::HomomorphicOperation { gas_consumed, .. } |
            CryptoInstructionResult::CommitmentGenerated { gas_consumed, .. } |
            CryptoInstructionResult::CommitmentRevealed { gas_consumed, .. } |
            CryptoInstructionResult::PredicateEvaluated { gas_consumed, .. } |
            CryptoInstructionResult::RangeProofGenerated { gas_consumed, .. } |
            CryptoInstructionResult::RandomnessGenerated { gas_consumed, .. } |
            CryptoInstructionResult::FieldElementComputed { gas_consumed, .. } |
            CryptoInstructionResult::FieldArithmetic { gas_consumed, .. } => *gas_consumed,
        };

        ((base_gas as f64) * self.config.crypto_gas_multiplier) as u64
    }

    fn get_instruction_type_name(&self, instruction: &EnhancedInstruction) -> String {
        match instruction {
            EnhancedInstruction::Core(core_inst) => format!("Core::{:?}", core_inst).split('(').next().unwrap_or("Unknown").to_string(),
            EnhancedInstruction::Crypto(crypto_inst) => format!("Crypto::{:?}", crypto_inst).split('{').next().unwrap_or("Unknown").to_string(),
        }
    }

    fn capture_memory_snapshot(&self) -> Option<MemorySnapshot> {
        if !self.config.enable_tracing {
            return None;
        }

        let memory_stats = self.core_vm.memory_manager.get_memory_stats();
        Some(MemorySnapshot {
            allocated_pages: memory_stats.allocated_pages,
            memory_usage: memory_stats.used_memory,
            encrypted_pages: memory_stats.encrypted_pages,
        })
    }

    fn capture_stack_snapshot(&self) -> Option<StackSnapshot> {
        if !self.config.enable_tracing {
            return None;
        }

        let stack_stats = self.core_vm.stack_manager.get_stack_stats();
        Some(StackSnapshot {
            depth: stack_stats.current_depth,
            encrypted_entries: stack_stats.encrypted_entries,
        })
    }

    fn calculate_performance_metrics(
        &self,
        total_instructions: u64,
        execution_time: u64,
        total_gas: u64,
        crypto_results: &[CryptoInstructionResult],
    ) -> PerformanceMetrics {
        let instructions_per_second = if execution_time > 0 {
            (total_instructions as f64) / (execution_time as f64 / 1000.0)
        } else {
            0.0
        };

        let memory_stats = self.core_vm.memory_manager.get_memory_stats();
        let memory_efficiency = if memory_stats.total_memory > 0 {
            (memory_stats.used_memory as f64) / (memory_stats.total_memory as f64)
        } else {
            0.0
        };

        let crypto_efficiency = if !crypto_results.is_empty() {
            let avg_crypto_gas: f64 = crypto_results.iter()
                .map(|r| self.calculate_crypto_instruction_gas(r) as f64)
                .sum::<f64>() / crypto_results.len() as f64;
            1.0 / (avg_crypto_gas / 1000.0) // Inverse of average gas cost
        } else {
            1.0
        };

        let performance_score = (instructions_per_second / 1000.0 + memory_efficiency + crypto_efficiency) / 3.0;

        PerformanceMetrics {
            instructions_per_second,
            memory_efficiency,
            crypto_efficiency,
            performance_score: performance_score.min(1.0),
        }
    }

    fn update_integrated_metrics(
        &mut self,
        total_instructions: u64,
        execution_time: u64,
        crypto_results: &[CryptoInstructionResult],
    ) {
        self.metrics.total_instructions += total_instructions;
        self.metrics.total_execution_time += execution_time;

        if total_instructions > 0 {
            self.metrics.crypto_operation_ratio = crypto_results.len() as f64 / total_instructions as f64;
        }

        // Update crypto metrics from processor
        self.metrics.crypto_metrics = self.crypto_processor.get_metrics().clone();
    }

    /// Get comprehensive VM statistics
    pub fn get_comprehensive_stats(&self) -> IntegratedVMStats {
        IntegratedVMStats {
            core_stats: self.core_vm.get_comprehensive_stats(),
            crypto_metrics: self.crypto_processor.get_metrics().clone(),
            integrated_metrics: self.metrics.clone(),
            config: self.config.clone(),
        }
    }

    /// Reset VM state for new execution
    pub fn reset(&mut self) {
        self.core_vm.reset();
        self.crypto_processor.reset_metrics();
        self.metrics = IntegratedVMMetrics::new();
    }

    /// Enable or disable instruction tracing
    pub fn set_tracing_enabled(&mut self, enabled: bool) {
        self.config.enable_tracing = enabled;
    }

    /// Get current execution metrics
    pub fn get_current_metrics(&self) -> &IntegratedVMMetrics {
        &self.metrics
    }
}

/// Enhanced instruction type that combines core and cryptographic instructions
#[derive(Debug, Clone)]
enum EnhancedInstruction {
    Core(PPVMInstruction),
    Crypto(CryptoInstruction),
}

/// Result of executing an instruction
#[derive(Debug, Clone)]
enum InstructionExecutionResult {
    Core(InstructionResult),
    Crypto(CryptoInstructionResult),
}

/// Comprehensive VM statistics
#[derive(Debug, Clone)]
pub struct IntegratedVMStats {
    pub core_stats: crate::core_vm::CoreVMStats,
    pub crypto_metrics: crate::crypto_instructions::CryptoMetrics,
    pub integrated_metrics: IntegratedVMMetrics,
    pub config: IntegratedVMConfig,
}

impl IntegratedVMMetrics {
    pub fn new() -> Self {
        Self {
            core_metrics: crate::core_vm::ExecutionMetrics::new(),
            crypto_metrics: crate::crypto_instructions::CryptoMetrics::new(),
            total_instructions: 0,
            total_execution_time: 0,
            gas_efficiency: 0.0,
            crypto_operation_ratio: 0.0,
        }
    }
}

fn current_timestamp() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ppvm::{ContractAddress};
    use nym_core::NymIdentity;
    use nym_crypto::Hash256;

    #[test]
    fn test_integrated_vm_creation() {
        let config = IntegratedVMConfig::default();
        let vm = IntegratedVM::new(config);
        
        assert!(vm.config.enable_crypto_instructions);
        assert!(vm.config.enable_advanced_privacy);
    }

    #[test]
    fn test_instruction_handler_mapping() {
        let config = IntegratedVMConfig::default();
        let vm = IntegratedVM::new(config);
        
        assert!(vm.instruction_handlers.contains_key("Nop"));
        assert!(vm.instruction_handlers.contains_key("GenerateStarkProof"));
        assert!(vm.instruction_handlers.contains_key("PedersenCommit"));
    }

    #[test]
    fn test_bytecode_parsing() {
        let config = IntegratedVMConfig::default();
        let vm = IntegratedVM::new(config);
        
        // Simple bytecode: NOP instruction
        let bytecode = vec![0x00];
        let instructions = vm.parse_enhanced_bytecode(&bytecode).unwrap();
        
        assert_eq!(instructions.len(), 1);
        match &instructions[0] {
            EnhancedInstruction::Core(PPVMInstruction::Nop) => {},
            _ => panic!("Expected Nop instruction"),
        }
    }

    #[test]
    fn test_gas_calculation() {
        let config = IntegratedVMConfig::default();
        let vm = IntegratedVM::new(config);
        
        let nop_gas = vm.calculate_core_instruction_gas(&PPVMInstruction::Nop);
        assert_eq!(nop_gas, 1);

        let crypto_result = CryptoInstructionResult::RandomnessGenerated {
            length: 32,
            gas_consumed: 100,
        };
        let crypto_gas = vm.calculate_crypto_instruction_gas(&crypto_result);
        assert_eq!(crypto_gas, 200); // 100 * 2.0 multiplier
    }

    #[test]
    fn test_performance_metrics() {
        let config = IntegratedVMConfig::default();
        let vm = IntegratedVM::new(config);
        
        let metrics = vm.calculate_performance_metrics(1000, 5000, 5000, &[]);
        
        assert!(metrics.instructions_per_second > 0.0);
        assert!(metrics.performance_score >= 0.0 && metrics.performance_score <= 1.0);
    }

    #[test]
    fn test_vm_reset() {
        let config = IntegratedVMConfig::default();
        let mut vm = IntegratedVM::new(config);
        
        // Simulate some execution
        vm.metrics.total_instructions = 1000;
        vm.metrics.total_execution_time = 5000;
        
        vm.reset();
        
        assert_eq!(vm.metrics.total_instructions, 0);
        assert_eq!(vm.metrics.total_execution_time, 0);
    }
}