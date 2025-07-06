//! NymScript Language - Privacy-preserving smart contract language
//! 
//! This module provides the complete NymScript language implementation:
//! - Language specification and syntax design
//! - Type system with privacy guarantees
//! - Parser and lexer
//! - Compiler architecture
//! - Standard library for privacy operations
//! - Code generation for the Nym VM

pub mod ast;
pub mod lexer;
pub mod parser;
pub mod types;
pub mod compiler;
pub mod codegen;
pub mod stdlib;
pub mod privacy;
pub mod analyzer;
pub mod optimizer;
pub mod error;
pub mod privacy_features;
pub mod privacy_syntax;
pub mod crypto_stdlib;
pub mod privacy_utils;
pub mod contract_deployment;
pub mod execution_environment;
pub mod storage_optimization;

pub use ast::{
    NymScriptAST, Statement, Expression, Declaration, Function, Contract,
    PrivacyAnnotation, SecurityLevel, TypeConstraint, PrivacyLevel
};
pub use lexer::{NymScriptLexer, Token, TokenType, LexerError};
pub use parser::{NymScriptParser, ParseResult, ParseError};
pub use types::{
    NymType, PrivacyType, TypeChecker, TypeInference,
    TypeEnvironment
};
pub use compiler::{
    NymScriptCompiler, CompilerConfig, CompilerResult, CompilerError,
    CompilationUnit, CompilerPass
};
pub use codegen::{
    CodeGenerator, BytecodeGenerator, VMInstructionGenerator,
    CodegenResult
};
pub use stdlib::{
    StandardLibrary, PrivacyPrimitives, CryptographicFunctions,
    UtilityFunctions, LibraryFunction
};
pub use privacy::{
    PrivacyAnalyzer, PrivacyChecker, InformationFlowAnalysis,
    PrivacyPreservingTransformation, PrivacyViolation
};
pub use analyzer::{
    SemanticAnalyzer, ScopeAnalyzer, ControlFlowAnalyzer,
    SecurityAnalyzer, AnalysisResult
};
pub use optimizer::{
    LanguageOptimizer, OptimizationLevel, OptimizationPass,
    ConstantFolding, DeadCodeElimination, PrivacyOptimization
};
pub use error::{NymScriptError, ErrorType, ErrorSeverity, ErrorContext};
pub use privacy_features::{
    PrivateVariableDeclaration, ZKProofGeneration, EncryptedComputation,
    AnonymousFunctionCall, PrivacyFeatureManager, EncryptionKey, ZKCircuit,
    ZKWitness, ZKProof, ProofSystem
};