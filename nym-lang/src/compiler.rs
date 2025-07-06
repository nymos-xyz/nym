//! NymScript Compiler Architecture - Week 61-62
//! 
//! This module implements the complete compiler architecture for NymScript:
//! - Multi-pass compilation pipeline
//! - Privacy-aware optimizations
//! - Target-specific code generation
//! - Compiler configuration and management

use crate::ast::{NymScriptAST, Expression, Statement, Function, Contract};
use crate::types::{TypeSystem, NymType, TypeError};
use crate::lexer::{NymScriptLexer, Token};
use crate::parser::{NymScriptParser, ParseError};
use crate::analyzer::{SemanticAnalyzer, AnalysisResult};
use crate::optimizer::{LanguageOptimizer, OptimizationLevel};
use crate::codegen::{CodeGenerator, BytecodeGenerator};
use crate::error::{NymScriptError, ErrorType, ErrorSeverity};
use serde::{Deserialize, Serialize};

/// Type alias for compiler errors
pub type CompilerError = NymScriptError;

/// Type alias for compilation results
pub type CompilerResult<T> = Result<T, CompilerError>;
use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Complete NymScript compiler
pub struct NymScriptCompiler {
    /// Compiler configuration
    config: CompilerConfig,
    /// Type system
    type_system: TypeSystem,
    /// Semantic analyzer
    analyzer: SemanticAnalyzer,
    /// Language optimizer
    optimizer: LanguageOptimizer,
    /// Code generator
    codegen: CodeGenerator,
    /// Compilation cache
    cache: CompilationCache,
    /// Compiler statistics
    stats: CompilerStatistics,
}

/// Compiler configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerConfig {
    /// Target platform
    pub target: CompilationTarget,
    /// Optimization level
    pub optimization_level: OptimizationLevel,
    /// Privacy enforcement level
    pub privacy_enforcement: PrivacyEnforcement,
    /// Security level
    pub security_level: SecurityLevel,
    /// Enable debug information
    pub debug_info: bool,
    /// Enable warnings
    pub warnings: bool,
    /// Treat warnings as errors
    pub warnings_as_errors: bool,
    /// Output directory
    pub output_dir: PathBuf,
    /// Library search paths
    pub library_paths: Vec<PathBuf>,
    /// Preprocessor definitions
    pub defines: HashMap<String, String>,
    /// Compiler features
    pub features: HashSet<CompilerFeature>,
    /// Memory limits
    pub memory_limits: MemoryLimits,
    /// Gas estimation settings
    pub gas_estimation: GasEstimationConfig,
}

/// Compilation targets
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CompilationTarget {
    /// Nym Virtual Machine
    NymVM,
    /// WebAssembly
    WASM,
    /// Native x86_64
    NativeX64,
    /// Native ARM64
    NativeARM64,
    /// LLVM IR
    LLVM,
    /// JavaScript
    JavaScript,
}

/// Privacy enforcement levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PrivacyEnforcement {
    /// No privacy enforcement
    None,
    /// Warning only
    Warning,
    /// Strict enforcement
    Strict,
    /// Cryptographic enforcement
    Cryptographic,
}

/// Security levels for compilation
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Development mode - relaxed security
    Development,
    /// Testing mode - moderate security
    Testing,
    /// Production mode - strict security
    Production,
    /// High security mode - maximum security
    HighSecurity,
}

/// Compiler features
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CompilerFeature {
    /// Zero-knowledge proofs
    ZeroKnowledge,
    /// Homomorphic encryption
    HomomorphicEncryption,
    /// Anonymous computation
    AnonymousComputation,
    /// Secure multi-party computation
    SecureMultiParty,
    /// Differential privacy
    DifferentialPrivacy,
    /// Threshold cryptography
    ThresholdCrypto,
    /// Post-quantum cryptography
    PostQuantumCrypto,
    /// Formal verification
    FormalVerification,
}

/// Memory limits for compilation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryLimits {
    /// Maximum heap size
    pub max_heap: usize,
    /// Maximum stack size
    pub max_stack: usize,
    /// Maximum compilation time
    pub max_compile_time: Duration,
    /// Maximum AST nodes
    pub max_ast_nodes: usize,
}

/// Gas estimation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasEstimationConfig {
    /// Enable gas estimation
    pub enabled: bool,
    /// Base gas costs
    pub base_costs: HashMap<String, u64>,
    /// Privacy operation multipliers
    pub privacy_multipliers: HashMap<String, f64>,
    /// Complexity factors
    pub complexity_factors: HashMap<String, f64>,
}

/// Compilation unit representing a single source file
#[derive(Debug, Clone)]
pub struct CompilationUnit {
    /// Source file path
    pub source_path: PathBuf,
    /// Source content
    pub source_content: String,
    /// Parsed AST
    pub ast: Option<NymScriptAST>,
    /// Type-checked AST
    pub typed_ast: Option<TypedAST>,
    /// Analysis results
    pub analysis: Option<AnalysisResult>,
    /// Generated code
    pub generated_code: Option<GeneratedCode>,
    /// Compilation metadata
    pub metadata: CompilationMetadata,
}

/// Type-checked AST with type annotations
#[derive(Debug, Clone)]
pub struct TypedAST {
    /// Original AST
    pub ast: NymScriptAST,
    /// Type annotations
    pub type_annotations: HashMap<String, NymType>,
    /// Privacy annotations
    pub privacy_annotations: HashMap<String, PrivacyInfo>,
    /// Security annotations
    pub security_annotations: HashMap<String, SecurityInfo>,
}

/// Generated code for a compilation unit
#[derive(Debug, Clone)]
pub struct GeneratedCode {
    /// Target platform
    pub target: CompilationTarget,
    /// Generated bytecode/code
    pub code: Vec<u8>,
    /// Debug information
    pub debug_info: Option<DebugInfo>,
    /// Symbol table
    pub symbols: SymbolTable,
    /// Metadata
    pub metadata: CodeMetadata,
}

/// Compilation metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilationMetadata {
    /// Compilation timestamp
    pub timestamp: u64,
    /// Compiler version
    pub compiler_version: String,
    /// Source hash
    pub source_hash: String,
    /// Dependencies
    pub dependencies: Vec<Dependency>,
    /// Compilation flags
    pub flags: HashMap<String, String>,
}

/// Privacy information for AST nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyInfo {
    /// Privacy level
    pub level: crate::ast::PrivacyLevel,
    /// Required proofs
    pub required_proofs: Vec<String>,
    /// Anonymity requirements
    pub anonymity_requirements: Vec<AnonymityRequirement>,
    /// Information flow constraints
    pub flow_constraints: Vec<FlowConstraint>,
}

/// Security information for AST nodes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityInfo {
    /// Security level
    pub level: crate::ast::SecurityLevel,
    /// Security policies
    pub policies: Vec<String>,
    /// Threat model
    pub threat_model: String,
    /// Security assumptions
    pub assumptions: Vec<String>,
}

/// Debug information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugInfo {
    /// Source maps
    pub source_maps: Vec<SourceMapping>,
    /// Line number table
    pub line_numbers: HashMap<u64, u32>,
    /// Variable names
    pub variable_names: HashMap<u64, String>,
    /// Function names
    pub function_names: HashMap<u64, String>,
}

/// Source mapping for debug info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceMapping {
    /// Generated code offset
    pub generated_offset: u64,
    /// Source file line
    pub source_line: u32,
    /// Source file column
    pub source_column: u32,
    /// Source file name
    pub source_file: String,
}

/// Symbol table
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SymbolTable {
    /// Global symbols
    pub globals: HashMap<String, Symbol>,
    /// Function symbols
    pub functions: HashMap<String, FunctionSymbol>,
    /// Type symbols
    pub types: HashMap<String, TypeSymbol>,
    /// Import symbols
    pub imports: HashMap<String, ImportSymbol>,
}

/// Symbol information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Symbol {
    /// Symbol name
    pub name: String,
    /// Symbol type
    pub symbol_type: NymType,
    /// Symbol address/offset
    pub address: u64,
    /// Symbol visibility
    pub visibility: SymbolVisibility,
    /// Privacy level
    pub privacy: crate::ast::PrivacyLevel,
}

/// Function symbol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSymbol {
    /// Function name
    pub name: String,
    /// Function signature
    pub signature: FunctionSignature,
    /// Function address
    pub address: u64,
    /// Parameter offsets
    pub parameter_offsets: Vec<u64>,
    /// Local variable offsets
    pub local_offsets: HashMap<String, u64>,
    /// Privacy level
    pub privacy: crate::ast::PrivacyLevel,
}

/// Function signature
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionSignature {
    /// Parameter types
    pub parameters: Vec<NymType>,
    /// Return type
    pub return_type: NymType,
    /// Privacy effects
    pub privacy_effects: Vec<PrivacyEffect>,
    /// Gas cost estimation
    pub gas_cost: Option<u64>,
}

/// Type symbol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeSymbol {
    /// Type name
    pub name: String,
    /// Type definition
    pub definition: TypeDefinition,
    /// Size in bytes
    pub size: usize,
    /// Alignment
    pub alignment: usize,
}

/// Import symbol
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImportSymbol {
    /// Import name
    pub name: String,
    /// Import path
    pub path: String,
    /// Imported symbols
    pub symbols: Vec<String>,
    /// Privacy level
    pub privacy: crate::ast::PrivacyLevel,
}

/// Symbol visibility
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SymbolVisibility {
    Private,
    Public,
    Internal,
    External,
}

/// Code metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeMetadata {
    /// Code size
    pub code_size: usize,
    /// Data size
    pub data_size: usize,
    /// Entry point
    pub entry_point: Option<u64>,
    /// Gas estimation
    pub gas_estimate: Option<u64>,
    /// Privacy level
    pub privacy_level: crate::ast::PrivacyLevel,
    /// Security level
    pub security_level: crate::ast::SecurityLevel,
}

/// Dependency information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    /// Dependency name
    pub name: String,
    /// Version
    pub version: String,
    /// Source
    pub source: DependencySource,
    /// Hash
    pub hash: String,
}

/// Dependency sources
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DependencySource {
    /// Local file system
    Local(PathBuf),
    /// Remote repository
    Remote(String),
    /// Package registry
    Registry(String),
}

/// Compilation cache
pub struct CompilationCache {
    /// Cached compilation units
    units: HashMap<String, CachedCompilationUnit>,
    /// Cache statistics
    stats: CacheStatistics,
    /// Cache configuration
    config: CacheConfig,
}

/// Cached compilation unit
#[derive(Debug, Clone)]
pub struct CachedCompilationUnit {
    /// Source hash
    pub source_hash: String,
    /// Compiled output
    pub output: GeneratedCode,
    /// Compilation time
    pub compile_time: Duration,
    /// Cache timestamp
    pub timestamp: Instant,
    /// Dependencies
    pub dependencies: Vec<String>,
}

/// Cache statistics
#[derive(Debug, Clone, Default)]
pub struct CacheStatistics {
    /// Cache hits
    pub hits: u64,
    /// Cache misses
    pub misses: u64,
    /// Cache invalidations
    pub invalidations: u64,
    /// Total cached units
    pub cached_units: usize,
    /// Cache size in bytes
    pub cache_size: usize,
}

/// Cache configuration
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Enable caching
    pub enabled: bool,
    /// Maximum cache size
    pub max_size: usize,
    /// Maximum age
    pub max_age: Duration,
    /// Cache directory
    pub cache_dir: PathBuf,
}

/// Compiler statistics
#[derive(Debug, Clone, Default)]
pub struct CompilerStatistics {
    /// Total compilation time
    pub total_compile_time: Duration,
    /// Files compiled
    pub files_compiled: usize,
    /// Lines of code compiled
    pub lines_compiled: usize,
    /// Errors encountered
    pub errors: usize,
    /// Warnings generated
    pub warnings: usize,
    /// Cache statistics
    pub cache_stats: CacheStatistics,
    /// Memory usage
    pub memory_usage: MemoryUsage,
}

/// Memory usage statistics
#[derive(Debug, Clone, Default)]
pub struct MemoryUsage {
    /// Peak heap usage
    pub peak_heap: usize,
    /// Peak stack usage
    pub peak_stack: usize,
    /// Total allocations
    pub total_allocations: usize,
    /// Total deallocations
    pub total_deallocations: usize,
}

/// Compilation result
#[derive(Debug)]
pub struct CompilerOutput {
    /// Compilation success
    pub success: bool,
    /// Generated code
    pub code: Option<GeneratedCode>,
    /// Compilation errors
    pub errors: Vec<NymScriptError>,
    /// Compilation warnings
    pub warnings: Vec<CompilerWarning>,
    /// Compilation statistics
    pub statistics: CompilerStatistics,
    /// Metadata
    pub metadata: CompilationMetadata,
}

/// Compiler warning
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CompilerWarning {
    /// Warning message
    pub message: String,
    /// Warning location
    pub location: Option<SourceLocation>,
    /// Warning kind
    pub kind: WarningKind,
    /// Suggested fix
    pub suggestion: Option<String>,
}

/// Warning kinds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum WarningKind {
    /// Unused variable
    UnusedVariable,
    /// Unused function
    UnusedFunction,
    /// Unreachable code
    UnreachableCode,
    /// Privacy warning
    Privacy(PrivacyWarningKind),
    /// Security warning
    Security(SecurityWarningKind),
    /// Performance warning
    Performance(String),
    /// Style warning
    Style(String),
}

/// Privacy warning kinds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivacyWarningKind {
    /// Potential privacy leak
    PotentialLeak,
    /// Suboptimal privacy level
    SuboptimalLevel,
    /// Missing anonymity
    MissingAnonymity,
    /// Insecure declassification
    InsecureDeclassification,
}

/// Security warning kinds
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityWarningKind {
    /// Potential vulnerability
    PotentialVulnerability(String),
    /// Insecure pattern
    InsecurePattern(String),
    /// Missing security check
    MissingSecurityCheck,
    /// Weak cryptography
    WeakCryptography,
}

/// Source location for error reporting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SourceLocation {
    /// File path
    pub file: String,
    /// Line number
    pub line: u32,
    /// Column number
    pub column: u32,
    /// Character offset
    pub offset: usize,
}

/// Compiler pass interface
pub trait CompilerPass {
    /// Pass name
    fn name(&self) -> &str;
    
    /// Execute the pass
    fn execute(&mut self, unit: &mut CompilationUnit) -> Result<(), Vec<NymScriptError>>;
    
    /// Pass dependencies
    fn dependencies(&self) -> Vec<&str> {
        Vec::new()
    }
    
    /// Pass requirements
    fn requirements(&self) -> PassRequirements {
        PassRequirements::default()
    }
}

/// Pass requirements
#[derive(Debug, Clone, Default)]
pub struct PassRequirements {
    /// Requires parsed AST
    pub requires_ast: bool,
    /// Requires type checking
    pub requires_type_checking: bool,
    /// Requires semantic analysis
    pub requires_semantic_analysis: bool,
    /// Modifies AST
    pub modifies_ast: bool,
    /// Generates code
    pub generates_code: bool,
}

// Placeholder types for complex structures
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnonymityRequirement {
    pub min_set_size: u32,
    pub diversity_requirements: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowConstraint {
    pub from: String,
    pub to: String,
    pub transformation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivacyEffect {
    pub effect_type: String,
    pub parameters: HashMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TypeDefinition {
    pub name: String,
    pub kind: TypeKind,
    pub fields: Vec<FieldInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TypeKind {
    Struct,
    Enum,
    Interface,
    Alias,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FieldInfo {
    pub name: String,
    pub field_type: NymType,
    pub offset: usize,
}

impl NymScriptCompiler {
    /// Create new compiler with configuration
    pub fn new(config: CompilerConfig) -> Self {
        Self {
            config,
            type_system: TypeSystem::new(),
            analyzer: SemanticAnalyzer::new(),
            optimizer: LanguageOptimizer::new(OptimizationLevel::Balanced),
            codegen: CodeGenerator::new(),
            cache: CompilationCache::new(),
            stats: CompilerStatistics::default(),
        }
    }

    /// Compile a single file
    pub fn compile_file<P: AsRef<Path>>(&mut self, source_path: P) -> CompilerOutput {
        let start_time = Instant::now();
        let source_path = source_path.as_ref().to_path_buf();
        
        // Read source file
        let source_content = match std::fs::read_to_string(&source_path) {
            Ok(content) => content,
            Err(e) => {
                return CompilerOutput {
                    success: false,
                    code: None,
                    errors: vec![NymScriptError::io_error(format!("Failed to read file: {}", e))],
                    warnings: Vec::new(),
                    statistics: self.stats.clone(),
                    metadata: CompilationMetadata::new(&source_path, &self.config),
                };
            }
        };

        // Create compilation unit
        let mut unit = CompilationUnit {
            source_path: source_path.clone(),
            source_content,
            ast: None,
            typed_ast: None,
            analysis: None,
            generated_code: None,
            metadata: CompilationMetadata::new(&source_path, &self.config),
        };

        // Execute compilation pipeline
        let result = self.compile_unit(&mut unit);
        
        // Update statistics
        self.stats.total_compile_time += start_time.elapsed();
        self.stats.files_compiled += 1;
        if let Some(ast) = &unit.ast {
            self.stats.lines_compiled += self.count_lines(&ast);
        }

        result
    }

    /// Compile multiple files
    pub fn compile_files<P: AsRef<Path>>(&mut self, source_paths: &[P]) -> Vec<CompilerOutput> {
        source_paths.iter()
            .map(|path| self.compile_file(path))
            .collect()
    }

    /// Compile a compilation unit
    fn compile_unit(&mut self, unit: &mut CompilationUnit) -> CompilerOutput {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        // Check cache first
        if self.cache.config.enabled {
            if let Some(cached) = self.cache.get(&unit.source_content) {
                self.stats.cache_stats.hits += 1;
                return CompilerOutput {
                    success: true,
                    code: Some(cached.output),
                    errors: Vec::new(),
                    warnings: Vec::new(),
                    statistics: self.stats.clone(),
                    metadata: unit.metadata.clone(),
                };
            }
            self.stats.cache_stats.misses += 1;
        }

        // Parse source code
        match self.parse_source(&unit.source_content) {
            Ok(ast) => unit.ast = Some(ast),
            Err(parse_errors) => {
                errors.extend(parse_errors.into_iter().map(NymScriptError::from));
            }
        }

        // Type checking
        if let Some(ref ast) = unit.ast {
            match self.type_system.type_check_program(ast) {
                Ok(()) => {
                    unit.typed_ast = Some(TypedAST {
                        ast: ast.clone(),
                        type_annotations: HashMap::new(),
                        privacy_annotations: HashMap::new(),
                        security_annotations: HashMap::new(),
                    });
                }
                Err(type_errors) => {
                    errors.extend(type_errors.into_iter().map(NymScriptError::from));
                }
            }
        }

        // Semantic analysis
        if let Some(ref typed_ast) = unit.typed_ast {
            match self.analyzer.analyze(&typed_ast.ast) {
                Ok(analysis) => unit.analysis = Some(analysis),
                Err(analysis_errors) => {
                    errors.extend(analysis_errors.into_iter().map(NymScriptError::from));
                }
            }
        }

        // Optimization
        if let Some(ref mut typed_ast) = unit.typed_ast {
            if let Err(opt_errors) = self.optimizer.optimize(&mut typed_ast.ast) {
                warnings.extend(opt_errors.into_iter().map(|e| CompilerWarning {
                    message: e.to_string(),
                    location: None,
                    kind: WarningKind::Performance("Optimization failed".to_string()),
                    suggestion: None,
                }));
            }
        }

        // Code generation
        if let Some(ref typed_ast) = unit.typed_ast {
            match self.codegen.generate(&typed_ast.ast, &self.config.target) {
                Ok(code) => {
                    unit.generated_code = Some(code.clone());
                    
                    // Cache the result
                    if self.cache.config.enabled {
                        self.cache.insert(&unit.source_content, &code);
                    }

                    CompilerOutput {
                        success: errors.is_empty(),
                        code: Some(code),
                        errors,
                        warnings,
                        statistics: self.stats.clone(),
                        metadata: unit.metadata.clone(),
                    }
                }
                Err(codegen_errors) => {
                    errors.extend(codegen_errors);
                    CompilerOutput {
                        success: false,
                        code: None,
                        errors,
                        warnings,
                        statistics: self.stats.clone(),
                        metadata: unit.metadata.clone(),
                    }
                }
            }
        } else {
            CompilerOutput {
                success: false,
                code: None,
                errors,
                warnings,
                statistics: self.stats.clone(),
                metadata: unit.metadata.clone(),
            }
        }
    }

    /// Parse source code
    fn parse_source(&mut self, source: &str) -> Result<NymScriptAST, Vec<ParseError>> {
        let mut lexer = NymScriptLexer::new(source);
        let tokens = lexer.tokenize()?;
        
        let mut parser = NymScriptParser::new(tokens);
        parser.parse()
    }

    /// Count lines in AST (for statistics)
    fn count_lines(&self, _ast: &NymScriptAST) -> usize {
        // Simplified line counting
        100 // Placeholder
    }

    /// Get compiler statistics
    pub fn get_statistics(&self) -> &CompilerStatistics {
        &self.stats
    }

    /// Get compiler configuration
    pub fn get_config(&self) -> &CompilerConfig {
        &self.config
    }

    /// Update compiler configuration
    pub fn update_config(&mut self, config: CompilerConfig) {
        self.config = config;
    }

    /// Clear compilation cache
    pub fn clear_cache(&mut self) {
        self.cache.clear();
    }

    /// Add compiler pass
    pub fn add_pass(&mut self, _pass: Box<dyn CompilerPass>) {
        // Implementation would add pass to pipeline
    }

    /// Remove compiler pass
    pub fn remove_pass(&mut self, _pass_name: &str) {
        // Implementation would remove pass from pipeline
    }
}

impl CompilationCache {
    pub fn new() -> Self {
        Self {
            units: HashMap::new(),
            stats: CacheStatistics::default(),
            config: CacheConfig {
                enabled: true,
                max_size: 100 * 1024 * 1024, // 100MB
                max_age: Duration::from_secs(3600), // 1 hour
                cache_dir: PathBuf::from(".cache"),
            },
        }
    }

    pub fn get(&mut self, source_content: &str) -> Option<CachedCompilationUnit> {
        let hash = self.hash_source(source_content);
        if let Some(unit) = self.units.get(&hash) {
            if unit.timestamp.elapsed() < self.config.max_age {
                self.stats.hits += 1;
                return Some(unit.clone());
            } else {
                self.units.remove(&hash);
                self.stats.invalidations += 1;
            }
        }
        self.stats.misses += 1;
        None
    }

    pub fn insert(&mut self, source_content: &str, code: &GeneratedCode) {
        let hash = self.hash_source(source_content);
        let unit = CachedCompilationUnit {
            source_hash: hash.clone(),
            output: code.clone(),
            compile_time: Duration::from_millis(100), // Placeholder
            timestamp: Instant::now(),
            dependencies: Vec::new(),
        };

        self.units.insert(hash, unit);
        self.stats.cached_units = self.units.len();
    }

    pub fn clear(&mut self) {
        self.units.clear();
        self.stats = CacheStatistics::default();
    }

    fn hash_source(&self, source: &str) -> String {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        source.hash(&mut hasher);
        format!("{:x}", hasher.finish())
    }
}

impl CompilationMetadata {
    pub fn new(source_path: &Path, config: &CompilerConfig) -> Self {
        Self {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            compiler_version: "0.1.0".to_string(),
            source_hash: "placeholder_hash".to_string(),
            dependencies: Vec::new(),
            flags: HashMap::new(),
        }
    }
}

impl Default for CompilerConfig {
    fn default() -> Self {
        Self {
            target: CompilationTarget::NymVM,
            optimization_level: OptimizationLevel::Balanced,
            privacy_enforcement: PrivacyEnforcement::Strict,
            security_level: SecurityLevel::Production,
            debug_info: true,
            warnings: true,
            warnings_as_errors: false,
            output_dir: PathBuf::from("./output"),
            library_paths: Vec::new(),
            defines: HashMap::new(),
            features: HashSet::new(),
            memory_limits: MemoryLimits {
                max_heap: 100 * 1024 * 1024, // 100MB
                max_stack: 1024 * 1024, // 1MB
                max_compile_time: Duration::from_secs(300), // 5 minutes
                max_ast_nodes: 1_000_000,
            },
            gas_estimation: GasEstimationConfig {
                enabled: true,
                base_costs: HashMap::new(),
                privacy_multipliers: HashMap::new(),
                complexity_factors: HashMap::new(),
            },
        }
    }
}

// Note: NymScriptError implementations moved to appropriate trait impls

impl From<TypeError> for NymScriptError {
    fn from(error: TypeError) -> Self {
        Self {
            message: error.message,
            error_type: ErrorType::Type,
            severity: ErrorSeverity::Error,
            location: error.location.map(|loc| crate::error::SourceLocation {
                file: loc.file.unwrap_or_default(),
                line: loc.line,
                column: loc.column,
                offset: 0,
            }),
            suggestions: error.suggestions,
            context: HashMap::new(),
        }
    }
}

impl From<ParseError> for NymScriptError {
    fn from(error: ParseError) -> Self {
        Self {
            message: error.message,
            error_type: ErrorType::Parse,
            severity: ErrorSeverity::Error,
            location: None,
            suggestions: Vec::new(),
            context: HashMap::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compiler_creation() {
        let config = CompilerConfig::default();
        let compiler = NymScriptCompiler::new(config);
        
        assert_eq!(compiler.config.target, CompilationTarget::NymVM);
        assert_eq!(compiler.config.optimization_level, OptimizationLevel::Balanced);
        assert_eq!(compiler.config.privacy_enforcement, PrivacyEnforcement::Strict);
    }

    #[test]
    fn test_compilation_cache() {
        let mut cache = CompilationCache::new();
        assert!(cache.config.enabled);
        assert_eq!(cache.stats.hits, 0);
        assert_eq!(cache.stats.misses, 0);

        // Test cache miss
        let result = cache.get("test source");
        assert!(result.is_none());
        assert_eq!(cache.stats.misses, 1);
    }

    #[test]
    fn test_compiler_config_default() {
        let config = CompilerConfig::default();
        
        assert_eq!(config.target, CompilationTarget::NymVM);
        assert_eq!(config.privacy_enforcement, PrivacyEnforcement::Strict);
        assert_eq!(config.security_level, SecurityLevel::Production);
        assert!(config.debug_info);
        assert!(config.warnings);
        assert!(!config.warnings_as_errors);
    }

    #[test]
    fn test_memory_limits() {
        let limits = MemoryLimits {
            max_heap: 50 * 1024 * 1024,
            max_stack: 512 * 1024,
            max_compile_time: Duration::from_secs(120),
            max_ast_nodes: 500_000,
        };

        assert_eq!(limits.max_heap, 50 * 1024 * 1024);
        assert_eq!(limits.max_stack, 512 * 1024);
        assert_eq!(limits.max_compile_time, Duration::from_secs(120));
        assert_eq!(limits.max_ast_nodes, 500_000);
    }

    #[test]
    fn test_compilation_unit() {
        let unit = CompilationUnit {
            source_path: PathBuf::from("test.nys"),
            source_content: "contract Test {}".to_string(),
            ast: None,
            typed_ast: None,
            analysis: None,
            generated_code: None,
            metadata: CompilationMetadata {
                timestamp: 0,
                compiler_version: "0.1.0".to_string(),
                source_hash: "test_hash".to_string(),
                dependencies: Vec::new(),
                flags: HashMap::new(),
            },
        };

        assert_eq!(unit.source_path, PathBuf::from("test.nys"));
        assert_eq!(unit.source_content, "contract Test {}");
        assert!(unit.ast.is_none());
    }

    #[test]
    fn test_compiler_features() {
        let mut features = HashSet::new();
        features.insert(CompilerFeature::ZeroKnowledge);
        features.insert(CompilerFeature::HomomorphicEncryption);
        features.insert(CompilerFeature::PostQuantumCrypto);

        assert!(features.contains(&CompilerFeature::ZeroKnowledge));
        assert!(features.contains(&CompilerFeature::HomomorphicEncryption));
        assert!(features.contains(&CompilerFeature::PostQuantumCrypto));
        assert!(!features.contains(&CompilerFeature::DifferentialPrivacy));
    }

    #[test]
    fn test_symbol_table() {
        let mut symbols = SymbolTable {
            globals: HashMap::new(),
            functions: HashMap::new(),
            types: HashMap::new(),
            imports: HashMap::new(),
        };

        let symbol = Symbol {
            name: "test_var".to_string(),
            symbol_type: NymType::int(),
            address: 0x1000,
            visibility: SymbolVisibility::Public,
            privacy: crate::ast::PrivacyLevel::Private,
        };

        symbols.globals.insert("test_var".to_string(), symbol);
        assert!(symbols.globals.contains_key("test_var"));
        assert_eq!(symbols.globals["test_var"].address, 0x1000);
    }

    #[test]
    fn test_compiler_statistics() {
        let mut stats = CompilerStatistics::default();
        
        stats.files_compiled = 5;
        stats.lines_compiled = 1000;
        stats.errors = 2;
        stats.warnings = 10;

        assert_eq!(stats.files_compiled, 5);
        assert_eq!(stats.lines_compiled, 1000);
        assert_eq!(stats.errors, 2);
        assert_eq!(stats.warnings, 10);
    }

    #[test]
    fn test_privacy_enforcement_levels() {
        assert_eq!(PrivacyEnforcement::None, PrivacyEnforcement::None);
        assert_eq!(PrivacyEnforcement::Warning, PrivacyEnforcement::Warning);
        assert_eq!(PrivacyEnforcement::Strict, PrivacyEnforcement::Strict);
        assert_eq!(PrivacyEnforcement::Cryptographic, PrivacyEnforcement::Cryptographic);
    }

    #[test]
    fn test_compilation_targets() {
        let targets = vec![
            CompilationTarget::NymVM,
            CompilationTarget::WASM,
            CompilationTarget::NativeX64,
            CompilationTarget::LLVM,
            CompilationTarget::JavaScript,
        ];

        assert_eq!(targets.len(), 5);
        assert!(targets.contains(&CompilationTarget::NymVM));
        assert!(targets.contains(&CompilationTarget::WASM));
    }
}