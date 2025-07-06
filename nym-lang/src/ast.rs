//! Abstract Syntax Tree for NymScript - Week 61-62
//! 
//! This module defines the complete AST structure for NymScript,
//! including privacy annotations and security levels.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

/// Complete NymScript Abstract Syntax Tree
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct NymScriptAST {
    /// Module name
    pub module_name: String,
    /// Import statements
    pub imports: Vec<ImportStatement>,
    /// Global declarations
    pub declarations: Vec<Declaration>,
    /// Contract definitions
    pub contracts: Vec<Contract>,
    /// Module metadata
    pub metadata: ModuleMetadata,
}

/// Module metadata
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModuleMetadata {
    /// Module version
    pub version: String,
    /// Privacy level
    pub privacy_level: PrivacyLevel,
    /// Security requirements
    pub security_requirements: Vec<SecurityRequirement>,
    /// Compilation targets
    pub targets: Vec<CompilationTarget>,
}

/// Import statement
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ImportStatement {
    /// Module path
    pub path: String,
    /// Imported items
    pub items: ImportItems,
    /// Privacy level for imports
    pub privacy: PrivacyAnnotation,
}

/// Import items specification
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ImportItems {
    /// Import all items
    All,
    /// Import specific items
    Specific(Vec<String>),
    /// Import with alias
    Aliased(HashMap<String, String>),
}

/// Top-level declarations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Declaration {
    /// Function declaration
    Function(Function),
    /// Struct declaration
    Struct(StructDeclaration),
    /// Enum declaration
    Enum(EnumDeclaration),
    /// Type alias
    TypeAlias(TypeAlias),
    /// Constant declaration
    Constant(ConstantDeclaration),
    /// Global variable
    Global(GlobalDeclaration),
    /// Interface definition
    Interface(InterfaceDeclaration),
    /// Macro declaration
    Macro(MacroDeclaration),
}

/// Function definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Function {
    /// Function name
    pub name: String,
    /// Function parameters
    pub parameters: Vec<Parameter>,
    /// Return type
    pub return_type: Option<TypeAnnotation>,
    /// Function body
    pub body: Block,
    /// Privacy annotations
    pub privacy: PrivacyAnnotation,
    /// Security level
    pub security_level: SecurityLevel,
    /// Function attributes
    pub attributes: Vec<FunctionAttribute>,
    /// Gas estimation
    pub gas_estimate: Option<u64>,
}

/// Function parameter
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Parameter {
    /// Parameter name
    pub name: String,
    /// Parameter type
    pub param_type: TypeAnnotation,
    /// Privacy annotation
    pub privacy: PrivacyAnnotation,
    /// Default value
    pub default: Option<Expression>,
    /// Parameter attributes
    pub attributes: Vec<ParameterAttribute>,
}

/// Contract definition
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Contract {
    /// Contract name
    pub name: String,
    /// Contract state variables
    pub state: Vec<StateVariable>,
    /// Contract functions
    pub functions: Vec<ContractFunction>,
    /// Contract events
    pub events: Vec<EventDeclaration>,
    /// Contract modifiers
    pub modifiers: Vec<ModifierDeclaration>,
    /// Contract inheritance
    pub inherits: Vec<String>,
    /// Privacy configuration
    pub privacy_config: ContractPrivacyConfig,
    /// Security policies
    pub security_policies: Vec<SecurityPolicy>,
}

/// Contract state variable
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StateVariable {
    /// Variable name
    pub name: String,
    /// Variable type
    pub var_type: TypeAnnotation,
    /// Visibility
    pub visibility: Visibility,
    /// Privacy annotation
    pub privacy: PrivacyAnnotation,
    /// Initial value
    pub initial_value: Option<Expression>,
    /// Storage location
    pub storage_location: StorageLocation,
}

/// Contract function
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractFunction {
    /// Base function
    pub function: Function,
    /// Function visibility
    pub visibility: Visibility,
    /// State mutability
    pub mutability: StateMutability,
    /// Function modifiers
    pub modifiers: Vec<String>,
    /// Gas limit
    pub gas_limit: Option<u64>,
}

/// Statement types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Statement {
    /// Expression statement
    Expression(Expression),
    /// Variable declaration
    Let(LetStatement),
    /// Assignment statement
    Assignment(AssignmentStatement),
    /// If statement
    If(IfStatement),
    /// While loop
    While(WhileStatement),
    /// For loop
    For(ForStatement),
    /// Match statement
    Match(MatchStatement),
    /// Return statement
    Return(ReturnStatement),
    /// Break statement
    Break,
    /// Continue statement
    Continue,
    /// Block statement
    Block(Block),
    /// Privacy operation
    Privacy(PrivacyStatement),
    /// Cryptographic operation
    Crypto(CryptoStatement),
    /// Assertion
    Assert(AssertStatement),
    /// Try-catch
    TryCatch(TryCatchStatement),
}

/// Expression types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Expression {
    /// Literal values
    Literal(Literal),
    /// Variable reference
    Identifier(Identifier),
    /// Binary operations
    Binary(BinaryExpression),
    /// Unary operations
    Unary(UnaryExpression),
    /// Function call
    Call(CallExpression),
    /// Member access
    Member(MemberExpression),
    /// Array access
    Index(IndexExpression),
    /// Array literal
    Array(ArrayExpression),
    /// Tuple literal
    Tuple(TupleExpression),
    /// Struct literal
    Struct(StructExpression),
    /// Lambda expression
    Lambda(LambdaExpression),
    /// Privacy operation
    Privacy(PrivacyExpression),
    /// Cryptographic operation
    Crypto(CryptoExpression),
    /// Type cast
    Cast(CastExpression),
    /// Conditional expression
    Conditional(ConditionalExpression),
}

/// Privacy annotations for language constructs
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacyAnnotation {
    /// Privacy level
    pub level: PrivacyLevel,
    /// Information flow constraints
    pub flow_constraints: Vec<FlowConstraint>,
    /// Anonymity requirements
    pub anonymity_level: AnonymityLevel,
    /// Zero-knowledge requirements
    pub zk_requirements: Vec<ZKRequirement>,
}

/// Privacy levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PrivacyLevel {
    /// Public - no privacy protection
    Public,
    /// Private - basic privacy protection
    Private,
    /// Confidential - strong privacy protection
    Confidential,
    /// Secret - maximum privacy protection
    Secret,
    /// Anonymous - anonymous execution required
    Anonymous,
}

/// Security levels for functions and data
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecurityLevel {
    /// Low security - basic protections
    Low,
    /// Medium security - standard protections
    Medium,
    /// High security - enhanced protections
    High,
    /// Critical security - maximum protections
    Critical,
}

/// Information flow constraints
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FlowConstraint {
    /// Source privacy level
    pub from: PrivacyLevel,
    /// Target privacy level
    pub to: PrivacyLevel,
    /// Allowed transformations
    pub transformations: Vec<PrivacyTransformation>,
}

/// Anonymity levels
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AnonymityLevel {
    /// No anonymity required
    None,
    /// Basic anonymity (k-anonymity)
    Basic(u32),
    /// Strong anonymity (l-diversity)
    Strong(u32),
    /// Perfect anonymity (differential privacy)
    Perfect(f64),
}

/// Zero-knowledge requirements
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZKRequirement {
    /// Property to prove
    pub property: String,
    /// Proof system to use
    pub proof_system: ProofSystem,
    /// Public inputs
    pub public_inputs: Vec<String>,
    /// Private witnesses
    pub private_witnesses: Vec<String>,
}

/// Supported proof systems
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum ProofSystem {
    /// zk-STARKs
    Stark,
    /// zk-SNARKs
    Snark,
    /// Bulletproofs
    Bulletproof,
    /// Custom proof system
    Custom(String),
}

/// Privacy transformations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PrivacyTransformation {
    /// Encryption
    Encrypt,
    /// Hashing
    Hash,
    /// Commitment
    Commit,
    /// Zero-knowledge proof
    ZKProof,
    /// Anonymization
    Anonymize,
    /// Differential privacy
    DifferentialPrivacy(f64),
}

/// Type annotations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TypeAnnotation {
    /// Base type
    pub base_type: BaseType,
    /// Generic parameters
    pub generics: Vec<TypeAnnotation>,
    /// Privacy type wrapper
    pub privacy_wrapper: Option<PrivacyWrapper>,
    /// Type constraints
    pub constraints: Vec<TypeConstraint>,
}

/// Base types in NymScript
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BaseType {
    /// Boolean type
    Bool,
    /// Integer types
    Int(IntType),
    /// Unsigned integer types
    UInt(IntType),
    /// Field element (for cryptographic operations)
    Field,
    /// String type
    String,
    /// Bytes type
    Bytes,
    /// Address type
    Address,
    /// Hash type
    Hash,
    /// Array type
    Array(Box<TypeAnnotation>, Option<usize>),
    /// Tuple type
    Tuple(Vec<TypeAnnotation>),
    /// Struct type
    Struct(String),
    /// Enum type
    Enum(String),
    /// Function type
    Function(Vec<TypeAnnotation>, Box<TypeAnnotation>),
    /// Generic type parameter
    Generic(String),
    /// Privacy type
    Privacy(Box<TypeAnnotation>, PrivacyLevel),
    /// Option type
    Option(Box<TypeAnnotation>),
    /// Result type
    Result(Box<TypeAnnotation>, Box<TypeAnnotation>),
}

/// Integer type sizes
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum IntType {
    /// 8-bit
    I8,
    /// 16-bit
    I16,
    /// 32-bit
    I32,
    /// 64-bit
    I64,
    /// 128-bit
    I128,
    /// 256-bit (for cryptographic operations)
    I256,
}

/// Privacy wrappers for types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PrivacyWrapper {
    /// Encrypted value
    Encrypted,
    /// Committed value
    Committed,
    /// Zero-knowledge value
    ZeroKnowledge,
    /// Anonymous value
    Anonymous,
}

/// Type constraints
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum TypeConstraint {
    /// Equality constraint
    Equals(TypeAnnotation),
    /// Subtype constraint
    Subtype(TypeAnnotation),
    /// Privacy constraint
    Privacy(PrivacyLevel),
    /// Size constraint
    Size(usize),
    /// Custom constraint
    Custom(String, Vec<String>),
}

/// Literal values
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Literal {
    /// Boolean literal
    Bool(bool),
    /// Integer literal
    Int(i64),
    /// Unsigned integer literal
    UInt(u64),
    /// Field element literal
    Field(String),
    /// String literal
    String(String),
    /// Bytes literal
    Bytes(Vec<u8>),
    /// Address literal
    Address(String),
    /// Hash literal
    Hash(String),
    /// Null literal
    Null,
}

/// Identifier
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Identifier {
    /// Name
    pub name: String,
    /// Type annotation
    pub type_annotation: Option<TypeAnnotation>,
    /// Privacy annotation
    pub privacy: Option<PrivacyAnnotation>,
}

/// Binary operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BinaryExpression {
    /// Left operand
    pub left: Box<Expression>,
    /// Operator
    pub operator: BinaryOperator,
    /// Right operand
    pub right: Box<Expression>,
    /// Privacy result
    pub privacy_result: Option<PrivacyLevel>,
}

/// Binary operators
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum BinaryOperator {
    // Arithmetic
    Add, Sub, Mul, Div, Mod,
    // Comparison
    Eq, Ne, Lt, Le, Gt, Ge,
    // Logical
    And, Or,
    // Bitwise
    BitAnd, BitOr, BitXor, Shl, Shr,
    // Privacy-preserving operations
    PrivateAdd, PrivateMul, PrivateEq,
    // Cryptographic operations
    CryptoAdd, CryptoMul, CryptoEq,
}

/// Unary operations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct UnaryExpression {
    /// Operator
    pub operator: UnaryOperator,
    /// Operand
    pub operand: Box<Expression>,
}

/// Unary operators
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum UnaryOperator {
    /// Logical not
    Not,
    /// Arithmetic negation
    Neg,
    /// Bitwise not
    BitNot,
    /// Privacy reveal
    Reveal,
    /// Privacy commit
    Commit,
    /// Reference
    Ref,
    /// Dereference
    Deref,
}

/// Function call expression
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CallExpression {
    /// Function being called
    pub function: Box<Expression>,
    /// Arguments
    pub arguments: Vec<Expression>,
    /// Generic type arguments
    pub type_arguments: Vec<TypeAnnotation>,
    /// Privacy context
    pub privacy_context: Option<PrivacyLevel>,
}

/// Member access expression
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MemberExpression {
    /// Object
    pub object: Box<Expression>,
    /// Member name
    pub member: String,
    /// Privacy preservation
    pub preserve_privacy: bool,
}

/// Privacy-specific expressions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PrivacyExpression {
    /// Encrypt value
    Encrypt(Box<Expression>, EncryptionScheme),
    /// Decrypt value
    Decrypt(Box<Expression>, Box<Expression>), // value, key
    /// Create commitment
    Commit(Box<Expression>, Option<Box<Expression>>), // value, randomness
    /// Reveal commitment
    Reveal(Box<Expression>, Box<Expression>), // commitment, randomness
    /// Generate zero-knowledge proof
    ZKProof(ZKProofExpression),
    /// Verify zero-knowledge proof
    ZKVerify(Box<Expression>, Box<Expression>), // proof, public_inputs
    /// Anonymous operation
    Anonymous(Box<Expression>),
}

/// Cryptographic expressions
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CryptoExpression {
    /// Hash function
    Hash(Box<Expression>, HashFunction),
    /// Digital signature
    Sign(Box<Expression>, Box<Expression>), // message, private_key
    /// Signature verification
    VerifySignature(Box<Expression>, Box<Expression>, Box<Expression>), // message, signature, public_key
    /// Key generation
    GenerateKey(KeyType),
    /// Random number generation
    Random(Option<u32>), // optional seed
    /// Field arithmetic
    FieldArithmetic(FieldOperation),
}

/// Block statement
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Block {
    /// Statements in the block
    pub statements: Vec<Statement>,
    /// Block privacy level
    pub privacy_level: Option<PrivacyLevel>,
    /// Block attributes
    pub attributes: Vec<BlockAttribute>,
}

/// Let statement for variable declarations
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LetStatement {
    /// Variable name
    pub name: String,
    /// Type annotation
    pub type_annotation: Option<TypeAnnotation>,
    /// Initial value
    pub value: Option<Expression>,
    /// Privacy annotation
    pub privacy: PrivacyAnnotation,
    /// Mutability
    pub mutable: bool,
}

/// Assignment statement
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssignmentStatement {
    /// Target of assignment
    pub target: Expression,
    /// Assignment operator
    pub operator: AssignmentOperator,
    /// Value being assigned
    pub value: Expression,
    /// Privacy preservation
    pub preserve_privacy: bool,
}

/// Assignment operators
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AssignmentOperator {
    /// Simple assignment
    Assign,
    /// Add and assign
    AddAssign,
    /// Subtract and assign
    SubAssign,
    /// Multiply and assign
    MulAssign,
    /// Divide and assign
    DivAssign,
}

/// If statement
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IfStatement {
    /// Condition
    pub condition: Expression,
    /// Then branch
    pub then_branch: Block,
    /// Else branch
    pub else_branch: Option<Box<Statement>>,
    /// Privacy context
    pub privacy_context: Option<PrivacyLevel>,
}

/// Privacy-specific statements
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PrivacyStatement {
    /// Enter privacy context
    EnterPrivacyContext(PrivacyLevel),
    /// Exit privacy context
    ExitPrivacyContext,
    /// Declassify private data
    Declassify(Expression, SecurityLevel),
    /// Create privacy boundary
    PrivacyBoundary(Block),
    /// Privacy assertion
    PrivacyAssert(Expression, PrivacyLevel),
}

/// Cryptographic statements
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CryptoStatement {
    /// Setup cryptographic context
    CryptoSetup(CryptoSetup),
    /// Generate cryptographic proof
    GenerateProof(ProofGeneration),
    /// Verify cryptographic proof
    VerifyProof(ProofVerification),
    /// Key management operation
    KeyManagement(KeyManagementOperation),
}

// Supporting types and enums
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructDeclaration {
    pub name: String,
    pub fields: Vec<StructField>,
    pub privacy: PrivacyAnnotation,
    pub attributes: Vec<StructAttribute>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructField {
    pub name: String,
    pub field_type: TypeAnnotation,
    pub privacy: PrivacyAnnotation,
    pub default: Option<Expression>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnumDeclaration {
    pub name: String,
    pub variants: Vec<EnumVariant>,
    pub privacy: PrivacyAnnotation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EnumVariant {
    pub name: String,
    pub fields: Option<Vec<TypeAnnotation>>,
    pub discriminant: Option<Expression>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Visibility {
    Private,
    Public,
    Internal,
    External,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StateMutability {
    Pure,
    View,
    Mutable,
    Payable,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum StorageLocation {
    Memory,
    Storage,
    Calldata,
    Stack,
}

// Additional supporting types would continue here...
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityRequirement {
    pub requirement_type: String,
    pub level: SecurityLevel,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum CompilationTarget {
    NymVM,
    WASM,
    Native,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ContractPrivacyConfig {
    pub default_privacy_level: PrivacyLevel,
    pub privacy_policies: Vec<PrivacyPolicy>,
    pub anonymity_sets: Vec<AnonymitySet>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacyPolicy {
    pub name: String,
    pub rules: Vec<PrivacyRule>,
    pub enforcement: PolicyEnforcement,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PrivacyRule {
    pub condition: String,
    pub action: PrivacyAction,
    pub priority: u32,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PrivacyAction {
    Allow,
    Deny,
    Transform(PrivacyTransformation),
    Audit,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum PolicyEnforcement {
    Strict,
    Permissive,
    Advisory,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AnonymitySet {
    pub name: String,
    pub size: u32,
    pub properties: Vec<AnonymityProperty>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AnonymityProperty {
    KAnonymity(u32),
    LDiversity(u32),
    TCloseness(f64),
    DifferentialPrivacy(f64),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityPolicy {
    pub name: String,
    pub rules: Vec<SecurityRule>,
    pub enforcement_level: SecurityLevel,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SecurityRule {
    pub condition: String,
    pub action: SecurityAction,
    pub severity: SecuritySeverity,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecurityAction {
    Allow,
    Deny,
    Warn,
    Audit,
    Sanitize,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum SecuritySeverity {
    Low,
    Medium,
    High,
    Critical,
}

// Placeholder types for complex structures
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FunctionAttribute {
    pub name: String,
    pub parameters: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ParameterAttribute {
    pub name: String,
    pub value: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct BlockAttribute {
    pub name: String,
    pub value: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructAttribute {
    pub name: String,
    pub parameters: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct EventDeclaration {
    pub name: String,
    pub parameters: Vec<Parameter>,
    pub anonymous: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ModifierDeclaration {
    pub name: String,
    pub parameters: Vec<Parameter>,
    pub body: Block,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TypeAlias {
    pub name: String,
    pub target_type: TypeAnnotation,
    pub privacy: PrivacyAnnotation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConstantDeclaration {
    pub name: String,
    pub const_type: TypeAnnotation,
    pub value: Expression,
    pub privacy: PrivacyAnnotation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct GlobalDeclaration {
    pub name: String,
    pub global_type: TypeAnnotation,
    pub initial_value: Option<Expression>,
    pub privacy: PrivacyAnnotation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct InterfaceDeclaration {
    pub name: String,
    pub functions: Vec<Function>,
    pub inherits: Vec<String>,
}

/// Macro declaration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MacroDeclaration {
    pub name: String,
    pub parameters: Vec<String>,
    pub body: Vec<Statement>,
    pub privacy: PrivacyAnnotation,
}

/// Export declaration
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExportDeclaration {
    pub items: Vec<String>,
    pub target: Option<String>,
    pub privacy: PrivacyAnnotation,
}

// Additional expression types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ArrayExpression {
    pub elements: Vec<Expression>,
    pub element_type: Option<TypeAnnotation>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TupleExpression {
    pub elements: Vec<Expression>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct StructExpression {
    pub struct_type: String,
    pub fields: Vec<FieldInitializer>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldInitializer {
    pub name: String,
    pub value: Expression,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LambdaExpression {
    pub parameters: Vec<Parameter>,
    pub return_type: Option<TypeAnnotation>,
    pub body: Box<Expression>,
    pub privacy: PrivacyAnnotation,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct IndexExpression {
    pub object: Box<Expression>,
    pub index: Box<Expression>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CastExpression {
    pub expression: Box<Expression>,
    pub target_type: TypeAnnotation,
    pub privacy_cast: Option<PrivacyLevel>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ConditionalExpression {
    pub condition: Box<Expression>,
    pub true_expr: Box<Expression>,
    pub false_expr: Box<Expression>,
}

// Statement types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WhileStatement {
    pub condition: Expression,
    pub body: Block,
    pub privacy_context: Option<PrivacyLevel>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ForStatement {
    pub iterator: String,
    pub iterable: Expression,
    pub body: Block,
    pub privacy_context: Option<PrivacyLevel>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchStatement {
    pub expression: Expression,
    pub arms: Vec<MatchArm>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct MatchArm {
    pub pattern: Pattern,
    pub guard: Option<Expression>,
    pub body: Block,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Pattern {
    Literal(Literal),
    Identifier(String),
    Wildcard,
    Tuple(Vec<Pattern>),
    Struct(String, Vec<FieldPattern>),
    Enum(String, Option<Vec<Pattern>>),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldPattern {
    pub name: String,
    pub pattern: Pattern,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ReturnStatement {
    pub value: Option<Expression>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct AssertStatement {
    pub condition: Expression,
    pub message: Option<Expression>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct TryCatchStatement {
    pub try_block: Block,
    pub catch_clauses: Vec<CatchClause>,
    pub finally_block: Option<Block>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CatchClause {
    pub exception_type: Option<TypeAnnotation>,
    pub variable: Option<String>,
    pub body: Block,
}

// Cryptographic and privacy-specific types
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ZKProofExpression {
    pub circuit: String,
    pub public_inputs: Vec<Expression>,
    pub private_inputs: Vec<Expression>,
    pub proof_system: ProofSystem,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum EncryptionScheme {
    AES,
    ChaCha20,
    Homomorphic(HomomorphicScheme),
    Threshold(u32, u32), // threshold, total
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HomomorphicScheme {
    Additive,
    Multiplicative,
    FullyHomomorphic,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum HashFunction {
    SHA256,
    SHA3,
    Blake2,
    Poseidon,
    MiMC,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyType {
    Symmetric(u32), // key size in bits
    Asymmetric(AsymmetricKeyType),
    Threshold(u32, u32), // threshold, total
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum AsymmetricKeyType {
    RSA(u32), // key size
    ECDSA,
    EdDSA,
    QuantumResistant(QuantumResistantScheme),
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum QuantumResistantScheme {
    Dilithium,
    Falcon,
    SPHINCS,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FieldOperation {
    pub operation: FieldOperationType,
    pub operands: Vec<Expression>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum FieldOperationType {
    Add,
    Multiply,
    Inverse,
    Power,
    SquareRoot,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CryptoSetup {
    pub scheme: String,
    pub parameters: Vec<Expression>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofGeneration {
    pub circuit_name: String,
    pub witness: Expression,
    pub public_inputs: Vec<Expression>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ProofVerification {
    pub proof: Expression,
    pub public_inputs: Vec<Expression>,
    pub verification_key: Expression,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct KeyManagementOperation {
    pub operation: KeyOperation,
    pub parameters: Vec<Expression>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum KeyOperation {
    Generate,
    Import,
    Export,
    Derive,
    Rotate,
    Revoke,
}

// Default implementations
impl Default for PrivacyAnnotation {
    fn default() -> Self {
        Self {
            level: PrivacyLevel::Private,
            flow_constraints: Vec::new(),
            anonymity_level: AnonymityLevel::None,
            zk_requirements: Vec::new(),
        }
    }
}

impl Default for SecurityLevel {
    fn default() -> Self {
        SecurityLevel::Medium
    }
}

impl Default for PrivacyLevel {
    fn default() -> Self {
        PrivacyLevel::Private
    }
}

// Display implementations for better debugging
impl fmt::Display for PrivacyLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PrivacyLevel::Public => write!(f, "public"),
            PrivacyLevel::Private => write!(f, "private"),
            PrivacyLevel::Confidential => write!(f, "confidential"),
            PrivacyLevel::Secret => write!(f, "secret"),
            PrivacyLevel::Anonymous => write!(f, "anonymous"),
        }
    }
}

impl fmt::Display for SecurityLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SecurityLevel::Low => write!(f, "low"),
            SecurityLevel::Medium => write!(f, "medium"),
            SecurityLevel::High => write!(f, "high"),
            SecurityLevel::Critical => write!(f, "critical"),
        }
    }
}

impl fmt::Display for BaseType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            BaseType::Bool => write!(f, "bool"),
            BaseType::Int(int_type) => write!(f, "{:?}", int_type),
            BaseType::UInt(int_type) => write!(f, "u{:?}", int_type),
            BaseType::Field => write!(f, "field"),
            BaseType::String => write!(f, "string"),
            BaseType::Bytes => write!(f, "bytes"),
            BaseType::Address => write!(f, "address"),
            BaseType::Hash => write!(f, "hash"),
            BaseType::Array(elem_type, size) => {
                if let Some(s) = size {
                    write!(f, "[{}; {}]", elem_type.base_type, s)
                } else {
                    write!(f, "[{}]", elem_type.base_type)
                }
            }
            BaseType::Tuple(types) => {
                write!(f, "(")?;
                for (i, t) in types.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{}", t.base_type)?;
                }
                write!(f, ")")
            }
            BaseType::Struct(name) => write!(f, "{}", name),
            BaseType::Enum(name) => write!(f, "{}", name),
            BaseType::Function(params, ret) => {
                write!(f, "fn(")?;
                for (i, p) in params.iter().enumerate() {
                    if i > 0 { write!(f, ", ")?; }
                    write!(f, "{}", p.base_type)?;
                }
                write!(f, ") -> {}", ret.base_type)
            }
            BaseType::Generic(name) => write!(f, "{}", name),
            BaseType::Privacy(inner, level) => write!(f, "{}[{}]", inner.base_type, level),
            BaseType::Option(inner) => write!(f, "Option<{}>", inner.base_type),
            BaseType::Result(ok, err) => write!(f, "Result<{}, {}>", ok.base_type, err.base_type),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_privacy_annotation_default() {
        let annotation = PrivacyAnnotation::default();
        assert_eq!(annotation.level, PrivacyLevel::Private);
        assert!(annotation.flow_constraints.is_empty());
        assert_eq!(annotation.anonymity_level, AnonymityLevel::None);
    }

    #[test]
    fn test_security_level_default() {
        let level = SecurityLevel::default();
        assert_eq!(level, SecurityLevel::Medium);
    }

    #[test]
    fn test_type_display() {
        let bool_type = BaseType::Bool;
        assert_eq!(bool_type.to_string(), "bool");

        let array_type = BaseType::Array(
            Box::new(TypeAnnotation {
                base_type: BaseType::Int(IntType::I32),
                generics: Vec::new(),
                privacy_wrapper: None,
                constraints: Vec::new(),
            }),
            Some(10)
        );
        assert_eq!(array_type.to_string(), "[I32; 10]");
    }

    #[test]
    fn test_privacy_level_display() {
        assert_eq!(PrivacyLevel::Public.to_string(), "public");
        assert_eq!(PrivacyLevel::Confidential.to_string(), "confidential");
        assert_eq!(PrivacyLevel::Anonymous.to_string(), "anonymous");
    }

    #[test]
    fn test_ast_serialization() {
        let function = Function {
            name: "test_function".to_string(),
            parameters: vec![],
            return_type: None,
            body: Block {
                statements: vec![],
                privacy_level: None,
                attributes: vec![],
            },
            privacy: PrivacyAnnotation::default(),
            security_level: SecurityLevel::Medium,
            attributes: vec![],
            gas_estimate: None,
        };

        let serialized = serde_json::to_string(&function).unwrap();
        let deserialized: Function = serde_json::from_str(&serialized).unwrap();
        
        assert_eq!(function.name, deserialized.name);
        assert_eq!(function.security_level, deserialized.security_level);
    }

    #[test]
    fn test_privacy_expression_creation() {
        let value = Expression::Literal(Literal::Int(42));
        let encrypt_expr = PrivacyExpression::Encrypt(
            Box::new(value),
            EncryptionScheme::AES
        );

        match encrypt_expr {
            PrivacyExpression::Encrypt(expr, scheme) => {
                assert!(matches!(**expr, Expression::Literal(Literal::Int(42))));
                assert!(matches!(scheme, EncryptionScheme::AES));
            }
            _ => panic!("Expected encrypt expression"),
        }
    }

    #[test]
    fn test_zk_requirement_creation() {
        let zk_req = ZKRequirement {
            property: "age_over_18".to_string(),
            proof_system: ProofSystem::Stark,
            public_inputs: vec!["commitment".to_string()],
            private_witnesses: vec!["age".to_string()],
        };

        assert_eq!(zk_req.property, "age_over_18");
        assert!(matches!(zk_req.proof_system, ProofSystem::Stark));
        assert_eq!(zk_req.public_inputs.len(), 1);
        assert_eq!(zk_req.private_witnesses.len(), 1);
    }
}