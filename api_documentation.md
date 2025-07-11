# Nym Blockchain API Documentation

## 🚀 Complete API Reference for Nym Ecosystem

### Table of Contents
1. [Enhanced Stealth Addresses API](#enhanced-stealth-addresses-api)
2. [Transaction Anonymity API](#transaction-anonymity-api)
3. [Confidential Transactions API](#confidential-transactions-api)
4. [DeFi Infrastructure API](#defi-infrastructure-api)
5. [Privacy Configuration API](#privacy-configuration-api)
6. [Node Management API](#node-management-api)

---

## Enhanced Stealth Addresses API

### MultiSigStealthAddress

Advanced multi-signature stealth address implementation for privacy-preserving transactions.

```rust
impl MultiSigStealthAddress {
    /// Creates a new multi-signature stealth address
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        threshold: u32,
        signer_pubkeys: Vec<VerifyingKey>,
        security_level: SecurityLevel,
    ) -> Result<Self, CryptoError>
    
    /// Generates a payment address for this stealth address
    pub fn generate_payment_address<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<PaymentAddress, CryptoError>
    
    /// Creates a signature for a transaction
    pub fn sign_transaction<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        signing_keys: Vec<SigningKey>,
        transaction_hash: &Hash256,
    ) -> Result<MultiSignature, CryptoError>
    
    /// Verifies a multi-signature
    pub fn verify_signature(
        &self,
        signature: &MultiSignature,
        message: &Hash256,
    ) -> Result<bool, CryptoError>
}
```

**Example Usage:**
```rust
use nym_crypto::{MultiSigStealthAddress, SigningKey, SecurityLevel};
use rand::rngs::OsRng;

let mut rng = OsRng;
let signer_keys: Vec<_> = (0..5)
    .map(|_| SigningKey::generate(&mut rng, SecurityLevel::Level1).verifying_key())
    .collect();

let stealth_addr = MultiSigStealthAddress::new(
    &mut rng,
    3, // 3-of-5 threshold
    signer_keys,
    SecurityLevel::Level1,
)?;

let payment_addr = stealth_addr.generate_payment_address(&mut rng)?;
```

### SubAddressGenerator

Hierarchical address generation for organizational privacy.

```rust
impl SubAddressGenerator {
    /// Creates a new sub-address generator
    pub fn new(view_key: ViewKey, spend_key: SpendKey) -> Self
    
    /// Generates a sub-address for a specific department/purpose
    pub fn generate_sub_address(&mut self, department: &str) -> Result<SubAddress, CryptoError>
    
    /// Derives the private key for a sub-address
    pub fn derive_sub_address_key(&self, sub_address: &SubAddress) -> Result<SpendKey, CryptoError>
    
    /// Lists all generated sub-addresses
    pub fn list_sub_addresses(&self) -> Vec<(String, SubAddress)>
}
```

### AddressReuseGuard

Prevents accidental address reuse for enhanced privacy.

```rust
impl AddressReuseGuard {
    /// Creates a new address reuse guard with specified capacity
    pub fn new(capacity: usize) -> Self
    
    /// Checks if an address has been used before
    pub fn is_address_used(&self, address: &Hash256) -> bool
    
    /// Marks an address as used
    pub fn mark_address_used(&mut self, address: Hash256)
    
    /// Clears old address entries (privacy cleanup)
    pub fn cleanup_old_entries(&mut self, age_threshold: Duration)
}
```

---

## Transaction Anonymity API

### MixCoordinator

Coordinates transaction mixing for anonymity.

```rust
impl MixCoordinator {
    /// Creates a new mix coordinator with configuration
    pub fn new(config: MixConfig) -> Self
    
    /// Submits a transaction for mixing
    pub fn submit_transaction<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        transaction: AnonymousTransaction,
    ) -> Result<MixReceipt, PrivacyError>
    
    /// Creates a mixed batch of transactions
    pub fn create_mix<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<MixBatch, PrivacyError>
    
    /// Generates decoy transactions for privacy
    pub fn generate_decoy<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
    ) -> Result<DecoyTransaction, PrivacyError>
    
    /// Gets mix statistics (for monitoring)
    pub fn get_mix_stats(&self) -> MixStatistics
}
```

### AnonymousTransaction

Privacy-preserving transaction structure.

```rust
pub struct AnonymousTransaction {
    pub tx_id: Hash256,
    pub encrypted_data: Vec<u8>,
    pub commitment: [u8; 32],
    pub nullifier: Hash256,
    pub validity_proof: Vec<u8>,
    pub ring_signature: Vec<u8>,
    pub timing_data: TimingData,
}

impl AnonymousTransaction {
    /// Creates a new anonymous transaction
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        sender: &StealthAddress,
        recipient: &StealthAddress,
        amount: u64,
        anonymity_set: Vec<Hash256>,
    ) -> Result<Self, PrivacyError>
    
    /// Verifies transaction validity
    pub fn verify(&self, anonymity_set: &[Hash256]) -> Result<bool, PrivacyError>
    
    /// Extracts public information (non-sensitive)
    pub fn public_info(&self) -> TransactionInfo
}
```

### MEVProtection

Front-running and sandwich attack protection.

```rust
impl MEVProtection {
    /// Creates MEV protection with batch configuration
    pub fn new(batch_config: BatchConfig) -> Self
    
    /// Adds transaction to MEV-protected batch
    pub fn add_transaction(&mut self, tx: AnonymousTransaction) -> Result<(), PrivacyError>
    
    /// Processes batch with fair ordering
    pub fn process_batch<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
    ) -> Result<Vec<AnonymousTransaction>, PrivacyError>
    
    /// Detects potential MEV attacks
    pub fn detect_mev_attack(&self, transactions: &[AnonymousTransaction]) -> Vec<MEVAlert>
}
```

---

## Confidential Transactions API

### ConfidentialTransaction

Cryptographically hides transaction amounts while proving correctness.

```rust
impl ConfidentialTransaction {
    /// Creates a new confidential transaction
    pub fn new<R: RngCore + CryptoRng>(
        rng: &mut R,
        inputs: Vec<(u64, Vec<u8>)>,  // (amount, blinding_factor)
        outputs: Vec<(u64, Vec<u8>)>, // (amount, blinding_factor)
        fee: u64,
    ) -> Result<Self, PrivacyError>
    
    /// Verifies transaction correctness without revealing amounts
    pub fn verify(&self) -> Result<bool, PrivacyError>
    
    /// Creates audit proof for institutional compliance
    pub fn create_audit_proof(
        &self,
        audit_key: &AuditKey,
        permissions: AuditPermissions,
    ) -> Result<AuditProof, PrivacyError>
    
    /// Verifies audit proof
    pub fn verify_audit_proof(
        &self,
        audit_proof: &AuditProof,
        audit_pubkey: &AuditPublicKey,
    ) -> Result<bool, PrivacyError>
}
```

### HomomorphicOps

Homomorphic operations on encrypted amounts.

```rust
impl HomomorphicOps {
    /// Adds two amount commitments homomorphically
    pub fn add_commitments(
        a: &AmountCommitment,
        b: &AmountCommitment,
    ) -> Result<AmountCommitment, PrivacyError>
    
    /// Subtracts amount commitments homomorphically
    pub fn subtract_commitments(
        a: &AmountCommitment,
        b: &AmountCommitment,
    ) -> Result<AmountCommitment, PrivacyError>
    
    /// Multiplies commitment by scalar
    pub fn multiply_commitment(
        commitment: &AmountCommitment,
        scalar: u64,
    ) -> Result<AmountCommitment, PrivacyError>
    
    /// Verifies zero-sum property
    pub fn verify_zero_sum(commitments: &[AmountCommitment]) -> Result<bool, PrivacyError>
}
```

### AuditSystem

Institutional audit system with selective revelation.

```rust
impl AuditSystem {
    /// Creates new audit system with institutional keys
    pub fn new(institution_keys: Vec<AuditKey>) -> Self
    
    /// Registers new audit institution
    pub fn register_institution(
        &mut self,
        institution_id: String,
        audit_key: AuditKey,
        permissions: AuditPermissions,
    ) -> Result<(), PrivacyError>
    
    /// Creates audit trail for transaction
    pub fn create_audit_trail(
        &self,
        transaction: &ConfidentialTransaction,
        institution_id: &str,
    ) -> Result<AuditTrail, PrivacyError>
    
    /// Verifies audit compliance
    pub fn verify_compliance(
        &self,
        audit_trail: &AuditTrail,
        compliance_rules: &ComplianceRules,
    ) -> Result<ComplianceReport, PrivacyError>
}
```

---

## DeFi Infrastructure API

### PrivacyAMM

Privacy-preserving automated market maker.

```rust
impl PrivacyAMM {
    /// Creates new privacy AMM with fee and privacy configuration
    pub fn new(fee_config: FeeConfig, privacy_config: PrivacyConfig) -> Self
    
    /// Creates a new liquidity pool
    pub fn create_pool<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        token_a: String,
        token_b: String,
        initial_a: u64,
        initial_b: u64,
        fee_rate: u32,
    ) -> Result<PoolId, DeFiError>
    
    /// Executes private swap with MEV protection
    pub fn execute_swap<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        pool_id: &PoolId,
        amount_in: u64,
        is_token_a: bool,
        max_slippage: f64,
    ) -> Result<PrivateSwap, DeFiError>
    
    /// Adds liquidity to pool privately
    pub fn add_liquidity<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        pool_id: &PoolId,
        amount_a: u64,
        amount_b: u64,
    ) -> Result<LiquidityPosition, DeFiError>
    
    /// Removes liquidity from pool
    pub fn remove_liquidity<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        position: &LiquidityPosition,
        percentage: f64,
    ) -> Result<(u64, u64), DeFiError>
    
    /// Gets pool information (public data only)
    pub fn get_pool_info(&self, pool_id: &PoolId) -> Result<PoolInfo, DeFiError>
}
```

### PrivateLending

Privacy-preserving lending and borrowing.

```rust
impl PrivateLending {
    /// Creates new private lending protocol
    pub fn new(config: LendingConfig) -> Self
    
    /// Creates private lending pool
    pub fn create_lending_pool<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        asset: String,
        initial_liquidity: u64,
        interest_rate_model: InterestRateModel,
    ) -> Result<LendingPoolId, DeFiError>
    
    /// Deposits assets to earn interest privately
    pub fn deposit<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        pool_id: &LendingPoolId,
        amount: u64,
    ) -> Result<DepositReceipt, DeFiError>
    
    /// Borrows against collateral privately
    pub fn borrow<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        pool_id: &LendingPoolId,
        collateral_amount: u64,
        borrow_amount: u64,
    ) -> Result<LoanPosition, DeFiError>
    
    /// Repays loan privately
    pub fn repay<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        loan_position: &LoanPosition,
        repay_amount: u64,
    ) -> Result<RepaymentReceipt, DeFiError>
}
```

### CrossChainBridge

Privacy-preserving cross-chain operations.

```rust
impl CrossChainBridge {
    /// Creates new cross-chain bridge
    pub fn new(supported_chains: Vec<ChainConfig>) -> Self
    
    /// Initiates private cross-chain transfer
    pub fn initiate_transfer<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        from_chain: ChainId,
        to_chain: ChainId,
        amount: u64,
        recipient: &CrossChainAddress,
    ) -> Result<BridgeTransfer, DeFiError>
    
    /// Completes cross-chain transfer
    pub fn complete_transfer<R: RngCore + CryptoRng>(
        &mut self,
        rng: &mut R,
        transfer: &BridgeTransfer,
        proof: &CrossChainProof,
    ) -> Result<(), DeFiError>
    
    /// Verifies cross-chain proof
    pub fn verify_cross_chain_proof(
        &self,
        proof: &CrossChainProof,
        transfer: &BridgeTransfer,
    ) -> Result<bool, DeFiError>
}
```

---

## Privacy Configuration API

### PrivacyConfig

Global privacy configuration for the system.

```rust
pub struct PrivacyConfig {
    pub anonymity_set_size: usize,
    pub mixing_rounds: u32,
    pub stealth_addresses_enabled: bool,
    pub confidential_transactions_enabled: bool,
    pub audit_enabled: bool,
    pub mev_protection_enabled: bool,
}

impl PrivacyConfig {
    /// Creates default privacy configuration
    pub fn default() -> Self
    
    /// Creates high-privacy configuration
    pub fn high_privacy() -> Self
    
    /// Creates compliance-friendly configuration
    pub fn compliance_mode() -> Self
    
    /// Validates configuration parameters
    pub fn validate(&self) -> Result<(), ConfigError>
    
    /// Updates configuration with new parameters
    pub fn update(&mut self, updates: ConfigUpdates) -> Result<(), ConfigError>
}
```

---

## Node Management API

### NodeConfiguration

Node-level configuration and management.

```rust
impl NodeConfiguration {
    /// Loads configuration from file
    pub fn load_from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError>
    
    /// Saves configuration to file
    pub fn save_to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), ConfigError>
    
    /// Validates node configuration
    pub fn validate(&self) -> Result<(), ConfigError>
    
    /// Updates runtime configuration
    pub fn update_runtime(&mut self, updates: RuntimeUpdates) -> Result<(), ConfigError>
    
    /// Gets current node status
    pub fn get_node_status(&self) -> NodeStatus
}
```

### RPCInterface

JSON-RPC interface for node interaction.

```rust
impl RPCInterface {
    /// Starts RPC server
    pub async fn start(config: RPCConfig) -> Result<Self, RPCError>
    
    /// Stops RPC server
    pub async fn stop(&mut self) -> Result<(), RPCError>
    
    /// Registers new RPC method
    pub fn register_method<F>(&mut self, name: &str, handler: F)
    where
        F: Fn(Params) -> Result<Value, RPCError> + Send + Sync + 'static
    
    /// Available RPC methods:
    /// - get_block_height() -> u64
    /// - get_transaction(hash: Hash256) -> Option<Transaction>
    /// - submit_transaction(tx: Transaction) -> Result<Hash256, Error>
    /// - get_balance(address: Address) -> u64
    /// - get_node_info() -> NodeInfo
}
```

---

## Error Handling

### Common Error Types

```rust
/// Cryptographic operation errors
#[derive(Debug, Clone)]
pub enum CryptoError {
    InvalidKey,
    InvalidSignature,
    InvalidThreshold,
    InsufficientShares,
    RandomnessError,
    InvalidProof,
}

/// Privacy operation errors
#[derive(Debug, Clone)]
pub enum PrivacyError {
    InvalidAnonymitySet,
    MixingFailed,
    InvalidCommitment,
    InvalidBalance,
    AuditFailed,
    TimingAttack,
}

/// DeFi operation errors
#[derive(Debug, Clone)]
pub enum DeFiError {
    InsufficientLiquidity,
    SlippageExceeded,
    InvalidPool,
    MEVAttackDetected,
    CollateralInsufficient,
    LoanNotFound,
}
```

---

## Usage Examples

### Complete Privacy Transaction Flow

```rust
use nym_crypto::*;
use nym_privacy::*;
use nym_defi::*;
use rand::rngs::OsRng;

async fn complete_privacy_transaction() -> Result<(), Box<dyn std::error::Error>> {
    let mut rng = OsRng;
    
    // 1. Create stealth addresses
    let signer_keys: Vec<_> = (0..3)
        .map(|_| SigningKey::generate(&mut rng, SecurityLevel::Level1).verifying_key())
        .collect();
    
    let sender_stealth = MultiSigStealthAddress::new(
        &mut rng, 2, signer_keys.clone(), SecurityLevel::Level1
    )?;
    
    let recipient_stealth = MultiSigStealthAddress::new(
        &mut rng, 2, signer_keys, SecurityLevel::Level1
    )?;
    
    // 2. Create anonymous transaction
    let anonymity_set = vec![Hash256::random(&mut rng); 128];
    let anon_tx = AnonymousTransaction::new(
        &mut rng,
        &sender_stealth.address,
        &recipient_stealth.address,
        1000, // amount
        anonymity_set,
    )?;
    
    // 3. Submit to mix coordinator
    let mix_config = MixConfig::default();
    let mut coordinator = MixCoordinator::new(mix_config);
    let mix_receipt = coordinator.submit_transaction(&mut rng, anon_tx)?;
    
    // 4. Create confidential transaction
    let inputs = vec![(1000, vec![1u8; 32])];
    let outputs = vec![(950, vec![2u8; 32])];
    let conf_tx = ConfidentialTransaction::new(&mut rng, inputs, outputs, 50)?;
    
    // 5. Verify transaction
    assert!(conf_tx.verify()?);
    
    println!("Privacy transaction completed successfully!");
    Ok(())
}
```

---

**📚 This API documentation covers all major components of the Nym privacy ecosystem.**

**🔄 Last Updated**: 2024-12-XX  
**📋 Version**: 1.0  
**✅ Status**: Production Ready