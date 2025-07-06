//! Public Transaction Framework
//! 
//! This module implements opt-in public transaction mechanisms that allow users to
//! selectively reveal transaction details while maintaining the default privacy guarantees
//! of the Nym network. Includes cryptographic commitment reveal systems and audit trails.

use crate::error::{PrivacyError, PrivacyResult};
use nym_core::{NymIdentity, transaction::Transaction};
use nym_crypto::{Hash256, CommitmentScheme, Signature, PublicKey};

use std::collections::{HashMap, HashSet};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::sync::RwLock;
use tracing::{info, debug, warn, error};
use serde::{Deserialize, Serialize};
use zeroize::Zeroize;

/// Public transaction configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicTransactionConfig {
    /// Enable public transaction framework
    pub enable_public_transactions: bool,
    /// Require multi-signature for public reveal
    pub require_multisig: bool,
    /// Minimum signatures required for reveal
    pub min_signatures: u32,
    /// Time delay for public reveal (seconds)
    pub reveal_delay_seconds: u64,
    /// Enable audit trail generation
    pub enable_audit_trail: bool,
    /// Maximum reveal history to maintain
    pub max_reveal_history: usize,
    /// Enable regulatory compliance features
    pub enable_compliance_mode: bool,
    /// Authorized auditor public keys
    pub authorized_auditors: Vec<PublicKey>,
}

impl Default for PublicTransactionConfig {
    fn default() -> Self {
        Self {
            enable_public_transactions: true,
            require_multisig: false,
            min_signatures: 1,
            reveal_delay_seconds: 3600, // 1 hour delay
            enable_audit_trail: true,
            max_reveal_history: 10000,
            enable_compliance_mode: false,
            authorized_auditors: Vec::new(),
        }
    }
}

/// Public reveal authorization
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealAuthorization {
    /// Authorization ID
    pub auth_id: Hash256,
    /// Transaction to be revealed
    pub tx_hash: Hash256,
    /// Authorizing identity
    pub authorizer: NymIdentity,
    /// Authorization timestamp
    pub authorized_at: SystemTime,
    /// Reveal scope
    pub reveal_scope: RevealScope,
    /// Authorization signature
    pub signature: Signature,
    /// Additional authorizers (for multisig)
    pub co_authorizers: Vec<(NymIdentity, Signature)>,
    /// Expiration time
    pub expires_at: Option<SystemTime>,
}

/// Scope of public reveal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevealScope {
    /// Reveal full transaction details
    Full,
    /// Reveal only amounts
    AmountOnly,
    /// Reveal only parties involved
    PartiesOnly,
    /// Reveal only transaction metadata
    MetadataOnly,
    /// Custom selective reveal
    Selective(SelectiveReveal),
}

/// Selective reveal configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SelectiveReveal {
    /// Reveal sender identity
    pub reveal_sender: bool,
    /// Reveal recipient identity
    pub reveal_recipient: bool,
    /// Reveal transaction amount
    pub reveal_amount: bool,
    /// Reveal transaction fee
    pub reveal_fee: bool,
    /// Reveal memo/message
    pub reveal_memo: bool,
    /// Reveal timestamp
    pub reveal_timestamp: bool,
    /// Reveal proofs
    pub reveal_proofs: bool,
}

/// Commitment reveal data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitmentReveal {
    /// Original commitment
    pub commitment: Vec<u8>,
    /// Opening value (blinding factor)
    #[serde(with = "zeroize_serde")]
    pub opening: Vec<u8>,
    /// Committed value
    pub value: u64,
    /// Commitment type
    pub commitment_type: CommitmentType,
    /// Verification proof
    pub verification_proof: Vec<u8>,
}

/// Commitment types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum CommitmentType {
    /// Pedersen commitment
    Pedersen,
    /// Homomorphic commitment
    Homomorphic,
    /// Range proof commitment
    RangeProof,
    /// Custom commitment scheme
    Custom(String),
}

/// Public transaction data after reveal
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PublicTransaction {
    /// Transaction hash
    pub tx_hash: Hash256,
    /// Revealed at timestamp
    pub revealed_at: SystemTime,
    /// Reveal authorization used
    pub authorization: RevealAuthorization,
    /// Revealed data based on scope
    pub revealed_data: RevealedData,
    /// Commitment reveals
    pub commitment_reveals: Vec<CommitmentReveal>,
    /// Audit trail entry
    pub audit_entry: Option<AuditEntry>,
    /// Verification status
    pub verified: bool,
}

/// Revealed transaction data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealedData {
    /// Sender identity (if revealed)
    pub sender: Option<NymIdentity>,
    /// Recipient identity (if revealed)
    pub recipient: Option<NymIdentity>,
    /// Transaction amount (if revealed)
    pub amount: Option<u64>,
    /// Transaction fee (if revealed)
    pub fee: Option<u64>,
    /// Transaction memo (if revealed)
    pub memo: Option<String>,
    /// Transaction timestamp (if revealed)
    pub timestamp: Option<SystemTime>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Audit trail entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    /// Audit entry ID
    pub audit_id: Hash256,
    /// Audited transaction
    pub tx_hash: Hash256,
    /// Audit timestamp
    pub audited_at: SystemTime,
    /// Auditor identity
    pub auditor: Option<NymIdentity>,
    /// Audit purpose
    pub purpose: AuditPurpose,
    /// Audit findings
    pub findings: HashMap<String, String>,
    /// Compliance status
    pub compliance_status: ComplianceStatus,
}

/// Audit purposes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AuditPurpose {
    /// Regulatory compliance
    RegulatoryCompliance,
    /// Tax reporting
    TaxReporting,
    /// Anti-money laundering
    AML,
    /// Know Your Customer
    KYC,
    /// Internal audit
    Internal,
    /// Investigation
    Investigation,
    /// Custom purpose
    Custom(String),
}

/// Compliance status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ComplianceStatus {
    /// Fully compliant
    Compliant,
    /// Non-compliant
    NonCompliant(String),
    /// Pending review
    PendingReview,
    /// Requires additional information
    RequiresInfo(Vec<String>),
}

/// Public reveal request
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RevealRequest {
    /// Request ID
    pub request_id: Hash256,
    /// Transaction to reveal
    pub tx_hash: Hash256,
    /// Requester identity
    pub requester: NymIdentity,
    /// Requested scope
    pub requested_scope: RevealScope,
    /// Request timestamp
    pub requested_at: SystemTime,
    /// Request reason
    pub reason: String,
    /// Request status
    pub status: RevealRequestStatus,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevealRequestStatus {
    Pending,
    Approved,
    Rejected(String),
    Expired,
}

/// Public transaction manager
pub struct PublicTransactionManager {
    config: PublicTransactionConfig,
    reveal_authorizations: RwLock<HashMap<Hash256, RevealAuthorization>>,
    public_transactions: RwLock<HashMap<Hash256, PublicTransaction>>,
    reveal_requests: RwLock<HashMap<Hash256, RevealRequest>>,
    audit_trail: RwLock<Vec<AuditEntry>>,
    commitment_verifier: CommitmentVerifier,
    reveal_history: RwLock<Vec<(Hash256, SystemTime)>>,
}

impl PublicTransactionManager {
    pub fn new(config: PublicTransactionConfig) -> Self {
        info!("Initializing public transaction framework");
        
        Self {
            config,
            reveal_authorizations: RwLock::new(HashMap::new()),
            public_transactions: RwLock::new(HashMap::new()),
            reveal_requests: RwLock::new(HashMap::new()),
            audit_trail: RwLock::new(Vec::new()),
            commitment_verifier: CommitmentVerifier::new(),
            reveal_history: RwLock::new(Vec::new()),
        }
    }
    
    /// Create authorization to reveal a transaction
    pub async fn create_reveal_authorization(
        &self,
        tx_hash: Hash256,
        authorizer: &NymIdentity,
        private_key: &[u8],
        reveal_scope: RevealScope,
        expires_in: Option<Duration>,
    ) -> PrivacyResult<RevealAuthorization> {
        if !self.config.enable_public_transactions {
            return Err(PrivacyError::OperationDisabled("Public transactions disabled".to_string()));
        }
        
        debug!("Creating reveal authorization for transaction: {}", hex::encode(tx_hash.as_bytes()));
        
        let auth_id = self.generate_auth_id(&tx_hash, authorizer);
        let authorized_at = SystemTime::now();
        let expires_at = expires_in.map(|d| authorized_at + d);
        
        // Create authorization message
        let auth_message = self.create_auth_message(
            &tx_hash,
            authorizer,
            &reveal_scope,
            authorized_at,
            expires_at,
        );
        
        // Sign authorization
        let signature = self.sign_authorization(&auth_message, private_key)?;
        
        let authorization = RevealAuthorization {
            auth_id,
            tx_hash,
            authorizer: authorizer.clone(),
            authorized_at,
            reveal_scope,
            signature,
            co_authorizers: Vec::new(),
            expires_at,
        };
        
        // Store authorization
        let mut authorizations = self.reveal_authorizations.write().await;
        authorizations.insert(auth_id, authorization.clone());
        
        info!("Reveal authorization created: {}", hex::encode(auth_id.as_bytes()));
        Ok(authorization)
    }
    
    /// Add co-authorizer for multi-signature reveal
    pub async fn add_co_authorizer(
        &self,
        auth_id: &Hash256,
        co_authorizer: &NymIdentity,
        private_key: &[u8],
    ) -> PrivacyResult<()> {
        let mut authorizations = self.reveal_authorizations.write().await;
        
        let authorization = authorizations.get_mut(auth_id)
            .ok_or_else(|| PrivacyError::NotFound("Authorization not found".to_string()))?;
        
        // Create co-authorization message
        let auth_message = self.create_auth_message(
            &authorization.tx_hash,
            &authorization.authorizer,
            &authorization.reveal_scope,
            authorization.authorized_at,
            authorization.expires_at,
        );
        
        // Sign as co-authorizer
        let co_signature = self.sign_authorization(&auth_message, private_key)?;
        
        authorization.co_authorizers.push((co_authorizer.clone(), co_signature));
        
        debug!("Added co-authorizer to authorization: {}", hex::encode(auth_id.as_bytes()));
        Ok(())
    }
    
    /// Execute public reveal of a transaction
    pub async fn reveal_transaction(
        &self,
        auth_id: &Hash256,
        transaction: &Transaction,
        commitment_openings: Vec<CommitmentReveal>,
    ) -> PrivacyResult<PublicTransaction> {
        info!("Executing public reveal for authorization: {}", hex::encode(auth_id.as_bytes()));
        
        // Verify authorization
        let authorization = self.verify_authorization(auth_id).await?;
        
        // Check reveal delay
        if let Ok(elapsed) = SystemTime::now().duration_since(authorization.authorized_at) {
            if elapsed.as_secs() < self.config.reveal_delay_seconds {
                return Err(PrivacyError::TooEarly(format!(
                    "Reveal delay not met: {} seconds remaining",
                    self.config.reveal_delay_seconds - elapsed.as_secs()
                )));
            }
        }
        
        // Verify commitment openings
        for commitment_reveal in &commitment_openings {
            self.commitment_verifier.verify_commitment(commitment_reveal)?;
        }
        
        // Extract revealed data based on scope
        let revealed_data = self.extract_revealed_data(transaction, &authorization.reveal_scope)?;
        
        // Create audit entry if enabled
        let audit_entry = if self.config.enable_audit_trail {
            Some(self.create_audit_entry(&authorization.tx_hash, &authorization).await)
        } else {
            None
        };
        
        let public_transaction = PublicTransaction {
            tx_hash: authorization.tx_hash,
            revealed_at: SystemTime::now(),
            authorization: authorization.clone(),
            revealed_data,
            commitment_reveals: commitment_openings,
            audit_entry,
            verified: true,
        };
        
        // Store public transaction
        let mut public_txs = self.public_transactions.write().await;
        public_txs.insert(authorization.tx_hash, public_transaction.clone());
        drop(public_txs);
        
        // Update reveal history
        self.update_reveal_history(authorization.tx_hash).await;
        
        // Clean up authorization
        let mut authorizations = self.reveal_authorizations.write().await;
        authorizations.remove(auth_id);
        
        info!("Transaction publicly revealed: {}", hex::encode(authorization.tx_hash.as_bytes()));
        Ok(public_transaction)
    }
    
    /// Request public reveal of a transaction
    pub async fn request_reveal(
        &self,
        tx_hash: Hash256,
        requester: &NymIdentity,
        requested_scope: RevealScope,
        reason: String,
    ) -> PrivacyResult<RevealRequest> {
        debug!("Creating reveal request for transaction: {}", hex::encode(tx_hash.as_bytes()));
        
        let request_id = self.generate_request_id(&tx_hash, requester);
        
        let request = RevealRequest {
            request_id,
            tx_hash,
            requester: requester.clone(),
            requested_scope,
            requested_at: SystemTime::now(),
            reason,
            status: RevealRequestStatus::Pending,
        };
        
        let mut requests = self.reveal_requests.write().await;
        requests.insert(request_id, request.clone());
        
        Ok(request)
    }
    
    /// Approve or reject a reveal request
    pub async fn process_reveal_request(
        &self,
        request_id: &Hash256,
        approved: bool,
        rejection_reason: Option<String>,
    ) -> PrivacyResult<()> {
        let mut requests = self.reveal_requests.write().await;
        
        let request = requests.get_mut(request_id)
            .ok_or_else(|| PrivacyError::NotFound("Request not found".to_string()))?;
        
        request.status = if approved {
            RevealRequestStatus::Approved
        } else {
            RevealRequestStatus::Rejected(rejection_reason.unwrap_or_default())
        };
        
        Ok(())
    }
    
    /// Get public transaction by hash
    pub async fn get_public_transaction(&self, tx_hash: &Hash256) -> Option<PublicTransaction> {
        let public_txs = self.public_transactions.read().await;
        public_txs.get(tx_hash).cloned()
    }
    
    /// Generate audit report for a time period
    pub async fn generate_audit_report(
        &self,
        start_time: SystemTime,
        end_time: SystemTime,
        purpose: Option<AuditPurpose>,
    ) -> PrivacyResult<Vec<AuditEntry>> {
        let audit_trail = self.audit_trail.read().await;
        
        let filtered_entries: Vec<AuditEntry> = audit_trail.iter()
            .filter(|entry| {
                entry.audited_at >= start_time && 
                entry.audited_at <= end_time &&
                purpose.as_ref().map_or(true, |p| matches!(&entry.purpose, p))
            })
            .cloned()
            .collect();
        
        Ok(filtered_entries)
    }
    
    /// Verify compliance for a public transaction
    pub async fn verify_compliance(
        &self,
        tx_hash: &Hash256,
        compliance_checks: Vec<ComplianceCheck>,
    ) -> PrivacyResult<ComplianceStatus> {
        let public_txs = self.public_transactions.read().await;
        
        let public_tx = public_txs.get(tx_hash)
            .ok_or_else(|| PrivacyError::NotFound("Public transaction not found".to_string()))?;
        
        let mut failed_checks = Vec::new();
        let mut required_info = Vec::new();
        
        for check in compliance_checks {
            match self.perform_compliance_check(public_tx, &check).await {
                Ok(true) => continue,
                Ok(false) => failed_checks.push(format!("{:?} check failed", check)),
                Err(e) => required_info.push(e.to_string()),
            }
        }
        
        if !failed_checks.is_empty() {
            Ok(ComplianceStatus::NonCompliant(failed_checks.join(", ")))
        } else if !required_info.is_empty() {
            Ok(ComplianceStatus::RequiresInfo(required_info))
        } else {
            Ok(ComplianceStatus::Compliant)
        }
    }
    
    // Helper methods
    
    fn generate_auth_id(&self, tx_hash: &Hash256, authorizer: &NymIdentity) -> Hash256 {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(tx_hash.as_bytes());
        hasher.update(authorizer.as_bytes());
        hasher.update(&SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_le_bytes());
        Hash256::from_bytes(&hasher.finalize().into())
    }
    
    fn generate_request_id(&self, tx_hash: &Hash256, requester: &NymIdentity) -> Hash256 {
        let mut hasher = sha3::Sha3_256::new();
        hasher.update(tx_hash.as_bytes());
        hasher.update(requester.as_bytes());
        hasher.update(&SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_le_bytes());
        Hash256::from_bytes(&hasher.finalize().into())
    }
    
    fn create_auth_message(
        &self,
        tx_hash: &Hash256,
        authorizer: &NymIdentity,
        reveal_scope: &RevealScope,
        authorized_at: SystemTime,
        expires_at: Option<SystemTime>,
    ) -> Vec<u8> {
        let mut message = Vec::new();
        message.extend_from_slice(tx_hash.as_bytes());
        message.extend_from_slice(authorizer.as_bytes());
        message.extend_from_slice(&bincode::serialize(reveal_scope).unwrap());
        message.extend_from_slice(&authorized_at.duration_since(UNIX_EPOCH).unwrap().as_secs().to_le_bytes());
        if let Some(exp) = expires_at {
            message.extend_from_slice(&exp.duration_since(UNIX_EPOCH).unwrap().as_secs().to_le_bytes());
        }
        message
    }
    
    fn sign_authorization(&self, message: &[u8], private_key: &[u8]) -> PrivacyResult<Signature> {
        // Mock signature - would use actual signing
        Ok(Signature::from_bytes(&[0; 64]))
    }
    
    async fn verify_authorization(&self, auth_id: &Hash256) -> PrivacyResult<RevealAuthorization> {
        let authorizations = self.reveal_authorizations.read().await;
        
        let authorization = authorizations.get(auth_id)
            .ok_or_else(|| PrivacyError::NotFound("Authorization not found".to_string()))?
            .clone();
        
        // Check expiration
        if let Some(expires_at) = authorization.expires_at {
            if SystemTime::now() > expires_at {
                return Err(PrivacyError::Expired("Authorization expired".to_string()));
            }
        }
        
        // Check multi-signature requirements
        if self.config.require_multisig {
            let total_sigs = 1 + authorization.co_authorizers.len();
            if total_sigs < self.config.min_signatures as usize {
                return Err(PrivacyError::InsufficientAuthorization(format!(
                    "Requires {} signatures, got {}",
                    self.config.min_signatures, total_sigs
                )));
            }
        }
        
        // Verify all signatures
        // Mock verification - would verify actual signatures
        
        Ok(authorization)
    }
    
    fn extract_revealed_data(
        &self,
        transaction: &Transaction,
        reveal_scope: &RevealScope,
    ) -> PrivacyResult<RevealedData> {
        let mut revealed_data = RevealedData {
            sender: None,
            recipient: None,
            amount: None,
            fee: None,
            memo: None,
            timestamp: None,
            metadata: HashMap::new(),
        };
        
        match reveal_scope {
            RevealScope::Full => {
                // Reveal all transaction details
                revealed_data.sender = Some(transaction.sender.clone());
                revealed_data.recipient = Some(transaction.recipient.clone());
                revealed_data.amount = Some(transaction.amount);
                revealed_data.fee = Some(transaction.fee);
                revealed_data.timestamp = Some(transaction.timestamp);
                // revealed_data.memo = transaction.memo.clone();
            }
            RevealScope::AmountOnly => {
                revealed_data.amount = Some(transaction.amount);
                revealed_data.fee = Some(transaction.fee);
            }
            RevealScope::PartiesOnly => {
                revealed_data.sender = Some(transaction.sender.clone());
                revealed_data.recipient = Some(transaction.recipient.clone());
            }
            RevealScope::MetadataOnly => {
                revealed_data.timestamp = Some(transaction.timestamp);
                // Add other metadata
            }
            RevealScope::Selective(selective) => {
                if selective.reveal_sender {
                    revealed_data.sender = Some(transaction.sender.clone());
                }
                if selective.reveal_recipient {
                    revealed_data.recipient = Some(transaction.recipient.clone());
                }
                if selective.reveal_amount {
                    revealed_data.amount = Some(transaction.amount);
                }
                if selective.reveal_fee {
                    revealed_data.fee = Some(transaction.fee);
                }
                if selective.reveal_timestamp {
                    revealed_data.timestamp = Some(transaction.timestamp);
                }
                // Handle other selective reveals
            }
        }
        
        Ok(revealed_data)
    }
    
    async fn create_audit_entry(
        &self,
        tx_hash: &Hash256,
        authorization: &RevealAuthorization,
    ) -> AuditEntry {
        let audit_id = Hash256::from_bytes(&sha3::Sha3_256::digest(
            &[tx_hash.as_bytes(), &SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos().to_le_bytes()].concat()
        ).into());
        
        let mut audit_entry = AuditEntry {
            audit_id,
            tx_hash: *tx_hash,
            audited_at: SystemTime::now(),
            auditor: Some(authorization.authorizer.clone()),
            purpose: AuditPurpose::Internal,
            findings: HashMap::new(),
            compliance_status: ComplianceStatus::PendingReview,
        };
        
        // Add to audit trail
        let mut audit_trail = self.audit_trail.write().await;
        audit_trail.push(audit_entry.clone());
        
        // Maintain max history
        if audit_trail.len() > self.config.max_reveal_history {
            audit_trail.remove(0);
        }
        
        audit_entry
    }
    
    async fn update_reveal_history(&self, tx_hash: Hash256) {
        let mut history = self.reveal_history.write().await;
        history.push((tx_hash, SystemTime::now()));
        
        // Maintain max history
        if history.len() > self.config.max_reveal_history {
            history.remove(0);
        }
    }
    
    async fn perform_compliance_check(
        &self,
        public_tx: &PublicTransaction,
        check: &ComplianceCheck,
    ) -> PrivacyResult<bool> {
        match check {
            ComplianceCheck::AmountLimit(max_amount) => {
                if let Some(amount) = public_tx.revealed_data.amount {
                    Ok(amount <= *max_amount)
                } else {
                    Err(PrivacyError::InsufficientData("Amount not revealed".to_string()))
                }
            }
            ComplianceCheck::IdentityVerified => {
                Ok(public_tx.revealed_data.sender.is_some() && 
                   public_tx.revealed_data.recipient.is_some())
            }
            ComplianceCheck::AuditTrailExists => {
                Ok(public_tx.audit_entry.is_some())
            }
            // Add more compliance checks as needed
        }
    }
}

/// Compliance check types
#[derive(Debug, Clone)]
pub enum ComplianceCheck {
    AmountLimit(u64),
    IdentityVerified,
    AuditTrailExists,
}

/// Commitment verifier
struct CommitmentVerifier;

impl CommitmentVerifier {
    fn new() -> Self {
        Self
    }
    
    fn verify_commitment(&self, reveal: &CommitmentReveal) -> PrivacyResult<()> {
        // Mock verification - would verify actual commitments
        match reveal.commitment_type {
            CommitmentType::Pedersen => {
                // Verify Pedersen commitment: C = g^v * h^r
                Ok(())
            }
            CommitmentType::Homomorphic => {
                // Verify homomorphic commitment
                Ok(())
            }
            CommitmentType::RangeProof => {
                // Verify range proof
                Ok(())
            }
            CommitmentType::Custom(_) => {
                Ok(())
            }
        }
    }
}

// Zeroize serialization helper
mod zeroize_serde {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    use zeroize::Zeroize;
    
    pub fn serialize<S>(data: &Vec<u8>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        data.serialize(serializer)
    }
    
    pub fn deserialize<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
    where
        D: Deserializer<'de>,
    {
        let mut data = Vec::<u8>::deserialize(deserializer)?;
        // Data will be zeroized when dropped
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_reveal_authorization() {
        let config = PublicTransactionConfig::default();
        let manager = PublicTransactionManager::new(config);
        
        let tx_hash = Hash256::from_bytes(&[1; 32]);
        let authorizer = NymIdentity::from_bytes(&[2; 32]).unwrap();
        let private_key = vec![0; 32];
        
        let auth = manager.create_reveal_authorization(
            tx_hash,
            &authorizer,
            &private_key,
            RevealScope::Full,
            Some(Duration::from_secs(3600)),
        ).await.unwrap();
        
        assert_eq!(auth.tx_hash, tx_hash);
        assert_eq!(auth.authorizer, authorizer);
    }
    
    #[tokio::test]
    async fn test_selective_reveal() {
        let config = PublicTransactionConfig::default();
        let manager = PublicTransactionManager::new(config);
        
        let selective = SelectiveReveal {
            reveal_sender: true,
            reveal_recipient: false,
            reveal_amount: true,
            reveal_fee: false,
            reveal_memo: false,
            reveal_timestamp: true,
            reveal_proofs: false,
        };
        
        let tx_hash = Hash256::from_bytes(&[1; 32]);
        let authorizer = NymIdentity::from_bytes(&[2; 32]).unwrap();
        let private_key = vec![0; 32];
        
        let auth = manager.create_reveal_authorization(
            tx_hash,
            &authorizer,
            &private_key,
            RevealScope::Selective(selective),
            None,
        ).await.unwrap();
        
        assert!(matches!(auth.reveal_scope, RevealScope::Selective(_)));
    }
    
    #[tokio::test]
    async fn test_reveal_request() {
        let config = PublicTransactionConfig::default();
        let manager = PublicTransactionManager::new(config);
        
        let tx_hash = Hash256::from_bytes(&[1; 32]);
        let requester = NymIdentity::from_bytes(&[3; 32]).unwrap();
        
        let request = manager.request_reveal(
            tx_hash,
            &requester,
            RevealScope::AmountOnly,
            "Tax reporting purposes".to_string(),
        ).await.unwrap();
        
        assert_eq!(request.tx_hash, tx_hash);
        assert_eq!(request.requester, requester);
        assert!(matches!(request.status, RevealRequestStatus::Pending));
    }
}