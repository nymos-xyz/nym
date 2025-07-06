//! Public Transaction Verification
//! 
//! This module provides public verification capabilities for transparent transactions
//! while maintaining privacy for confidential transactions.

use crate::{VerificationResult, TransparencyLevel, ComplianceStatus};
use serde::{Deserialize, Serialize};
use sha3::{Digest, Sha3_256};
use std::collections::HashMap;

/// Public transaction verifier
pub struct PublicTransactionVerifier {
    verification_cache: HashMap<String, VerificationResult>,
    verification_rules: Vec<VerificationRule>,
}

/// Verification rule for public transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationRule {
    pub rule_id: String,
    pub description: String,
    pub verification_type: VerificationType,
    pub enabled: bool,
    pub parameters: HashMap<String, String>,
}

/// Types of verification checks
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum VerificationType {
    SignatureValidation,
    AmountConsistency,
    TimestampValidation,
    ProofVerification,
    ComplianceCheck,
    IntegrityCheck,
}

/// Transaction data for verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionData {
    pub transaction_hash: String,
    pub sender: Option<String>,
    pub receiver: Option<String>,
    pub amount: Option<String>,
    pub timestamp: u64,
    pub signature: String,
    pub proof_data: Option<String>,
    pub transparency_level: TransparencyLevel,
    pub metadata: HashMap<String, String>,
}

/// Verification context
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationContext {
    pub verifier_id: String,
    pub verification_time: u64,
    pub network_state: String,
    pub compliance_requirements: Vec<String>,
}

impl PublicTransactionVerifier {
    /// Create new public transaction verifier
    pub fn new() -> Self {
        let mut verifier = Self {
            verification_cache: HashMap::new(),
            verification_rules: Vec::new(),
        };
        verifier.initialize_default_rules();
        verifier
    }

    /// Initialize default verification rules
    fn initialize_default_rules(&mut self) {
        let rules = vec![
            VerificationRule {
                rule_id: "signature_validation".to_string(),
                description: "Validate digital signatures".to_string(),
                verification_type: VerificationType::SignatureValidation,
                enabled: true,
                parameters: HashMap::new(),
            },
            VerificationRule {
                rule_id: "amount_consistency".to_string(),
                description: "Verify amount consistency".to_string(),
                verification_type: VerificationType::AmountConsistency,
                enabled: true,
                parameters: HashMap::new(),
            },
            VerificationRule {
                rule_id: "timestamp_validation".to_string(),
                description: "Validate transaction timestamps".to_string(),
                verification_type: VerificationType::TimestampValidation,
                enabled: true,
                parameters: HashMap::from([
                    ("max_age_seconds".to_string(), "3600".to_string()),
                ]),
            },
            VerificationRule {
                rule_id: "proof_verification".to_string(),
                description: "Verify zero-knowledge proofs".to_string(),
                verification_type: VerificationType::ProofVerification,
                enabled: true,
                parameters: HashMap::new(),
            },
            VerificationRule {
                rule_id: "compliance_check".to_string(),
                description: "Perform compliance verification".to_string(),
                verification_type: VerificationType::ComplianceCheck,
                enabled: true,
                parameters: HashMap::new(),
            },
            VerificationRule {
                rule_id: "integrity_check".to_string(),
                description: "Verify data integrity".to_string(),
                verification_type: VerificationType::IntegrityCheck,
                enabled: true,
                parameters: HashMap::new(),
            },
        ];

        self.verification_rules = rules;
    }

    /// Verify a public transaction
    pub fn verify_transaction(
        &mut self,
        transaction: &TransactionData,
        context: &VerificationContext,
    ) -> Result<VerificationResult, String> {
        // Check cache first
        if let Some(cached_result) = self.verification_cache.get(&transaction.transaction_hash) {
            return Ok(cached_result.clone());
        }

        let mut is_valid = true;
        let mut compliance_status = ComplianceStatus {
            aml_check: true,
            kyc_verified: true,
            sanctions_check: true,
            regulatory_flags: Vec::new(),
            compliance_score: 1.0,
        };

        // Run all enabled verification rules
        for rule in &self.verification_rules {
            if !rule.enabled {
                continue;
            }

            let rule_result = self.apply_verification_rule(rule, transaction, context)?;
            if !rule_result {
                is_valid = false;
                compliance_status.regulatory_flags.push(format!("Failed rule: {}", rule.rule_id));
                compliance_status.compliance_score *= 0.8;
            }
        }

        // Generate verification proof
        let verification_proof = self.generate_verification_proof(transaction, context)?;

        let result = VerificationResult {
            transaction_hash: transaction.transaction_hash.clone(),
            is_valid,
            transparency_level: transaction.transparency_level.clone(),
            verified_at: context.verification_time,
            verification_proof: Some(verification_proof),
            compliance_status,
        };

        // Cache the result
        self.verification_cache.insert(transaction.transaction_hash.clone(), result.clone());

        Ok(result)
    }

    /// Apply a specific verification rule
    fn apply_verification_rule(
        &self,
        rule: &VerificationRule,
        transaction: &TransactionData,
        context: &VerificationContext,
    ) -> Result<bool, String> {
        match rule.verification_type {
            VerificationType::SignatureValidation => {
                self.verify_signature(transaction)
            }
            VerificationType::AmountConsistency => {
                self.verify_amount_consistency(transaction)
            }
            VerificationType::TimestampValidation => {
                self.verify_timestamp(transaction, context, rule)
            }
            VerificationType::ProofVerification => {
                self.verify_proof_data(transaction)
            }
            VerificationType::ComplianceCheck => {
                self.verify_compliance(transaction)
            }
            VerificationType::IntegrityCheck => {
                self.verify_integrity(transaction)
            }
        }
    }

    /// Verify digital signature
    fn verify_signature(&self, transaction: &TransactionData) -> Result<bool, String> {
        // Simplified signature verification
        // In real implementation, this would use proper cryptographic verification
        Ok(!transaction.signature.is_empty() && transaction.signature.len() >= 64)
    }

    /// Verify amount consistency
    fn verify_amount_consistency(&self, transaction: &TransactionData) -> Result<bool, String> {
        match &transaction.amount {
            Some(amount) => {
                // Verify amount is valid
                amount.parse::<f64>()
                    .map(|amt| amt > 0.0)
                    .map_err(|_| "Invalid amount format".to_string())
            }
            None => {
                // For private transactions, amount verification might not be possible
                match transaction.transparency_level {
                    TransparencyLevel::Private => Ok(true),
                    _ => Err("Amount required for non-private transactions".to_string()),
                }
            }
        }
    }

    /// Verify timestamp
    fn verify_timestamp(
        &self,
        transaction: &TransactionData,
        context: &VerificationContext,
        rule: &VerificationRule,
    ) -> Result<bool, String> {
        let max_age = rule.parameters
            .get("max_age_seconds")
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(3600);

        let age = context.verification_time.saturating_sub(transaction.timestamp);
        Ok(age <= max_age)
    }

    /// Verify zero-knowledge proof data
    fn verify_proof_data(&self, transaction: &TransactionData) -> Result<bool, String> {
        match &transaction.proof_data {
            Some(proof) => {
                // Simplified proof verification
                // In real implementation, this would verify zk-STARK proofs
                Ok(!proof.is_empty() && proof.len() >= 32)
            }
            None => {
                // Proof not required for all transaction types
                Ok(true)
            }
        }
    }

    /// Verify compliance requirements
    fn verify_compliance(&self, transaction: &TransactionData) -> Result<bool, String> {
        // Basic compliance checks
        match transaction.transparency_level {
            TransparencyLevel::ComplianceOnly | TransparencyLevel::Public => {
                // Require sender/receiver for compliance transactions
                Ok(transaction.sender.is_some() && transaction.receiver.is_some())
            }
            _ => Ok(true), // Private transactions pass compliance by default
        }
    }

    /// Verify data integrity
    fn verify_integrity(&self, transaction: &TransactionData) -> Result<bool, String> {
        // Calculate and verify transaction hash
        let mut hasher = Sha3_256::new();
        hasher.update(transaction.transaction_hash.as_bytes());
        
        if let Some(sender) = &transaction.sender {
            hasher.update(sender.as_bytes());
        }
        if let Some(receiver) = &transaction.receiver {
            hasher.update(receiver.as_bytes());
        }
        if let Some(amount) = &transaction.amount {
            hasher.update(amount.as_bytes());
        }
        
        hasher.update(transaction.timestamp.to_be_bytes());
        hasher.update(transaction.signature.as_bytes());

        let calculated_hash = hex::encode(hasher.finalize());
        
        // For demo purposes, we'll consider it valid if the hash is properly formatted
        Ok(transaction.transaction_hash.len() == 64)
    }

    /// Generate verification proof
    fn generate_verification_proof(
        &self,
        transaction: &TransactionData,
        context: &VerificationContext,
    ) -> Result<String, String> {
        let mut hasher = Sha3_256::new();
        hasher.update(b"verification_proof");
        hasher.update(transaction.transaction_hash.as_bytes());
        hasher.update(context.verifier_id.as_bytes());
        hasher.update(context.verification_time.to_be_bytes());
        hasher.update(context.network_state.as_bytes());

        Ok(hex::encode(hasher.finalize()))
    }

    /// Get verification result from cache
    pub fn get_verification_result(&self, transaction_hash: &str) -> Option<&VerificationResult> {
        self.verification_cache.get(transaction_hash)
    }

    /// Batch verify multiple transactions
    pub fn batch_verify_transactions(
        &mut self,
        transactions: &[TransactionData],
        context: &VerificationContext,
    ) -> Result<Vec<VerificationResult>, String> {
        let mut results = Vec::new();
        
        for transaction in transactions {
            let result = self.verify_transaction(transaction, context)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Clear verification cache
    pub fn clear_cache(&mut self) {
        self.verification_cache.clear();
    }

    /// Get verification statistics
    pub fn get_verification_stats(&self) -> VerificationStats {
        let total_verifications = self.verification_cache.len();
        let valid_transactions = self.verification_cache
            .values()
            .filter(|r| r.is_valid)
            .count();

        let transparency_distribution = self.verification_cache
            .values()
            .fold(HashMap::new(), |mut acc, result| {
                *acc.entry(result.transparency_level.clone()).or_insert(0) += 1;
                acc
            });

        VerificationStats {
            total_verifications,
            valid_transactions,
            invalid_transactions: total_verifications - valid_transactions,
            success_rate: if total_verifications > 0 {
                valid_transactions as f64 / total_verifications as f64
            } else {
                0.0
            },
            transparency_distribution,
        }
    }

    /// Add custom verification rule
    pub fn add_verification_rule(&mut self, rule: VerificationRule) {
        self.verification_rules.push(rule);
    }

    /// Remove verification rule
    pub fn remove_verification_rule(&mut self, rule_id: &str) -> bool {
        let initial_len = self.verification_rules.len();
        self.verification_rules.retain(|rule| rule.rule_id != rule_id);
        self.verification_rules.len() < initial_len
    }

    /// Enable/disable verification rule
    pub fn set_rule_enabled(&mut self, rule_id: &str, enabled: bool) -> bool {
        if let Some(rule) = self.verification_rules.iter_mut().find(|r| r.rule_id == rule_id) {
            rule.enabled = enabled;
            true
        } else {
            false
        }
    }
}

/// Verification statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStats {
    pub total_verifications: usize,
    pub valid_transactions: usize,
    pub invalid_transactions: usize,
    pub success_rate: f64,
    pub transparency_distribution: HashMap<TransparencyLevel, usize>,
}

impl Default for PublicTransactionVerifier {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_transaction() -> TransactionData {
        TransactionData {
            transaction_hash: "a".repeat(64),
            sender: Some("sender123".to_string()),
            receiver: Some("receiver456".to_string()),
            amount: Some("1000.0".to_string()),
            timestamp: 1000000,
            signature: "b".repeat(64),
            proof_data: Some("proof123".to_string()),
            transparency_level: TransparencyLevel::Public,
            metadata: HashMap::new(),
        }
    }

    fn create_test_context() -> VerificationContext {
        VerificationContext {
            verifier_id: "test_verifier".to_string(),
            verification_time: 1000100,
            network_state: "active".to_string(),
            compliance_requirements: vec!["aml".to_string(), "kyc".to_string()],
        }
    }

    #[test]
    fn test_verifier_creation() {
        let verifier = PublicTransactionVerifier::new();
        assert!(!verifier.verification_rules.is_empty());
        assert!(verifier.verification_cache.is_empty());
    }

    #[test]
    fn test_transaction_verification() {
        let mut verifier = PublicTransactionVerifier::new();
        let transaction = create_test_transaction();
        let context = create_test_context();

        let result = verifier.verify_transaction(&transaction, &context);
        assert!(result.is_ok());

        let verification_result = result.unwrap();
        assert_eq!(verification_result.transaction_hash, transaction.transaction_hash);
        assert!(verification_result.is_valid);
    }

    #[test]
    fn test_verification_caching() {
        let mut verifier = PublicTransactionVerifier::new();
        let transaction = create_test_transaction();
        let context = create_test_context();

        // First verification
        let result1 = verifier.verify_transaction(&transaction, &context).unwrap();
        
        // Second verification should use cache
        let result2 = verifier.verify_transaction(&transaction, &context).unwrap();
        
        assert_eq!(result1.verified_at, result2.verified_at);
    }

    #[test]
    fn test_batch_verification() {
        let mut verifier = PublicTransactionVerifier::new();
        let transactions = vec![create_test_transaction(), create_test_transaction()];
        let context = create_test_context();

        let results = verifier.batch_verify_transactions(&transactions, &context);
        assert!(results.is_ok());
        assert_eq!(results.unwrap().len(), 2);
    }

    #[test]
    fn test_verification_stats() {
        let mut verifier = PublicTransactionVerifier::new();
        let transaction = create_test_transaction();
        let context = create_test_context();

        verifier.verify_transaction(&transaction, &context).unwrap();
        
        let stats = verifier.get_verification_stats();
        assert_eq!(stats.total_verifications, 1);
        assert_eq!(stats.valid_transactions, 1);
        assert_eq!(stats.success_rate, 1.0);
    }
}