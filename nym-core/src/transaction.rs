//! Transaction types with privacy features and QuID authentication

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use nym_crypto::{Hash256, StealthAddress, Signature};
use crate::{CoreError, CoreResult, EncryptedBalance, BalanceProof, NymIdentity};

/// Transaction identifier
pub type TransactionId = Hash256;

/// Different types of transactions in Nym
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionType {
    /// Private transfer between accounts
    PrivateTransfer,
    /// Public transfer (for transparency/compliance)
    PublicTransfer,
    /// Smart contract execution
    ContractExecution,
    /// Staking transaction
    Staking,
    /// Mining reward
    MiningReward,
}

/// A private transaction with encrypted amounts and stealth addresses
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PrivateTransaction {
    /// Unique transaction ID
    id: TransactionId,
    /// Transaction type
    tx_type: TransactionType,
    /// Timestamp
    timestamp: DateTime<Utc>,
    /// Input stealth addresses and encrypted balances
    inputs: Vec<TransactionInput>,
    /// Output stealth addresses and encrypted balances
    outputs: Vec<TransactionOutput>,
    /// Privacy proof that the transaction is valid
    balance_proof: BalanceProof,
    /// QuID-based signature from sender
    signature: Vec<u8>,
    /// Transaction fee (encrypted)
    fee: EncryptedBalance,
}

/// Input to a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionInput {
    /// The stealth address being spent from
    stealth_address: StealthAddress,
    /// Encrypted balance being spent
    encrypted_balance: EncryptedBalance,
    /// Proof that the sender owns this stealth address
    ownership_proof: Vec<u8>,
}

/// Output of a transaction
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionOutput {
    /// The recipient's stealth address
    stealth_address: StealthAddress,
    /// Encrypted balance being sent
    encrypted_balance: EncryptedBalance,
}

/// A public transaction (for compliance/transparency)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Transaction {
    /// Unique transaction ID
    id: TransactionId,
    /// Transaction type
    tx_type: TransactionType,
    /// Timestamp
    timestamp: DateTime<Utc>,
    /// Sender account ID (public)
    sender: Hash256,
    /// Recipient account ID (public)
    recipient: Hash256,
    /// Amount (public)
    amount: u64,
    /// Transaction fee
    fee: u64,
    /// QuID-based signature
    signature: Vec<u8>,
    /// Optional memo
    memo: Option<String>,
}

impl PrivateTransaction {
    /// Create a new private transaction
    pub fn new(
        tx_type: TransactionType,
        inputs: Vec<TransactionInput>,
        outputs: Vec<TransactionOutput>,
        balance_proof: BalanceProof,
        fee: EncryptedBalance,
        sender_identity: &NymIdentity,
    ) -> CoreResult<Self> {
        let timestamp = Utc::now();
        
        // Calculate transaction ID from inputs and outputs
        let id = Self::calculate_id(&inputs, &outputs, &timestamp)?;
        
        // Sign the transaction with QuID
        let signature_data = Self::prepare_signature_data(&id, &tx_type, &inputs, &outputs)?;
        let signature = sender_identity.sign_message(&signature_data)?;
        
        Ok(Self {
            id,
            tx_type,
            timestamp,
            inputs,
            outputs,
            balance_proof,
            signature,
            fee,
        })
    }
    
    /// Get transaction ID
    pub fn id(&self) -> &TransactionId {
        &self.id
    }
    
    /// Get transaction type
    pub fn tx_type(&self) -> &TransactionType {
        &self.tx_type
    }
    
    /// Get inputs
    pub fn inputs(&self) -> &[TransactionInput] {
        &self.inputs
    }
    
    /// Get outputs
    pub fn outputs(&self) -> &[TransactionOutput] {
        &self.outputs
    }
    
    /// Get balance proof
    pub fn balance_proof(&self) -> &BalanceProof {
        &self.balance_proof
    }
    
    /// Get fee
    pub fn fee(&self) -> &EncryptedBalance {
        &self.fee
    }
    
    /// Verify the transaction's validity
    pub fn verify(&self, sender_identity: &NymIdentity) -> CoreResult<bool> {
        // Verify balance proof
        if !self.balance_proof.verify()? {
            return Ok(false);
        }
        
        // Verify signature
        let signature_data = Self::prepare_signature_data(
            &self.id, 
            &self.tx_type, 
            &self.inputs, 
            &self.outputs
        )?;
        
        let signature_valid = sender_identity.verify_signature(&signature_data, &self.signature)?;
        if !signature_valid {
            return Ok(false);
        }
        
        // Verify ownership proofs for inputs
        for input in &self.inputs {
            if !self.verify_input_ownership(input, sender_identity)? {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Check if this transaction can be detected by an identity (for recipients)
    pub fn can_be_detected_by(&self, identity: &NymIdentity) -> bool {
        // Check if any output stealth address belongs to this identity
        self.outputs.iter().any(|output| {
            identity.owns_stealth_address(&output.stealth_address)
        })
    }
    
    /// Get outputs that belong to a specific identity
    pub fn outputs_for_identity(&self, identity: &NymIdentity) -> Vec<&TransactionOutput> {
        self.outputs.iter()
            .filter(|output| identity.owns_stealth_address(&output.stealth_address))
            .collect()
    }
    
    /// Calculate transaction ID
    fn calculate_id(
        inputs: &[TransactionInput],
        outputs: &[TransactionOutput],
        timestamp: &DateTime<Utc>,
    ) -> CoreResult<TransactionId> {
        let mut data = Vec::new();
        
        // Add timestamp
        data.extend_from_slice(&timestamp.timestamp().to_le_bytes());
        
        // Add inputs
        for input in inputs {
            data.extend_from_slice(input.stealth_address.address().as_slice());
        }
        
        // Add outputs
        for output in outputs {
            data.extend_from_slice(output.stealth_address.address().as_slice());
        }
        
        Ok(nym_crypto::hash::hash(&data))
    }
    
    /// Prepare data for signing
    fn prepare_signature_data(
        id: &TransactionId,
        tx_type: &TransactionType,
        inputs: &[TransactionInput],
        outputs: &[TransactionOutput],
    ) -> CoreResult<Vec<u8>> {
        let mut data = Vec::new();
        
        data.extend_from_slice(id.as_slice());
        
        // Add transaction type
        let tx_type_bytes = bincode::serialize(tx_type)
            .map_err(|e| CoreError::SerializationError { 
                reason: e.to_string() 
            })?;
        data.extend_from_slice(&tx_type_bytes);
        
        // Add inputs and outputs
        for input in inputs {
            data.extend_from_slice(input.stealth_address.address().as_slice());
        }
        
        for output in outputs {
            data.extend_from_slice(output.stealth_address.address().as_slice());
        }
        
        Ok(data)
    }
    
    /// Verify that an input is owned by the sender
    fn verify_input_ownership(
        &self,
        input: &TransactionInput,
        sender_identity: &NymIdentity,
    ) -> CoreResult<bool> {
        // Check if the sender owns this stealth address
        if !sender_identity.owns_stealth_address(&input.stealth_address) {
            return Ok(false);
        }
        
        // Verify ownership proof (placeholder - real implementation would use zk-STARKs)
        let expected_proof = sender_identity.sign_message(
            input.stealth_address.address().as_slice()
        )?;
        
        Ok(input.ownership_proof == expected_proof)
    }
}

impl TransactionInput {
    /// Create a new transaction input
    pub fn new(
        stealth_address: StealthAddress,
        encrypted_balance: EncryptedBalance,
        sender_identity: &NymIdentity,
    ) -> CoreResult<Self> {
        // Generate ownership proof
        let ownership_proof = sender_identity.sign_message(
            stealth_address.address().as_slice()
        )?;
        
        Ok(Self {
            stealth_address,
            encrypted_balance,
            ownership_proof,
        })
    }
    
    /// Get the stealth address
    pub fn stealth_address(&self) -> &StealthAddress {
        &self.stealth_address
    }
    
    /// Get the encrypted balance
    pub fn encrypted_balance(&self) -> &EncryptedBalance {
        &self.encrypted_balance
    }
}

impl TransactionOutput {
    /// Create a new transaction output
    pub fn new(stealth_address: StealthAddress, encrypted_balance: EncryptedBalance) -> Self {
        Self {
            stealth_address,
            encrypted_balance,
        }
    }
    
    /// Get the stealth address
    pub fn stealth_address(&self) -> &StealthAddress {
        &self.stealth_address
    }
    
    /// Get the encrypted balance
    pub fn encrypted_balance(&self) -> &EncryptedBalance {
        &self.encrypted_balance
    }
}

impl Transaction {
    /// Create a new public transaction
    pub fn new(
        tx_type: TransactionType,
        sender: Hash256,
        recipient: Hash256,
        amount: u64,
        fee: u64,
        memo: Option<String>,
        sender_identity: &NymIdentity,
    ) -> CoreResult<Self> {
        let timestamp = Utc::now();
        
        // Calculate transaction ID
        let mut data = Vec::new();
        data.extend_from_slice(sender.as_slice());
        data.extend_from_slice(recipient.as_slice());
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(&timestamp.timestamp().to_le_bytes());
        let id = nym_crypto::hash::hash(&data);
        
        // Sign the transaction
        let mut signature_data = Vec::new();
        signature_data.extend_from_slice(id.as_slice());
        signature_data.extend_from_slice(&amount.to_le_bytes());
        signature_data.extend_from_slice(&fee.to_le_bytes());
        let signature = sender_identity.sign_message(&signature_data)?;
        
        Ok(Self {
            id,
            tx_type,
            timestamp,
            sender,
            recipient,
            amount,
            fee,
            signature,
            memo,
        })
    }
    
    /// Verify the transaction
    pub fn verify(&self, sender_identity: &NymIdentity) -> CoreResult<bool> {
        // Verify signature
        let mut signature_data = Vec::new();
        signature_data.extend_from_slice(self.id.as_slice());
        signature_data.extend_from_slice(&self.amount.to_le_bytes());
        signature_data.extend_from_slice(&self.fee.to_le_bytes());
        
        sender_identity.verify_signature(&signature_data, &self.signature)
    }
    
    /// Get transaction ID
    pub fn id(&self) -> &TransactionId {
        &self.id
    }
    
    /// Get sender
    pub fn sender(&self) -> &Hash256 {
        &self.sender
    }
    
    /// Get recipient
    pub fn recipient(&self) -> &Hash256 {
        &self.recipient
    }
    
    /// Get amount
    pub fn amount(&self) -> u64 {
        self.amount
    }
    
    /// Get fee
    pub fn fee(&self) -> u64 {
        self.fee
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{QuIDAuth, BalanceManager};
    use nym_crypto::SecurityLevel;
    use rand::{thread_rng, RngCore};

    #[test]
    fn test_private_transaction_creation() {
        let mut rng = thread_rng();
        let mut master_key = vec![0u8; 32];
        rng.fill_bytes(&mut master_key);
        
        let quid_auth = QuIDAuth::new(master_key, SecurityLevel::Level1);
        let sender_identity = quid_auth.create_nym_identity(0).unwrap();
        let recipient_identity = quid_auth.create_nym_identity(1).unwrap();
        
        let balance_manager = BalanceManager::new(
            sender_identity.view_key().as_bytes().to_vec(),
            SecurityLevel::Level1
        );
        
        // Create balances
        let (input_balance, _) = balance_manager.create_balance(1000).unwrap();
        let (output_balance1, _) = balance_manager.create_balance(600).unwrap();
        let (output_balance2, _) = balance_manager.create_balance(400).unwrap();
        let (fee_balance, _) = balance_manager.create_balance(10).unwrap();
        
        // Create stealth addresses
        let input_addr = sender_identity.generate_stealth_address().unwrap();
        let output_addr1 = recipient_identity.generate_stealth_address().unwrap();
        let output_addr2 = sender_identity.generate_stealth_address().unwrap(); // Change
        
        // Create transaction
        let input = TransactionInput::new(input_addr, input_balance, &sender_identity).unwrap();
        let output1 = TransactionOutput::new(output_addr1, output_balance1);
        let output2 = TransactionOutput::new(output_addr2, output_balance2);
        
        let balance_proof = balance_manager.create_transaction_proof(
            &[&input.encrypted_balance],
            &[&output1.encrypted_balance, &output2.encrypted_balance]
        ).unwrap();
        
        let tx = PrivateTransaction::new(
            TransactionType::PrivateTransfer,
            vec![input],
            vec![output1, output2],
            balance_proof,
            fee_balance,
            &sender_identity,
        ).unwrap();
        
        // Verify transaction
        assert!(tx.verify(&sender_identity).unwrap());
        
        // Test detection
        assert!(tx.can_be_detected_by(&recipient_identity));
        assert!(tx.can_be_detected_by(&sender_identity)); // Change output
    }
    
    #[test]
    fn test_public_transaction() {
        let mut rng = thread_rng();
        let mut master_key = vec![0u8; 32];
        rng.fill_bytes(&mut master_key);
        
        let quid_auth = QuIDAuth::new(master_key, SecurityLevel::Level1);
        let sender_identity = quid_auth.create_nym_identity(0).unwrap();
        let recipient_identity = quid_auth.create_nym_identity(1).unwrap();
        
        let tx = Transaction::new(
            TransactionType::PublicTransfer,
            sender_identity.account_id(),
            recipient_identity.account_id(),
            1000,
            10,
            Some("Test payment".to_string()),
            &sender_identity,
        ).unwrap();
        
        assert!(tx.verify(&sender_identity).unwrap());
        assert_eq!(tx.amount(), 1000);
        assert_eq!(tx.fee(), 10);
    }
}