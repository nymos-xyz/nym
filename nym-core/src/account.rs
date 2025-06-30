//! Account management with QuID-based authentication

use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use std::collections::HashMap;
use nym_crypto::Hash256;
use crate::{
    CoreError, CoreResult, NymIdentity, EncryptedBalance, 
    TransactionId, PrivateTransaction, Transaction
};

/// A Nym account with encrypted balances and transaction history
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    /// Account ID (derived from QuID)
    id: Hash256,
    /// Account creation timestamp
    created_at: DateTime<Utc>,
    /// Current encrypted balance
    balance: EncryptedBalance,
    /// Account nonce for transaction ordering
    nonce: u64,
    /// Account type
    account_type: AccountType,
}

/// Type of account
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AccountType {
    /// Regular user account
    User,
    /// Smart contract account
    Contract,
    /// Validator account
    Validator,
    /// System account (for rewards, etc.)
    System,
}

/// Individual account chain for storing transactions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccountChain {
    /// Account ID this chain belongs to
    account_id: Hash256,
    /// List of transaction IDs in chronological order
    transaction_ids: Vec<TransactionId>,
    /// Transaction details cache
    transactions: HashMap<TransactionId, TransactionEntry>,
    /// Current chain state
    state: ChainState,
}

/// Entry in an account chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionEntry {
    /// Transaction ID
    id: TransactionId,
    /// Block height where this transaction was confirmed
    block_height: u64,
    /// Transaction type (private or public)
    entry_type: TransactionEntryType,
    /// Timestamp
    timestamp: DateTime<Utc>,
}

/// Type of transaction entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum TransactionEntryType {
    /// Private transaction (encrypted)
    Private(PrivateTransaction),
    /// Public transaction
    Public(Transaction),
    /// Reference to transaction stored elsewhere
    Reference { hash: Hash256 },
}

/// State of an account chain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainState {
    /// Last transaction ID
    last_transaction: Option<TransactionId>,
    /// Current balance commitment
    balance_commitment: Option<nym_crypto::Commitment>,
    /// Chain length
    length: u64,
    /// Last update timestamp
    last_updated: DateTime<Utc>,
}

impl Account {
    /// Create a new account from QuID identity
    pub fn new(identity: &NymIdentity, initial_balance: EncryptedBalance) -> Self {
        Self {
            id: identity.account_id(),
            created_at: Utc::now(),
            balance: initial_balance,
            nonce: 0,
            account_type: AccountType::User,
        }
    }
    
    /// Create a system account
    pub fn new_system(id: Hash256, initial_balance: EncryptedBalance) -> Self {
        Self {
            id,
            created_at: Utc::now(),
            balance: initial_balance,
            nonce: 0,
            account_type: AccountType::System,
        }
    }
    
    /// Get account ID
    pub fn id(&self) -> &Hash256 {
        &self.id
    }
    
    /// Get current balance
    pub fn balance(&self) -> &EncryptedBalance {
        &self.balance
    }
    
    /// Get current nonce
    pub fn nonce(&self) -> u64 {
        self.nonce
    }
    
    /// Get account type
    pub fn account_type(&self) -> &AccountType {
        &self.account_type
    }
    
    /// Update balance (during transaction processing)
    pub fn update_balance(&mut self, new_balance: EncryptedBalance) {
        self.balance = new_balance;
        self.nonce += 1;
    }
    
    /// Verify account ownership using QuID identity
    pub fn verify_ownership(&self, identity: &NymIdentity) -> bool {
        self.id == identity.account_id()
    }
}

impl AccountChain {
    /// Create a new account chain
    pub fn new(account_id: Hash256) -> Self {
        Self {
            account_id,
            transaction_ids: Vec::new(),
            transactions: HashMap::new(),
            state: ChainState {
                last_transaction: None,
                balance_commitment: None,
                length: 0,
                last_updated: Utc::now(),
            },
        }
    }
    
    /// Get account ID
    pub fn account_id(&self) -> &Hash256 {
        &self.account_id
    }
    
    /// Add a private transaction to the chain
    pub fn add_private_transaction(
        &mut self,
        transaction: PrivateTransaction,
        block_height: u64,
    ) -> CoreResult<()> {
        let tx_id = *transaction.id();
        let timestamp = Utc::now();
        
        let entry = TransactionEntry {
            id: tx_id,
            block_height,
            entry_type: TransactionEntryType::Private(transaction),
            timestamp,
        };
        
        self.transaction_ids.push(tx_id);
        self.transactions.insert(tx_id, entry);
        
        self.state.last_transaction = Some(tx_id);
        self.state.length += 1;
        self.state.last_updated = timestamp;
        
        Ok(())
    }
    
    /// Add a public transaction to the chain
    pub fn add_public_transaction(
        &mut self,
        transaction: Transaction,
        block_height: u64,
    ) -> CoreResult<()> {
        let tx_id = *transaction.id();
        let timestamp = Utc::now();
        
        let entry = TransactionEntry {
            id: tx_id,
            block_height,
            entry_type: TransactionEntryType::Public(transaction),
            timestamp,
        };
        
        self.transaction_ids.push(tx_id);
        self.transactions.insert(tx_id, entry);
        
        self.state.last_transaction = Some(tx_id);
        self.state.length += 1;
        self.state.last_updated = timestamp;
        
        Ok(())
    }
    
    /// Get transaction by ID
    pub fn get_transaction(&self, tx_id: &TransactionId) -> Option<&TransactionEntry> {
        self.transactions.get(tx_id)
    }
    
    /// Get all transaction IDs in chronological order
    pub fn transaction_ids(&self) -> &[TransactionId] {
        &self.transaction_ids
    }
    
    /// Get recent transactions
    pub fn recent_transactions(&self, limit: usize) -> Vec<&TransactionEntry> {
        self.transaction_ids.iter()
            .rev()
            .take(limit)
            .filter_map(|id| self.transactions.get(id))
            .collect()
    }
    
    /// Get transactions in a specific block height range
    pub fn transactions_in_range(&self, from_height: u64, to_height: u64) -> Vec<&TransactionEntry> {
        self.transactions.values()
            .filter(|entry| entry.block_height >= from_height && entry.block_height <= to_height)
            .collect()
    }
    
    /// Get chain state
    pub fn state(&self) -> &ChainState {
        &self.state
    }
    
    /// Get chain length
    pub fn length(&self) -> u64 {
        self.state.length
    }
    
    /// Verify chain integrity
    pub fn verify_integrity(&self) -> CoreResult<bool> {
        // Check that transaction count matches length
        if self.transaction_ids.len() as u64 != self.state.length {
            return Ok(false);
        }
        
        // Check that all transaction IDs have corresponding entries
        for tx_id in &self.transaction_ids {
            if !self.transactions.contains_key(tx_id) {
                return Ok(false);
            }
        }
        
        // Check last transaction
        if let Some(last_tx) = self.state.last_transaction {
            if self.transaction_ids.last() != Some(&last_tx) {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Export chain data for backup
    pub fn export(&self) -> CoreResult<Vec<u8>> {
        bincode::serialize(self)
            .map_err(|e| CoreError::SerializationError { 
                reason: e.to_string() 
            })
    }
    
    /// Import chain data from backup
    pub fn import(data: &[u8]) -> CoreResult<Self> {
        bincode::deserialize(data)
            .map_err(|e| CoreError::SerializationError { 
                reason: e.to_string() 
            })
    }
}

/// Account manager for handling multiple accounts with QuID authentication
pub struct AccountManager {
    /// Map of account ID to account
    accounts: HashMap<Hash256, Account>,
    /// Map of account ID to account chain
    chains: HashMap<Hash256, AccountChain>,
}

impl AccountManager {
    /// Create a new account manager
    pub fn new() -> Self {
        Self {
            accounts: HashMap::new(),
            chains: HashMap::new(),
        }
    }
    
    /// Create a new account from QuID identity
    pub fn create_account(
        &mut self,
        identity: &NymIdentity,
        initial_balance: EncryptedBalance,
    ) -> CoreResult<()> {
        let account_id = identity.account_id();
        
        if self.accounts.contains_key(&account_id) {
            return Err(CoreError::InvalidAccountId { 
                id: "Account already exists".to_string() 
            });
        }
        
        let account = Account::new(identity, initial_balance);
        let chain = AccountChain::new(account_id);
        
        self.accounts.insert(account_id, account);
        self.chains.insert(account_id, chain);
        
        Ok(())
    }
    
    /// Get an account by ID
    pub fn get_account(&self, account_id: &Hash256) -> Option<&Account> {
        self.accounts.get(account_id)
    }
    
    /// Get a mutable reference to an account
    pub fn get_account_mut(&mut self, account_id: &Hash256) -> Option<&mut Account> {
        self.accounts.get_mut(account_id)
    }
    
    /// Get an account chain by ID
    pub fn get_chain(&self, account_id: &Hash256) -> Option<&AccountChain> {
        self.chains.get(account_id)
    }
    
    /// Get a mutable reference to an account chain
    pub fn get_chain_mut(&mut self, account_id: &Hash256) -> Option<&mut AccountChain> {
        self.chains.get_mut(account_id)
    }
    
    /// List all accounts
    pub fn list_accounts(&self) -> Vec<&Account> {
        self.accounts.values().collect()
    }
    
    /// Verify account ownership using QuID identity
    pub fn verify_account_ownership(
        &self,
        account_id: &Hash256,
        identity: &NymIdentity,
    ) -> CoreResult<bool> {
        match self.get_account(account_id) {
            Some(account) => Ok(account.verify_ownership(identity)),
            None => Err(CoreError::AccountNotFound { 
                id: account_id.to_hex() 
            }),
        }
    }
}

impl Default for AccountManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{QuIDAuth, BalanceManager};
    use nym_crypto::SecurityLevel;
    use rand::{thread_rng, RngCore};

    #[test]
    fn test_account_creation() {
        let mut rng = thread_rng();
        let mut master_key = vec![0u8; 32];
        rng.fill_bytes(&mut master_key);
        
        let quid_auth = QuIDAuth::new(master_key, SecurityLevel::Level1);
        let identity = quid_auth.create_nym_identity(0).unwrap();
        
        let balance_manager = BalanceManager::new(
            identity.view_key().as_bytes().to_vec(),
            SecurityLevel::Level1
        );
        let (balance, _) = balance_manager.create_balance(1000).unwrap();
        
        let account = Account::new(&identity, balance);
        
        assert_eq!(*account.id(), identity.account_id());
        assert_eq!(account.nonce(), 0);
        assert_eq!(account.account_type(), &AccountType::User);
        assert!(account.verify_ownership(&identity));
    }
    
    #[test]
    fn test_account_chain() {
        let mut rng = thread_rng();
        let mut master_key = vec![0u8; 32];
        rng.fill_bytes(&mut master_key);
        
        let quid_auth = QuIDAuth::new(master_key, SecurityLevel::Level1);
        let identity = quid_auth.create_nym_identity(0).unwrap();
        
        let mut chain = AccountChain::new(identity.account_id());
        assert_eq!(chain.length(), 0);
        
        // Create a public transaction
        let tx = Transaction::new(
            crate::transaction::TransactionType::PublicTransfer,
            identity.account_id(),
            Hash256::from_bytes([1u8; 32]),
            1000,
            10,
            None,
            &identity,
        ).unwrap();
        
        chain.add_public_transaction(tx, 100).unwrap();
        assert_eq!(chain.length(), 1);
        assert!(chain.verify_integrity().unwrap());
    }
    
    #[test]
    fn test_account_manager() {
        let mut rng = thread_rng();
        let mut master_key = vec![0u8; 32];
        rng.fill_bytes(&mut master_key);
        
        let quid_auth = QuIDAuth::new(master_key, SecurityLevel::Level1);
        let identity = quid_auth.create_nym_identity(0).unwrap();
        
        let balance_manager = BalanceManager::new(
            identity.view_key().as_bytes().to_vec(),
            SecurityLevel::Level1
        );
        let (balance, _) = balance_manager.create_balance(1000).unwrap();
        
        let mut manager = AccountManager::new();
        manager.create_account(&identity, balance).unwrap();
        
        assert!(manager.get_account(&identity.account_id()).is_some());
        assert!(manager.verify_account_ownership(&identity.account_id(), &identity).unwrap());
        
        let accounts = manager.list_accounts();
        assert_eq!(accounts.len(), 1);
    }
}