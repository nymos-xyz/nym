use crate::error::{NodeError, Result};
use crate::light_client::LightClient;
use crate::config::NodeConfig;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::RwLock;

/// Mobile interface for Nym wallet integration
/// Provides a simplified API for mobile wallet applications
#[derive(Debug)]
pub struct MobileInterface {
    light_client: Arc<LightClient>,
    wallet_state: Arc<RwLock<WalletState>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletState {
    pub accounts: Vec<Account>,
    pub active_account: Option<String>,
    pub network_status: NetworkStatus,
    pub last_sync: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub address: String,
    pub balance: u64,
    pub label: String,
    pub is_default: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkStatus {
    pub connected: bool,
    pub peers: usize,
    pub sync_progress: f64,
    pub latest_block: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRequest {
    pub from: String,
    pub to: String,
    pub amount: u64,
    pub memo: Option<String>,
    pub fee: u64,
    pub privacy_mode: PrivacyMode,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivacyMode {
    Public,
    Private,
    Anonymous,
}

impl Default for WalletState {
    fn default() -> Self {
        Self {
            accounts: Vec::new(),
            active_account: None,
            network_status: NetworkStatus {
                connected: false,
                peers: 0,
                sync_progress: 0.0,
                latest_block: 0,
            },
            last_sync: chrono::Utc::now(),
        }
    }
}

impl MobileInterface {
    pub fn new(config: NodeConfig) -> Self {
        let light_client = Arc::new(LightClient::new(config));
        
        Self {
            light_client,
            wallet_state: Arc::new(RwLock::new(WalletState::default())),
        }
    }
    
    /// Initialize the mobile interface
    pub async fn initialize(&self) -> Result<()> {
        println!("📱 Initializing mobile interface...");
        
        // Start light client
        self.light_client.start().await?;
        
        // Update network status
        self.update_network_status().await?;
        
        println!("✅ Mobile interface initialized");
        Ok(())
    }
    
    /// Shutdown the mobile interface
    pub async fn shutdown(&self) -> Result<()> {
        println!("📱 Shutting down mobile interface...");
        
        self.light_client.stop().await?;
        
        println!("✅ Mobile interface shutdown complete");
        Ok(())
    }
    
    /// Create a new account
    pub async fn create_account(&self, label: String) -> Result<Account> {
        // Generate new account address (simplified)
        let address = format!("nym1mobile{}", chrono::Utc::now().timestamp());
        
        let account = Account {
            address: address.clone(),
            balance: 0,
            label,
            is_default: false,
        };
        
        let mut state = self.wallet_state.write().await;
        
        // Set as default if it's the first account
        let is_first = state.accounts.is_empty();
        let mut new_account = account;
        
        if is_first {
            new_account.is_default = true;
            state.active_account = Some(new_account.address.clone());
        }
        
        state.accounts.push(new_account.clone());
        
        println!("🆕 Created account: {} ({})", new_account.address, new_account.label);
        Ok(new_account)
    }
    
    /// Import an existing account
    pub async fn import_account(&self, address: String, label: String) -> Result<Account> {
        // Verify account exists on network
        let balance = self.light_client.get_balance(&address).await?;
        
        let account = Account {
            address: address.clone(),
            balance,
            label,
            is_default: false,
        };
        
        let mut state = self.wallet_state.write().await;
        
        // Check if account already exists
        if state.accounts.iter().any(|a| a.address == address) {
            return Err(NodeError::Config("Account already exists".to_string()));
        }
        
        state.accounts.push(account.clone());
        
        println!("📥 Imported account: {} ({})", account.address, account.label);
        Ok(account)
    }
    
    /// Get all accounts
    pub async fn get_accounts(&self) -> Vec<Account> {
        self.wallet_state.read().await.accounts.clone()
    }
    
    /// Set active account
    pub async fn set_active_account(&self, address: String) -> Result<()> {
        let mut state = self.wallet_state.write().await;
        
        // Verify account exists
        if !state.accounts.iter().any(|a| a.address == address) {
            return Err(NodeError::Config("Account not found".to_string()));
        }
        
        state.active_account = Some(address.clone());
        println!("🔄 Set active account: {}", address);
        Ok(())
    }
    
    /// Get active account
    pub async fn get_active_account(&self) -> Option<Account> {
        let state = self.wallet_state.read().await;
        
        if let Some(active_addr) = &state.active_account {
            state.accounts.iter()
                .find(|a| &a.address == active_addr)
                .cloned()
        } else {
            None
        }
    }
    
    /// Refresh account balances
    pub async fn refresh_balances(&self) -> Result<()> {
        let mut state = self.wallet_state.write().await;
        
        for account in &mut state.accounts {
            match self.light_client.get_balance(&account.address).await {
                Ok(balance) => account.balance = balance,
                Err(e) => eprintln!("Failed to refresh balance for {}: {}", account.address, e),
            }
        }
        
        state.last_sync = chrono::Utc::now();
        Ok(())
    }
    
    /// Send transaction
    pub async fn send_transaction(&self, request: TransactionRequest) -> Result<String> {
        // Validate sender account
        let state = self.wallet_state.read().await;
        let sender_account = state.accounts.iter()
            .find(|a| a.address == request.from)
            .ok_or_else(|| NodeError::Config("Sender account not found".to_string()))?;
        
        // Check balance
        if sender_account.balance < request.amount + request.fee {
            return Err(NodeError::Config("Insufficient balance".to_string()));
        }
        
        // Send transaction via light client
        let tx_hash = self.light_client.send_transaction(&request.to, request.amount).await?;
        
        println!("💸 Transaction sent: {} ({} NYM to {})", 
            tx_hash, request.amount, request.to);
        
        Ok(tx_hash)
    }
    
    /// Get transaction status
    pub async fn get_transaction_status(&self, tx_hash: &str) -> Result<String> {
        self.light_client.get_transaction_status(tx_hash).await
    }
    
    /// Get wallet state
    pub async fn get_wallet_state(&self) -> WalletState {
        self.wallet_state.read().await.clone()
    }
    
    /// Update network status
    async fn update_network_status(&self) -> Result<()> {
        let client_state = self.light_client.get_state().await;
        let peers = self.light_client.get_peers().await;
        
        let mut state = self.wallet_state.write().await;
        state.network_status = NetworkStatus {
            connected: self.light_client.is_running().await,
            peers: peers.len(),
            sync_progress: client_state.sync_progress,
            latest_block: client_state.latest_block_height,
        };
        
        Ok(())
    }
    
    /// Get network status
    pub async fn get_network_status(&self) -> Result<NetworkStatus> {
        self.update_network_status().await?;
        Ok(self.wallet_state.read().await.network_status.clone())
    }
    
    /// Export wallet data
    pub async fn export_wallet(&self) -> Result<String> {
        let state = self.wallet_state.read().await;
        let wallet_data = serde_json::to_string_pretty(&*state)?;
        Ok(wallet_data)
    }
    
    /// Import wallet data
    pub async fn import_wallet(&self, wallet_data: &str) -> Result<()> {
        let imported_state: WalletState = serde_json::from_str(wallet_data)?;
        
        let mut state = self.wallet_state.write().await;
        *state = imported_state;
        
        println!("📥 Imported wallet with {} accounts", state.accounts.len());
        Ok(())
    }
}

/// Mobile-specific utilities
pub struct MobileUtils;

impl MobileUtils {
    /// Format balance for display
    pub fn format_balance(balance: u64) -> String {
        if balance >= 1_000_000 {
            format!("{:.2}M NYM", balance as f64 / 1_000_000.0)
        } else if balance >= 1_000 {
            format!("{:.2}K NYM", balance as f64 / 1_000.0)
        } else {
            format!("{} NYM", balance)
        }
    }
    
    /// Format address for display
    pub fn format_address(address: &str) -> String {
        if address.len() > 12 {
            format!("{}...{}", &address[..8], &address[address.len()-4..])
        } else {
            address.to_string()
        }
    }
    
    /// Validate address format
    pub fn validate_address(address: &str) -> bool {
        address.starts_with("nym1") && address.len() >= 20
    }
    
    /// Generate QR code data for address
    pub fn generate_qr_data(address: &str, amount: Option<u64>) -> String {
        if let Some(amt) = amount {
            format!("nym:{}?amount={}", address, amt)
        } else {
            format!("nym:{}", address)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::NodeConfig;
    
    #[tokio::test]
    async fn test_mobile_interface_creation() {
        let config = NodeConfig::default();
        let mobile = MobileInterface::new(config);
        
        let accounts = mobile.get_accounts().await;
        assert_eq!(accounts.len(), 0);
        
        let active = mobile.get_active_account().await;
        assert!(active.is_none());
    }
    
    #[tokio::test]
    async fn test_account_creation() {
        let config = NodeConfig::default();
        let mobile = MobileInterface::new(config);
        
        let account = mobile.create_account("Test Account".to_string()).await.unwrap();
        assert_eq!(account.label, "Test Account");
        assert!(account.is_default);
        
        let accounts = mobile.get_accounts().await;
        assert_eq!(accounts.len(), 1);
        
        let active = mobile.get_active_account().await;
        assert!(active.is_some());
        assert_eq!(active.unwrap().address, account.address);
    }
    
    #[test]
    fn test_mobile_utils() {
        assert_eq!(MobileUtils::format_balance(1_500_000), "1.50M NYM");
        assert_eq!(MobileUtils::format_balance(2_500), "2.50K NYM");
        assert_eq!(MobileUtils::format_balance(100), "100 NYM");
        
        assert_eq!(MobileUtils::format_address("nym1abcdefghijklmnopqrstuvwxyz"), "nym1abcd...wxyz");
        assert_eq!(MobileUtils::format_address("nym1short"), "nym1short");
        
        assert!(MobileUtils::validate_address("nym1abcdefghijklmnopqr"));
        assert!(!MobileUtils::validate_address("invalid"));
        assert!(!MobileUtils::validate_address("nym1short"));
        
        assert_eq!(MobileUtils::generate_qr_data("nym1test", Some(1000)), "nym:nym1test?amount=1000");
        assert_eq!(MobileUtils::generate_qr_data("nym1test", None), "nym:nym1test");
    }
}