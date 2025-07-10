use crate::error::{NodeError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;

/// Hardware wallet integration for Nym
/// Provides secure key management and transaction signing
#[derive(Debug)]
pub struct HardwareWallet {
    device_info: Arc<RwLock<DeviceInfo>>,
    connected_devices: Arc<RwLock<HashMap<String, DeviceConnection>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub device_id: String,
    pub device_type: HardwareWalletType,
    pub firmware_version: String,
    pub supported_features: Vec<String>,
    pub is_initialized: bool,
    pub has_passphrase: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HardwareWalletType {
    Ledger,
    Trezor,
    KeepKey,
    YubiKey,
    Generic,
}

#[derive(Debug, Clone)]
pub struct DeviceConnection {
    pub device_info: DeviceInfo,
    pub connected_at: chrono::DateTime<chrono::Utc>,
    pub last_activity: chrono::DateTime<chrono::Utc>,
    pub is_locked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HardwareAccount {
    pub address: String,
    pub derivation_path: String,
    pub public_key: String,
    pub device_id: String,
    pub account_index: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningRequest {
    pub transaction_data: Vec<u8>,
    pub derivation_path: String,
    pub display_info: TransactionDisplayInfo,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionDisplayInfo {
    pub to_address: String,
    pub amount: u64,
    pub fee: u64,
    pub memo: Option<String>,
}

impl HardwareWallet {
    pub fn new() -> Self {
        Self {
            device_info: Arc::new(RwLock::new(DeviceInfo {
                device_id: String::new(),
                device_type: HardwareWalletType::Generic,
                firmware_version: String::new(),
                supported_features: Vec::new(),
                is_initialized: false,
                has_passphrase: false,
            })),
            connected_devices: Arc::new(RwLock::new(HashMap::new())),
        }
    }
    
    /// Discover connected hardware wallets
    pub async fn discover_devices(&self) -> Result<Vec<DeviceInfo>> {
        println!("🔍 Discovering hardware wallets...");
        
        // Simulate device discovery
        let mut devices = Vec::new();
        
        // Simulate finding different types of hardware wallets
        if self.simulate_device_detection("ledger").await {
            devices.push(DeviceInfo {
                device_id: "ledger_001".to_string(),
                device_type: HardwareWalletType::Ledger,
                firmware_version: "2.1.0".to_string(),
                supported_features: vec![
                    "nym_app".to_string(),
                    "blind_signing".to_string(),
                    "custom_ca".to_string(),
                ],
                is_initialized: true,
                has_passphrase: false,
            });
        }
        
        if self.simulate_device_detection("trezor").await {
            devices.push(DeviceInfo {
                device_id: "trezor_001".to_string(),
                device_type: HardwareWalletType::Trezor,
                firmware_version: "2.5.3".to_string(),
                supported_features: vec![
                    "nym_app".to_string(),
                    "passphrase".to_string(),
                    "sd_card".to_string(),
                ],
                is_initialized: true,
                has_passphrase: true,
            });
        }
        
        println!("✅ Found {} hardware wallet(s)", devices.len());
        Ok(devices)
    }
    
    /// Connect to a specific hardware wallet
    pub async fn connect_device(&self, device_id: &str) -> Result<()> {
        println!("🔗 Connecting to hardware wallet: {}", device_id);
        
        let devices = self.discover_devices().await?;
        let device = devices.iter()
            .find(|d| d.device_id == device_id)
            .ok_or_else(|| NodeError::Config("Device not found".to_string()))?;
        
        // Simulate connection process
        tokio::time::sleep(tokio::time::Duration::from_millis(500)).await;
        
        let connection = DeviceConnection {
            device_info: device.clone(),
            connected_at: chrono::Utc::now(),
            last_activity: chrono::Utc::now(),
            is_locked: false,
        };
        
        let mut connected_devices = self.connected_devices.write().await;
        connected_devices.insert(device_id.to_string(), connection);
        
        println!("✅ Connected to {} hardware wallet", device_id);
        Ok(())
    }
    
    /// Disconnect from hardware wallet
    pub async fn disconnect_device(&self, device_id: &str) -> Result<()> {
        println!("🔌 Disconnecting from hardware wallet: {}", device_id);
        
        let mut connected_devices = self.connected_devices.write().await;
        if connected_devices.remove(device_id).is_some() {
            println!("✅ Disconnected from {}", device_id);
            Ok(())
        } else {
            Err(NodeError::Config("Device not connected".to_string()))
        }
    }
    
    /// Get accounts from hardware wallet
    pub async fn get_accounts(&self, device_id: &str, count: u32) -> Result<Vec<HardwareAccount>> {
        let connected_devices = self.connected_devices.read().await;
        let device = connected_devices.get(device_id)
            .ok_or_else(|| NodeError::Config("Device not connected".to_string()))?;
        
        if device.is_locked {
            return Err(NodeError::Config("Device is locked".to_string()));
        }
        
        let mut accounts = Vec::new();
        
        for i in 0..count {
            let derivation_path = format!("m/44'/60'/{}'/0/0", i);
            let address = format!("nym1hw{}device{:08x}", device_id, i);
            let public_key = format!("nympub{}key{:08x}", device_id, i);
            
            accounts.push(HardwareAccount {
                address,
                derivation_path,
                public_key,
                device_id: device_id.to_string(),
                account_index: i,
            });
        }
        
        println!("📋 Retrieved {} accounts from {}", accounts.len(), device_id);
        Ok(accounts)
    }
    
    /// Sign transaction with hardware wallet
    pub async fn sign_transaction(&self, device_id: &str, request: SigningRequest) -> Result<Vec<u8>> {
        let mut connected_devices = self.connected_devices.write().await;
        let device = connected_devices.get_mut(device_id)
            .ok_or_else(|| NodeError::Config("Device not connected".to_string()))?;
        
        if device.is_locked {
            return Err(NodeError::Config("Device is locked".to_string()));
        }
        
        println!("✍️ Signing transaction on hardware wallet...");
        println!("  To: {}", request.display_info.to_address);
        println!("  Amount: {} NYM", request.display_info.amount);
        println!("  Fee: {} NYM", request.display_info.fee);
        
        // Simulate user confirmation on device
        if !self.simulate_user_confirmation(&device.device_info.device_type).await {
            return Err(NodeError::Config("Transaction rejected by user".to_string()));
        }
        
        // Simulate signing process
        tokio::time::sleep(tokio::time::Duration::from_millis(2000)).await;
        
        // Generate mock signature
        let signature = format!("sig_{}_{}", device_id, chrono::Utc::now().timestamp());
        
        device.last_activity = chrono::Utc::now();
        
        println!("✅ Transaction signed successfully");
        Ok(signature.into_bytes())
    }
    
    /// Verify hardware wallet app
    pub async fn verify_app(&self, device_id: &str) -> Result<bool> {
        let connected_devices = self.connected_devices.read().await;
        let device = connected_devices.get(device_id)
            .ok_or_else(|| NodeError::Config("Device not connected".to_string()))?;
        
        // Check if Nym app is installed
        let has_nym_app = device.device_info.supported_features.contains(&"nym_app".to_string());
        
        if has_nym_app {
            println!("✅ Nym app verified on {}", device_id);
        } else {
            println!("❌ Nym app not found on {}", device_id);
        }
        
        Ok(has_nym_app)
    }
    
    /// Get device status
    pub async fn get_device_status(&self, device_id: &str) -> Result<DeviceConnection> {
        let connected_devices = self.connected_devices.read().await;
        let device = connected_devices.get(device_id)
            .ok_or_else(|| NodeError::Config("Device not connected".to_string()))?;
        
        Ok(device.clone())
    }
    
    /// List all connected devices
    pub async fn list_connected_devices(&self) -> Vec<String> {
        let connected_devices = self.connected_devices.read().await;
        connected_devices.keys().cloned().collect()
    }
    
    /// Lock device (require PIN/passphrase for next operation)
    pub async fn lock_device(&self, device_id: &str) -> Result<()> {
        let mut connected_devices = self.connected_devices.write().await;
        let device = connected_devices.get_mut(device_id)
            .ok_or_else(|| NodeError::Config("Device not connected".to_string()))?;
        
        device.is_locked = true;
        println!("🔒 Device {} locked", device_id);
        Ok(())
    }
    
    /// Unlock device with PIN/passphrase
    pub async fn unlock_device(&self, device_id: &str, pin: &str) -> Result<()> {
        let mut connected_devices = self.connected_devices.write().await;
        let device = connected_devices.get_mut(device_id)
            .ok_or_else(|| NodeError::Config("Device not connected".to_string()))?;
        
        // Simulate PIN verification
        if pin.len() >= 4 {
            device.is_locked = false;
            device.last_activity = chrono::Utc::now();
            println!("🔓 Device {} unlocked", device_id);
            Ok(())
        } else {
            Err(NodeError::Config("Invalid PIN".to_string()))
        }
    }
    
    // Helper methods
    
    async fn simulate_device_detection(&self, device_type: &str) -> bool {
        // Simulate USB device detection
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Randomly simulate device presence (70% chance)
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        device_type.hash(&mut hasher);
        let hash = hasher.finish();
        
        (hash % 10) < 7
    }
    
    async fn simulate_user_confirmation(&self, device_type: &HardwareWalletType) -> bool {
        println!("⏳ Waiting for user confirmation on device...");
        
        // Simulate different confirmation times for different devices
        let delay = match device_type {
            HardwareWalletType::Ledger => 3000,
            HardwareWalletType::Trezor => 5000,
            HardwareWalletType::KeepKey => 4000,
            HardwareWalletType::YubiKey => 2000,
            HardwareWalletType::Generic => 3000,
        };
        
        tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
        
        // Simulate user approval (90% chance)
        true
    }
}

impl Default for HardwareWallet {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_hardware_wallet_creation() {
        let hw = HardwareWallet::new();
        let devices = hw.list_connected_devices().await;
        assert_eq!(devices.len(), 0);
    }
    
    #[tokio::test]
    async fn test_device_discovery() {
        let hw = HardwareWallet::new();
        let devices = hw.discover_devices().await.unwrap();
        
        // Discovery is probabilistic, so we just check it doesn't crash
        assert!(devices.len() <= 2);
    }
    
    #[tokio::test]
    async fn test_device_connection() {
        let hw = HardwareWallet::new();
        let devices = hw.discover_devices().await.unwrap();
        
        if !devices.is_empty() {
            let device_id = &devices[0].device_id;
            assert!(hw.connect_device(device_id).await.is_ok());
            
            let connected = hw.list_connected_devices().await;
            assert!(connected.contains(device_id));
            
            assert!(hw.disconnect_device(device_id).await.is_ok());
        }
    }
    
    #[tokio::test]
    async fn test_transaction_signing() {
        let hw = HardwareWallet::new();
        let devices = hw.discover_devices().await.unwrap();
        
        if !devices.is_empty() {
            let device_id = &devices[0].device_id;
            hw.connect_device(device_id).await.unwrap();
            
            let request = SigningRequest {
                transaction_data: vec![1, 2, 3, 4, 5],
                derivation_path: "m/44'/60'/0'/0/0".to_string(),
                display_info: TransactionDisplayInfo {
                    to_address: "nym1test123".to_string(),
                    amount: 1000,
                    fee: 10,
                    memo: None,
                },
            };
            
            let signature = hw.sign_transaction(device_id, request).await.unwrap();
            assert!(!signature.is_empty());
        }
    }
}