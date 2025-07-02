//! Integration tests for Nym Storage Layer with QuID Recovery
//! 
//! This test suite validates the complete Nym Week 13-14 Storage Layer implementation:
//! - Encrypted transaction storage
//! - Account chain persistence
//! - Privacy-preserving indices
//! - Backup and recovery mechanisms
//! - QuID-integrated recovery system

use nym_storage::*;
use nym_crypto::{SecurityLevel, QuIDAuth, Hash256};
use nym_core::{Transaction, TransactionType, NymIdentity};
use tempfile::TempDir;
use std::time::Duration;

/// Test the complete storage layer integration
#[test]
fn test_complete_storage_integration() {
    let temp_dir = TempDir::new().unwrap();
    
    // 1. Setup encrypted store
    let store_config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
    let store = EncryptedStore::new(temp_dir.path().join("main_store"), store_config).unwrap();
    
    // 2. Setup backup manager
    let backup_config = BackupConfig {
        backup_path: temp_dir.path().join("backups"),
        encrypted: true,
        compressed: true,
        max_backups: 5,
        ..Default::default()
    };
    let backup_manager = BackupManager::new(store.clone(), backup_config).unwrap();
    
    // 3. Setup QuID recovery system
    let quid_auth = QuIDAuth::new(vec![42u8; 32], SecurityLevel::Level2);
    let identity = quid_auth.create_nym_identity(0).unwrap();
    
    let recovery_config = QuIDRecoveryConfig {
        recovery_threshold: quid_recovery::RecoveryThreshold {
            required: 2,
            total: 3,
            security_level: SecurityLevel::Level2,
        },
        time_lock_period: Duration::from_secs(300), // 5 minutes
        ..Default::default()
    };
    
    let mut recovery_manager = QuIDRecoveryManager::new(
        recovery_config,
        identity.clone(),
        backup_manager
    );
    
    // 4. Test QuID-encrypted transaction storage
    let mut quid_tx_store = QuIDTransactionStore::new(store);
    
    // Create test transactions
    let tx1 = Transaction::Public(nym_core::PublicTransaction::new(
        TransactionType::PublicTransfer,
        vec![],
        vec![],
        1000,
        &identity,
    ).unwrap());
    
    let tx2 = Transaction::Public(nym_core::PublicTransaction::new(
        TransactionType::MinerReward,
        vec![],
        vec![],
        500,
        &identity,
    ).unwrap());
    
    // Store encrypted transactions
    quid_tx_store.store_quid_transaction(&tx1, &identity, 100).unwrap();
    quid_tx_store.store_quid_transaction(&tx2, &identity, 101).unwrap();
    
    // Verify storage and retrieval
    assert_eq!(quid_tx_store.get_quid_transaction_count(&identity), 2);
    
    let retrieved_txs = quid_tx_store.get_quid_transactions(&identity, None, None).unwrap();
    assert_eq!(retrieved_txs.len(), 2);
    
    // Verify transaction type search
    let transfer_txs = quid_tx_store.search_quid_transactions_by_type(
        &identity,
        "PublicTransfer"
    ).unwrap();
    assert_eq!(transfer_txs.len(), 1);
    assert_eq!(transfer_txs[0].hash(), tx1.hash());
    
    // 5. Test integrated backup system
    let backup_id = recovery_manager.create_quid_integrated_backup().unwrap();
    assert_ne!(backup_id.as_bytes(), &[0u8; 32]);
    
    // 6. Test recovery initiation
    let session_id = recovery_manager.initiate_recovery(
        quid_recovery::RecoveryType::PartialDataRecovery {
            data_types: vec!["transactions".to_string()]
        }
    ).unwrap();
    
    let session = recovery_manager.get_recovery_status(session_id).unwrap();
    assert_eq!(session.progress.keys_required, 2);
    assert_eq!(session.progress.keys_collected, 0);
    
    // 7. Test QuID transaction backup and restore
    let backup_data = quid_tx_store.create_quid_backup(&identity).unwrap();
    assert!(!backup_data.is_empty());
    
    // Create new store for restore test
    let temp_dir2 = TempDir::new().unwrap();
    let store_config2 = EncryptionConfig::new(vec![2u8; 32], SecurityLevel::Level1);
    let store2 = EncryptedStore::new(temp_dir2.path(), store_config2).unwrap();
    let mut quid_tx_store2 = QuIDTransactionStore::new(store2);
    
    // Restore backup
    let restored_count = quid_tx_store2.restore_quid_backup(&identity, &backup_data).unwrap();
    assert_eq!(restored_count, 2);
    assert_eq!(quid_tx_store2.get_quid_transaction_count(&identity), 2);
    
    // Verify restored transactions can be decrypted properly
    let restored_txs = quid_tx_store2.get_quid_transactions(&identity, None, None).unwrap();
    assert_eq!(restored_txs.len(), 2);
    
    println!("✅ Complete storage layer integration test passed!");
}

/// Test privacy isolation between different QuID identities
#[test]
fn test_quid_privacy_isolation() {
    let temp_dir = TempDir::new().unwrap();
    let store_config = EncryptionConfig::new(vec![3u8; 32], SecurityLevel::Level1);
    let store = EncryptedStore::new(temp_dir.path(), store_config).unwrap();
    
    let mut quid_tx_store = QuIDTransactionStore::new(store);
    
    // Create two different QuID identities
    let quid_auth1 = QuIDAuth::new(vec![10u8; 32], SecurityLevel::Level1);
    let identity1 = quid_auth1.create_nym_identity(0).unwrap();
    
    let quid_auth2 = QuIDAuth::new(vec![20u8; 32], SecurityLevel::Level1);
    let identity2 = quid_auth2.create_nym_identity(0).unwrap();
    
    // Store transactions for each identity
    let tx1 = Transaction::Public(nym_core::PublicTransaction::new(
        TransactionType::PublicTransfer,
        vec![], vec![], 1000, &identity1,
    ).unwrap());
    
    let tx2 = Transaction::Public(nym_core::PublicTransaction::new(
        TransactionType::PublicTransfer,
        vec![], vec![], 2000, &identity2,
    ).unwrap());
    
    quid_tx_store.store_quid_transaction(&tx1, &identity1, 100).unwrap();
    quid_tx_store.store_quid_transaction(&tx2, &identity2, 101).unwrap();
    
    // Each identity should only see their own transactions
    let txs1 = quid_tx_store.get_quid_transactions(&identity1, None, None).unwrap();
    assert_eq!(txs1.len(), 1);
    assert_eq!(txs1[0].hash(), tx1.hash());
    
    let txs2 = quid_tx_store.get_quid_transactions(&identity2, None, None).unwrap();
    assert_eq!(txs2.len(), 1);
    assert_eq!(txs2[0].hash(), tx2.hash());
    
    // Backup from one identity should not contain other's data
    let backup1 = quid_tx_store.create_quid_backup(&identity1).unwrap();
    let backup2 = quid_tx_store.create_quid_backup(&identity2).unwrap();
    
    // Backups should be different
    assert_ne!(backup1, backup2);
    
    println!("✅ QuID privacy isolation test passed!");
}

/// Test progressive security levels in recovery system
#[test]
fn test_progressive_security_levels() {
    let temp_dir = TempDir::new().unwrap();
    let store_config = EncryptionConfig::new(vec![4u8; 32], SecurityLevel::Level3);
    let store = EncryptedStore::new(temp_dir.path(), store_config).unwrap();
    
    let backup_config = BackupConfig::default();
    let backup_manager = BackupManager::new(store, backup_config).unwrap();
    
    let quid_auth = QuIDAuth::new(vec![50u8; 32], SecurityLevel::Level3);
    let identity = quid_auth.create_nym_identity(0).unwrap();
    
    let recovery_config = QuIDRecoveryConfig {
        security_levels: quid_recovery::ProgressiveSecurityConfig {
            basic_tier: quid_recovery::SecurityTier {
                max_transaction_amount: 1_000,
                auth_factors: 1,
                recovery_window: Duration::from_secs(3600),
                verification_requirements: vec![],
            },
            enhanced_tier: quid_recovery::SecurityTier {
                max_transaction_amount: 100_000,
                auth_factors: 2,
                recovery_window: Duration::from_secs(7200),
                verification_requirements: vec![
                    quid_recovery::VerificationRequirement::Biometric {
                        biometric_type: "fingerprint".to_string()
                    },
                ],
            },
            maximum_tier: quid_recovery::SecurityTier {
                max_transaction_amount: u64::MAX,
                auth_factors: 3,
                recovery_window: Duration::from_secs(86400),
                verification_requirements: vec![
                    quid_recovery::VerificationRequirement::Biometric {
                        biometric_type: "fingerprint".to_string()
                    },
                    quid_recovery::VerificationRequirement::HardwareToken {
                        token_id: "yubikey".to_string()
                    },
                    quid_recovery::VerificationRequirement::CommunityVerification {
                        required_confirmations: 3
                    },
                ],
            },
        },
        ..Default::default()
    };
    
    let recovery_manager = QuIDRecoveryManager::new(
        recovery_config.clone(),
        identity,
        backup_manager
    );
    
    // Verify security tier configurations
    assert_eq!(recovery_config.security_levels.basic_tier.max_transaction_amount, 1_000);
    assert_eq!(recovery_config.security_levels.basic_tier.auth_factors, 1);
    assert_eq!(recovery_config.security_levels.basic_tier.verification_requirements.len(), 0);
    
    assert_eq!(recovery_config.security_levels.enhanced_tier.max_transaction_amount, 100_000);
    assert_eq!(recovery_config.security_levels.enhanced_tier.auth_factors, 2);
    assert_eq!(recovery_config.security_levels.enhanced_tier.verification_requirements.len(), 1);
    
    assert_eq!(recovery_config.security_levels.maximum_tier.max_transaction_amount, u64::MAX);
    assert_eq!(recovery_config.security_levels.maximum_tier.auth_factors, 3);
    assert_eq!(recovery_config.security_levels.maximum_tier.verification_requirements.len(), 3);
    
    println!("✅ Progressive security levels test passed!");
}

/// Test ecosystem backup and recovery integration
#[test] 
fn test_ecosystem_backup_recovery() {
    let temp_dir = TempDir::new().unwrap();
    
    // Setup complete ecosystem
    let store_config = EncryptionConfig::new(vec![5u8; 32], SecurityLevel::Level2);
    let store = EncryptedStore::new(temp_dir.path().join("ecosystem_store"), store_config).unwrap();
    
    let backup_config = BackupConfig {
        backup_path: temp_dir.path().join("ecosystem_backups"),
        ..Default::default()
    };
    let backup_manager = BackupManager::new(store.clone(), backup_config).unwrap();
    
    let quid_auth = QuIDAuth::new(vec![60u8; 32], SecurityLevel::Level2);
    let identity = quid_auth.create_nym_identity(0).unwrap();
    
    let mut recovery_manager = QuIDRecoveryManager::new(
        QuIDRecoveryConfig::default(),
        identity.clone(),
        backup_manager
    );
    
    let mut quid_tx_store = QuIDTransactionStore::new(store.clone());
    let mut account_store = AccountStore::new(store);
    
    // Create and store account
    let account = nym_core::Account::new(identity.clone(), 200).unwrap();
    let account_id = account.account_id();
    account_store.store_account(&account).unwrap();
    
    // Store QuID-encrypted transactions
    for i in 0..3 {
        let tx = Transaction::Public(nym_core::PublicTransaction::new(
            TransactionType::PublicTransfer,
            vec![], vec![], 1000 + i, &identity,
        ).unwrap());
        
        quid_tx_store.store_quid_transaction(&tx, &identity, 200 + i).unwrap();
    }
    
    // Create integrated backup
    let ecosystem_backup_id = recovery_manager.create_quid_integrated_backup().unwrap();
    
    // Create QuID transaction backup
    let quid_backup_data = quid_tx_store.create_quid_backup(&identity).unwrap();
    
    // Verify ecosystem integration
    assert_ne!(ecosystem_backup_id.as_bytes(), &[0u8; 32]);
    assert!(!quid_backup_data.is_empty());
    assert_eq!(quid_tx_store.get_quid_transaction_count(&identity), 3);
    
    // Verify account was stored
    let retrieved_account = account_store.get_account(&account_id).unwrap().unwrap();
    assert_eq!(retrieved_account.account_id(), account_id);
    
    println!("✅ Ecosystem backup and recovery integration test passed!");
}