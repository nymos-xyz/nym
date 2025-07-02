//! QuID-integrated recovery system for Nym storage
//! 
//! This module integrates the QuID recovery strategies with Nym's storage layer,
//! enabling users to recover their Nym cryptocurrency data using their QuID identity
//! recovery mechanisms (multi-signature, time-locked migration, etc.)

use std::collections::HashMap;
use std::path::PathBuf;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use nym_crypto::{Hash256, SecurityLevel};
use nym_core::NymIdentity;
use crate::{StorageError, StorageResult, BackupManager, BackupConfig};

/// QuID recovery configuration for Nym storage
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QuIDRecoveryConfig {
    /// Recovery threshold (e.g., 3-of-5 keys)
    pub recovery_threshold: RecoveryThreshold,
    /// Time-lock period for recovery operations
    pub time_lock_period: Duration,
    /// Recovery key storage locations
    pub recovery_locations: Vec<RecoveryLocation>,
    /// Emergency revocation settings
    pub emergency_revocation: EmergencyRevocationConfig,
    /// Progressive security levels
    pub security_levels: ProgressiveSecurityConfig,
}

/// Recovery threshold configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryThreshold {
    /// Required number of recovery keys
    pub required: usize,
    /// Total number of recovery keys
    pub total: usize,
    /// Security level for recovery operations
    pub security_level: SecurityLevel,
}

/// Recovery key storage location
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryLocation {
    /// Location identifier
    pub id: String,
    /// Location type
    pub location_type: RecoveryLocationType,
    /// Encrypted recovery key fragment
    pub key_fragment: Vec<u8>,
    /// Verification data
    pub verification_hash: Hash256,
    /// Last verified timestamp
    pub last_verified: u64,
}

/// Types of recovery locations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryLocationType {
    /// Hardware Security Module
    HSM { device_id: String },
    /// Trusted family member
    TrustedContact { contact_id: String },
    /// Professional escrow service
    EscrowService { service_id: String },
    /// Physical secure storage
    PhysicalStorage { location_id: String },
    /// Institutional custodian
    InstitutionalCustodian { institution_id: String },
}

/// Emergency revocation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EmergencyRevocationConfig {
    /// Emergency key for immediate revocation
    pub emergency_key: Vec<u8>,
    /// Revocation authority contacts
    pub revocation_authorities: Vec<String>,
    /// Automatic revocation triggers
    pub auto_revocation_triggers: Vec<RevocationTrigger>,
}

/// Triggers for automatic revocation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RevocationTrigger {
    /// Suspicious activity detected
    SuspiciousActivity { threshold: f64 },
    /// Multiple failed recovery attempts
    FailedRecoveryAttempts { max_attempts: u32 },
    /// Geographic anomaly
    GeographicAnomaly { distance_km: f64 },
    /// Time-based anomaly
    TimeAnomaly { unusual_hours: bool },
}

/// Progressive security configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProgressiveSecurityConfig {
    /// Basic tier limits
    pub basic_tier: SecurityTier,
    /// Enhanced tier limits
    pub enhanced_tier: SecurityTier,
    /// Maximum tier limits
    pub maximum_tier: SecurityTier,
}

/// Security tier configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityTier {
    /// Maximum transaction amount
    pub max_transaction_amount: u64,
    /// Required authentication factors
    pub auth_factors: u32,
    /// Recovery time window
    pub recovery_window: Duration,
    /// Additional verification requirements
    pub verification_requirements: Vec<VerificationRequirement>,
}

/// Verification requirements
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum VerificationRequirement {
    /// Biometric verification
    Biometric { biometric_type: String },
    /// Hardware token
    HardwareToken { token_id: String },
    /// Geographic verification
    GeographicVerification { allowed_regions: Vec<String> },
    /// Time-based verification
    TimeBasedVerification { allowed_hours: (u8, u8) },
    /// Community verification
    CommunityVerification { required_confirmations: u32 },
}

/// QuID recovery manager for Nym storage
pub struct QuIDRecoveryManager {
    /// Recovery configuration
    config: QuIDRecoveryConfig,
    /// QuID identity
    identity: NymIdentity,
    /// Backup manager for storage operations
    backup_manager: BackupManager,
    /// Recovery state
    recovery_state: RecoveryState,
    /// Active recovery sessions
    active_recovery_sessions: HashMap<Hash256, RecoverySession>,
}

/// Recovery state
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryState {
    /// Last backup timestamp
    pub last_backup: Option<u64>,
    /// Recovery attempts in progress
    pub active_recoveries: Vec<Hash256>,
    /// Failed recovery attempts
    pub failed_attempts: Vec<FailedRecoveryAttempt>,
    /// Security level
    pub current_security_level: SecurityLevel,
}

/// Recovery session
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoverySession {
    /// Session ID
    pub session_id: Hash256,
    /// Recovery type
    pub recovery_type: RecoveryType,
    /// Start timestamp
    pub started_at: u64,
    /// Time lock expires at
    pub time_lock_expires: u64,
    /// Collected recovery keys
    pub collected_keys: Vec<RecoveryKeyFragment>,
    /// Verification status
    pub verification_status: VerificationStatus,
    /// Recovery progress
    pub progress: RecoveryProgress,
}

/// Types of recovery operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryType {
    /// Full identity recovery
    FullIdentityRecovery,
    /// Partial data recovery
    PartialDataRecovery { data_types: Vec<String> },
    /// Emergency revocation
    EmergencyRevocation,
    /// Security level migration
    SecurityLevelMigration { target_level: SecurityLevel },
}

/// Recovery key fragment
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryKeyFragment {
    /// Fragment ID
    pub fragment_id: String,
    /// Encrypted key data
    pub encrypted_key_data: Vec<u8>,
    /// Source location
    pub source_location: RecoveryLocationType,
    /// Verification proof
    pub verification_proof: Vec<u8>,
    /// Timestamp collected
    pub collected_at: u64,
}

/// Verification status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationStatus {
    /// Biometric verification complete
    pub biometric_verified: bool,
    /// Hardware token verified
    pub hardware_token_verified: bool,
    /// Geographic verification complete
    pub geographic_verified: bool,
    /// Time-based verification complete
    pub time_verified: bool,
    /// Community verification status
    pub community_verification: CommunityVerificationStatus,
}

/// Community verification status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommunityVerificationStatus {
    /// Required confirmations
    pub required_confirmations: u32,
    /// Received confirmations
    pub received_confirmations: u32,
    /// Confirming parties
    pub confirming_parties: Vec<String>,
    /// Challenge period expires
    pub challenge_period_expires: u64,
}

/// Recovery progress
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryProgress {
    /// Keys collected
    pub keys_collected: usize,
    /// Keys required
    pub keys_required: usize,
    /// Verification steps completed
    pub verification_completed: usize,
    /// Total verification steps
    pub verification_total: usize,
    /// Estimated completion time
    pub estimated_completion: Option<u64>,
}

/// Failed recovery attempt
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FailedRecoveryAttempt {
    /// Attempt timestamp
    pub timestamp: u64,
    /// Failure reason
    pub reason: String,
    /// Source IP/location
    pub source_location: Option<String>,
    /// Recovery type attempted
    pub recovery_type: RecoveryType,
}

impl Default for QuIDRecoveryConfig {
    fn default() -> Self {
        Self {
            recovery_threshold: RecoveryThreshold {
                required: 3,
                total: 5,
                security_level: SecurityLevel::Level2,
            },
            time_lock_period: Duration::from_secs(7 * 24 * 3600), // 7 days
            recovery_locations: Vec::new(),
            emergency_revocation: EmergencyRevocationConfig {
                emergency_key: vec![0u8; 32], // Should be properly generated
                revocation_authorities: Vec::new(),
                auto_revocation_triggers: vec![
                    RevocationTrigger::FailedRecoveryAttempts { max_attempts: 5 },
                    RevocationTrigger::SuspiciousActivity { threshold: 0.8 },
                ],
            },
            security_levels: ProgressiveSecurityConfig {
                basic_tier: SecurityTier {
                    max_transaction_amount: 100_000, // 100 NYM
                    auth_factors: 1,
                    recovery_window: Duration::from_secs(24 * 3600), // 24 hours
                    verification_requirements: vec![],
                },
                enhanced_tier: SecurityTier {
                    max_transaction_amount: 10_000_000, // 10,000 NYM  
                    auth_factors: 2,
                    recovery_window: Duration::from_secs(48 * 3600), // 48 hours
                    verification_requirements: vec![
                        VerificationRequirement::Biometric {
                            biometric_type: "fingerprint".to_string(),
                        },
                    ],
                },
                maximum_tier: SecurityTier {
                    max_transaction_amount: u64::MAX,
                    auth_factors: 3,
                    recovery_window: Duration::from_secs(7 * 24 * 3600), // 7 days
                    verification_requirements: vec![
                        VerificationRequirement::Biometric {
                            biometric_type: "fingerprint".to_string(),
                        },
                        VerificationRequirement::HardwareToken {
                            token_id: "yubikey".to_string(),
                        },
                        VerificationRequirement::CommunityVerification {
                            required_confirmations: 3,
                        },
                    ],
                },
            },
        }
    }
}

impl QuIDRecoveryManager {
    /// Create a new QuID recovery manager
    pub fn new(
        config: QuIDRecoveryConfig,
        identity: NymIdentity,
        backup_manager: BackupManager,
    ) -> Self {
        Self {
            config,
            identity,
            backup_manager,
            recovery_state: RecoveryState {
                last_backup: None,
                active_recoveries: Vec::new(),
                failed_attempts: Vec::new(),
                current_security_level: SecurityLevel::Level1,
            },
            active_recovery_sessions: HashMap::new(),
        }
    }
    
    /// Initiate recovery process
    pub fn initiate_recovery(&mut self, recovery_type: RecoveryType) -> StorageResult<Hash256> {
        let session_id = Hash256::from_bytes(rand::random::<[u8; 32]>());
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let time_lock_expires = now + self.config.time_lock_period.as_secs();
        
        let session = RecoverySession {
            session_id,
            recovery_type: recovery_type.clone(),
            started_at: now,
            time_lock_expires,
            collected_keys: Vec::new(),
            verification_status: VerificationStatus {
                biometric_verified: false,
                hardware_token_verified: false,
                geographic_verified: false,
                time_verified: false,
                community_verification: CommunityVerificationStatus {
                    required_confirmations: 3,
                    received_confirmations: 0,
                    confirming_parties: Vec::new(),
                    challenge_period_expires: time_lock_expires,
                },
            },
            progress: RecoveryProgress {
                keys_collected: 0,
                keys_required: self.config.recovery_threshold.required,
                verification_completed: 0,
                verification_total: self.get_verification_steps_for_type(&recovery_type),
                estimated_completion: Some(time_lock_expires),
            },
        };
        
        self.active_recovery_sessions.insert(session_id, session);
        self.recovery_state.active_recoveries.push(session_id);
        
        tracing::info!(
            "Initiated recovery session {} for type {:?}",
            session_id,
            recovery_type
        );
        
        Ok(session_id)
    }
    
    /// Submit recovery key fragment
    pub fn submit_recovery_key(
        &mut self,
        session_id: Hash256,
        fragment: RecoveryKeyFragment,
    ) -> StorageResult<bool> {
        let session = self.active_recovery_sessions.get_mut(&session_id)
            .ok_or_else(|| StorageError::RecoveryFailed {
                reason: "Recovery session not found".to_string(),
            })?;
        
        // Verify the key fragment
        if !self.verify_key_fragment(&fragment)? {
            return Err(StorageError::RecoveryFailed {
                reason: "Invalid recovery key fragment".to_string(),
            });
        }
        
        // Add to collected keys
        session.collected_keys.push(fragment);
        session.progress.keys_collected = session.collected_keys.len();
        
        // Check if we have enough keys
        let threshold_met = session.progress.keys_collected >= session.progress.keys_required;
        
        if threshold_met {
            tracing::info!(
                "Recovery threshold met for session {}",
                session_id
            );
        }
        
        Ok(threshold_met)
    }
    
    /// Submit verification proof
    pub fn submit_verification_proof(
        &mut self,
        session_id: Hash256,
        verification_type: VerificationRequirement,
        proof: Vec<u8>,
    ) -> StorageResult<bool> {
        let session = self.active_recovery_sessions.get_mut(&session_id)
            .ok_or_else(|| StorageError::RecoveryFailed {
                reason: "Recovery session not found".to_string(),
            })?;
        
        // Verify the proof
        if !self.verify_proof(&verification_type, &proof)? {
            return Err(StorageError::RecoveryFailed {
                reason: "Invalid verification proof".to_string(),
            });
        }
        
        // Update verification status
        match verification_type {
            VerificationRequirement::Biometric { .. } => {
                session.verification_status.biometric_verified = true;
            }
            VerificationRequirement::HardwareToken { .. } => {
                session.verification_status.hardware_token_verified = true;
            }
            VerificationRequirement::GeographicVerification { .. } => {
                session.verification_status.geographic_verified = true;
            }
            VerificationRequirement::TimeBasedVerification { .. } => {
                session.verification_status.time_verified = true;
            }
            VerificationRequirement::CommunityVerification { .. } => {
                session.verification_status.community_verification.received_confirmations += 1;
            }
        }
        
        // Update progress
        session.progress.verification_completed = self.count_completed_verifications(session);
        
        let all_verified = session.progress.verification_completed >= session.progress.verification_total;
        
        if all_verified {
            tracing::info!(
                "All verifications completed for session {}",
                session_id
            );
        }
        
        Ok(all_verified)
    }
    
    /// Execute recovery after time lock and verifications
    pub fn execute_recovery(&mut self, session_id: Hash256) -> StorageResult<()> {
        let session = self.active_recovery_sessions.get(&session_id)
            .ok_or_else(|| StorageError::RecoveryFailed {
                reason: "Recovery session not found".to_string(),
            })?;
        
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        // Check time lock
        if now < session.time_lock_expires {
            return Err(StorageError::RecoveryFailed {
                reason: format!(
                    "Time lock not expired. {} seconds remaining",
                    session.time_lock_expires - now
                ),
            });
        }
        
        // Check threshold
        if session.progress.keys_collected < session.progress.keys_required {
            return Err(StorageError::RecoveryFailed {
                reason: "Insufficient recovery keys".to_string(),
            });
        }
        
        // Check verifications
        if session.progress.verification_completed < session.progress.verification_total {
            return Err(StorageError::RecoveryFailed {
                reason: "Incomplete verification requirements".to_string(),
            });
        }
        
        // Execute the recovery based on type
        match &session.recovery_type {
            RecoveryType::FullIdentityRecovery => {
                self.execute_full_recovery(session)?;
            }
            RecoveryType::PartialDataRecovery { data_types } => {
                self.execute_partial_recovery(session, data_types)?;
            }
            RecoveryType::EmergencyRevocation => {
                self.execute_emergency_revocation(session)?;
            }
            RecoveryType::SecurityLevelMigration { target_level } => {
                self.execute_security_migration(session, *target_level)?;
            }
        }
        
        // Clean up session
        self.active_recovery_sessions.remove(&session_id);
        self.recovery_state.active_recoveries.retain(|&id| id != session_id);
        
        tracing::info!("Recovery session {} executed successfully", session_id);
        
        Ok(())
    }
    
    /// Get recovery session status
    pub fn get_recovery_status(&self, session_id: Hash256) -> Option<&RecoverySession> {
        self.active_recovery_sessions.get(&session_id)
    }
    
    /// Create encrypted backup integrated with QuID recovery
    pub fn create_quid_integrated_backup(&mut self) -> StorageResult<Hash256> {
        // Create backup using the backup manager
        let backup_metadata = self.backup_manager.create_full_backup()?;
        
        // Create recovery-specific backup metadata
        let recovery_backup = RecoveryBackup {
            backup_id: Hash256::from_bytes(rand::random::<[u8; 32]>()),
            standard_backup_timestamp: backup_metadata.timestamp,
            quid_identity: self.identity.clone(),
            recovery_config: self.config.clone(),
            encrypted_with_recovery_keys: true,
            created_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };
        
        // Store recovery backup metadata
        self.store_recovery_backup_metadata(&recovery_backup)?;
        
        self.recovery_state.last_backup = Some(recovery_backup.created_at);
        
        Ok(recovery_backup.backup_id)
    }
    
    // Private helper methods
    
    fn get_verification_steps_for_type(&self, recovery_type: &RecoveryType) -> usize {
        match recovery_type {
            RecoveryType::FullIdentityRecovery => {
                self.config.security_levels.maximum_tier.verification_requirements.len()
            }
            RecoveryType::PartialDataRecovery { .. } => {
                self.config.security_levels.enhanced_tier.verification_requirements.len()
            }
            RecoveryType::EmergencyRevocation => 1, // Just emergency key
            RecoveryType::SecurityLevelMigration { .. } => {
                self.config.security_levels.enhanced_tier.verification_requirements.len()
            }
        }
    }
    
    fn verify_key_fragment(&self, fragment: &RecoveryKeyFragment) -> StorageResult<bool> {
        // Simplified verification - in production, would use proper cryptographic verification
        Ok(!fragment.encrypted_key_data.is_empty() && 
           fragment.verification_proof.len() > 0)
    }
    
    fn verify_proof(&self, verification_type: &VerificationRequirement, proof: &[u8]) -> StorageResult<bool> {
        // Simplified verification - in production, would implement proper verification for each type
        Ok(!proof.is_empty())
    }
    
    fn count_completed_verifications(&self, session: &RecoverySession) -> usize {
        let mut count = 0;
        
        if session.verification_status.biometric_verified { count += 1; }
        if session.verification_status.hardware_token_verified { count += 1; }
        if session.verification_status.geographic_verified { count += 1; }
        if session.verification_status.time_verified { count += 1; }
        
        if session.verification_status.community_verification.received_confirmations >= 
           session.verification_status.community_verification.required_confirmations {
            count += 1;
        }
        
        count
    }
    
    fn execute_full_recovery(&mut self, session: &RecoverySession) -> StorageResult<()> {
        tracing::info!("Executing full identity recovery for session {}", session.session_id);
        
        // Reconstruct master key from fragments
        let _master_key = self.reconstruct_master_key(&session.collected_keys)?;
        
        // In a full implementation:
        // 1. Decrypt all stored data with reconstructed key
        // 2. Restore account chains and transaction history
        // 3. Re-establish stealth addresses and view keys
        // 4. Update identity with new keys while maintaining account continuity
        
        Ok(())
    }
    
    fn execute_partial_recovery(&mut self, session: &RecoverySession, data_types: &[String]) -> StorageResult<()> {
        tracing::info!("Executing partial recovery for session {} with data types: {:?}", 
                      session.session_id, data_types);
        
        // Reconstruct key for specific data types
        let _partial_key = self.reconstruct_partial_key(&session.collected_keys, data_types)?;
        
        // In a full implementation:
        // 1. Decrypt only requested data types
        // 2. Restore specific account chains or transaction subsets
        // 3. Maintain privacy for non-recovered data
        
        Ok(())
    }
    
    fn execute_emergency_revocation(&mut self, session: &RecoverySession) -> StorageResult<()> {
        tracing::info!("Executing emergency revocation for session {}", session.session_id);
        
        // In a full implementation:
        // 1. Immediately revoke old identity
        // 2. Generate new identity with new keys
        // 3. Transfer account balances to new identity
        // 4. Invalidate old stealth addresses
        // 5. Notify network of identity migration
        
        Ok(())
    }
    
    fn execute_security_migration(&mut self, session: &RecoverySession, target_level: SecurityLevel) -> StorageResult<()> {
        tracing::info!("Executing security level migration for session {} to level {:?}", 
                      session.session_id, target_level);
        
        self.recovery_state.current_security_level = target_level;
        
        // In a full implementation:
        // 1. Generate new keys appropriate for target security level
        // 2. Re-encrypt data with stronger/weaker encryption as needed
        // 3. Update recovery thresholds and time locks
        // 4. Adjust transaction limits and verification requirements
        
        Ok(())
    }
    
    fn reconstruct_master_key(&self, fragments: &[RecoveryKeyFragment]) -> StorageResult<Vec<u8>> {
        // Simplified reconstruction - in production, would use proper threshold cryptography
        if fragments.len() < self.config.recovery_threshold.required {
            return Err(StorageError::RecoveryFailed {
                reason: "Insufficient key fragments for reconstruction".to_string(),
            });
        }
        
        // Placeholder reconstruction
        Ok(vec![42u8; 32])
    }
    
    fn reconstruct_partial_key(&self, fragments: &[RecoveryKeyFragment], _data_types: &[String]) -> StorageResult<Vec<u8>> {
        // Simplified reconstruction for partial data
        self.reconstruct_master_key(fragments)
    }
    
    fn store_recovery_backup_metadata(&self, backup: &RecoveryBackup) -> StorageResult<()> {
        // Store the recovery backup metadata
        // In a full implementation, this would be stored securely
        tracing::info!("Stored recovery backup metadata for backup {}", backup.backup_id);
        Ok(())
    }
}

/// Recovery backup metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryBackup {
    /// Unique backup ID
    pub backup_id: Hash256,
    /// Standard backup timestamp reference
    pub standard_backup_timestamp: u64,
    /// QuID identity associated with backup
    pub quid_identity: NymIdentity,
    /// Recovery configuration used
    pub recovery_config: QuIDRecoveryConfig,
    /// Whether backup is encrypted with recovery keys
    pub encrypted_with_recovery_keys: bool,
    /// Creation timestamp
    pub created_at: u64,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use crate::{EncryptedStore, EncryptionConfig};
    use nym_crypto::QuIDAuth;
    use std::time::Duration;
    
    fn create_test_identity() -> NymIdentity {
        let quid_auth = QuIDAuth::new(vec![1u8; 32], SecurityLevel::Level1);
        quid_auth.create_nym_identity(0).unwrap()
    }
    
    fn create_test_recovery_config() -> QuIDRecoveryConfig {
        QuIDRecoveryConfig {
            recovery_threshold: RecoveryThreshold {
                required: 2, // Lower threshold for testing
                total: 3,
                security_level: SecurityLevel::Level1,
            },
            time_lock_period: Duration::from_secs(60), // 1 minute for testing
            recovery_locations: vec![
                RecoveryLocation {
                    id: "hsm1".to_string(),
                    location_type: RecoveryLocationType::HSM { device_id: "test_hsm_1".to_string() },
                    key_fragment: vec![1, 2, 3, 4],
                    verification_hash: Hash256::from_bytes([1u8; 32]),
                    last_verified: 0,
                },
                RecoveryLocation {
                    id: "contact1".to_string(),
                    location_type: RecoveryLocationType::TrustedContact { contact_id: "alice@example.com".to_string() },
                    key_fragment: vec![5, 6, 7, 8],
                    verification_hash: Hash256::from_bytes([2u8; 32]),
                    last_verified: 0,
                },
            ],
            emergency_revocation: EmergencyRevocationConfig {
                emergency_key: vec![42u8; 32],
                revocation_authorities: vec!["authority1@example.com".to_string()],
                auto_revocation_triggers: vec![
                    RevocationTrigger::FailedRecoveryAttempts { max_attempts: 3 },
                ],
            },
            security_levels: ProgressiveSecurityConfig {
                basic_tier: SecurityTier {
                    max_transaction_amount: 1000,
                    auth_factors: 1,
                    recovery_window: Duration::from_secs(3600),
                    verification_requirements: vec![],
                },
                enhanced_tier: SecurityTier {
                    max_transaction_amount: 10000,
                    auth_factors: 2,
                    recovery_window: Duration::from_secs(7200),
                    verification_requirements: vec![
                        VerificationRequirement::Biometric { biometric_type: "fingerprint".to_string() },
                    ],
                },
                maximum_tier: SecurityTier {
                    max_transaction_amount: u64::MAX,
                    auth_factors: 3,
                    recovery_window: Duration::from_secs(86400),
                    verification_requirements: vec![
                        VerificationRequirement::Biometric { biometric_type: "fingerprint".to_string() },
                        VerificationRequirement::HardwareToken { token_id: "yubikey".to_string() },
                    ],
                },
            },
        }
    }
    
    #[test]
    fn test_recovery_manager_creation() {
        let temp_dir = TempDir::new().unwrap();
        let identity = create_test_identity();
        
        let store_config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path().join("store"), store_config).unwrap();
        
        let backup_config = BackupConfig::default();
        let backup_manager = BackupManager::new(store, backup_config).unwrap();
        
        let recovery_config = create_test_recovery_config();
        let recovery_manager = QuIDRecoveryManager::new(recovery_config, identity, backup_manager);
        
        assert_eq!(recovery_manager.active_recovery_sessions.len(), 0);
        assert_eq!(recovery_manager.recovery_state.active_recoveries.len(), 0);
        assert_eq!(recovery_manager.recovery_state.current_security_level, SecurityLevel::Level1);
    }
    
    #[test]
    fn test_recovery_initiation() {
        let temp_dir = TempDir::new().unwrap();
        let identity = create_test_identity();
        
        let store_config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path().join("store"), store_config).unwrap();
        
        let backup_config = BackupConfig::default();
        let backup_manager = BackupManager::new(store, backup_config).unwrap();
        
        let recovery_config = create_test_recovery_config();
        let mut recovery_manager = QuIDRecoveryManager::new(recovery_config, identity, backup_manager);
        
        let session_id = recovery_manager.initiate_recovery(RecoveryType::FullIdentityRecovery).unwrap();
        
        assert_eq!(recovery_manager.active_recovery_sessions.len(), 1);
        assert_eq!(recovery_manager.recovery_state.active_recoveries.len(), 1);
        assert!(recovery_manager.get_recovery_status(session_id).is_some());
        
        if let Some(session) = recovery_manager.get_recovery_status(session_id) {
            assert_eq!(session.progress.keys_required, 2); // Our test config threshold
            assert_eq!(session.progress.keys_collected, 0);
            assert!(matches!(session.recovery_type, RecoveryType::FullIdentityRecovery));
        }
    }
    
    #[test]
    fn test_recovery_key_submission() {
        let temp_dir = TempDir::new().unwrap();
        let identity = create_test_identity();
        
        let store_config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path().join("store"), store_config).unwrap();
        
        let backup_config = BackupConfig::default();
        let backup_manager = BackupManager::new(store, backup_config).unwrap();
        
        let recovery_config = create_test_recovery_config();
        let mut recovery_manager = QuIDRecoveryManager::new(recovery_config, identity, backup_manager);
        
        let session_id = recovery_manager.initiate_recovery(RecoveryType::FullIdentityRecovery).unwrap();
        
        // Submit first key fragment
        let fragment1 = RecoveryKeyFragment {
            fragment_id: "test_fragment_1".to_string(),
            encrypted_key_data: vec![1, 2, 3, 4],
            source_location: RecoveryLocationType::HSM { device_id: "test_hsm_1".to_string() },
            verification_proof: vec![5, 6, 7, 8],
            collected_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        let result = recovery_manager.submit_recovery_key(session_id, fragment1).unwrap();
        assert!(!result); // Should not meet threshold with just 1 key
        
        // Submit second key fragment
        let fragment2 = RecoveryKeyFragment {
            fragment_id: "test_fragment_2".to_string(),
            encrypted_key_data: vec![9, 10, 11, 12],
            source_location: RecoveryLocationType::TrustedContact { contact_id: "alice@example.com".to_string() },
            verification_proof: vec![13, 14, 15, 16],
            collected_at: SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs(),
        };
        
        let result = recovery_manager.submit_recovery_key(session_id, fragment2).unwrap();
        assert!(result); // Should meet threshold with 2 keys
        
        if let Some(session) = recovery_manager.get_recovery_status(session_id) {
            assert_eq!(session.progress.keys_collected, 2);
            assert_eq!(session.collected_keys.len(), 2);
        }
    }
    
    #[test]
    fn test_verification_submission() {
        let temp_dir = TempDir::new().unwrap();
        let identity = create_test_identity();
        
        let store_config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path().join("store"), store_config).unwrap();
        
        let backup_config = BackupConfig::default();
        let backup_manager = BackupManager::new(store, backup_config).unwrap();
        
        let recovery_config = create_test_recovery_config();
        let mut recovery_manager = QuIDRecoveryManager::new(recovery_config, identity, backup_manager);
        
        let session_id = recovery_manager.initiate_recovery(RecoveryType::PartialDataRecovery { 
            data_types: vec!["transactions".to_string()] 
        }).unwrap();
        
        // Submit biometric verification
        let biometric_verification = VerificationRequirement::Biometric { 
            biometric_type: "fingerprint".to_string() 
        };
        let proof = vec![1, 2, 3, 4]; // Mock biometric proof
        
        let result = recovery_manager.submit_verification_proof(session_id, biometric_verification, proof).unwrap();
        assert!(result); // Should complete all verifications for partial recovery
        
        if let Some(session) = recovery_manager.get_recovery_status(session_id) {
            assert!(session.verification_status.biometric_verified);
            assert_eq!(session.progress.verification_completed, 1);
        }
    }
    
    #[test]
    fn test_recovery_execution_time_lock() {
        let temp_dir = TempDir::new().unwrap();
        let identity = create_test_identity();
        
        let store_config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path().join("store"), store_config).unwrap();
        
        let backup_config = BackupConfig::default();
        let backup_manager = BackupManager::new(store, backup_config).unwrap();
        
        let recovery_config = create_test_recovery_config();
        let mut recovery_manager = QuIDRecoveryManager::new(recovery_config, identity, backup_manager);
        
        let session_id = recovery_manager.initiate_recovery(RecoveryType::EmergencyRevocation).unwrap();
        
        // Try to execute recovery before time lock expires
        let result = recovery_manager.execute_recovery(session_id);
        assert!(result.is_err());
        
        if let Err(StorageError::RecoveryFailed { reason }) = result {
            assert!(reason.contains("Time lock not expired"));
        }
    }
    
    #[test]
    fn test_quid_integrated_backup() {
        let temp_dir = TempDir::new().unwrap();
        let identity = create_test_identity();
        
        let store_config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path().join("store"), store_config).unwrap();
        
        let backup_config = BackupConfig {
            backup_path: temp_dir.path().join("backups"),
            ..Default::default()
        };
        let backup_manager = BackupManager::new(store, backup_config).unwrap();
        
        let recovery_config = create_test_recovery_config();
        let mut recovery_manager = QuIDRecoveryManager::new(recovery_config, identity, backup_manager);
        
        let backup_id = recovery_manager.create_quid_integrated_backup().unwrap();
        
        // Verify backup was created
        assert!(recovery_manager.recovery_state.last_backup.is_some());
        
        // Verify backup ID is valid
        assert_ne!(backup_id.as_bytes(), &[0u8; 32]);
    }
    
    #[test]
    fn test_recovery_types() {
        let temp_dir = TempDir::new().unwrap();
        let identity = create_test_identity();
        
        let store_config = EncryptionConfig::new(vec![1u8; 32], SecurityLevel::Level1);
        let store = EncryptedStore::new(temp_dir.path().join("store"), store_config).unwrap();
        
        let backup_config = BackupConfig::default();
        let backup_manager = BackupManager::new(store, backup_config).unwrap();
        
        let recovery_config = create_test_recovery_config();
        let mut recovery_manager = QuIDRecoveryManager::new(recovery_config, identity, backup_manager);
        
        // Test different recovery types
        let recovery_types = vec![
            RecoveryType::FullIdentityRecovery,
            RecoveryType::PartialDataRecovery { data_types: vec!["accounts".to_string()] },
            RecoveryType::EmergencyRevocation,
            RecoveryType::SecurityLevelMigration { target_level: SecurityLevel::Level2 },
        ];
        
        for recovery_type in recovery_types {
            let session_id = recovery_manager.initiate_recovery(recovery_type.clone()).unwrap();
            
            if let Some(session) = recovery_manager.get_recovery_status(session_id) {
                assert_eq!(session.recovery_type, recovery_type);
                assert!(session.time_lock_expires > 0);
            }
        }
        
        assert_eq!(recovery_manager.active_recovery_sessions.len(), 4);
    }
    
    #[test]
    fn test_progressive_security_config() {
        let config = create_test_recovery_config();
        
        // Test basic tier limits
        assert_eq!(config.security_levels.basic_tier.max_transaction_amount, 1000);
        assert_eq!(config.security_levels.basic_tier.auth_factors, 1);
        assert_eq!(config.security_levels.basic_tier.verification_requirements.len(), 0);
        
        // Test enhanced tier requirements
        assert_eq!(config.security_levels.enhanced_tier.max_transaction_amount, 10000);
        assert_eq!(config.security_levels.enhanced_tier.auth_factors, 2);
        assert_eq!(config.security_levels.enhanced_tier.verification_requirements.len(), 1);
        
        // Test maximum tier requirements
        assert_eq!(config.security_levels.maximum_tier.max_transaction_amount, u64::MAX);
        assert_eq!(config.security_levels.maximum_tier.auth_factors, 3);
        assert_eq!(config.security_levels.maximum_tier.verification_requirements.len(), 2);
    }
    
    #[test]
    fn test_recovery_location_types() {
        let config = create_test_recovery_config();
        
        assert_eq!(config.recovery_locations.len(), 2);
        
        // Test HSM location
        if let RecoveryLocationType::HSM { device_id } = &config.recovery_locations[0].location_type {
            assert_eq!(device_id, "test_hsm_1");
        } else {
            panic!("Expected HSM location type");
        }
        
        // Test trusted contact location
        if let RecoveryLocationType::TrustedContact { contact_id } = &config.recovery_locations[1].location_type {
            assert_eq!(contact_id, "alice@example.com");
        } else {
            panic!("Expected TrustedContact location type");
        }
    }
    
    #[test]
    fn test_emergency_revocation_config() {
        let config = create_test_recovery_config();
        
        assert_eq!(config.emergency_revocation.emergency_key, vec![42u8; 32]);
        assert_eq!(config.emergency_revocation.revocation_authorities.len(), 1);
        assert_eq!(config.emergency_revocation.auto_revocation_triggers.len(), 1);
        
        if let RevocationTrigger::FailedRecoveryAttempts { max_attempts } = &config.emergency_revocation.auto_revocation_triggers[0] {
            assert_eq!(*max_attempts, 3);
        } else {
            panic!("Expected FailedRecoveryAttempts trigger");
        }
    }
}