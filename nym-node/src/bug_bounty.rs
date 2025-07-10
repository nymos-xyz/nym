use crate::error::{NodeError, Result};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};

/// Bug bounty program management for Nym network
/// Handles vulnerability submissions, validation, and reward distribution
#[derive(Debug)]
pub struct BugBountyProgram {
    submissions: Arc<RwLock<HashMap<String, BugSubmission>>>,
    program_config: Arc<RwLock<BountyProgramConfig>>,
    researchers: Arc<RwLock<HashMap<String, SecurityResearcher>>>,
    reward_pool: Arc<RwLock<RewardPool>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BugSubmission {
    pub submission_id: String,
    pub researcher_id: String,
    pub timestamp: DateTime<Utc>,
    pub title: String,
    pub description: String,
    pub severity: BugSeverity,
    pub category: BugCategory,
    pub affected_components: Vec<String>,
    pub proof_of_concept: Option<String>,
    pub impact_assessment: ImpactAssessment,
    pub status: SubmissionStatus,
    pub assigned_reviewer: Option<String>,
    pub review_notes: Vec<ReviewNote>,
    pub reward_amount: Option<u64>,
    pub public_disclosure_date: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BugSeverity {
    Critical,
    High,
    Medium,
    Low,
    Informational,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum BugCategory {
    CryptographicVulnerability,
    ConsensusAttack,
    PrivacyBreach,
    NetworkSecurity,
    SmartContractBug,
    AccessControl,
    DenialOfService,
    InformationDisclosure,
    InputValidation,
    BusinessLogic,
    ConfigurationIssue,
    DependencyVulnerability,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImpactAssessment {
    pub confidentiality_impact: ImpactLevel,
    pub integrity_impact: ImpactLevel,
    pub availability_impact: ImpactLevel,
    pub scope: ImpactScope,
    pub attack_complexity: AttackComplexity,
    pub privileges_required: PrivilegesRequired,
    pub user_interaction: UserInteraction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImpactLevel {
    None,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ImpactScope {
    Unchanged,
    Changed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AttackComplexity {
    Low,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum PrivilegesRequired {
    None,
    Low,
    High,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum UserInteraction {
    None,
    Required,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SubmissionStatus {
    Submitted,
    UnderReview,
    ValidatedAccepted,
    ValidatedRejected,
    Duplicate,
    OutOfScope,
    Fixed,
    Rewarded,
    PubliclyDisclosed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReviewNote {
    pub reviewer: String,
    pub timestamp: DateTime<Utc>,
    pub note: String,
    pub action: ReviewAction,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ReviewAction {
    InitialAssessment,
    TechnicalValidation,
    SeverityAdjustment,
    RewardCalculation,
    FixVerification,
    PublicDisclosure,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityResearcher {
    pub researcher_id: String,
    pub name: String,
    pub email: String,
    pub reputation_score: f64,
    pub total_submissions: u32,
    pub valid_submissions: u32,
    pub total_rewards: u64,
    pub registration_date: DateTime<Utc>,
    pub hall_of_fame: bool,
    pub preferred_contact: ContactMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ContactMethod {
    Email,
    Discord,
    Telegram,
    Signal,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BountyProgramConfig {
    pub program_active: bool,
    pub max_reward_per_bug: u64,
    pub reward_multipliers: HashMap<BugSeverity, f64>,
    pub scope_components: Vec<String>,
    pub out_of_scope: Vec<String>,
    pub disclosure_timeline_days: u32,
    pub minimum_severity_for_reward: BugSeverity,
    pub duplicate_reward_percentage: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RewardPool {
    pub total_pool: u64,
    pub allocated_rewards: u64,
    pub paid_rewards: u64,
    pub reserved_for_critical: u64,
    pub monthly_budget: u64,
}

impl Default for BountyProgramConfig {
    fn default() -> Self {
        let mut reward_multipliers = HashMap::new();
        reward_multipliers.insert(BugSeverity::Critical, 1.0);
        reward_multipliers.insert(BugSeverity::High, 0.7);
        reward_multipliers.insert(BugSeverity::Medium, 0.4);
        reward_multipliers.insert(BugSeverity::Low, 0.2);
        reward_multipliers.insert(BugSeverity::Informational, 0.1);
        
        Self {
            program_active: true,
            max_reward_per_bug: 100_000, // 100K NYM
            reward_multipliers,
            scope_components: vec![
                "nym-core".to_string(),
                "nym-consensus".to_string(),
                "nym-crypto".to_string(),
                "nym-network".to_string(),
                "nym-vm".to_string(),
                "nym-node".to_string(),
            ],
            out_of_scope: vec![
                "Documentation typos".to_string(),
                "UI/UX suggestions".to_string(),
                "Rate limiting bypass".to_string(),
                "Social engineering".to_string(),
            ],
            disclosure_timeline_days: 90,
            minimum_severity_for_reward: BugSeverity::Low,
            duplicate_reward_percentage: 0.1,
        }
    }
}

impl Default for RewardPool {
    fn default() -> Self {
        Self {
            total_pool: 1_000_000, // 1M NYM
            allocated_rewards: 0,
            paid_rewards: 0,
            reserved_for_critical: 500_000, // 500K NYM reserved for critical bugs
            monthly_budget: 50_000, // 50K NYM per month
        }
    }
}

impl BugBountyProgram {
    pub fn new() -> Self {
        Self {
            submissions: Arc::new(RwLock::new(HashMap::new())),
            program_config: Arc::new(RwLock::new(BountyProgramConfig::default())),
            researchers: Arc::new(RwLock::new(HashMap::new())),
            reward_pool: Arc::new(RwLock::new(RewardPool::default())),
        }
    }
    
    /// Register a new security researcher
    pub async fn register_researcher(
        &self,
        name: String,
        email: String,
        preferred_contact: ContactMethod,
    ) -> Result<String> {
        let researcher_id = format!("researcher_{}", Utc::now().timestamp());
        
        let researcher = SecurityResearcher {
            researcher_id: researcher_id.clone(),
            name,
            email,
            reputation_score: 0.0,
            total_submissions: 0,
            valid_submissions: 0,
            total_rewards: 0,
            registration_date: Utc::now(),
            hall_of_fame: false,
            preferred_contact,
        };
        
        let mut researchers = self.researchers.write().await;
        researchers.insert(researcher_id.clone(), researcher);
        
        println!("✅ Registered new security researcher: {}", researcher_id);
        Ok(researcher_id)
    }
    
    /// Submit a new bug report
    pub async fn submit_bug_report(
        &self,
        researcher_id: String,
        title: String,
        description: String,
        severity: BugSeverity,
        category: BugCategory,
        affected_components: Vec<String>,
        proof_of_concept: Option<String>,
    ) -> Result<String> {
        let config = self.program_config.read().await;
        
        if !config.program_active {
            return Err(NodeError::Config("Bug bounty program is not currently active".to_string()));
        }
        
        // Verify researcher exists
        {
            let researchers = self.researchers.read().await;
            if !researchers.contains_key(&researcher_id) {
                return Err(NodeError::Config("Researcher not registered".to_string()));
            }
        }
        
        // Check if components are in scope
        let in_scope = affected_components.iter()
            .any(|comp| config.scope_components.iter().any(|scope| comp.contains(scope)));
        
        if !in_scope {
            return Err(NodeError::Config("Reported components are out of scope".to_string()));
        }
        
        let submission_id = format!("bug_{}", Utc::now().timestamp());
        
        let submission = BugSubmission {
            submission_id: submission_id.clone(),
            researcher_id: researcher_id.clone(),
            timestamp: Utc::now(),
            title,
            description,
            severity: severity.clone(),
            category,
            affected_components,
            proof_of_concept,
            impact_assessment: Self::calculate_impact_assessment(&severity),
            status: SubmissionStatus::Submitted,
            assigned_reviewer: None,
            review_notes: Vec::new(),
            reward_amount: None,
            public_disclosure_date: None,
        };
        
        // Store submission
        {
            let mut submissions = self.submissions.write().await;
            submissions.insert(submission_id.clone(), submission);
        }
        
        // Update researcher stats
        {
            let mut researchers = self.researchers.write().await;
            if let Some(researcher) = researchers.get_mut(&researcher_id) {
                researcher.total_submissions += 1;
            }
        }
        
        println!("🐛 New bug submission received: {} ({})", submission_id, researcher_id);
        Ok(submission_id)
    }
    
    /// Assign a reviewer to a submission
    pub async fn assign_reviewer(&self, submission_id: &str, reviewer: String) -> Result<()> {
        let mut submissions = self.submissions.write().await;
        
        if let Some(submission) = submissions.get_mut(submission_id) {
            submission.assigned_reviewer = Some(reviewer.clone());
            submission.status = SubmissionStatus::UnderReview;
            
            submission.review_notes.push(ReviewNote {
                reviewer: reviewer.clone(),
                timestamp: Utc::now(),
                note: "Submission assigned for review".to_string(),
                action: ReviewAction::InitialAssessment,
            });
            
            println!("👨‍💻 Assigned reviewer {} to submission {}", reviewer, submission_id);
            Ok(())
        } else {
            Err(NodeError::Config("Submission not found".to_string()))
        }
    }
    
    /// Validate and process a bug submission
    pub async fn validate_submission(
        &self,
        submission_id: &str,
        reviewer: String,
        is_valid: bool,
        severity_adjustment: Option<BugSeverity>,
        review_note: String,
    ) -> Result<()> {
        let mut submissions = self.submissions.write().await;
        
        if let Some(submission) = submissions.get_mut(submission_id) {
            // Update severity if adjusted
            if let Some(new_severity) = severity_adjustment {
                submission.severity = new_severity;
                submission.impact_assessment = Self::calculate_impact_assessment(&submission.severity);
            }
            
            submission.status = if is_valid {
                SubmissionStatus::ValidatedAccepted
            } else {
                SubmissionStatus::ValidatedRejected
            };
            
            submission.review_notes.push(ReviewNote {
                reviewer: reviewer.clone(),
                timestamp: Utc::now(),
                note: review_note,
                action: ReviewAction::TechnicalValidation,
            });
            
            // Calculate reward if valid
            if is_valid {
                let reward = self.calculate_reward_amount(&submission.severity).await?;
                submission.reward_amount = Some(reward);
                
                // Update researcher stats
                {
                    let mut researchers = self.researchers.write().await;
                    if let Some(researcher) = researchers.get_mut(&submission.researcher_id) {
                        researcher.valid_submissions += 1;
                        researcher.reputation_score += match submission.severity {
                            BugSeverity::Critical => 10.0,
                            BugSeverity::High => 7.0,
                            BugSeverity::Medium => 4.0,
                            BugSeverity::Low => 2.0,
                            BugSeverity::Informational => 1.0,
                        };
                    }
                }
            }
            
            println!("✅ Validated submission {} - Valid: {}", submission_id, is_valid);
            Ok(())
        } else {
            Err(NodeError::Config("Submission not found".to_string()))
        }
    }
    
    /// Calculate reward amount based on severity
    async fn calculate_reward_amount(&self, severity: &BugSeverity) -> Result<u64> {
        let config = self.program_config.read().await;
        let base_reward = config.max_reward_per_bug;
        let multiplier = config.reward_multipliers.get(severity).unwrap_or(&0.1);
        
        Ok((base_reward as f64 * multiplier) as u64)
    }
    
    /// Process reward payment
    pub async fn process_reward_payment(&self, submission_id: &str) -> Result<String> {
        let mut submissions = self.submissions.write().await;
        let mut reward_pool = self.reward_pool.write().await;
        
        if let Some(submission) = submissions.get_mut(submission_id) {
            if submission.status != SubmissionStatus::ValidatedAccepted {
                return Err(NodeError::Config("Submission not validated for reward".to_string()));
            }
            
            if let Some(reward_amount) = submission.reward_amount {
                // Check if reward pool has sufficient funds
                if reward_pool.total_pool - reward_pool.allocated_rewards < reward_amount {
                    return Err(NodeError::Config("Insufficient funds in reward pool".to_string()));
                }
                
                // Allocate reward
                reward_pool.allocated_rewards += reward_amount;
                reward_pool.paid_rewards += reward_amount;
                
                submission.status = SubmissionStatus::Rewarded;
                
                // Update researcher total rewards
                {
                    let mut researchers = self.researchers.write().await;
                    if let Some(researcher) = researchers.get_mut(&submission.researcher_id) {
                        researcher.total_rewards += reward_amount;
                        
                        // Check for hall of fame eligibility
                        if researcher.total_rewards >= 50_000 || researcher.valid_submissions >= 10 {
                            researcher.hall_of_fame = true;
                        }
                    }
                }
                
                let transaction_id = format!("reward_tx_{}", Utc::now().timestamp());
                println!("💰 Processed reward payment: {} NYM to researcher {} (tx: {})", 
                    reward_amount, submission.researcher_id, transaction_id);
                
                Ok(transaction_id)
            } else {
                Err(NodeError::Config("No reward amount calculated".to_string()))
            }
        } else {
            Err(NodeError::Config("Submission not found".to_string()))
        }
    }
    
    /// Mark bug as fixed
    pub async fn mark_bug_fixed(
        &self,
        submission_id: &str,
        reviewer: String,
        fix_description: String,
    ) -> Result<()> {
        let mut submissions = self.submissions.write().await;
        
        if let Some(submission) = submissions.get_mut(submission_id) {
            submission.status = SubmissionStatus::Fixed;
            
            submission.review_notes.push(ReviewNote {
                reviewer,
                timestamp: Utc::now(),
                note: format!("Bug fixed: {}", fix_description),
                action: ReviewAction::FixVerification,
            });
            
            // Set disclosure date (90 days from now by default)
            let config = self.program_config.read().await;
            submission.public_disclosure_date = Some(
                Utc::now() + chrono::Duration::days(config.disclosure_timeline_days as i64)
            );
            
            println!("🔧 Marked bug {} as fixed", submission_id);
            Ok(())
        } else {
            Err(NodeError::Config("Submission not found".to_string()))
        }
    }
    
    /// Get all submissions for a researcher
    pub async fn get_researcher_submissions(&self, researcher_id: &str) -> Vec<BugSubmission> {
        let submissions = self.submissions.read().await;
        submissions.values()
            .filter(|s| s.researcher_id == researcher_id)
            .cloned()
            .collect()
    }
    
    /// Get submissions by status
    pub async fn get_submissions_by_status(&self, status: SubmissionStatus) -> Vec<BugSubmission> {
        let submissions = self.submissions.read().await;
        submissions.values()
            .filter(|s| std::mem::discriminant(&s.status) == std::mem::discriminant(&status))
            .cloned()
            .collect()
    }
    
    /// Get program statistics
    pub async fn get_program_statistics(&self) -> BugBountyStatistics {
        let submissions = self.submissions.read().await;
        let researchers = self.researchers.read().await;
        let reward_pool = self.reward_pool.read().await;
        
        let total_submissions = submissions.len();
        let valid_submissions = submissions.values()
            .filter(|s| matches!(s.status, SubmissionStatus::ValidatedAccepted | SubmissionStatus::Fixed | SubmissionStatus::Rewarded))
            .count();
        
        let mut severity_breakdown = HashMap::new();
        for submission in submissions.values() {
            *severity_breakdown.entry(submission.severity.clone()).or_insert(0) += 1;
        }
        
        BugBountyStatistics {
            total_submissions: total_submissions as u32,
            valid_submissions: valid_submissions as u32,
            total_researchers: researchers.len() as u32,
            total_rewards_paid: reward_pool.paid_rewards,
            severity_breakdown,
            hall_of_fame_researchers: researchers.values()
                .filter(|r| r.hall_of_fame)
                .count() as u32,
        }
    }
    
    /// Calculate impact assessment based on severity
    fn calculate_impact_assessment(severity: &BugSeverity) -> ImpactAssessment {
        match severity {
            BugSeverity::Critical => ImpactAssessment {
                confidentiality_impact: ImpactLevel::High,
                integrity_impact: ImpactLevel::High,
                availability_impact: ImpactLevel::High,
                scope: ImpactScope::Changed,
                attack_complexity: AttackComplexity::Low,
                privileges_required: PrivilegesRequired::None,
                user_interaction: UserInteraction::None,
            },
            BugSeverity::High => ImpactAssessment {
                confidentiality_impact: ImpactLevel::High,
                integrity_impact: ImpactLevel::Medium,
                availability_impact: ImpactLevel::Medium,
                scope: ImpactScope::Changed,
                attack_complexity: AttackComplexity::Low,
                privileges_required: PrivilegesRequired::Low,
                user_interaction: UserInteraction::None,
            },
            BugSeverity::Medium => ImpactAssessment {
                confidentiality_impact: ImpactLevel::Medium,
                integrity_impact: ImpactLevel::Low,
                availability_impact: ImpactLevel::Low,
                scope: ImpactScope::Unchanged,
                attack_complexity: AttackComplexity::High,
                privileges_required: PrivilegesRequired::Low,
                user_interaction: UserInteraction::Required,
            },
            BugSeverity::Low => ImpactAssessment {
                confidentiality_impact: ImpactLevel::Low,
                integrity_impact: ImpactLevel::None,
                availability_impact: ImpactLevel::None,
                scope: ImpactScope::Unchanged,
                attack_complexity: AttackComplexity::High,
                privileges_required: PrivilegesRequired::High,
                user_interaction: UserInteraction::Required,
            },
            BugSeverity::Informational => ImpactAssessment {
                confidentiality_impact: ImpactLevel::None,
                integrity_impact: ImpactLevel::None,
                availability_impact: ImpactLevel::None,
                scope: ImpactScope::Unchanged,
                attack_complexity: AttackComplexity::High,
                privileges_required: PrivilegesRequired::High,
                user_interaction: UserInteraction::Required,
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BugBountyStatistics {
    pub total_submissions: u32,
    pub valid_submissions: u32,
    pub total_researchers: u32,
    pub total_rewards_paid: u64,
    pub severity_breakdown: HashMap<BugSeverity, u32>,
    pub hall_of_fame_researchers: u32,
}

impl Default for BugBountyProgram {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[tokio::test]
    async fn test_bug_bounty_program_creation() {
        let program = BugBountyProgram::new();
        let stats = program.get_program_statistics().await;
        assert_eq!(stats.total_submissions, 0);
    }
    
    #[tokio::test]
    async fn test_researcher_registration() {
        let program = BugBountyProgram::new();
        
        let researcher_id = program.register_researcher(
            "Alice Security".to_string(),
            "alice@security.com".to_string(),
            ContactMethod::Email,
        ).await.unwrap();
        
        assert!(researcher_id.starts_with("researcher_"));
    }
    
    #[tokio::test]
    async fn test_bug_submission() {
        let program = BugBountyProgram::new();
        
        // Register researcher
        let researcher_id = program.register_researcher(
            "Bob Security".to_string(),
            "bob@security.com".to_string(),
            ContactMethod::Discord,
        ).await.unwrap();
        
        // Submit bug
        let submission_id = program.submit_bug_report(
            researcher_id,
            "Critical RCE in consensus".to_string(),
            "Found a remote code execution vulnerability".to_string(),
            BugSeverity::Critical,
            BugCategory::ConsensusAttack,
            vec!["nym-consensus".to_string()],
            Some("curl -X POST...".to_string()),
        ).await.unwrap();
        
        assert!(submission_id.starts_with("bug_"));
    }
    
    #[tokio::test]
    async fn test_submission_validation() {
        let program = BugBountyProgram::new();
        
        // Register and submit
        let researcher_id = program.register_researcher(
            "Charlie Security".to_string(),
            "charlie@security.com".to_string(),
            ContactMethod::Email,
        ).await.unwrap();
        
        let submission_id = program.submit_bug_report(
            researcher_id,
            "Medium severity bug".to_string(),
            "Description".to_string(),
            BugSeverity::Medium,
            BugCategory::NetworkSecurity,
            vec!["nym-network".to_string()],
            None,
        ).await.unwrap();
        
        // Assign reviewer
        program.assign_reviewer(&submission_id, "reviewer1".to_string()).await.unwrap();
        
        // Validate
        program.validate_submission(
            &submission_id,
            "reviewer1".to_string(),
            true,
            None,
            "Valid vulnerability confirmed".to_string(),
        ).await.unwrap();
        
        let submissions = program.get_submissions_by_status(SubmissionStatus::ValidatedAccepted).await;
        assert_eq!(submissions.len(), 1);
    }
    
    #[tokio::test]
    async fn test_reward_processing() {
        let program = BugBountyProgram::new();
        
        // Register and submit
        let researcher_id = program.register_researcher(
            "Dave Security".to_string(),
            "dave@security.com".to_string(),
            ContactMethod::Signal,
        ).await.unwrap();
        
        let submission_id = program.submit_bug_report(
            researcher_id,
            "High severity bug".to_string(),
            "Description".to_string(),
            BugSeverity::High,
            BugCategory::CryptographicVulnerability,
            vec!["nym-crypto".to_string()],
            None,
        ).await.unwrap();
        
        // Validate
        program.validate_submission(
            &submission_id,
            "reviewer1".to_string(),
            true,
            None,
            "Valid vulnerability".to_string(),
        ).await.unwrap();
        
        // Process reward
        let tx_id = program.process_reward_payment(&submission_id).await.unwrap();
        assert!(tx_id.starts_with("reward_tx_"));
    }
}