use crate::{
    error::{ConsensusError, ConsensusResult},
    types::{ValidatorInfo, StakeInfo},
};
use nym_core::NymIdentity;

use std::collections::{HashMap, BTreeSet};
use serde::{Deserialize, Serialize};
use tracing::{info, debug, warn};
use chrono::{DateTime, Utc, Duration};

#[derive(Debug, Clone)]
pub struct ValidatorSet {
    active_validators: HashMap<NymIdentity, ValidatorInfo>,
    candidate_validators: HashMap<NymIdentity, ValidatorInfo>,
    rotation_schedule: Vec<NymIdentity>,
    last_rotation: DateTime<Utc>,
}

impl ValidatorSet {
    pub fn new() -> Self {
        Self {
            active_validators: HashMap::new(),
            candidate_validators: HashMap::new(),
            rotation_schedule: Vec::new(),
            last_rotation: Utc::now(),
        }
    }

    pub fn add_validator(&mut self, validator_info: ValidatorInfo) -> ConsensusResult<()> {
        info!("Adding validator: {}", validator_info.identity.to_string());
        
        self.candidate_validators.insert(validator_info.identity.clone(), validator_info);
        Ok(())
    }

    pub fn activate_validator(&mut self, validator_id: &NymIdentity) -> ConsensusResult<()> {
        let validator_info = self.candidate_validators.remove(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError(
                "Validator not found in candidates".to_string()
            ))?;

        self.active_validators.insert(validator_id.clone(), validator_info);
        self.rebuild_rotation_schedule();
        
        info!("Activated validator: {}", validator_id.to_string());
        Ok(())
    }

    pub fn deactivate_validator(&mut self, validator_id: &NymIdentity) -> ConsensusResult<()> {
        let validator_info = self.active_validators.remove(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError(
                "Validator not found in active set".to_string()
            ))?;

        self.candidate_validators.insert(validator_id.clone(), validator_info);
        self.rebuild_rotation_schedule();
        
        warn!("Deactivated validator: {}", validator_id.to_string());
        Ok(())
    }

    fn rebuild_rotation_schedule(&mut self) {
        self.rotation_schedule = self.active_validators.keys().cloned().collect();
        
        // Sort by stake amount for fair rotation
        self.rotation_schedule.sort_by(|a, b| {
            let stake_a = self.active_validators.get(a).map(|v| v.stake_amount).unwrap_or(0);
            let stake_b = self.active_validators.get(b).map(|v| v.stake_amount).unwrap_or(0);
            stake_b.cmp(&stake_a) // Higher stake first
        });
    }

    pub fn get_active_validators(&self) -> Vec<&ValidatorInfo> {
        self.active_validators.values().collect()
    }

    pub fn is_active(&self, validator_id: &NymIdentity) -> bool {
        self.active_validators.contains_key(validator_id)
    }

    pub fn get_validator_count(&self) -> usize {
        self.active_validators.len()
    }
}

pub struct ValidatorManager {
    validator_set: ValidatorSet,
    performance_tracker: PerformanceTracker,
    slashing_tracker: SlashingTracker,
}

#[derive(Debug)]
struct PerformanceTracker {
    block_proposals: HashMap<NymIdentity, u64>,
    successful_proposals: HashMap<NymIdentity, u64>,
    vote_participation: HashMap<NymIdentity, (u64, u64)>, // (votes_cast, votes_possible)
    uptime_records: HashMap<NymIdentity, Vec<UptimeRecord>>,
}

#[derive(Debug, Clone)]
struct UptimeRecord {
    timestamp: DateTime<Utc>,
    is_online: bool,
}

#[derive(Debug)]
struct SlashingTracker {
    slashing_events: HashMap<NymIdentity, Vec<SlashingRecord>>,
    warning_counts: HashMap<NymIdentity, u32>,
}

#[derive(Debug, Clone)]
struct SlashingRecord {
    timestamp: DateTime<Utc>,
    reason: String,
    amount_slashed: u64,
    severity: SlashingSeverity,
}

#[derive(Debug, Clone)]
enum SlashingSeverity {
    Minor,
    Major,
    Critical,
}

impl ValidatorManager {
    pub fn new() -> Self {
        Self {
            validator_set: ValidatorSet::new(),
            performance_tracker: PerformanceTracker::new(),
            slashing_tracker: SlashingTracker::new(),
        }
    }

    pub fn add_validator(&mut self, validator_info: ValidatorInfo) -> ConsensusResult<()> {
        self.validator_set.add_validator(validator_info.clone())?;
        self.performance_tracker.initialize_validator(&validator_info.identity);
        Ok(())
    }

    pub fn update_validator_performance(
        &mut self,
        validator_id: &NymIdentity,
        proposed_block: bool,
        voted: bool,
        is_online: bool,
    ) -> ConsensusResult<()> {
        self.performance_tracker.record_performance(validator_id, proposed_block, voted, is_online)?;
        self.update_validator_scores(validator_id)?;
        Ok(())
    }

    fn update_validator_scores(&mut self, validator_id: &NymIdentity) -> ConsensusResult<()> {
        if let Some(validator) = self.validator_set.active_validators.get_mut(validator_id) {
            let performance = self.performance_tracker.calculate_performance_score(validator_id);
            let uptime = self.performance_tracker.calculate_uptime_percentage(validator_id);
            
            validator.reputation_score = (performance + uptime) / 2.0;
            validator.uptime_percentage = uptime;
        }
        Ok(())
    }

    pub fn slash_validator(
        &mut self,
        validator_id: &NymIdentity,
        reason: String,
        severity: SlashingSeverity,
    ) -> ConsensusResult<u64> {
        let slash_percentage = match severity {
            SlashingSeverity::Minor => 0.01,   // 1%
            SlashingSeverity::Major => 0.05,   // 5%
            SlashingSeverity::Critical => 0.20, // 20%
        };

        let validator = self.validator_set.active_validators.get_mut(validator_id)
            .ok_or_else(|| ConsensusError::ValidatorError(
                "Validator not found".to_string()
            ))?;

        let slash_amount = (validator.stake_amount as f64 * slash_percentage) as u64;
        validator.stake_amount -= slash_amount;
        validator.reputation_score *= 0.8; // Reduce reputation

        let slashing_record = SlashingRecord {
            timestamp: Utc::now(),
            reason: reason.clone(),
            amount_slashed: slash_amount,
            severity,
        };

        self.slashing_tracker.slashing_events
            .entry(validator_id.clone())
            .or_default()
            .push(slashing_record);

        warn!("Slashed validator {}: {} ({})", 
              validator_id.to_string(), slash_amount, reason);

        Ok(slash_amount)
    }

    pub fn get_validator_set(&self) -> &ValidatorSet {
        &self.validator_set
    }

    pub fn get_performance_report(&self, validator_id: &NymIdentity) -> Option<PerformanceReport> {
        self.performance_tracker.generate_report(validator_id)
    }
}

impl PerformanceTracker {
    fn new() -> Self {
        Self {
            block_proposals: HashMap::new(),
            successful_proposals: HashMap::new(),
            vote_participation: HashMap::new(),
            uptime_records: HashMap::new(),
        }
    }

    fn initialize_validator(&mut self, validator_id: &NymIdentity) {
        self.block_proposals.insert(validator_id.clone(), 0);
        self.successful_proposals.insert(validator_id.clone(), 0);
        self.vote_participation.insert(validator_id.clone(), (0, 0));
        self.uptime_records.insert(validator_id.clone(), Vec::new());
    }

    fn record_performance(
        &mut self,
        validator_id: &NymIdentity,
        proposed_block: bool,
        voted: bool,
        is_online: bool,
    ) -> ConsensusResult<()> {
        if proposed_block {
            *self.block_proposals.entry(validator_id.clone()).or_insert(0) += 1;
            *self.successful_proposals.entry(validator_id.clone()).or_insert(0) += 1;
        }

        if let Some((votes_cast, votes_possible)) = self.vote_participation.get_mut(validator_id) {
            *votes_possible += 1;
            if voted {
                *votes_cast += 1;
            }
        }

        let uptime_record = UptimeRecord {
            timestamp: Utc::now(),
            is_online,
        };
        
        self.uptime_records.entry(validator_id.clone())
            .or_default()
            .push(uptime_record);

        // Keep only last 1000 uptime records
        if let Some(records) = self.uptime_records.get_mut(validator_id) {
            if records.len() > 1000 {
                records.drain(0..records.len() - 1000);
            }
        }

        Ok(())
    }

    fn calculate_performance_score(&self, validator_id: &NymIdentity) -> f64 {
        let proposals = self.block_proposals.get(validator_id).unwrap_or(&0);
        let successful = self.successful_proposals.get(validator_id).unwrap_or(&0);
        
        let proposal_rate = if *proposals > 0 {
            *successful as f64 / *proposals as f64
        } else {
            1.0
        };

        let (votes_cast, votes_possible) = self.vote_participation.get(validator_id)
            .unwrap_or(&(0, 0));
        
        let vote_rate = if *votes_possible > 0 {
            *votes_cast as f64 / *votes_possible as f64
        } else {
            1.0
        };

        (proposal_rate + vote_rate) / 2.0
    }

    fn calculate_uptime_percentage(&self, validator_id: &NymIdentity) -> f64 {
        let records = self.uptime_records.get(validator_id);
        
        match records {
            Some(records) if !records.is_empty() => {
                let online_count = records.iter().filter(|r| r.is_online).count();
                online_count as f64 / records.len() as f64
            }
            _ => 1.0, // Default to 100% for new validators
        }
    }

    fn generate_report(&self, validator_id: &NymIdentity) -> Option<PerformanceReport> {
        Some(PerformanceReport {
            validator_id: validator_id.clone(),
            total_proposals: *self.block_proposals.get(validator_id)?,
            successful_proposals: *self.successful_proposals.get(validator_id)?,
            vote_participation: *self.vote_participation.get(validator_id)?,
            uptime_percentage: self.calculate_uptime_percentage(validator_id),
            performance_score: self.calculate_performance_score(validator_id),
        })
    }
}

impl SlashingTracker {
    fn new() -> Self {
        Self {
            slashing_events: HashMap::new(),
            warning_counts: HashMap::new(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct PerformanceReport {
    pub validator_id: NymIdentity,
    pub total_proposals: u64,
    pub successful_proposals: u64,
    pub vote_participation: (u64, u64),
    pub uptime_percentage: f64,
    pub performance_score: f64,
}