//! Performance benchmarks for Nym ecosystem components
//! 
//! Comprehensive benchmarking suite for all privacy features and DeFi components

use criterion::{criterion_group, criterion_main, Criterion, BenchmarkId};
use rand::rngs::OsRng;
use std::time::Duration;

// Import all the modules we want to benchmark
use nym_crypto::{
    Hash256, SecurityLevel, SigningKey, VerifyingKey,
    MultiSigStealthAddress, SubAddressGenerator, AddressReuseGuard,
    commit
};
use nym_privacy::{
    MixCoordinator, AnonymousTransaction, ConfidentialTransaction,
    HomomorphicOps, MixConfig, PrivacyConfig
};
use nym_defi::{PrivacyAMM, FeeConfig};

/// Benchmark cryptographic operations
fn bench_crypto_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("crypto_operations");
    
    // Benchmark hash generation
    group.bench_function("hash_generation", |b| {
        let mut rng = OsRng;
        b.iter(|| Hash256::random(&mut rng))
    });
    
    // Benchmark key generation
    group.bench_function("key_generation", |b| {
        let mut rng = OsRng;
        b.iter(|| SigningKey::generate(&mut rng, SecurityLevel::Level1))
    });
    
    // Benchmark commitment generation
    group.bench_function("commitment_generation", |b| {
        let mut rng = OsRng;
        let amount = 1000u64;
        let blinding = vec![0u8; 32];
        b.iter(|| commit(amount, &blinding))
    });
    
    group.finish();
}

/// Benchmark enhanced stealth address operations
fn bench_stealth_addresses(c: &mut Criterion) {
    let mut group = c.benchmark_group("stealth_addresses");
    
    // Benchmark multi-sig stealth address creation
    group.bench_function("multisig_stealth_creation", |b| {
        let mut rng = OsRng;
        let signer_keys: Vec<_> = (0..5)
            .map(|_| SigningKey::generate(&mut rng, SecurityLevel::Level1).verifying_key())
            .collect();
        
        b.iter(|| {
            MultiSigStealthAddress::new(
                &mut rng,
                3, // 3-of-5 threshold
                signer_keys.clone(),
                SecurityLevel::Level1,
            )
        })
    });
    
    // Benchmark sub-address generation
    group.bench_function("sub_address_generation", |b| {
        let mut rng = OsRng;
        let view_key = nym_crypto::ViewKey::generate(&mut rng, SecurityLevel::Level1);
        let spend_key = nym_crypto::SpendKey::generate(&mut rng, SecurityLevel::Level1);
        let mut generator = SubAddressGenerator::new(view_key, spend_key);
        
        b.iter(|| generator.generate_sub_address("department_1"))
    });
    
    // Benchmark address reuse checking
    group.bench_function("address_reuse_check", |b| {
        let mut guard = AddressReuseGuard::new(1000);
        let address = Hash256::random(&mut OsRng);
        
        b.iter(|| guard.is_address_used(&address))
    });
    
    group.finish();
}

/// Benchmark transaction anonymity operations
fn bench_transaction_anonymity(c: &mut Criterion) {
    let mut group = c.benchmark_group("transaction_anonymity");
    
    // Benchmark mix coordinator operations
    group.bench_function("transaction_mixing", |b| {
        let mut rng = OsRng;
        let config = MixConfig::default();
        let mut coordinator = MixCoordinator::new(config);
        
        // Pre-populate with transactions
        for _ in 0..20 {
            let tx = create_anonymous_transaction(&mut rng);
            coordinator.submit_transaction(&mut rng, tx).unwrap();
        }
        
        b.iter(|| coordinator.create_mix(&mut rng))
    });
    
    // Benchmark decoy generation
    group.bench_function("decoy_generation", |b| {
        let mut rng = OsRng;
        let config = MixConfig::default();
        let coordinator = MixCoordinator::new(config);
        
        b.iter(|| coordinator.generate_decoy(&mut rng))
    });
    
    group.finish();
}

/// Benchmark confidential transactions
fn bench_confidential_transactions(c: &mut Criterion) {
    let mut group = c.benchmark_group("confidential_transactions");
    
    // Benchmark confidential transaction creation
    group.bench_function("confidential_tx_creation", |b| {
        let mut rng = OsRng;
        let inputs = vec![(1000, vec![1u8; 32]), (500, vec![2u8; 32])];
        let outputs = vec![(1200, vec![3u8; 32]), (250, vec![4u8; 32])];
        let fee = 50;
        
        b.iter(|| ConfidentialTransaction::new(&mut rng, inputs.clone(), outputs.clone(), fee))
    });
    
    // Benchmark homomorphic operations
    group.bench_function("homomorphic_addition", |b| {
        let a = commit(100, &vec![1u8; 32]).unwrap();
        let b = commit(200, &vec![2u8; 32]).unwrap();
        
        b.iter(|| HomomorphicOps::add_commitments(&a, &b))
    });
    
    // Benchmark transaction verification
    group.bench_function("confidential_tx_verification", |b| {
        let mut rng = OsRng;
        let inputs = vec![(1000, vec![1u8; 32])];
        let outputs = vec![(950, vec![2u8; 32])];
        let tx = ConfidentialTransaction::new(&mut rng, inputs, outputs, 50).unwrap();
        
        b.iter(|| tx.verify())
    });
    
    group.finish();
}

/// Benchmark DeFi operations
fn bench_defi_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("defi_operations");
    
    // Benchmark AMM pool creation
    group.bench_function("amm_pool_creation", |b| {
        let mut rng = OsRng;
        let fee_config = FeeConfig::default();
        let privacy_config = PrivacyConfig::default();
        let mut amm = PrivacyAMM::new(fee_config, privacy_config);
        
        b.iter(|| {
            amm.create_pool(
                &mut rng,
                "TokenA".to_string(),
                "TokenB".to_string(),
                100000,
                50000,
                30,
            )
        })
    });
    
    // Benchmark private swap execution
    group.bench_function("private_swap_execution", |b| {
        let mut rng = OsRng;
        let fee_config = FeeConfig::default();
        let privacy_config = PrivacyConfig::default();
        let mut amm = PrivacyAMM::new(fee_config, privacy_config);
        
        let pool_id = amm.create_pool(
            &mut rng,
            "TokenA".to_string(),
            "TokenB".to_string(),
            100000,
            50000,
            30,
        ).unwrap();
        
        b.iter(|| {
            amm.execute_swap(&mut rng, &pool_id, 1000, true, 0.05)
        })
    });
    
    group.finish();
}

/// Benchmark cross-system integration
fn bench_integration_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("integration_performance");
    
    // Benchmark end-to-end privacy transaction
    group.bench_function("e2e_privacy_transaction", |b| {
        let mut rng = OsRng;
        
        b.iter(|| {
            // Create stealth address
            let signer_keys: Vec<_> = (0..3)
                .map(|_| SigningKey::generate(&mut rng, SecurityLevel::Level1).verifying_key())
                .collect();
            let _stealth_addr = MultiSigStealthAddress::new(
                &mut rng, 2, signer_keys, SecurityLevel::Level1
            ).unwrap();
            
            // Create confidential transaction
            let inputs = vec![(1000, vec![1u8; 32])];
            let outputs = vec![(950, vec![2u8; 32])];
            let _conf_tx = ConfidentialTransaction::new(&mut rng, inputs, outputs, 50).unwrap();
            
            // Mix transaction
            let tx = create_anonymous_transaction(&mut rng);
            let config = MixConfig::default();
            let mut coordinator = MixCoordinator::new(config);
            let _result = coordinator.submit_transaction(&mut rng, tx);
        })
    });
    
    group.finish();
}

/// Benchmark memory usage and allocation patterns
fn bench_memory_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_performance");
    group.measurement_time(Duration::from_secs(10));
    
    // Benchmark memory usage for large anonymity sets
    for size in [100, 500, 1000, 5000].iter() {
        group.bench_with_input(
            BenchmarkId::new("anonymity_set_memory", size),
            size,
            |b, &size| {
                let mut rng = OsRng;
                b.iter(|| {
                    let _transactions: Vec<_> = (0..size)
                        .map(|_| create_anonymous_transaction(&mut rng))
                        .collect();
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark network and serialization performance
fn bench_serialization_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("serialization_performance");
    
    // Benchmark transaction serialization
    group.bench_function("transaction_serialization", |b| {
        let mut rng = OsRng;
        let tx = create_anonymous_transaction(&mut rng);
        
        b.iter(|| {
            let serialized = serde_json::to_vec(&tx).unwrap();
            let _deserialized: AnonymousTransaction = serde_json::from_slice(&serialized).unwrap();
        })
    });
    
    // Benchmark confidential transaction serialization
    group.bench_function("confidential_tx_serialization", |b| {
        let mut rng = OsRng;
        let inputs = vec![(1000, vec![1u8; 32])];
        let outputs = vec![(950, vec![2u8; 32])];
        let tx = ConfidentialTransaction::new(&mut rng, inputs, outputs, 50).unwrap();
        
        b.iter(|| {
            let serialized = serde_json::to_vec(&tx).unwrap();
            let _deserialized: ConfidentialTransaction = serde_json::from_slice(&serialized).unwrap();
        })
    });
    
    group.finish();
}

// Helper function to create anonymous transactions for testing
fn create_anonymous_transaction(rng: &mut OsRng) -> AnonymousTransaction {
    use nym_privacy::{AnonymousTransaction, AmountCommitment, TimingData};
    
    AnonymousTransaction {
        tx_id: Hash256::random(rng),
        encrypted_data: vec![0u8; 256],
        commitment: [0u8; 32],
        nullifier: Hash256::random(rng),
        validity_proof: vec![0u8; 128],
        ring_signature: vec![0u8; 256],
        timing_data: TimingData {
            submit_time: 0,
            delay: 1000,
            jitter: 500,
            batch_round: 1,
        },
    }
}

// Benchmark configuration
criterion_group!(
    benches,
    bench_crypto_operations,
    bench_stealth_addresses,
    bench_transaction_anonymity,
    bench_confidential_transactions,
    bench_defi_operations,
    bench_integration_performance,
    bench_memory_performance,
    bench_serialization_performance,
);

criterion_main!(benches);

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_benchmark_setup() {
        // Ensure all benchmark functions can be called without panicking
        let mut rng = OsRng;
        
        // Test crypto operations
        let _hash = Hash256::random(&mut rng);
        let _key = SigningKey::generate(&mut rng, SecurityLevel::Level1);
        let _commitment = commit(1000, &vec![0u8; 32]).unwrap();
        
        // Test stealth addresses
        let signer_keys: Vec<_> = (0..3)
            .map(|_| SigningKey::generate(&mut rng, SecurityLevel::Level1).verifying_key())
            .collect();
        let _stealth = MultiSigStealthAddress::new(&mut rng, 2, signer_keys, SecurityLevel::Level1).unwrap();
        
        // Test confidential transactions
        let inputs = vec![(1000, vec![1u8; 32])];
        let outputs = vec![(950, vec![2u8; 32])];
        let _tx = ConfidentialTransaction::new(&mut rng, inputs, outputs, 50).unwrap();
        
        // Test DeFi operations
        let fee_config = FeeConfig::default();
        let privacy_config = PrivacyConfig::default();
        let mut amm = PrivacyAMM::new(fee_config, privacy_config);
        let _pool = amm.create_pool(&mut rng, "A".to_string(), "B".to_string(), 1000, 1000, 30).unwrap();
    }
    
    #[test]
    fn test_performance_regression() {
        // Basic performance regression test
        let mut rng = OsRng;
        let start = std::time::Instant::now();
        
        // Perform a series of operations and ensure they complete within reasonable time
        for _ in 0..100 {
            let _hash = Hash256::random(&mut rng);
        }
        
        let duration = start.elapsed();
        assert!(duration.as_millis() < 1000, "Hash generation taking too long: {:?}", duration);
    }
}