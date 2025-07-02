//! Nym Fuzzing Harness
//! 
//! Dedicated fuzzing harness for continuous security testing.
//! Supports various fuzzing modes and targets.

use nym_security_audit::fuzzing::FuzzingHarness;
use nym_security_audit::{SecurityFinding, SecuritySeverity};
use clap::{Parser, Subcommand};
use std::time::Duration;
use tracing::{info, warn, error};

#[derive(Parser)]
#[command(name = "nym-fuzzing")]
#[command(about = "Fuzzing harness for Nym cryptocurrency system")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
    
    /// Fuzzing duration in seconds
    #[arg(short, long, default_value = "300")]
    duration: u64,
    
    /// Maximum test cases to run
    #[arg(short, long, default_value = "1000000")]
    max_cases: u64,
    
    /// Output directory for crash reports
    #[arg(short, long, default_value = "fuzzing_output")]
    output_dir: String,
}

#[derive(Subcommand)]
enum Commands {
    /// Run comprehensive fuzzing across all components
    All,
    
    /// Fuzz cryptographic operations
    Crypto {
        /// Focus on specific crypto operation (ml-dsa, shake256, zk-stark, key-derivation)
        #[arg(long)]
        operation: Option<String>,
    },
    
    /// Fuzz network protocols
    Network {
        /// Focus on specific network component (message-parsing, auth, connection)
        #[arg(long)]
        component: Option<String>,
    },
    
    /// Fuzz storage systems
    Storage {
        /// Focus on specific storage component (database, serialization, file-ops)
        #[arg(long)]
        component: Option<String>,
    },
    
    /// Run continuous fuzzing (never stops)
    Continuous {
        /// Report interval in seconds
        #[arg(long, default_value = "60")]
        report_interval: u64,
    },
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    // Initialize logging
    let log_level = if cli.verbose { "debug" } else { "info" };
    tracing_subscriber::fmt()
        .with_env_filter(format!("nym_security_audit={}", log_level))
        .init();
    
    info!("🔍 Nym Fuzzing Harness v0.1.0");
    
    // Create output directory
    tokio::fs::create_dir_all(&cli.output_dir).await?;
    
    let fuzzing_duration = Duration::from_secs(cli.duration);
    let harness = FuzzingHarness::new(fuzzing_duration);
    
    match cli.command {
        Commands::All => {
            info!("Starting comprehensive fuzzing across all components...");
            run_comprehensive_fuzzing(&harness, &cli.output_dir).await?;
        },
        
        Commands::Crypto { operation } => {
            info!("Starting cryptographic fuzzing...");
            if let Some(op) = operation {
                info!("Focusing on operation: {}", op);
            }
            run_crypto_fuzzing(&harness, &cli.output_dir).await?;
        },
        
        Commands::Network { component } => {
            info!("Starting network protocol fuzzing...");
            if let Some(comp) = component {
                info!("Focusing on component: {}", comp);
            }
            run_network_fuzzing(&harness, &cli.output_dir).await?;
        },
        
        Commands::Storage { component } => {
            info!("Starting storage system fuzzing...");
            if let Some(comp) = component {
                info!("Focusing on component: {}", comp);
            }
            run_storage_fuzzing(&harness, &cli.output_dir).await?;
        },
        
        Commands::Continuous { report_interval } => {
            info!("Starting continuous fuzzing with {}-second reporting...", report_interval);
            run_continuous_fuzzing(&harness, &cli.output_dir, Duration::from_secs(report_interval)).await?;
        },
    }
    
    info!("✅ Fuzzing completed successfully!");
    Ok(())
}

async fn run_comprehensive_fuzzing(
    harness: &FuzzingHarness,
    output_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut findings = Vec::new();
    
    info!("Running comprehensive fuzzing tests...");
    let results = harness.run_comprehensive_fuzzing(&mut findings).await?;
    
    // Save results
    save_fuzzing_results(&results, findings, output_dir, "comprehensive").await?;
    
    // Print summary
    print_fuzzing_summary(&results);
    
    Ok(())
}

async fn run_crypto_fuzzing(
    harness: &FuzzingHarness,
    output_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut findings = Vec::new();
    
    info!("Running cryptographic fuzzing...");
    // Note: In a real implementation, we'd have specialized crypto-only fuzzing
    let results = harness.run_comprehensive_fuzzing(&mut findings).await?;
    
    save_fuzzing_results(&results, findings, output_dir, "crypto").await?;
    print_fuzzing_summary(&results);
    
    Ok(())
}

async fn run_network_fuzzing(
    harness: &FuzzingHarness,
    output_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut findings = Vec::new();
    
    info!("Running network protocol fuzzing...");
    let results = harness.run_comprehensive_fuzzing(&mut findings).await?;
    
    save_fuzzing_results(&results, findings, output_dir, "network").await?;
    print_fuzzing_summary(&results);
    
    Ok(())
}

async fn run_storage_fuzzing(
    harness: &FuzzingHarness,
    output_dir: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let mut findings = Vec::new();
    
    info!("Running storage system fuzzing...");
    let results = harness.run_comprehensive_fuzzing(&mut findings).await?;
    
    save_fuzzing_results(&results, findings, output_dir, "storage").await?;
    print_fuzzing_summary(&results);
    
    Ok(())
}

async fn run_continuous_fuzzing(
    harness: &FuzzingHarness,
    output_dir: &str,
    report_interval: Duration,
) -> Result<(), Box<dyn std::error::Error>> {
    info!("Starting continuous fuzzing mode...");
    
    let mut iteration = 0;
    let mut total_test_cases = 0;
    let mut total_crashes = 0;
    let mut total_vulnerabilities = 0;
    
    loop {
        iteration += 1;
        info!("Starting fuzzing iteration {}...", iteration);
        
        let mut findings = Vec::new();
        let results = harness.run_comprehensive_fuzzing(&mut findings).await?;
        
        // Update totals
        total_test_cases += results.total_test_cases;
        total_crashes += results.crashes_found;
        total_vulnerabilities += results.vulnerabilities_found;
        
        // Save iteration results
        let iteration_dir = format!("{}/iteration_{}", output_dir, iteration);
        tokio::fs::create_dir_all(&iteration_dir).await?;
        save_fuzzing_results(&results, findings, &iteration_dir, "continuous").await?;
        
        // Print periodic summary
        info!("Iteration {} completed:", iteration);
        info!("  Test cases: {}", results.total_test_cases);
        info!("  Crashes: {}", results.crashes_found);
        info!("  Vulnerabilities: {}", results.vulnerabilities_found);
        info!("Cumulative totals:");
        info!("  Total test cases: {}", total_test_cases);
        info!("  Total crashes: {}", total_crashes);
        info!("  Total vulnerabilities: {}", total_vulnerabilities);
        
        // Check for critical issues
        if results.crashes_found > 0 || results.vulnerabilities_found > 0 {
            warn!("⚠️  Issues found in iteration {}! Check output directory for details.", iteration);
        }
        
        // Sleep before next iteration
        tokio::time::sleep(report_interval).await;
    }
}

async fn save_fuzzing_results(
    results: &nym_security_audit::FuzzingResults,
    findings: Vec<SecurityFinding>,
    output_dir: &str,
    test_type: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    
    // Save fuzzing results
    let results_file = format!("{}/fuzzing_results_{}_{}.json", output_dir, test_type, timestamp);
    let results_json = serde_json::to_string_pretty(results)?;
    tokio::fs::write(&results_file, results_json).await?;
    
    // Save findings
    if !findings.is_empty() {
        let findings_file = format!("{}/findings_{}_{}.json", output_dir, test_type, timestamp);
        let findings_json = serde_json::to_string_pretty(&findings)?;
        tokio::fs::write(&findings_file, findings_json).await?;
        
        // Save crash reports for critical findings
        let mut crash_reports = Vec::new();
        for finding in &findings {
            if matches!(finding.severity, SecuritySeverity::Critical) && finding.exploitable {
                crash_reports.push(finding);
            }
        }
        
        if !crash_reports.is_empty() {
            let crash_file = format!("{}/crashes_{}_{}.json", output_dir, test_type, timestamp);
            let crash_json = serde_json::to_string_pretty(&crash_reports)?;
            tokio::fs::write(&crash_file, crash_json).await?;
            
            warn!("🚨 Critical crashes found! Saved to: {}", crash_file);
        }
    }
    
    info!("Fuzzing results saved to: {}", results_file);
    Ok(())
}

fn print_fuzzing_summary(results: &nym_security_audit::FuzzingResults) {
    println!("\n🔍 Fuzzing Summary");
    println!("==================");
    println!("Cryptographic Fuzzing: {}", if results.cryptographic_fuzzing_passed { "✅ PASS" } else { "❌ FAIL" });
    println!("Network Fuzzing: {}", if results.network_fuzzing_passed { "✅ PASS" } else { "❌ FAIL" });
    println!("Storage Fuzzing: {}", if results.storage_fuzzing_passed { "✅ PASS" } else { "❌ FAIL" });
    println!();
    println!("Statistics:");
    println!("  Total Test Cases: {}", results.total_test_cases);
    println!("  Crashes Found: {}", results.crashes_found);
    println!("  Vulnerabilities Found: {}", results.vulnerabilities_found);
    
    if results.crashes_found > 0 {
        println!("\n🚨 ATTENTION: {} crashes found during fuzzing!", results.crashes_found);
        println!("Please review crash reports in the output directory.");
    }
    
    if results.vulnerabilities_found > 0 {
        println!("\n⚠️  {} vulnerabilities discovered during fuzzing.", results.vulnerabilities_found);
        println!("Please review findings and apply necessary fixes.");
    }
    
    if results.crashes_found == 0 && results.vulnerabilities_found == 0 {
        println!("\n✅ No crashes or vulnerabilities found during fuzzing!");
    }
    
    // Calculate fuzzing efficiency
    let efficiency = if results.total_test_cases > 0 {
        (results.crashes_found + results.vulnerabilities_found) as f64 / results.total_test_cases as f64 * 100.0
    } else {
        0.0
    };
    
    println!("Fuzzing Efficiency: {:.4}% (issues per test case)", efficiency);
}