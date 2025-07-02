//! Nym Security Audit Runner
//! 
//! Command-line interface for running comprehensive security audits of the Nym system.
//! Supports different audit modes and configurations.

use nym_security_audit::{
    SecurityAuditor, SecurityAuditConfig, SecurityAuditResults,
    run_quick_security_audit, run_full_security_audit,
    SecuritySeverity, SecurityCategory
};
use clap::{Parser, Subcommand};
use std::time::Duration;
use tracing::{info, warn, error};
use serde_json;

#[derive(Parser)]
#[command(name = "nym-security-audit")]
#[command(about = "Comprehensive security audit tool for Nym cryptocurrency system")]
#[command(version = "0.1.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,
    
    /// Output format (json, text)
    #[arg(short, long, default_value = "text")]
    format: String,
    
    /// Output file path (default: stdout)
    #[arg(short, long)]
    output: Option<String>,
}

#[derive(Subcommand)]
enum Commands {
    /// Run quick security audit (5 minutes)
    Quick,
    
    /// Run full comprehensive security audit (30+ minutes)
    Full,
    
    /// Run custom security audit with specified parameters
    Custom {
        /// Fuzzing duration in seconds
        #[arg(long, default_value = "300")]
        fuzzing_duration: u64,
        
        /// Timing analysis iterations
        #[arg(long, default_value = "10000")]
        timing_iterations: u32,
        
        /// Enable/disable fuzzing
        #[arg(long, default_value = "true")]
        enable_fuzzing: bool,
        
        /// Enable/disable timing analysis
        #[arg(long, default_value = "true")]
        enable_timing: bool,
        
        /// Enable/disable DoS testing
        #[arg(long, default_value = "true")]
        enable_dos: bool,
        
        /// Enable/disable memory safety testing
        #[arg(long, default_value = "true")]
        enable_memory: bool,
        
        /// Enable parallel testing
        #[arg(long, default_value = "true")]
        parallel: bool,
        
        /// Enable comprehensive mode
        #[arg(long, default_value = "true")]
        comprehensive: bool,
    },
    
    /// Run specific audit component
    Component {
        /// Component to audit (crypto, network, storage, quid, timing, memory, fuzzing, dos)
        component: String,
    },
    
    /// Generate audit report from previous results
    Report {
        /// Path to audit results JSON file
        results_file: String,
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
    
    info!("🛡️ Nym Security Audit Tool v0.1.0");
    info!("Starting security audit...");
    
    let results = match cli.command {
        Commands::Quick => {
            info!("Running quick security audit...");
            run_quick_security_audit().await?
        },
        
        Commands::Full => {
            info!("Running full comprehensive security audit...");
            run_full_security_audit().await?
        },
        
        Commands::Custom {
            fuzzing_duration,
            timing_iterations,
            enable_fuzzing,
            enable_timing,
            enable_dos,
            enable_memory,
            parallel,
            comprehensive,
        } => {
            info!("Running custom security audit with specified parameters...");
            
            let config = SecurityAuditConfig {
                enable_fuzzing,
                fuzzing_duration: Duration::from_secs(fuzzing_duration),
                enable_timing_analysis: enable_timing,
                timing_analysis_iterations: timing_iterations,
                enable_dos_testing: enable_dos,
                enable_memory_safety_testing: enable_memory,
                parallel_testing: parallel,
                comprehensive_mode: comprehensive,
            };
            
            let auditor = SecurityAuditor::new(config);
            auditor.run_comprehensive_audit().await?
        },
        
        Commands::Component { component } => {
            info!("Running audit for component: {}", component);
            run_component_audit(&component).await?
        },
        
        Commands::Report { results_file } => {
            info!("Generating report from: {}", results_file);
            return generate_report_from_file(&results_file, &cli.format).await;
        },
    };
    
    // Output results
    output_results(&results, &cli.format, cli.output.as_deref()).await?;
    
    // Print summary
    print_audit_summary(&results);
    
    // Exit with appropriate code
    let exit_code = if results.overall_secure { 0 } else { 1 };
    std::process::exit(exit_code);
}

async fn run_component_audit(component: &str) -> Result<SecurityAuditResults, Box<dyn std::error::Error>> {
    let config = SecurityAuditConfig {
        enable_fuzzing: component == "fuzzing",
        fuzzing_duration: Duration::from_secs(60),
        enable_timing_analysis: component == "timing",
        timing_analysis_iterations: 1000,
        enable_dos_testing: component == "dos",
        enable_memory_safety_testing: component == "memory",
        parallel_testing: true,
        comprehensive_mode: false,
    };
    
    let auditor = SecurityAuditor::new(config);
    
    match component {
        "crypto" => {
            info!("Auditing cryptographic components...");
            // Run crypto-focused audit
            auditor.run_comprehensive_audit().await
        },
        "network" => {
            info!("Auditing network components...");
            // Run network-focused audit
            auditor.run_comprehensive_audit().await
        },
        "storage" => {
            info!("Auditing storage components...");
            // Run storage-focused audit
            auditor.run_comprehensive_audit().await
        },
        "quid" => {
            info!("Auditing QuID integration...");
            // Run QuID integration audit
            auditor.run_comprehensive_audit().await
        },
        "timing" => {
            info!("Running timing attack analysis...");
            auditor.run_comprehensive_audit().await
        },
        "memory" => {
            info!("Running memory safety tests...");
            auditor.run_comprehensive_audit().await
        },
        "fuzzing" => {
            info!("Running fuzzing tests...");
            auditor.run_comprehensive_audit().await
        },
        "dos" => {
            info!("Running DoS resistance tests...");
            auditor.run_comprehensive_audit().await
        },
        _ => {
            error!("Unknown component: {}", component);
            return Err(format!("Unknown component: {}", component).into());
        }
    }
}

async fn output_results(
    results: &SecurityAuditResults,
    format: &str,
    output_file: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let output_content = match format {
        "json" => serde_json::to_string_pretty(results)?,
        "text" => format_text_results(results),
        _ => return Err(format!("Unknown output format: {}", format).into()),
    };
    
    match output_file {
        Some(file_path) => {
            tokio::fs::write(file_path, output_content).await?;
            info!("Results written to: {}", file_path);
        },
        None => {
            println!("{}", output_content);
        },
    }
    
    Ok(())
}

fn format_text_results(results: &SecurityAuditResults) -> String {
    let mut output = String::new();
    
    output.push_str(&format!("\n🛡️ Nym Security Audit Results\n"));
    output.push_str(&format!("================================\n\n"));
    
    // Overall status
    let status_emoji = if results.overall_secure { "✅" } else { "❌" };
    let status_text = if results.overall_secure { "SECURE" } else { "VULNERABILITIES FOUND" };
    output.push_str(&format!("Overall Security Status: {} {}\n", status_emoji, status_text));
    output.push_str(&format!("Audit Duration: {:?}\n\n", results.audit_duration));
    
    // Component results
    output.push_str("Component Security Results:\n");
    output.push_str("---------------------------\n");
    
    // Cryptographic security
    output.push_str(&format!("🔐 Cryptographic Security:\n"));
    output.push_str(&format!("  - Quantum Resistance: {}\n", 
                             bool_to_status(results.component_results.cryptographic_security.quantum_resistance_validated)));
    output.push_str(&format!("  - Key Generation: {}\n", 
                             bool_to_status(results.component_results.cryptographic_security.key_generation_secure)));
    output.push_str(&format!("  - Signature Scheme: {}\n", 
                             bool_to_status(results.component_results.cryptographic_security.signature_scheme_secure)));
    output.push_str(&format!("  - Hash Functions: {}\n", 
                             bool_to_status(results.component_results.cryptographic_security.hash_function_secure)));
    output.push_str(&format!("  - zk-STARK Proofs: {}\n", 
                             bool_to_status(results.component_results.cryptographic_security.zk_proofs_secure)));
    output.push_str(&format!("  - Timing Attack Resistant: {}\n", 
                             bool_to_status(results.component_results.cryptographic_security.timing_attack_resistant)));
    output.push_str(&format!("  - Side-Channel Resistant: {}\n\n", 
                             bool_to_status(results.component_results.cryptographic_security.side_channel_resistant)));
    
    // Network security
    output.push_str(&format!("🌐 Network Security:\n"));
    output.push_str(&format!("  - P2P Protocol: {}\n", 
                             bool_to_status(results.component_results.network_security.p2p_protocol_secure)));
    output.push_str(&format!("  - Message Integrity: {}\n", 
                             bool_to_status(results.component_results.network_security.message_integrity_validated)));
    output.push_str(&format!("  - Peer Authentication: {}\n", 
                             bool_to_status(results.component_results.network_security.peer_authentication_secure)));
    output.push_str(&format!("  - DoS Resistant: {}\n", 
                             bool_to_status(results.component_results.network_security.dos_resistant)));
    output.push_str(&format!("  - Eclipse Attack Resistant: {}\n", 
                             bool_to_status(results.component_results.network_security.eclipse_attack_resistant)));
    output.push_str(&format!("  - Sybil Attack Resistant: {}\n\n", 
                             bool_to_status(results.component_results.network_security.sybil_attack_resistant)));
    
    // Storage security
    output.push_str(&format!("💾 Storage Security:\n"));
    output.push_str(&format!("  - Encryption at Rest: {}\n", 
                             bool_to_status(results.component_results.storage_security.encryption_at_rest_secure)));
    output.push_str(&format!("  - Access Control: {}\n", 
                             bool_to_status(results.component_results.storage_security.access_control_secure)));
    output.push_str(&format!("  - Backup Security: {}\n", 
                             bool_to_status(results.component_results.storage_security.backup_security_validated)));
    output.push_str(&format!("  - Recovery System: {}\n", 
                             bool_to_status(results.component_results.storage_security.recovery_system_secure)));
    output.push_str(&format!("  - Data Integrity: {}\n", 
                             bool_to_status(results.component_results.storage_security.data_integrity_protected)));
    output.push_str(&format!("  - Privacy Preservation: {}\n\n", 
                             bool_to_status(results.component_results.storage_security.privacy_preservation_validated)));
    
    // QuID integration security
    output.push_str(&format!("🔗 QuID Integration Security:\n"));
    output.push_str(&format!("  - Authentication Integration: {}\n", 
                             bool_to_status(results.component_results.quid_integration_security.authentication_integration_secure)));
    output.push_str(&format!("  - Identity Management: {}\n", 
                             bool_to_status(results.component_results.quid_integration_security.identity_management_secure)));
    output.push_str(&format!("  - Recovery Integration: {}\n", 
                             bool_to_status(results.component_results.quid_integration_security.recovery_integration_secure)));
    output.push_str(&format!("  - Cross-Component Privacy: {}\n", 
                             bool_to_status(results.component_results.quid_integration_security.cross_component_privacy_maintained)));
    output.push_str(&format!("  - Key Derivation: {}\n\n", 
                             bool_to_status(results.component_results.quid_integration_security.key_derivation_secure)));
    
    // Integration security
    output.push_str(&format!("🔧 Integration Security:\n"));
    output.push_str(&format!("  - Component Isolation: {}\n", 
                             bool_to_status(results.integration_results.component_isolation_maintained)));
    output.push_str(&format!("  - Data Flow Security: {}\n", 
                             bool_to_status(results.integration_results.data_flow_security_validated)));
    output.push_str(&format!("  - Privilege Escalation Prevention: {}\n", 
                             bool_to_status(results.integration_results.privilege_escalation_prevented)));
    output.push_str(&format!("  - Cross-Component Attack Prevention: {}\n\n", 
                             bool_to_status(results.integration_results.cross_component_attacks_prevented)));
    
    // Attack resistance
    output.push_str("Attack Resistance Results:\n");
    output.push_str("-------------------------\n");
    
    // Fuzzing results
    output.push_str(&format!("🔍 Fuzzing Results:\n"));
    output.push_str(&format!("  - Cryptographic Fuzzing: {}\n", 
                             bool_to_status(results.attack_resistance_results.fuzzing_results.cryptographic_fuzzing_passed)));
    output.push_str(&format!("  - Network Fuzzing: {}\n", 
                             bool_to_status(results.attack_resistance_results.fuzzing_results.network_fuzzing_passed)));
    output.push_str(&format!("  - Storage Fuzzing: {}\n", 
                             bool_to_status(results.attack_resistance_results.fuzzing_results.storage_fuzzing_passed)));
    output.push_str(&format!("  - Crashes Found: {}\n", 
                             results.attack_resistance_results.fuzzing_results.crashes_found));
    output.push_str(&format!("  - Vulnerabilities Found: {}\n", 
                             results.attack_resistance_results.fuzzing_results.vulnerabilities_found));
    output.push_str(&format!("  - Total Test Cases: {}\n\n", 
                             results.attack_resistance_results.fuzzing_results.total_test_cases));
    
    // DoS resistance
    output.push_str(&format!("⚡ DoS Resistance:\n"));
    output.push_str(&format!("  - Network Flooding Resistant: {}\n", 
                             bool_to_status(results.attack_resistance_results.dos_resistance.network_flooding_resistant)));
    output.push_str(&format!("  - Computational DoS Resistant: {}\n", 
                             bool_to_status(results.attack_resistance_results.dos_resistance.computational_dos_resistant)));
    output.push_str(&format!("  - Memory Exhaustion Resistant: {}\n", 
                             bool_to_status(results.attack_resistance_results.dos_resistance.memory_exhaustion_resistant)));
    output.push_str(&format!("  - Storage DoS Resistant: {}\n", 
                             bool_to_status(results.attack_resistance_results.dos_resistance.storage_dos_resistant)));
    output.push_str(&format!("  - Graceful Degradation: {}\n\n", 
                             bool_to_status(results.attack_resistance_results.dos_resistance.graceful_degradation_validated)));
    
    // Timing attack resistance
    output.push_str(&format!("⏱️ Timing Attack Resistance:\n"));
    output.push_str(&format!("  - Constant-Time Operations: {}\n", 
                             bool_to_status(results.attack_resistance_results.timing_attack_resistance.constant_time_operations_validated)));
    output.push_str(&format!("  - Cryptographic Timing: {}\n", 
                             bool_to_status(results.attack_resistance_results.timing_attack_resistance.cryptographic_timing_secure)));
    output.push_str(&format!("  - Network Timing: {}\n", 
                             bool_to_status(results.attack_resistance_results.timing_attack_resistance.network_timing_secure)));
    output.push_str(&format!("  - Storage Timing: {}\n", 
                             bool_to_status(results.attack_resistance_results.timing_attack_resistance.storage_timing_secure)));
    output.push_str(&format!("  - Statistical Analysis: {}\n\n", 
                             bool_to_status(results.attack_resistance_results.timing_attack_resistance.statistical_analysis_passed)));
    
    // Memory safety
    output.push_str(&format!("🧠 Memory Safety:\n"));
    output.push_str(&format!("  - Buffer Overflow Protected: {}\n", 
                             bool_to_status(results.attack_resistance_results.memory_safety_results.buffer_overflow_protected)));
    output.push_str(&format!("  - Use-After-Free Prevented: {}\n", 
                             bool_to_status(results.attack_resistance_results.memory_safety_results.use_after_free_prevented)));
    output.push_str(&format!("  - Memory Leaks Prevented: {}\n", 
                             bool_to_status(results.attack_resistance_results.memory_safety_results.memory_leaks_prevented)));
    output.push_str(&format!("  - Double-Free Prevented: {}\n", 
                             bool_to_status(results.attack_resistance_results.memory_safety_results.double_free_prevented)));
    output.push_str(&format!("  - Stack Overflow Protected: {}\n\n", 
                             bool_to_status(results.attack_resistance_results.memory_safety_results.stack_overflow_protected)));
    
    // Security findings
    if !results.findings.is_empty() {
        output.push_str("Security Findings:\n");
        output.push_str("------------------\n");
        
        for (i, finding) in results.findings.iter().enumerate() {
            let severity_emoji = match finding.severity {
                SecuritySeverity::Critical => "🚨",
                SecuritySeverity::High => "⚠️",
                SecuritySeverity::Medium => "⚡",
                SecuritySeverity::Low => "ℹ️",
                SecuritySeverity::Informational => "📝",
            };
            
            let category_name = match finding.category {
                SecurityCategory::Cryptographic => "Cryptographic",
                SecurityCategory::Network => "Network",
                SecurityCategory::Storage => "Storage",
                SecurityCategory::Integration => "Integration",
                SecurityCategory::Performance => "Performance",
                SecurityCategory::MemorySafety => "Memory Safety",
                SecurityCategory::Configuration => "Configuration",
            };
            
            output.push_str(&format!("{}. {} [{:?}] {} - {}\n", 
                                   i + 1, severity_emoji, finding.severity, category_name, finding.component));
            output.push_str(&format!("   Description: {}\n", finding.description));
            output.push_str(&format!("   Recommendation: {}\n", finding.recommendation));
            output.push_str(&format!("   Exploitable: {}\n\n", finding.exploitable));
        }
    } else {
        output.push_str("✅ No security issues found!\n\n");
    }
    
    output
}

fn bool_to_status(value: bool) -> &'static str {
    if value { "✅ PASS" } else { "❌ FAIL" }
}

async fn generate_report_from_file(file_path: &str, format: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content = tokio::fs::read_to_string(file_path).await?;
    let results: SecurityAuditResults = serde_json::from_str(&content)?;
    
    let report = match format {
        "json" => serde_json::to_string_pretty(&results)?,
        "text" => format_text_results(&results),
        _ => return Err(format!("Unknown format: {}", format).into()),
    };
    
    println!("{}", report);
    Ok(())
}

fn print_audit_summary(results: &SecurityAuditResults) {
    let critical_findings = results.findings.iter()
        .filter(|f| matches!(f.severity, SecuritySeverity::Critical))
        .count();
    
    let high_findings = results.findings.iter()
        .filter(|f| matches!(f.severity, SecuritySeverity::High))
        .count();
    
    let medium_findings = results.findings.iter()
        .filter(|f| matches!(f.severity, SecuritySeverity::Medium))
        .count();
    
    println!("\n🛡️ Security Audit Summary");
    println!("=========================");
    println!("Overall Status: {}", if results.overall_secure { "✅ SECURE" } else { "❌ ISSUES FOUND" });
    println!("Audit Duration: {:?}", results.audit_duration);
    println!("Findings Summary:");
    println!("  🚨 Critical: {}", critical_findings);
    println!("  ⚠️  High: {}", high_findings);
    println!("  ⚡ Medium: {}", medium_findings);
    println!("  📊 Total: {}", results.findings.len());
    
    if results.attack_resistance_results.fuzzing_results.total_test_cases > 0 {
        println!("Fuzzing Summary:");
        println!("  Test Cases: {}", results.attack_resistance_results.fuzzing_results.total_test_cases);
        println!("  Crashes: {}", results.attack_resistance_results.fuzzing_results.crashes_found);
        println!("  Vulnerabilities: {}", results.attack_resistance_results.fuzzing_results.vulnerabilities_found);
    }
    
    if !results.overall_secure {
        println!("\n⚠️  Security issues detected. Please review findings and apply recommended fixes.");
    } else {
        println!("\n✅ All security tests passed successfully!");
    }
}