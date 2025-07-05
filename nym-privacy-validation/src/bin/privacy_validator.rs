//! Privacy Validator Binary
//! 
//! Comprehensive privacy validation CLI tool for the Nym cryptocurrency system.
//! Supports multiple analysis modes and output formats.

use nym_privacy_validation::*;
use clap::{Parser, Subcommand, ValueEnum};
use serde_json;
use std::fs::File;
use std::io::Write;
use std::path::PathBuf;
use std::time::Instant;
use tracing::{info, warn, error};
use tracing_subscriber::{fmt, EnvFilter};

#[derive(Parser)]
#[command(name = "privacy-validator")]
#[command(about = "Comprehensive privacy validation for Nym cryptocurrency system")]
#[command(long_about = "
Privacy Validator analyzes the privacy properties of the Nym cryptocurrency system,
including zero-knowledge proofs, anonymity sets, privacy leaks, and cryptographic assumptions.

The tool supports multiple analysis modes:
- Quick: Fast analysis with basic checks
- Standard: Comprehensive analysis with statistical validation
- Exhaustive: In-depth analysis with maximum security guarantees

Output formats include human-readable text and machine-readable JSON.
")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
    
    /// Output format
    #[arg(short, long, default_value = "text")]
    output: OutputFormat,
    
    /// Output file path (if not specified, output to stdout)
    #[arg(short = 'f', long)]
    output_file: Option<PathBuf>,
    
    /// Verbose output
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
    
    /// Enable parallel analysis
    #[arg(short, long, default_value = "true")]
    parallel: bool,
    
    /// Statistical confidence level (0.0-1.0)
    #[arg(short, long, default_value = "0.95")]
    confidence: f64,
}

#[derive(Subcommand)]
enum Commands {
    /// Run quick privacy analysis
    Quick {
        /// Number of transactions to analyze
        #[arg(long, default_value = "1000")]
        sample_size: usize,
        
        /// Disable specific analysis modules
        #[arg(long)]
        disable_zkproof: bool,
        
        #[arg(long)]
        disable_anonymity: bool,
        
        #[arg(long)]
        disable_privacy_leak: bool,
        
        #[arg(long)]
        disable_crypto_assumptions: bool,
        
        #[arg(long)]
        disable_transaction_graph: bool,
        
        #[arg(long)]
        disable_metadata_privacy: bool,
        
        #[arg(long)]
        disable_differential_privacy: bool,
    },
    
    /// Run standard privacy analysis
    Standard {
        /// Number of transactions to analyze
        #[arg(long, default_value = "10000")]
        sample_size: usize,
        
        /// Number of network nodes to consider
        #[arg(long, default_value = "1000")]
        network_size: usize,
        
        /// Disable specific analysis modules
        #[arg(long)]
        disable_zkproof: bool,
        
        #[arg(long)]
        disable_anonymity: bool,
        
        #[arg(long)]
        disable_privacy_leak: bool,
        
        #[arg(long)]
        disable_crypto_assumptions: bool,
        
        #[arg(long)]
        disable_transaction_graph: bool,
        
        #[arg(long)]
        disable_metadata_privacy: bool,
        
        #[arg(long)]
        disable_differential_privacy: bool,
    },
    
    /// Run comprehensive privacy analysis
    Comprehensive {
        /// Number of transactions to analyze
        #[arg(long, default_value = "100000")]
        sample_size: usize,
        
        /// Number of network nodes to consider
        #[arg(long, default_value = "10000")]
        network_size: usize,
        
        /// Enable all analysis modules (cannot be disabled)
        #[arg(long, default_value = "true")]
        all_modules: bool,
    },
    
    /// Run zero-knowledge proof analysis only
    ZkProof {
        /// Number of proofs to analyze
        #[arg(long, default_value = "1000")]
        proof_count: usize,
        
        /// Test iterations per proof
        #[arg(long, default_value = "100")]
        test_iterations: usize,
    },
    
    /// Run anonymity set analysis only
    Anonymity {
        /// Number of transactions to analyze
        #[arg(long, default_value = "10000")]
        sample_size: usize,
        
        /// Minimum anonymity set size threshold
        #[arg(long, default_value = "100")]
        min_anonymity_size: usize,
    },
    
    /// Run privacy leak detection only
    PrivacyLeak {
        /// Analysis depth
        #[arg(long, default_value = "standard")]
        depth: AnalysisDepthArg,
    },
    
    /// Generate privacy report
    Report {
        /// Include recommendations
        #[arg(long, default_value = "true")]
        include_recommendations: bool,
        
        /// Include detailed analysis
        #[arg(long, default_value = "true")]
        include_details: bool,
        
        /// Report format
        #[arg(long, default_value = "markdown")]
        format: ReportFormat,
    },
}

#[derive(ValueEnum, Clone, Debug)]
enum OutputFormat {
    Text,
    Json,
    Yaml,
}

#[derive(ValueEnum, Clone, Debug)]
enum AnalysisDepthArg {
    Basic,
    Standard,
    Comprehensive,
    Exhaustive,
}

#[derive(ValueEnum, Clone, Debug)]
enum ReportFormat {
    Markdown,
    Html,
    Pdf,
}

impl From<AnalysisDepthArg> for AnalysisDepth {
    fn from(depth: AnalysisDepthArg) -> Self {
        match depth {
            AnalysisDepthArg::Basic => AnalysisDepth::Basic,
            AnalysisDepthArg::Standard => AnalysisDepth::Standard,
            AnalysisDepthArg::Comprehensive => AnalysisDepth::Comprehensive,
            AnalysisDepthArg::Exhaustive => AnalysisDepth::Exhaustive,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();
    
    // Initialize tracing
    let log_level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };
    
    let filter = EnvFilter::try_from_default_env()
        .or_else(|_| EnvFilter::try_new(log_level))
        .unwrap();
    
    fmt()
        .with_env_filter(filter)
        .with_target(false)
        .with_thread_ids(false)
        .with_file(false)
        .with_line_number(false)
        .init();
    
    info!("🔍 Starting Nym Privacy Validator");
    
    let start_time = Instant::now();
    
    // Execute command
    let result = match cli.command {
        Commands::Quick { 
            sample_size, 
            disable_zkproof,
            disable_anonymity,
            disable_privacy_leak,
            disable_crypto_assumptions,
            disable_transaction_graph,
            disable_metadata_privacy,
            disable_differential_privacy,
        } => {
            let config = create_config(
                sample_size,
                100,
                AnalysisDepth::Basic,
                cli.parallel,
                cli.confidence,
                disable_zkproof,
                disable_anonymity,
                disable_privacy_leak,
                disable_crypto_assumptions,
                disable_transaction_graph,
                disable_metadata_privacy,
                disable_differential_privacy,
            );
            
            run_analysis(config).await
        },
        
        Commands::Standard { 
            sample_size, 
            network_size,
            disable_zkproof,
            disable_anonymity,
            disable_privacy_leak,
            disable_crypto_assumptions,
            disable_transaction_graph,
            disable_metadata_privacy,
            disable_differential_privacy,
        } => {
            let config = create_config(
                sample_size,
                network_size,
                AnalysisDepth::Standard,
                cli.parallel,
                cli.confidence,
                disable_zkproof,
                disable_anonymity,
                disable_privacy_leak,
                disable_crypto_assumptions,
                disable_transaction_graph,
                disable_metadata_privacy,
                disable_differential_privacy,
            );
            
            run_analysis(config).await
        },
        
        Commands::Comprehensive { 
            sample_size, 
            network_size,
            all_modules: _,
        } => {
            let config = create_config(
                sample_size,
                network_size,
                AnalysisDepth::Comprehensive,
                cli.parallel,
                cli.confidence,
                false, // Enable all modules
                false,
                false,
                false,
                false,
                false,
                false,
            );
            
            run_analysis(config).await
        },
        
        Commands::ZkProof { proof_count: _, test_iterations: _ } => {
            let config = create_config(
                1000,
                100,
                AnalysisDepth::Standard,
                cli.parallel,
                cli.confidence,
                false, // Enable only zkproof
                true,  // Disable others
                true,
                true,
                true,
                true,
                true,
            );
            
            run_analysis(config).await
        },
        
        Commands::Anonymity { sample_size, min_anonymity_size: _ } => {
            let config = create_config(
                sample_size,
                100,
                AnalysisDepth::Standard,
                cli.parallel,
                cli.confidence,
                true,  // Disable others
                false, // Enable only anonymity
                true,
                true,
                true,
                true,
                true,
            );
            
            run_analysis(config).await
        },
        
        Commands::PrivacyLeak { depth } => {
            let config = create_config(
                10000,
                1000,
                depth.into(),
                cli.parallel,
                cli.confidence,
                true,  // Disable others
                true,
                false, // Enable only privacy leak
                true,
                true,
                true,
                true,
            );
            
            run_analysis(config).await
        },
        
        Commands::Report { include_recommendations, include_details, format } => {
            let config = PrivacyValidationConfig::default();
            let results = run_analysis(config).await?;
            
            generate_report(&results, include_recommendations, include_details, format).await
        },
    };
    
    let total_time = start_time.elapsed();
    
    match result {
        Ok(results) => {
            info!("✅ Privacy validation completed in {:?}", total_time);
            
            // Output results
            let output_content = match cli.output {
                OutputFormat::Text => format_text_output(&results),
                OutputFormat::Json => format_json_output(&results)?,
                OutputFormat::Yaml => format_yaml_output(&results)?,
            };
            
            // Write output
            if let Some(output_file) = cli.output_file {
                let mut file = File::create(&output_file)?;
                file.write_all(output_content.as_bytes())?;
                info!("📄 Results written to {}", output_file.display());
            } else {
                println!("{}", output_content);
            }
            
            // Return appropriate exit code based on results
            if results.overall_privacy_score < 0.5 {
                std::process::exit(1);
            } else if results.overall_privacy_score < 0.8 {
                std::process::exit(2);
            }
        },
        Err(e) => {
            error!("❌ Privacy validation failed: {}", e);
            std::process::exit(3);
        }
    }
    
    Ok(())
}

fn create_config(
    sample_size: usize,
    network_size: usize,
    depth: AnalysisDepth,
    parallel: bool,
    confidence: f64,
    disable_zkproof: bool,
    disable_anonymity: bool,
    disable_privacy_leak: bool,
    disable_crypto_assumptions: bool,
    disable_transaction_graph: bool,
    disable_metadata_privacy: bool,
    disable_differential_privacy: bool,
) -> PrivacyValidationConfig {
    PrivacyValidationConfig {
        enable_zkproof_analysis: !disable_zkproof,
        enable_anonymity_analysis: !disable_anonymity,
        enable_privacy_leak_detection: !disable_privacy_leak,
        enable_crypto_assumption_validation: !disable_crypto_assumptions,
        enable_transaction_graph_analysis: !disable_transaction_graph,
        enable_metadata_privacy_analysis: !disable_metadata_privacy,
        enable_differential_privacy_analysis: !disable_differential_privacy,
        transaction_sample_size: sample_size,
        network_sample_size: network_size,
        analysis_depth: depth,
        parallel_analysis: parallel,
        confidence_level: confidence,
    }
}

async fn run_analysis(config: PrivacyValidationConfig) -> Result<PrivacyValidationResults> {
    let validator = PrivacyValidator::new(config);
    validator.validate_privacy().await
}

fn format_text_output(results: &PrivacyValidationResults) -> String {
    let mut output = String::new();
    
    // Header
    output.push_str("🔍 NYM PRIVACY VALIDATION RESULTS\n");
    output.push_str("═══════════════════════════════════════════════════════════════════════════════\n\n");
    
    // Overall score
    let score_emoji = if results.overall_privacy_score >= 0.9 {
        "🟢"
    } else if results.overall_privacy_score >= 0.7 {
        "🟡"
    } else if results.overall_privacy_score >= 0.5 {
        "🟠"
    } else {
        "🔴"
    };
    
    output.push_str(&format!("Overall Privacy Score: {} {:.1}%\n", score_emoji, results.overall_privacy_score * 100.0));
    output.push_str(&format!("Analysis Duration: {:?}\n\n", results.analysis_duration));
    
    // Component scores
    output.push_str("COMPONENT ANALYSIS\n");
    output.push_str("─────────────────────────────────────────────────────────────────────────────\n");
    output.push_str(&format!("🔒 Zero-Knowledge Proofs:    {:.1}%\n", results.zkproof_results.overall_score * 100.0));
    output.push_str(&format!("👥 Anonymity Sets:           {:.1}%\n", results.anonymity_results.overall_anonymity_score * 100.0));
    output.push_str(&format!("🔐 Privacy Leak Detection:   {:.1}%\n", results.privacy_leak_results.overall_privacy_score * 100.0));
    output.push_str(&format!("🔑 Crypto Assumptions:       {:.1}%\n", results.crypto_assumption_results.overall_security_score * 100.0));
    output.push_str(&format!("📊 Transaction Graph:        {:.1}%\n", results.transaction_graph_results.privacy_score * 100.0));
    output.push_str(&format!("📝 Metadata Privacy:         {:.1}%\n", results.metadata_privacy_results.privacy_score * 100.0));
    output.push_str(&format!("🔀 Differential Privacy:     {:.1}%\n\n", results.differential_privacy_results.privacy_score * 100.0));
    
    // Vulnerabilities
    if !results.vulnerabilities.is_empty() {
        output.push_str("VULNERABILITIES DETECTED\n");
        output.push_str("─────────────────────────────────────────────────────────────────────────────\n");
        
        for (i, vuln) in results.vulnerabilities.iter().enumerate() {
            let severity_emoji = match vuln.severity {
                PrivacySeverity::Critical => "🔴",
                PrivacySeverity::High => "🟠",
                PrivacySeverity::Medium => "🟡",
                PrivacySeverity::Low => "🔵",
                PrivacySeverity::Informational => "ℹ️",
            };
            
            output.push_str(&format!("{}. {} {:?} - {}\n", i + 1, severity_emoji, vuln.severity, vuln.component));
            output.push_str(&format!("   {}\n", vuln.description));
            output.push_str(&format!("   Impact: {}\n", vuln.impact));
            output.push_str(&format!("   Privacy Loss: {:.1}%\n", vuln.privacy_loss * 100.0));
            output.push_str(&format!("   Mitigation: {}\n\n", vuln.mitigation));
        }
    }
    
    // Recommendations
    if !results.recommendations.is_empty() {
        output.push_str("RECOMMENDATIONS\n");
        output.push_str("─────────────────────────────────────────────────────────────────────────────\n");
        
        for (i, rec) in results.recommendations.iter().enumerate() {
            let priority_emoji = match rec.priority {
                RecommendationPriority::Critical => "🔴",
                RecommendationPriority::High => "🟠",
                RecommendationPriority::Medium => "🟡",
                RecommendationPriority::Low => "🔵",
            };
            
            output.push_str(&format!("{}. {} {:?} - {}\n", i + 1, priority_emoji, rec.priority, rec.title));
            output.push_str(&format!("   Component: {}\n", rec.component));
            output.push_str(&format!("   {}\n", rec.description));
            output.push_str(&format!("   Privacy Improvement: {:.1}%\n", rec.privacy_improvement * 100.0));
            output.push_str(&format!("   Effort: {}\n\n", rec.effort_estimate));
        }
    }
    
    // Summary
    output.push_str("SUMMARY\n");
    output.push_str("─────────────────────────────────────────────────────────────────────────────\n");
    output.push_str(&format!("• {} vulnerabilities found\n", results.vulnerabilities.len()));
    output.push_str(&format!("• {} recommendations generated\n", results.recommendations.len()));
    
    let critical_vulns = results.vulnerabilities.iter().filter(|v| matches!(v.severity, PrivacySeverity::Critical)).count();
    let high_vulns = results.vulnerabilities.iter().filter(|v| matches!(v.severity, PrivacySeverity::High)).count();
    
    if critical_vulns > 0 {
        output.push_str(&format!("• 🔴 {} critical vulnerabilities require immediate attention\n", critical_vulns));
    }
    if high_vulns > 0 {
        output.push_str(&format!("• 🟠 {} high severity vulnerabilities found\n", high_vulns));
    }
    
    output.push_str(&format!("• Overall privacy rating: {}\n", 
        if results.overall_privacy_score >= 0.9 { "Excellent" }
        else if results.overall_privacy_score >= 0.7 { "Good" }
        else if results.overall_privacy_score >= 0.5 { "Fair" }
        else { "Poor" }
    ));
    
    output
}

fn format_json_output(results: &PrivacyValidationResults) -> Result<String> {
    Ok(serde_json::to_string_pretty(results)?)
}

fn format_yaml_output(results: &PrivacyValidationResults) -> Result<String> {
    Ok(serde_yaml::to_string(results)?)
}

async fn generate_report(
    results: &PrivacyValidationResults,
    include_recommendations: bool,
    include_details: bool,
    format: ReportFormat,
) -> Result<PrivacyValidationResults> {
    info!("📊 Generating privacy validation report");
    
    match format {
        ReportFormat::Markdown => {
            let report = generate_markdown_report(results, include_recommendations, include_details);
            println!("{}", report);
        },
        ReportFormat::Html => {
            warn!("HTML report generation not yet implemented");
        },
        ReportFormat::Pdf => {
            warn!("PDF report generation not yet implemented");
        },
    }
    
    Ok(results.clone())
}

fn generate_markdown_report(
    results: &PrivacyValidationResults,
    include_recommendations: bool,
    include_details: bool,
) -> String {
    let mut report = String::new();
    
    // Header
    report.push_str("# Nym Privacy Validation Report\n\n");
    report.push_str(&format!("**Generated:** {}\n", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC")));
    report.push_str(&format!("**Analysis Duration:** {:?}\n\n", results.analysis_duration));
    
    // Executive Summary
    report.push_str("## Executive Summary\n\n");
    report.push_str(&format!("The Nym cryptocurrency system achieved an overall privacy score of **{:.1}%**.\n\n", results.overall_privacy_score * 100.0));
    
    // Component Analysis
    report.push_str("## Component Analysis\n\n");
    report.push_str("| Component | Score | Status |\n");
    report.push_str("|-----------|-------|--------|\n");
    report.push_str(&format!("| Zero-Knowledge Proofs | {:.1}% | {} |\n", results.zkproof_results.overall_score * 100.0, status_emoji(results.zkproof_results.overall_score)));
    report.push_str(&format!("| Anonymity Sets | {:.1}% | {} |\n", results.anonymity_results.overall_anonymity_score * 100.0, status_emoji(results.anonymity_results.overall_anonymity_score)));
    report.push_str(&format!("| Privacy Leak Detection | {:.1}% | {} |\n", results.privacy_leak_results.overall_privacy_score * 100.0, status_emoji(results.privacy_leak_results.overall_privacy_score)));
    report.push_str(&format!("| Crypto Assumptions | {:.1}% | {} |\n", results.crypto_assumption_results.overall_security_score * 100.0, status_emoji(results.crypto_assumption_results.overall_security_score)));
    report.push_str(&format!("| Transaction Graph | {:.1}% | {} |\n", results.transaction_graph_results.privacy_score * 100.0, status_emoji(results.transaction_graph_results.privacy_score)));
    report.push_str(&format!("| Metadata Privacy | {:.1}% | {} |\n", results.metadata_privacy_results.privacy_score * 100.0, status_emoji(results.metadata_privacy_results.privacy_score)));
    report.push_str(&format!("| Differential Privacy | {:.1}% | {} |\n\n", results.differential_privacy_results.privacy_score * 100.0, status_emoji(results.differential_privacy_results.privacy_score)));
    
    // Vulnerabilities
    if !results.vulnerabilities.is_empty() {
        report.push_str("## Vulnerabilities\n\n");
        
        for (i, vuln) in results.vulnerabilities.iter().enumerate() {
            report.push_str(&format!("### {}. {} - {}\n\n", i + 1, severity_badge(&vuln.severity), vuln.component));
            report.push_str(&format!("**Description:** {}\n\n", vuln.description));
            report.push_str(&format!("**Impact:** {}\n\n", vuln.impact));
            report.push_str(&format!("**Privacy Loss:** {:.1}%\n\n", vuln.privacy_loss * 100.0));
            report.push_str(&format!("**Mitigation:** {}\n\n", vuln.mitigation));
        }
    }
    
    // Recommendations
    if include_recommendations && !results.recommendations.is_empty() {
        report.push_str("## Recommendations\n\n");
        
        for (i, rec) in results.recommendations.iter().enumerate() {
            report.push_str(&format!("### {}. {} - {}\n\n", i + 1, priority_badge(&rec.priority), rec.title));
            report.push_str(&format!("**Component:** {}\n\n", rec.component));
            report.push_str(&format!("**Description:** {}\n\n", rec.description));
            report.push_str(&format!("**Expected Improvement:** {:.1}%\n\n", rec.privacy_improvement * 100.0));
            report.push_str(&format!("**Effort Estimate:** {}\n\n", rec.effort_estimate));
        }
    }
    
    // Detailed Analysis
    if include_details {
        report.push_str("## Detailed Analysis\n\n");
        report.push_str("### Zero-Knowledge Proof Analysis\n\n");
        report.push_str(&format!("- **Soundness Verified:** {}\n", results.zkproof_results.soundness_results.soundness_verified));
        report.push_str(&format!("- **Zero-Knowledge Verified:** {}\n", results.zkproof_results.zero_knowledge_results.zero_knowledge_verified));
        report.push_str(&format!("- **Completeness Verified:** {}\n", results.zkproof_results.completeness_results.completeness_verified));
        report.push_str(&format!("- **Proof Generation Time:** {:?}\n", results.zkproof_results.performance_results.proof_generation_time));
        report.push_str(&format!("- **Proof Verification Time:** {:?}\n", results.zkproof_results.performance_results.proof_verification_time));
        report.push_str(&format!("- **Proof Size:** {} bytes\n\n", results.zkproof_results.performance_results.proof_size_bytes));
        
        // Add more detailed analysis sections as needed
    }
    
    report
}

fn status_emoji(score: f64) -> &'static str {
    if score >= 0.9 { "🟢" }
    else if score >= 0.7 { "🟡" }
    else if score >= 0.5 { "🟠" }
    else { "🔴" }
}

fn severity_badge(severity: &PrivacySeverity) -> &'static str {
    match severity {
        PrivacySeverity::Critical => "🔴 **CRITICAL**",
        PrivacySeverity::High => "🟠 **HIGH**",
        PrivacySeverity::Medium => "🟡 **MEDIUM**",
        PrivacySeverity::Low => "🔵 **LOW**",
        PrivacySeverity::Informational => "ℹ️ **INFO**",
    }
}

fn priority_badge(priority: &RecommendationPriority) -> &'static str {
    match priority {
        RecommendationPriority::Critical => "🔴 **CRITICAL**",
        RecommendationPriority::High => "🟠 **HIGH**",
        RecommendationPriority::Medium => "🟡 **MEDIUM**",
        RecommendationPriority::Low => "🔵 **LOW**",
    }
}