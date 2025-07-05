//! Performance Optimizer Binary
//!
//! Main optimization runner that executes comprehensive performance improvements
//! across all Nym blockchain components.

use std::time::{Duration, Instant};
use tokio::time::interval;
use clap::{Parser, Subcommand};
use tracing::{info, warn, error, debug};
use tracing_subscriber::{fmt, layer::SubscriberExt, util::SubscriberInitExt};
use serde_json;

use nym_performance::{
    PerformanceManager, PerformanceConfig, PerformanceError, Result,
    zkstark_optimizer::{ProofOptions, ProofPriority},
    monitoring::AlertRule,
    config::OptimizationLevel,
};

#[derive(Parser)]
#[command(name = "perf-optimizer")]
#[command(about = "Nym Blockchain Performance Optimizer")]
#[command(version = "1.0.0")]
struct Cli {
    #[command(subcommand)]
    command: Commands,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Configuration file path
    #[arg(short, long, default_value = "performance.toml")]
    config: String,

    /// Optimization level
    #[arg(short, long, default_value = "balanced")]
    level: String,

    /// Enable continuous optimization
    #[arg(long)]
    continuous: bool,

    /// Optimization interval in seconds (for continuous mode)
    #[arg(long, default_value = "300")]
    interval: u64,
}

#[derive(Subcommand)]
enum Commands {
    /// Run comprehensive optimization
    Optimize {
        /// Target components to optimize
        #[arg(short, long, value_delimiter = ',')]
        components: Option<Vec<String>>,
        
        /// Maximum optimization time in seconds
        #[arg(short, long, default_value = "600")]
        timeout: u64,
        
        /// Save optimization results to file
        #[arg(short, long)]
        output: Option<String>,
    },
    
    /// Run performance analysis
    Analyze {
        /// Analysis duration in seconds
        #[arg(short, long, default_value = "60")]
        duration: u64,
        
        /// Generate detailed report
        #[arg(long)]
        detailed: bool,
        
        /// Export format (json, yaml, csv)
        #[arg(long, default_value = "json")]
        format: String,
    },
    
    /// Start performance monitoring
    Monitor {
        /// Monitoring duration in seconds (0 = continuous)
        #[arg(short, long, default_value = "0")]
        duration: u64,
        
        /// Alert threshold configuration
        #[arg(long)]
        alerts: Option<String>,
        
        /// Dashboard port
        #[arg(long, default_value = "8080")]
        dashboard_port: u16,
    },
    
    /// Benchmark performance
    Benchmark {
        /// Benchmark suite to run
        #[arg(short, long, default_value = "all")]
        suite: String,
        
        /// Number of iterations
        #[arg(short, long, default_value = "10")]
        iterations: u32,
        
        /// Warm-up iterations
        #[arg(long, default_value = "3")]
        warmup: u32,
    },
    
    /// Reset optimization state
    Reset {
        /// Reset specific component
        #[arg(short, long)]
        component: Option<String>,
        
        /// Confirm reset without prompt
        #[arg(short, long)]
        force: bool,
    },
    
    /// Show current performance status
    Status {
        /// Show detailed status
        #[arg(short, long)]
        detailed: bool,
        
        /// Refresh interval in seconds
        #[arg(short, long)]
        refresh: Option<u64>,
    },
}

/// Optimization configuration
#[derive(Debug, Clone)]
struct OptimizationConfig {
    level: OptimizationLevel,
    components: Vec<String>,
    timeout: Duration,
    continuous: bool,
    interval: Duration,
}

/// Analysis configuration
#[derive(Debug, Clone)]
struct AnalysisConfig {
    duration: Duration,
    detailed: bool,
    export_format: String,
}

/// Monitoring configuration
#[derive(Debug, Clone)]
struct MonitoringConfig {
    duration: Option<Duration>,
    dashboard_port: u16,
    alert_config: Option<String>,
}

/// Benchmark configuration
#[derive(Debug, Clone)]
struct BenchmarkConfig {
    suite: String,
    iterations: u32,
    warmup_iterations: u32,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
    // Initialize logging
    initialize_logging(cli.verbose)?;
    
    info!("Starting Nym Performance Optimizer v1.0.0");
    
    // Load configuration
    let config = load_configuration(&cli.config).await?;
    
    // Create performance manager
    let manager = PerformanceManager::with_config(config)?;
    
    // Execute command
    match cli.command {
        Commands::Optimize { components, timeout, output } => {
            let opt_config = OptimizationConfig {
                level: parse_optimization_level(&cli.level)?,
                components: components.unwrap_or_else(|| vec!["all".to_string()]),
                timeout: Duration::from_secs(timeout),
                continuous: cli.continuous,
                interval: Duration::from_secs(cli.interval),
            };
            
            run_optimization(&manager, opt_config, output).await?;
        }
        
        Commands::Analyze { duration, detailed, format } => {
            let analysis_config = AnalysisConfig {
                duration: Duration::from_secs(duration),
                detailed,
                export_format: format,
            };
            
            run_analysis(&manager, analysis_config).await?;
        }
        
        Commands::Monitor { duration, alerts, dashboard_port } => {
            let monitor_config = MonitoringConfig {
                duration: if duration > 0 { Some(Duration::from_secs(duration)) } else { None },
                dashboard_port,
                alert_config: alerts,
            };
            
            run_monitoring(&manager, monitor_config).await?;
        }
        
        Commands::Benchmark { suite, iterations, warmup } => {
            let benchmark_config = BenchmarkConfig {
                suite,
                iterations,
                warmup_iterations: warmup,
            };
            
            run_benchmarks(&manager, benchmark_config).await?;
        }
        
        Commands::Reset { component, force } => {
            run_reset(&manager, component, force).await?;
        }
        
        Commands::Status { detailed, refresh } => {
            run_status(&manager, detailed, refresh).await?;
        }
    }
    
    info!("Performance optimizer completed successfully");
    Ok(())
}

async fn run_optimization(
    manager: &PerformanceManager,
    config: OptimizationConfig,
    output_file: Option<String>,
) -> Result<()> {
    info!("Starting optimization with level: {:?}", config.level);
    info!("Target components: {:?}", config.components);
    info!("Timeout: {:?}", config.timeout);
    
    // Start the performance manager
    manager.start().await?;
    
    if config.continuous {
        info!("Running continuous optimization with interval: {:?}", config.interval);
        run_continuous_optimization(manager, config).await?;
    } else {
        info!("Running single optimization pass");
        run_single_optimization(manager, &config).await?;
    }
    
    // Save results if requested
    if let Some(output_path) = output_file {
        save_optimization_results(manager, &output_path).await?;
    }
    
    manager.stop().await?;
    Ok(())
}

async fn run_continuous_optimization(
    manager: &PerformanceManager,
    config: OptimizationConfig,
) -> Result<()> {
    let mut interval_timer = interval(config.interval);
    let start_time = Instant::now();
    
    loop {
        interval_timer.tick().await;
        
        info!("Running optimization cycle at {:?}", start_time.elapsed());
        
        if let Err(e) = run_single_optimization(manager, &config).await {
            error!("Optimization cycle failed: {}", e);
            continue;
        }
        
        // Check if we should stop (could add signal handling here)
        if start_time.elapsed() > config.timeout {
            info!("Optimization timeout reached, stopping continuous optimization");
            break;
        }
    }
    
    Ok(())
}

async fn run_single_optimization(
    manager: &PerformanceManager,
    config: &OptimizationConfig,
) -> Result<()> {
    let start_time = Instant::now();
    
    // Run component-specific optimizations
    for component in &config.components {
        match component.as_str() {
            "all" => {
                info!("Running comprehensive optimization");
                manager.optimize().await?;
            }
            "zkstark" => {
                info!("Optimizing zk-STARK operations");
                manager.zkstark_optimizer().optimize().await?;
            }
            "memory" => {
                info!("Optimizing memory usage");
                manager.memory_optimizer().optimize().await?;
            }
            "network" => {
                info!("Optimizing network operations");
                manager.network_optimizer().optimize().await?;
            }
            _ => {
                warn!("Unknown component: {}, skipping", component);
            }
        }
    }
    
    let optimization_time = start_time.elapsed();
    info!("Optimization completed in {:?}", optimization_time);
    
    // Display optimization results
    display_optimization_results(manager).await?;
    
    Ok(())
}

async fn run_analysis(manager: &PerformanceManager, config: AnalysisConfig) -> Result<()> {
    info!("Starting performance analysis for {:?}", config.duration);
    
    manager.start().await?;
    
    // Start profiling
    manager.profiler().start().await?;
    
    // Wait for analysis duration
    tokio::time::sleep(config.duration).await;
    
    // Generate analysis report
    let report = manager.profile().await?;
    
    info!("Analysis completed. Generated {} samples", report.summary.duration.as_millis());
    
    // Display or export results
    if config.detailed {
        display_detailed_analysis(&report)?;
    } else {
        display_summary_analysis(&report)?;
    }
    
    // Export if requested
    export_analysis_results(&report, &config.export_format).await?;
    
    manager.profiler().stop().await?;
    manager.stop().await?;
    
    Ok(())
}

async fn run_monitoring(manager: &PerformanceManager, config: MonitoringConfig) -> Result<()> {
    info!("Starting performance monitoring");
    
    if let Some(duration) = config.duration {
        info!("Monitoring duration: {:?}", duration);
    } else {
        info!("Continuous monitoring enabled");
    }
    
    manager.start().await?;
    
    // Configure alerts if provided
    if let Some(alert_config_path) = &config.alert_config {
        configure_alerts(manager, alert_config_path).await?;
    }
    
    // Start monitoring
    let monitor = manager.monitor();
    
    // Monitor for specified duration or continuously
    if let Some(duration) = config.duration {
        tokio::time::sleep(duration).await;
    } else {
        // Run until interrupted (would add signal handling in real implementation)
        info!("Press Ctrl+C to stop monitoring");
        tokio::signal::ctrl_c().await.map_err(|e| 
            PerformanceError::monitoring(format!("Failed to wait for interrupt: {}", e)))?;
    }
    
    // Display final monitoring results
    display_monitoring_results(manager).await?;
    
    manager.stop().await?;
    
    Ok(())
}

async fn run_benchmarks(manager: &PerformanceManager, config: BenchmarkConfig) -> Result<()> {
    info!("Starting performance benchmarks");
    info!("Suite: {}, Iterations: {}, Warmup: {}", 
          config.suite, config.iterations, config.warmup_iterations);
    
    manager.start().await?;
    
    // Run benchmarks
    let benchmark_results = manager.benchmark().await?;
    
    info!("Benchmarks completed successfully");
    
    // Display results
    display_benchmark_results(&benchmark_results)?;
    
    manager.stop().await?;
    
    Ok(())
}

async fn run_reset(manager: &PerformanceManager, component: Option<String>, force: bool) -> Result<()> {
    if !force {
        println!("This will reset optimization state. Are you sure? (y/N)");
        let mut input = String::new();
        std::io::stdin().read_line(&mut input).map_err(|e|
            PerformanceError::general(format!("Failed to read input: {}", e)))?;
        
        if !input.trim().eq_ignore_ascii_case("y") {
            info!("Reset cancelled");
            return Ok(());
        }
    }
    
    match component {
        Some(comp) => {
            info!("Resetting component: {}", comp);
            // Reset specific component
            match comp.as_str() {
                "zkstark" => manager.zkstark_optimizer().clear_cache().await?,
                "memory" => manager.memory_optimizer().reset().await?,
                "network" => manager.network_optimizer().reset().await?,
                _ => {
                    error!("Unknown component: {}", comp);
                    return Err(PerformanceError::general(format!("Unknown component: {}", comp)));
                }
            }
        }
        None => {
            info!("Resetting all optimization state");
            // Reset all components
            manager.zkstark_optimizer().clear_cache().await?;
            manager.memory_optimizer().reset().await?;
            manager.network_optimizer().reset().await?;
        }
    }
    
    info!("Reset completed successfully");
    Ok(())
}

async fn run_status(manager: &PerformanceManager, detailed: bool, refresh: Option<u64>) -> Result<()> {
    match refresh {
        Some(interval_secs) => {
            info!("Displaying status with refresh interval: {}s", interval_secs);
            let mut interval_timer = interval(Duration::from_secs(interval_secs));
            
            loop {
                interval_timer.tick().await;
                display_current_status(manager, detailed).await?;
                
                // Clear screen for next update (optional)
                print!("\x1B[2J\x1B[1;1H");
            }
        }
        None => {
            display_current_status(manager, detailed).await?;
        }
    }
    
    Ok(())
}

// Helper functions

fn initialize_logging(verbose: bool) -> Result<()> {
    let level = if verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::INFO
    };
    
    tracing_subscriber::registry()
        .with(fmt::layer().with_target(false))
        .with(tracing_subscriber::filter::LevelFilter::from_level(level))
        .init();
    
    Ok(())
}

async fn load_configuration(config_path: &str) -> Result<PerformanceConfig> {
    // Try to load from file, fallback to default
    match std::fs::read_to_string(config_path) {
        Ok(contents) => {
            toml::from_str(&contents).map_err(|e|
                PerformanceError::general(format!("Failed to parse config: {}", e)))
        }
        Err(_) => {
            warn!("Config file not found, using default configuration");
            Ok(PerformanceConfig::default())
        }
    }
}

fn parse_optimization_level(level: &str) -> Result<OptimizationLevel> {
    match level.to_lowercase().as_str() {
        "minimal" => Ok(OptimizationLevel::Minimal),
        "balanced" => Ok(OptimizationLevel::Balanced),
        "aggressive" => Ok(OptimizationLevel::Aggressive),
        "maximum" => Ok(OptimizationLevel::Maximum),
        _ => Err(PerformanceError::general(format!("Invalid optimization level: {}", level))),
    }
}

async fn save_optimization_results(manager: &PerformanceManager, output_path: &str) -> Result<()> {
    let metrics = manager.get_metrics().await;
    let json_output = serde_json::to_string_pretty(&metrics)
        .map_err(|e| PerformanceError::general(format!("Failed to serialize results: {}", e)))?;
    
    std::fs::write(output_path, json_output)
        .map_err(|e| PerformanceError::general(format!("Failed to write results: {}", e)))?;
    
    info!("Optimization results saved to: {}", output_path);
    Ok(())
}

async fn display_optimization_results(manager: &PerformanceManager) -> Result<()> {
    let metrics = manager.get_metrics().await;
    
    println!("\n=== Optimization Results ===");
    println!("Optimization runs: {}", metrics.optimization_runs);
    println!("Last optimization: {}", metrics.last_optimization);
    println!("Memory usage: {:.2} MB", metrics.memory_usage_mb);
    println!("Network efficiency: {:.2}%", metrics.network_efficiency * 100.0);
    println!("zk-STARK performance: {:.2}%", metrics.zkstark_performance * 100.0);
    
    Ok(())
}

fn display_detailed_analysis(report: &nym_performance::profiling::ProfileReport) -> Result<()> {
    println!("\n=== Detailed Performance Analysis ===");
    println!("Duration: {:?}", report.summary.duration);
    println!("CPU Usage: {:.2}%", report.summary.cpu_usage_percent);
    println!("Memory Usage: {:.2} MB", report.summary.memory_usage_mb);
    println!("Peak Memory: {:.2} MB", report.summary.peak_memory_mb);
    println!("Thread Count: {}", report.summary.thread_count);
    
    if !report.hotspots.is_empty() {
        println!("\nPerformance Hotspots:");
        for hotspot in &report.hotspots {
            println!("  {} - Impact: {:.2}%, Samples: {}", 
                    hotspot.location, hotspot.impact * 100.0, hotspot.samples);
        }
    }
    
    if !report.recommendations.is_empty() {
        println!("\nRecommendations:");
        for recommendation in &report.recommendations {
            println!("  - {}", recommendation);
        }
    }
    
    Ok(())
}

fn display_summary_analysis(report: &nym_performance::profiling::ProfileReport) -> Result<()> {
    println!("\n=== Performance Analysis Summary ===");
    println!("Duration: {:?}", report.summary.duration);
    println!("CPU Usage: {:.2}%", report.summary.cpu_usage_percent);
    println!("Memory Usage: {:.2} MB", report.summary.memory_usage_mb);
    println!("Hotspots found: {}", report.hotspots.len());
    println!("Recommendations: {}", report.recommendations.len());
    
    Ok(())
}

async fn export_analysis_results(
    report: &nym_performance::profiling::ProfileReport,
    format: &str,
) -> Result<()> {
    let timestamp = chrono::Utc::now().format("%Y%m%d_%H%M%S");
    let filename = format!("performance_analysis_{}.{}", timestamp, format);
    
    match format {
        "json" => {
            let json = serde_json::to_string_pretty(report)
                .map_err(|e| PerformanceError::general(format!("JSON serialization failed: {}", e)))?;
            std::fs::write(&filename, json)
                .map_err(|e| PerformanceError::general(format!("Failed to write file: {}", e)))?;
        }
        "yaml" => {
            let yaml = serde_yaml::to_string(report)
                .map_err(|e| PerformanceError::general(format!("YAML serialization failed: {}", e)))?;
            std::fs::write(&filename, yaml)
                .map_err(|e| PerformanceError::general(format!("Failed to write file: {}", e)))?;
        }
        _ => {
            warn!("Unsupported export format: {}, skipping export", format);
            return Ok(());
        }
    }
    
    info!("Analysis results exported to: {}", filename);
    Ok(())
}

async fn configure_alerts(manager: &PerformanceManager, config_path: &str) -> Result<()> {
    // Load alert configuration from file
    let config_content = std::fs::read_to_string(config_path)
        .map_err(|e| PerformanceError::general(format!("Failed to read alert config: {}", e)))?;
    
    // Parse alert rules (simplified - would use proper config format)
    info!("Configuring alerts from: {}", config_path);
    
    Ok(())
}

async fn display_monitoring_results(manager: &PerformanceManager) -> Result<()> {
    let stats = manager.monitor().get_stats().await;
    
    println!("\n=== Monitoring Results ===");
    println!("Metrics recorded: {}", stats.metrics_recorded);
    println!("Alerts triggered: {}", stats.alerts_triggered);
    println!("Alerts resolved: {}", stats.alerts_resolved);
    println!("Active alerts: {}", stats.active_alerts);
    println!("Uptime: {:?}", stats.uptime);
    
    Ok(())
}

fn display_benchmark_results(results: &nym_performance::benchmarking::BenchmarkResults) -> Result<()> {
    println!("\n=== Benchmark Results ===");
    println!("Total duration: {:?}", results.total_duration);
    println!("Iterations completed: {}", results.iterations_completed);
    
    if !results.individual_results.is_empty() {
        println!("\nIndividual Benchmark Results:");
        for result in &results.individual_results {
            println!("  {} - Duration: {:?}, Success: {}", 
                    result.name, result.duration, result.success);
        }
    }
    
    if !results.summary.is_empty() {
        println!("\nSummary:");
        for (metric, value) in &results.summary {
            println!("  {}: {}", metric, value);
        }
    }
    
    Ok(())
}

async fn display_current_status(manager: &PerformanceManager, detailed: bool) -> Result<()> {
    let metrics = manager.get_metrics().await;
    
    println!("\n=== Performance Status ===");
    println!("Last updated: {}", chrono::Utc::now().format("%Y-%m-%d %H:%M:%S UTC"));
    println!("Optimization runs: {}", metrics.optimization_runs);
    println!("Memory usage: {:.2} MB", metrics.memory_usage_mb);
    println!("Network efficiency: {:.2}%", metrics.network_efficiency * 100.0);
    
    if detailed {
        println!("\nDetailed Status:");
        
        // zk-STARK metrics
        let zkstark_metrics = manager.zkstark_optimizer().get_metrics().await;
        println!("  zk-STARK:");
        println!("    Proofs generated: {}", zkstark_metrics.total_proofs_generated);
        println!("    Cache hit ratio: {:.2}%", 
                zkstark_metrics.cache_hits as f64 / 
                (zkstark_metrics.cache_hits + zkstark_metrics.cache_misses).max(1) as f64 * 100.0);
        println!("    Avg generation time: {:?}", zkstark_metrics.average_generation_time);
        
        // Memory metrics
        let memory_metrics = manager.memory_optimizer().get_metrics().await;
        println!("  Memory:");
        println!("    Current allocated: {:.2} MB", memory_metrics.current_allocated_mb);
        println!("    Peak allocated: {:.2} MB", memory_metrics.peak_allocated_mb);
        println!("    Allocation rate: {:.2}/s", memory_metrics.allocation_rate);
        
        // Network metrics
        let network_metrics = manager.network_optimizer().get_metrics().await;
        println!("  Network:");
        println!("    Throughput: {:.2} MB/s", network_metrics.throughput_mbps);
        println!("    Latency: {:.2} ms", network_metrics.avg_latency_ms);
        println!("    Compression ratio: {:.2}x", network_metrics.compression_ratio);
    }
    
    Ok(())
}

// Add missing dependencies to Cargo.toml
use toml;
use serde_yaml;