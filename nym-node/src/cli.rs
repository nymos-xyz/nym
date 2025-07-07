use clap::{Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "nym-node")]
#[command(about = "Nym full node implementation", long_about = None)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
    
    /// Path to configuration file
    #[arg(short, long, global = true)]
    pub config: Option<PathBuf>,
    
    /// Set logging level (error, warn, info, debug, trace)
    #[arg(short, long, global = true, default_value = "info")]
    pub log_level: String,
}

#[derive(Subcommand)]
pub enum Commands {
    /// Initialize a new node with default configuration
    Init {
        /// Directory to initialize the node in
        #[arg(short, long)]
        data_dir: Option<PathBuf>,
        
        /// Create configuration for testnet
        #[arg(long)]
        testnet: bool,
        
        /// Create configuration for mainnet
        #[arg(long)]
        mainnet: bool,
    },
    
    /// Start the node
    Start {
        /// Run as daemon in background
        #[arg(short, long)]
        daemon: bool,
        
        /// Enable mining
        #[arg(long)]
        mine: bool,
        
        /// Enable validator mode
        #[arg(long)]
        validator: bool,
        
        /// Disable compute jobs
        #[arg(long)]
        no_compute: bool,
    },
    
    /// Stop the node
    Stop {
        /// Force stop without graceful shutdown
        #[arg(short, long)]
        force: bool,
    },
    
    /// Show node status
    Status {
        /// Output format (json, text)
        #[arg(short, long, default_value = "text")]
        format: String,
        
        /// Show detailed status
        #[arg(short, long)]
        verbose: bool,
    },
    
    /// Manage accounts
    Account {
        #[command(subcommand)]
        command: AccountCommands,
    },
    
    /// Manage validator operations
    Validator {
        #[command(subcommand)]
        command: ValidatorCommands,
    },
    
    /// Mining operations
    Mining {
        #[command(subcommand)]
        command: MiningCommands,
    },
    
    /// Manage the node's configuration
    Config {
        #[command(subcommand)]
        command: ConfigCommands,
    },
    
    /// Generate genesis block for test network
    Genesis {
        /// Output file for genesis block
        #[arg(short, long)]
        output: PathBuf,
        
        /// Initial validators (comma-separated addresses)
        #[arg(long)]
        validators: Option<String>,
        
        /// Initial token distribution (address:amount pairs)
        #[arg(long)]
        balances: Option<String>,
        
        /// Chain ID
        #[arg(long, default_value = "nym-testnet")]
        chain_id: String,
    },
}

#[derive(Subcommand)]
pub enum AccountCommands {
    /// Create a new account
    New {
        /// Use specific QuID identity
        #[arg(long)]
        quid_identity: Option<PathBuf>,
    },
    
    /// List accounts
    List,
    
    /// Show account balance
    Balance {
        /// Account address
        address: Option<String>,
    },
    
    /// Import account from file
    Import {
        /// Path to account file
        path: PathBuf,
    },
    
    /// Export account to file
    Export {
        /// Account address
        address: String,
        
        /// Output path
        #[arg(short, long)]
        output: PathBuf,
    },
}

#[derive(Subcommand)]
pub enum ValidatorCommands {
    /// Register as validator
    Register {
        /// Amount to stake
        #[arg(long)]
        stake: u64,
        
        /// Commission rate (0-100)
        #[arg(long)]
        commission: u8,
    },
    
    /// Deregister as validator
    Deregister,
    
    /// Show validator info
    Info {
        /// Validator address (defaults to self)
        address: Option<String>,
    },
    
    /// Delegate stake to validator
    Delegate {
        /// Validator address
        validator: String,
        
        /// Amount to delegate
        amount: u64,
    },
    
    /// Undelegate stake
    Undelegate {
        /// Validator address
        validator: String,
        
        /// Amount to undelegate
        amount: u64,
    },
}

#[derive(Subcommand)]
pub enum MiningCommands {
    /// Start mining
    Start {
        /// Number of threads to use
        #[arg(short, long)]
        threads: Option<usize>,
        
        /// Mining address (defaults to primary account)
        #[arg(long)]
        address: Option<String>,
    },
    
    /// Stop mining
    Stop,
    
    /// Show mining statistics
    Stats {
        /// Show detailed statistics
        #[arg(short, long)]
        verbose: bool,
    },
}

#[derive(Subcommand)]
pub enum ConfigCommands {
    /// Show current configuration
    Show {
        /// Show specific section only
        #[arg(short, long)]
        section: Option<String>,
    },
    
    /// Set configuration value
    Set {
        /// Configuration key (e.g., network.max_peers)
        key: String,
        
        /// Value to set
        value: String,
    },
    
    /// Get configuration value
    Get {
        /// Configuration key
        key: String,
    },
    
    /// Reset configuration to defaults
    Reset {
        /// Confirm reset
        #[arg(long)]
        confirm: bool,
    },
    
    /// Validate configuration
    Validate,
}

pub fn parse_args() -> Cli {
    Cli::parse()
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_cli_parsing() {
        let args = vec!["nym-node", "status"];
        let cli = Cli::parse_from(args);
        
        match cli.command {
            Commands::Status { .. } => {},
            _ => panic!("Expected Status command"),
        }
    }
    
    #[test]
    fn test_init_command() {
        let args = vec!["nym-node", "init", "--testnet"];
        let cli = Cli::parse_from(args);
        
        match cli.command {
            Commands::Init { testnet, .. } => {
                assert!(testnet);
            },
            _ => panic!("Expected Init command"),
        }
    }
}