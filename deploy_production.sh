#!/bin/bash

# Nym Blockchain Production Deployment Script
# Automated deployment for mainnet nodes with security and performance optimization

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NODE_HOME="${NODE_HOME:-$HOME/.nym}"
CHAIN_ID="${CHAIN_ID:-nym-mainnet-1}"
MONIKER="${MONIKER:-nym-node}"
NODE_TYPE="${NODE_TYPE:-validator}"  # validator, full, light
NETWORK_TYPE="${NETWORK_TYPE:-mainnet}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging
LOG_FILE="${NODE_HOME}/deployment.log"
mkdir -p "$(dirname "$LOG_FILE")"

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $*" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[ERROR]${NC} $*" | tee -a "$LOG_FILE"
    exit 1
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $*" | tee -a "$LOG_FILE"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $*" | tee -a "$LOG_FILE"
}

# Pre-deployment checks
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if running as root (should not be)
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root for security reasons"
    fi
    
    # Check system requirements
    local available_memory=$(free -m | awk 'NR==2{print $7}')
    if [[ $available_memory -lt 8192 ]]; then
        warning "Available memory ($available_memory MB) is less than recommended 8GB"
    fi
    
    local available_disk=$(df -m "$HOME" | awk 'NR==2{print $4}')
    if [[ $available_disk -lt 102400 ]]; then
        warning "Available disk space ($available_disk MB) is less than recommended 100GB"
    fi
    
    # Check if required tools are installed
    for tool in curl wget jq; do
        if ! command -v "$tool" &> /dev/null; then
            error "$tool is required but not installed"
        fi
    done
    
    success "Prerequisites check completed"
}

# Security setup
setup_security() {
    log "Setting up security measures..."
    
    # Create secure directories
    mkdir -p "$NODE_HOME"/{config,data,keys,logs,backups}
    chmod 700 "$NODE_HOME"
    chmod 700 "$NODE_HOME"/keys
    
    # Set up firewall rules (if ufw is available)
    if command -v ufw &> /dev/null; then
        log "Configuring firewall..."
        sudo ufw --force reset
        sudo ufw default deny incoming
        sudo ufw default allow outgoing
        
        # Allow SSH
        sudo ufw allow ssh
        
        # Allow Nym node ports
        sudo ufw allow 26656/tcp comment "Nym P2P"
        sudo ufw allow 26657/tcp comment "Nym RPC"
        
        # Allow monitoring port (restrict to specific IPs in production)
        sudo ufw allow 8080/tcp comment "Metrics"
        
        sudo ufw --force enable
    fi
    
    # Setup fail2ban if available
    if command -v fail2ban-client &> /dev/null; then
        log "Configuring fail2ban..."
        sudo systemctl enable fail2ban
        sudo systemctl start fail2ban
    fi
    
    success "Security setup completed"
}

# Build and install node
build_node() {
    log "Building Nym node..."
    
    # Build optimized release version
    cd "$SCRIPT_DIR"
    
    # Clean previous builds
    cargo clean
    
    # Build with security and performance optimizations
    RUSTFLAGS="-C target-cpu=native -C opt-level=3 -C lto=fat -C codegen-units=1" \
    cargo build --release --bin nym-node --features "production,security-audit"
    
    # Install binary
    sudo cp target/release/nym-node /usr/local/bin/
    sudo chmod +x /usr/local/bin/nym-node
    
    # Verify installation
    nym-node version
    
    success "Node build and installation completed"
}

# Initialize node configuration
initialize_node() {
    log "Initializing node configuration..."
    
    # Initialize node
    nym-node init \
        --chain-id "$CHAIN_ID" \
        --moniker "$MONIKER" \
        --home "$NODE_HOME"
    
    # Copy production configuration
    cp "$SCRIPT_DIR/production_config.toml" "$NODE_HOME/config/config.toml"
    
    # Download genesis file
    case "$NETWORK_TYPE" in
        mainnet)
            wget -O "$NODE_HOME/config/genesis.json" \
                "https://raw.githubusercontent.com/nymverse/mainnet/main/genesis.json"
            ;;
        testnet)
            wget -O "$NODE_HOME/config/genesis.json" \
                "https://raw.githubusercontent.com/nymverse/testnet/main/genesis.json"
            ;;
        *)
            error "Unknown network type: $NETWORK_TYPE"
            ;;
    esac
    
    # Validate genesis file
    nym-node validate-genesis --home "$NODE_HOME"
    
    # Configure node-specific settings
    configure_node_type
    
    success "Node initialization completed"
}

# Configure based on node type
configure_node_type() {
    log "Configuring node for type: $NODE_TYPE"
    
    case "$NODE_TYPE" in
        validator)
            configure_validator
            ;;
        full)
            configure_full_node
            ;;
        light)
            configure_light_node
            ;;
        *)
            error "Unknown node type: $NODE_TYPE"
            ;;
    esac
}

configure_validator() {
    log "Configuring validator node..."
    
    # Generate validator key
    nym-node keys add validator \
        --home "$NODE_HOME" \
        --keyring-backend file
    
    # Configure validator-specific settings
    cat >> "$NODE_HOME/config/config.toml" << EOF

[validator]
enabled = true
commission_rate = 0.05
max_commission_rate = 0.20
max_commission_change_rate = 0.01
min_self_delegation = "1000000"

[staking]
auto_compound = true
compound_frequency = "24h"

EOF
    
    warning "IMPORTANT: Backup your validator key securely!"
    warning "Key location: $NODE_HOME/config/priv_validator_key.json"
}

configure_full_node() {
    log "Configuring full node..."
    
    # Configure full node settings
    cat >> "$NODE_HOME/config/config.toml" << EOF

[sync]
fast_sync = true
state_sync_enabled = false
snapshot_enabled = true

[indexer]
enabled = true
index_all_keys = true

EOF
}

configure_light_node() {
    log "Configuring light node..."
    
    # Configure light node settings
    cat >> "$NODE_HOME/config/config.toml" << EOF

[sync]
fast_sync = true
state_sync_enabled = true
light_client_mode = true

[storage]
pruning = "everything"

EOF
}

# Setup monitoring and logging
setup_monitoring() {
    log "Setting up monitoring and logging..."
    
    # Create log rotation configuration
    sudo tee /etc/logrotate.d/nym-node << EOF
$NODE_HOME/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 644 $(whoami) $(whoami)
    postrotate
        systemctl reload nym-node || true
    endscript
}
EOF
    
    # Setup metrics collection
    mkdir -p "$NODE_HOME/metrics"
    
    # Configure Prometheus (if available)
    if command -v prometheus &> /dev/null; then
        log "Configuring Prometheus monitoring..."
        
        cat > "$NODE_HOME/metrics/prometheus.yml" << EOF
global:
  scrape_interval: 15s
  evaluation_interval: 15s

scrape_configs:
  - job_name: 'nym-node'
    static_configs:
      - targets: ['localhost:8080']
    scrape_interval: 5s
    metrics_path: /metrics

EOF
    fi
    
    success "Monitoring and logging setup completed"
}

# Create systemd service
create_systemd_service() {
    log "Creating systemd service..."
    
    sudo tee /etc/systemd/system/nym-node.service << EOF
[Unit]
Description=Nym Blockchain Node
After=network.target
Wants=network.target

[Service]
Type=simple
User=$(whoami)
Group=$(whoami)
WorkingDirectory=$NODE_HOME
ExecStart=/usr/local/bin/nym-node start --home $NODE_HOME
ExecReload=/bin/kill -HUP \$MAINPID
Restart=always
RestartSec=10
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal
SyslogIdentifier=nym-node

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ReadWritePaths=$NODE_HOME
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true

# Resource limits
MemoryMax=8G
CPUQuota=400%

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable nym-node
    
    success "Systemd service created and enabled"
}

# Setup backup system
setup_backup() {
    log "Setting up backup system..."
    
    # Create backup script
    cat > "$NODE_HOME/backup.sh" << 'EOF'
#!/bin/bash

BACKUP_DIR="$NODE_HOME/backups"
DATE=$(date +"%Y%m%d_%H%M%S")
BACKUP_FILE="$BACKUP_DIR/nym_backup_$DATE.tar.gz"

# Create backup directory
mkdir -p "$BACKUP_DIR"

# Stop node for consistent backup
systemctl stop nym-node

# Create backup
tar -czf "$BACKUP_FILE" \
    -C "$NODE_HOME" \
    config/ \
    data/ \
    keys/

# Restart node
systemctl start nym-node

# Clean old backups (keep last 7 days)
find "$BACKUP_DIR" -name "nym_backup_*.tar.gz" -mtime +7 -delete

echo "Backup completed: $BACKUP_FILE"
EOF

    chmod +x "$NODE_HOME/backup.sh"
    
    # Add cron job for daily backups
    (crontab -l 2>/dev/null; echo "0 2 * * * $NODE_HOME/backup.sh") | crontab -
    
    success "Backup system configured"
}

# Performance optimization
optimize_performance() {
    log "Applying performance optimizations..."
    
    # System optimizations
    cat >> /tmp/nym_sysctl.conf << EOF
# Network optimizations
net.core.rmem_max = 134217728
net.core.wmem_max = 134217728
net.ipv4.tcp_rmem = 4096 87380 134217728
net.ipv4.tcp_wmem = 4096 65536 134217728
net.core.netdev_max_backlog = 5000

# File system optimizations
vm.swappiness = 10
vm.dirty_ratio = 20
vm.dirty_background_ratio = 5

# Memory optimizations
vm.overcommit_memory = 1
EOF

    sudo cp /tmp/nym_sysctl.conf /etc/sysctl.d/99-nym.conf
    sudo sysctl -p /etc/sysctl.d/99-nym.conf
    
    # RocksDB optimizations
    mkdir -p "$NODE_HOME/config/db"
    cat > "$NODE_HOME/config/db/rocksdb.conf" << EOF
# RocksDB performance configuration
max_open_files=-1
max_file_opening_threads=16
max_background_jobs=4
max_subcompactions=4
max_write_buffer_number=4
write_buffer_size=134217728
target_file_size_base=67108864
level0_file_num_compaction_trigger=4
level0_slowdown_writes_trigger=20
level0_stop_writes_trigger=36
EOF
    
    success "Performance optimizations applied"
}

# Security hardening
security_hardening() {
    log "Applying security hardening..."
    
    # Set proper file permissions
    find "$NODE_HOME" -type f -exec chmod 600 {} \;
    find "$NODE_HOME" -type d -exec chmod 700 {} \;
    
    # Secure key files
    chmod 400 "$NODE_HOME"/config/priv_validator_key.json 2>/dev/null || true
    chmod 400 "$NODE_HOME"/config/node_key.json 2>/dev/null || true
    
    # Setup key backup
    if [[ -f "$NODE_HOME/config/priv_validator_key.json" ]]; then
        cp "$NODE_HOME/config/priv_validator_key.json" "$NODE_HOME/keys/priv_validator_key.backup"
        chmod 400 "$NODE_HOME/keys/priv_validator_key.backup"
        warning "Validator key backed up to: $NODE_HOME/keys/priv_validator_key.backup"
        warning "Store this backup securely offline!"
    fi
    
    success "Security hardening completed"
}

# Pre-flight checks
preflight_checks() {
    log "Running pre-flight checks..."
    
    # Check configuration syntax
    nym-node validate-config --home "$NODE_HOME"
    
    # Check genesis file
    nym-node validate-genesis --home "$NODE_HOME"
    
    # Check network connectivity
    if ! ping -c 3 8.8.8.8 &> /dev/null; then
        warning "Internet connectivity check failed"
    fi
    
    # Check available disk space
    local available_space=$(df -BG "$NODE_HOME" | awk 'NR==2{gsub(/G/,"",$4); print $4}')
    if [[ $available_space -lt 50 ]]; then
        warning "Low disk space: ${available_space}GB available"
    fi
    
    # Test node startup (dry run)
    log "Testing node startup..."
    timeout 30s nym-node start --home "$NODE_HOME" --check-config || true
    
    success "Pre-flight checks completed"
}

# Main deployment function
deploy() {
    log "Starting Nym Blockchain Production Deployment"
    log "============================================="
    log "Node Type: $NODE_TYPE"
    log "Network: $NETWORK_TYPE"
    log "Chain ID: $CHAIN_ID"
    log "Moniker: $MONIKER"
    log "Home Directory: $NODE_HOME"
    log ""
    
    # Run deployment steps
    check_prerequisites
    setup_security
    build_node
    initialize_node
    setup_monitoring
    create_systemd_service
    setup_backup
    optimize_performance
    security_hardening
    preflight_checks
    
    log ""
    log "🎉 Deployment completed successfully!"
    log ""
    log "Next steps:"
    log "1. Start the node: sudo systemctl start nym-node"
    log "2. Check status: sudo systemctl status nym-node"
    log "3. View logs: sudo journalctl -u nym-node -f"
    log "4. Monitor: http://localhost:8080/metrics"
    log ""
    
    if [[ "$NODE_TYPE" == "validator" ]]; then
        log "Validator setup:"
        log "1. Fund your validator address with NYM tokens"
        log "2. Create validator: nym-node tx staking create-validator"
        log "3. Backup validator key: $NODE_HOME/keys/priv_validator_key.backup"
        log ""
    fi
    
    log "Configuration files:"
    log "- Node config: $NODE_HOME/config/config.toml"
    log "- Genesis: $NODE_HOME/config/genesis.json"
    log "- Logs: $NODE_HOME/logs/"
    log "- Backups: $NODE_HOME/backups/"
    log ""
    
    warning "IMPORTANT: Secure your validator keys and backup files!"
    success "Nym node is ready for production!"
}

# Handle command line arguments
case "${1:-deploy}" in
    deploy)
        deploy
        ;;
    check)
        check_prerequisites
        ;;
    security)
        setup_security
        security_hardening
        ;;
    monitor)
        setup_monitoring
        ;;
    backup)
        setup_backup
        ;;
    *)
        echo "Usage: $0 [deploy|check|security|monitor|backup]"
        echo ""
        echo "Commands:"
        echo "  deploy   - Full production deployment (default)"
        echo "  check    - Check prerequisites only"
        echo "  security - Setup security measures only"
        echo "  monitor  - Setup monitoring only"
        echo "  backup   - Setup backup system only"
        echo ""
        echo "Environment variables:"
        echo "  NODE_HOME - Node data directory (default: ~/.nym)"
        echo "  CHAIN_ID  - Chain identifier (default: nym-mainnet-1)"
        echo "  MONIKER   - Node name (default: nym-node)"
        echo "  NODE_TYPE - Node type: validator|full|light (default: validator)"
        echo "  NETWORK_TYPE - Network: mainnet|testnet (default: mainnet)"
        exit 1
        ;;
esac