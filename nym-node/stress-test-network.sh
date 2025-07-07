#!/usr/bin/env bash

# Comprehensive Network Stress Testing System
# Tests the Nym network with 1000+ nodes and high transaction loads

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

# Configuration
MAX_NODES=1000
TRANSACTIONS_PER_SECOND=500
TEST_DURATION_MINUTES=30
LOG_DIR="$SCRIPT_DIR/stress-test-logs"
RESULTS_DIR="$SCRIPT_DIR/stress-test-results"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                     NYM NETWORK STRESS TEST                     ║${NC}"
    echo -e "${BLUE}║                  Comprehensive Load Testing                     ║${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

print_status() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

print_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

setup_test_environment() {
    print_status "Setting up stress test environment..."
    
    # Create directories
    mkdir -p "$LOG_DIR" "$RESULTS_DIR"
    
    # Clean up any existing test nodes
    pkill -f "nym-node" || true
    sleep 2
    
    # Build the latest version
    print_status "Building Nym node..."
    cd "$PROJECT_ROOT"
    cargo build --release --package nym-node
    
    if [ ! -f "$PROJECT_ROOT/target/release/nym-node" ]; then
        print_error "Failed to build nym-node"
        exit 1
    fi
    
    print_status "Test environment setup complete"
}

generate_node_configs() {
    local num_nodes=$1
    print_status "Generating configurations for $num_nodes nodes..."
    
    local config_dir="$SCRIPT_DIR/stress-test-configs"
    mkdir -p "$config_dir"
    
    for i in $(seq 0 $((num_nodes-1))); do
        local node_dir="$config_dir/node$i"
        mkdir -p "$node_dir"
        
        local p2p_port=$((30000 + i))
        local rpc_port=$((9000 + i))
        
        cat > "$node_dir/config.toml" << EOF
[node]
node_id = "node$i"
data_dir = "$node_dir/data"

[network]
p2p_port = $p2p_port
rpc_port = $rpc_port
bootstrap_peers = []

[consensus]
type = "hybrid"
pow_weight = 0.5
pos_weight = 0.5

[performance]
max_connections = 1000
connection_timeout_ms = 5000
enable_metrics = true

[stress_test]
enable_high_throughput = true
max_transactions_per_second = 1000
EOF
        
        # Add bootstrap peers for first 10 nodes
        if [ $i -lt 10 ] && [ $i -gt 0 ]; then
            echo "bootstrap_peers = [\"127.0.0.1:30000\"]" >> "$node_dir/config.toml"
        fi
    done
    
    print_status "Node configurations generated"
}

start_bootstrap_nodes() {
    print_status "Starting bootstrap nodes..."
    
    local config_dir="$SCRIPT_DIR/stress-test-configs"
    local bootstrap_count=10
    
    for i in $(seq 0 $((bootstrap_count-1))); do
        local node_dir="$config_dir/node$i"
        local log_file="$LOG_DIR/node$i.log"
        
        print_status "Starting bootstrap node $i..."
        
        "$PROJECT_ROOT/target/release/nym-node" \
            --config "$node_dir/config.toml" \
            --log-level info \
            > "$log_file" 2>&1 &
        
        local node_pid=$!
        echo $node_pid > "$LOG_DIR/node$i.pid"
        
        # Wait a bit between bootstrap nodes
        sleep 1
    done
    
    # Wait for bootstrap nodes to be ready
    sleep 10
    print_status "Bootstrap nodes started and ready"
}

start_stress_nodes() {
    local start_index=$1
    local end_index=$2
    print_status "Starting stress nodes $start_index to $end_index..."
    
    local config_dir="$SCRIPT_DIR/stress-test-configs"
    
    for i in $(seq $start_index $end_index); do
        local node_dir="$config_dir/node$i"
        local log_file="$LOG_DIR/node$i.log"
        
        if [ $((i % 50)) -eq 0 ]; then
            print_status "Starting node $i..."
        fi
        
        "$PROJECT_ROOT/target/release/nym-node" \
            --config "$node_dir/config.toml" \
            --log-level warn \
            > "$log_file" 2>&1 &
        
        local node_pid=$!
        echo $node_pid > "$LOG_DIR/node$i.pid"
        
        # Brief pause to avoid overwhelming the system
        if [ $((i % 10)) -eq 0 ]; then
            sleep 1
        fi
    done
    
    print_status "Stress nodes $start_index-$end_index started"
}

generate_transaction_load() {
    local tps=$1
    local duration_seconds=$2
    print_status "Generating $tps TPS for $duration_seconds seconds..."
    
    local total_transactions=$((tps * duration_seconds))
    local interval=$(echo "scale=3; 1 / $tps" | bc)
    
    print_status "Total transactions to generate: $total_transactions"
    print_status "Transaction interval: ${interval}s"
    
    # Create transaction generator script
    cat > "$SCRIPT_DIR/transaction_generator.sh" << 'EOF'
#!/usr/bin/env bash

TPS=$1
DURATION=$2
RPC_PORTS=($(seq 9000 9009))  # Use first 10 nodes for RPC
TOTAL_TRANSACTIONS=$((TPS * DURATION))

generate_transaction() {
    local rpc_port=${RPC_PORTS[$RANDOM % ${#RPC_PORTS[@]}]}
    local tx_data=$(openssl rand -hex 32)
    
    curl -s -X POST \
        -H "Content-Type: application/json" \
        -d "{\"jsonrpc\":\"2.0\",\"method\":\"submit_transaction\",\"params\":{\"data\":\"$tx_data\"},\"id\":1}" \
        "http://127.0.0.1:$rpc_port" \
        > /dev/null 2>&1 || true
}

for i in $(seq 1 $TOTAL_TRANSACTIONS); do
    generate_transaction &
    
    if [ $((i % TPS)) -eq 0 ]; then
        wait  # Wait for current batch to complete
        if [ $((i % (TPS * 10))) -eq 0 ]; then
            echo "Generated $i transactions..."
        fi
        sleep 1
    fi
done

wait
echo "Transaction generation complete: $TOTAL_TRANSACTIONS transactions"
EOF
    
    chmod +x "$SCRIPT_DIR/transaction_generator.sh"
    
    # Run transaction generator in background
    "$SCRIPT_DIR/transaction_generator.sh" $tps $duration_seconds > "$LOG_DIR/transaction_generator.log" 2>&1 &
    echo $! > "$LOG_DIR/transaction_generator.pid"
}

monitor_network_health() {
    local monitor_duration=$1
    print_status "Monitoring network health for $monitor_duration seconds..."
    
    local monitor_file="$RESULTS_DIR/network_health.json"
    local start_time=$(date +%s)
    local end_time=$((start_time + monitor_duration))
    
    # Initialize monitoring data
    echo '{"monitoring_sessions": []}' > "$monitor_file"
    
    local session_count=0
    while [ $(date +%s) -lt $end_time ]; do
        local current_time=$(date +%s)
        local elapsed=$((current_time - start_time))
        
        # Collect metrics from active nodes
        local active_nodes=0
        local total_connections=0
        local total_transactions=0
        local memory_usage=0
        local cpu_usage=0
        
        # Count active node processes
        active_nodes=$(pgrep -f "nym-node" | wc -l)
        
        # Sample CPU and memory usage
        if command -v ps >/dev/null 2>&1; then
            local node_pids=$(pgrep -f "nym-node" | head -10)  # Sample first 10 nodes
            if [ -n "$node_pids" ]; then
                memory_usage=$(ps -o rss= -p $node_pids | awk '{sum+=$1} END {print sum/1024}' 2>/dev/null || echo "0")
                cpu_usage=$(ps -o %cpu= -p $node_pids | awk '{sum+=$1} END {print sum}' 2>/dev/null || echo "0")
            fi
        fi
        
        # Try to get network metrics from one of the nodes
        local network_stats="{\"connections\": 0, \"transactions\": 0}"
        if command -v curl >/dev/null 2>&1; then
            network_stats=$(curl -s -X POST \
                -H "Content-Type: application/json" \
                -d '{"jsonrpc":"2.0","method":"get_network_stats","params":{},"id":1}' \
                "http://127.0.0.1:9000" 2>/dev/null | jq -r '.result // {"connections": 0, "transactions": 0}' 2>/dev/null || echo '{"connections": 0, "transactions": 0}')
        fi
        
        # Create monitoring session
        local session=$(cat << EOF
{
    "session_id": $session_count,
    "timestamp": "$current_time",
    "elapsed_seconds": $elapsed,
    "active_nodes": $active_nodes,
    "memory_usage_mb": $memory_usage,
    "cpu_usage_percent": $cpu_usage,
    "network_stats": $network_stats
}
EOF
)
        
        # Append to monitoring file
        jq ".monitoring_sessions += [$session]" "$monitor_file" > "${monitor_file}.tmp" && mv "${monitor_file}.tmp" "$monitor_file"
        
        session_count=$((session_count + 1))
        
        # Print status every 30 seconds
        if [ $((elapsed % 30)) -eq 0 ]; then
            print_status "Monitoring: ${elapsed}s elapsed, $active_nodes nodes active, ${memory_usage}MB memory, ${cpu_usage}% CPU"
        fi
        
        sleep 5
    done
    
    print_status "Network health monitoring complete"
}

analyze_performance() {
    print_status "Analyzing network performance..."
    
    local analysis_file="$RESULTS_DIR/performance_analysis.json"
    
    # Get final counts
    local total_nodes=$(find "$LOG_DIR" -name "node*.pid" | wc -l)
    local active_nodes=$(pgrep -f "nym-node" | wc -l || echo "0")
    local failed_nodes=$((total_nodes - active_nodes))
    
    # Analyze logs for errors and performance
    local total_errors=0
    local connection_errors=0
    local consensus_errors=0
    
    if [ -d "$LOG_DIR" ]; then
        total_errors=$(grep -r "ERROR" "$LOG_DIR"/*.log 2>/dev/null | wc -l || echo "0")
        connection_errors=$(grep -r "connection.*failed\|connection.*error" "$LOG_DIR"/*.log 2>/dev/null | wc -l || echo "0")
        consensus_errors=$(grep -r "consensus.*error\|consensus.*failed" "$LOG_DIR"/*.log 2>/dev/null | wc -l || echo "0")
    fi
    
    # Transaction analysis
    local transaction_log="$LOG_DIR/transaction_generator.log"
    local generated_transactions=0
    local transaction_errors=0
    
    if [ -f "$transaction_log" ]; then
        generated_transactions=$(grep -c "Generated.*transactions" "$transaction_log" 2>/dev/null || echo "0")
        transaction_errors=$(grep -c "error\|failed" "$transaction_log" 2>/dev/null || echo "0")
    fi
    
    # Calculate success rates
    local node_success_rate=0
    local transaction_success_rate=0
    
    if [ $total_nodes -gt 0 ]; then
        node_success_rate=$(echo "scale=2; $active_nodes * 100 / $total_nodes" | bc 2>/dev/null || echo "0")
    fi
    
    if [ $generated_transactions -gt 0 ]; then
        local successful_transactions=$((generated_transactions - transaction_errors))
        transaction_success_rate=$(echo "scale=2; $successful_transactions * 100 / $generated_transactions" | bc 2>/dev/null || echo "0")
    fi
    
    # Create analysis report
    cat > "$analysis_file" << EOF
{
    "test_summary": {
        "test_date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
        "test_duration_minutes": $TEST_DURATION_MINUTES,
        "target_nodes": $MAX_NODES,
        "target_tps": $TRANSACTIONS_PER_SECOND
    },
    "node_performance": {
        "total_nodes_started": $total_nodes,
        "nodes_remaining_active": $active_nodes,
        "failed_nodes": $failed_nodes,
        "node_success_rate": "$node_success_rate%"
    },
    "transaction_performance": {
        "transactions_generated": $generated_transactions,
        "transaction_errors": $transaction_errors,
        "transaction_success_rate": "$transaction_success_rate%"
    },
    "error_analysis": {
        "total_errors": $total_errors,
        "connection_errors": $connection_errors,
        "consensus_errors": $consensus_errors
    },
    "network_health": {
        "monitoring_data": "See network_health.json for detailed metrics"
    }
}
EOF
    
    print_status "Performance analysis complete"
}

cleanup_test_environment() {
    print_status "Cleaning up test environment..."
    
    # Stop transaction generator
    if [ -f "$LOG_DIR/transaction_generator.pid" ]; then
        local tx_pid=$(cat "$LOG_DIR/transaction_generator.pid")
        kill $tx_pid 2>/dev/null || true
    fi
    
    # Stop all nodes
    if [ -d "$LOG_DIR" ]; then
        for pid_file in "$LOG_DIR"/node*.pid; do
            if [ -f "$pid_file" ]; then
                local pid=$(cat "$pid_file")
                kill $pid 2>/dev/null || true
            fi
        done
    fi
    
    # Force kill any remaining nym-node processes
    pkill -f "nym-node" || true
    
    # Wait for cleanup
    sleep 5
    
    # Remove PID files
    rm -f "$LOG_DIR"/*.pid
    
    print_status "Cleanup complete"
}

generate_final_report() {
    print_status "Generating final test report..."
    
    local report_file="$RESULTS_DIR/stress_test_report.md"
    
    cat > "$report_file" << EOF
# Nym Network Stress Test Report

**Test Date:** $(date -u +%Y-%m-%d\ %H:%M:%S\ UTC)  
**Test Duration:** $TEST_DURATION_MINUTES minutes  
**Target Configuration:** $MAX_NODES nodes, $TRANSACTIONS_PER_SECOND TPS  

## Test Overview

This stress test evaluated the Nym network's performance under high load conditions with:
- Large-scale node deployment ($MAX_NODES nodes)
- High transaction throughput ($TRANSACTIONS_PER_SECOND TPS)
- Extended duration testing ($TEST_DURATION_MINUTES minutes)

## Results Summary

### Node Performance
EOF
    
    if [ -f "$RESULTS_DIR/performance_analysis.json" ]; then
        local analysis=$(cat "$RESULTS_DIR/performance_analysis.json")
        local total_nodes=$(echo "$analysis" | jq -r '.node_performance.total_nodes_started // 0')
        local active_nodes=$(echo "$analysis" | jq -r '.node_performance.nodes_remaining_active // 0')
        local success_rate=$(echo "$analysis" | jq -r '.node_performance.node_success_rate // "0%"')
        
        cat >> "$report_file" << EOF
- **Total nodes started:** $total_nodes
- **Nodes remaining active:** $active_nodes  
- **Node success rate:** $success_rate

### Transaction Performance
EOF
        
        local transactions=$(echo "$analysis" | jq -r '.transaction_performance.transactions_generated // 0')
        local tx_success_rate=$(echo "$analysis" | jq -r '.transaction_performance.transaction_success_rate // "0%"')
        
        cat >> "$report_file" << EOF
- **Transactions generated:** $transactions
- **Transaction success rate:** $tx_success_rate

### Error Analysis
EOF
        
        local total_errors=$(echo "$analysis" | jq -r '.error_analysis.total_errors // 0')
        local connection_errors=$(echo "$analysis" | jq -r '.error_analysis.connection_errors // 0')
        
        cat >> "$report_file" << EOF
- **Total errors:** $total_errors
- **Connection errors:** $connection_errors

## Conclusion

The stress test $(if [ "$success_rate" != "0%" ] && [ "${success_rate%\%}" -gt 80 ]; then echo "PASSED"; else echo "NEEDS IMPROVEMENT"; fi) with the network demonstrating $(if [ "${success_rate%\%}" -gt 80 ]; then echo "strong resilience"; else echo "areas for optimization"; fi) under load.

## Files Generated

- \`performance_analysis.json\` - Detailed performance metrics
- \`network_health.json\` - Real-time monitoring data  
- \`stress-test-logs/\` - Individual node logs
- \`stress-test-configs/\` - Node configurations used

EOF
    else
        cat >> "$report_file" << EOF
- **Status:** Test data not available

## Files Generated

- Check \`stress-test-results/\` directory for available data files
- Check \`stress-test-logs/\` directory for node logs

EOF
    fi
    
    print_status "Final report generated: $report_file"
}

main() {
    print_header
    
    print_status "Starting comprehensive Nym network stress test"
    print_status "Configuration: $MAX_NODES nodes, $TRANSACTIONS_PER_SECOND TPS, ${TEST_DURATION_MINUTES}min duration"
    
    # Check dependencies
    if ! command -v bc >/dev/null 2>&1; then
        print_error "bc calculator is required but not installed"
        exit 1
    fi
    
    trap cleanup_test_environment EXIT
    
    # Main test phases
    setup_test_environment
    generate_node_configs $MAX_NODES
    start_bootstrap_nodes
    
    # Start nodes in batches to avoid overwhelming the system
    local batch_size=100
    local current_batch=10  # Start after bootstrap nodes
    
    while [ $current_batch -lt $MAX_NODES ]; do
        local batch_end=$((current_batch + batch_size - 1))
        if [ $batch_end -gt $((MAX_NODES - 1)) ]; then
            batch_end=$((MAX_NODES - 1))
        fi
        
        start_stress_nodes $current_batch $batch_end
        
        # Wait between batches
        sleep 10
        current_batch=$((batch_end + 1))
    done
    
    # Wait for network to stabilize
    print_status "Waiting for network to stabilize..."
    sleep 30
    
    # Start transaction load and monitoring
    local test_duration_seconds=$((TEST_DURATION_MINUTES * 60))
    generate_transaction_load $TRANSACTIONS_PER_SECOND $test_duration_seconds &
    monitor_network_health $test_duration_seconds
    
    # Wait for transaction generator to complete
    wait
    
    # Analyze results
    analyze_performance
    generate_final_report
    
    print_status "Stress test completed successfully!"
    print_status "Results available in: $RESULTS_DIR"
    
    # Show summary
    if [ -f "$RESULTS_DIR/performance_analysis.json" ]; then
        echo
        print_status "=== TEST SUMMARY ==="
        local analysis=$(cat "$RESULTS_DIR/performance_analysis.json")
        echo "Nodes: $(echo "$analysis" | jq -r '.node_performance.nodes_remaining_active // 0')/$(echo "$analysis" | jq -r '.node_performance.total_nodes_started // 0') active"
        echo "Success Rate: $(echo "$analysis" | jq -r '.node_performance.node_success_rate // "0%"')"
        echo "Transactions: $(echo "$analysis" | jq -r '.transaction_performance.transactions_generated // 0') generated"
        echo "Transaction Success: $(echo "$analysis" | jq -r '.transaction_performance.transaction_success_rate // "0%"')"
    fi
}

# Script execution
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
    main "$@"
fi