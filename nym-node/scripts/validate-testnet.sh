#!/bin/bash

# Nym Testnet Validation Script
# This script validates the deployed testnet for proper functionality

set -e

TESTNET_DIR="./testnet"
NUM_NODES=3
RPC_BASE_PORT=9933

echo "🔍 Validating Nym Testnet..."
echo "================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Helper functions
print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

print_error() {
    echo -e "${RED}❌ $1${NC}"
}

print_warning() {
    echo -e "${YELLOW}⚠️  $1${NC}"
}

print_info() {
    echo -e "${BLUE}ℹ️  $1${NC}"
}

# Check if testnet directory exists
if [ ! -d "$TESTNET_DIR" ]; then
    print_error "Testnet directory not found. Run ./setup-testnet.sh first."
    exit 1
fi

print_info "Testnet directory found"

# Test 1: Check if all nodes are running
echo ""
echo "Test 1: Node Status Check"
echo "-------------------------"

all_nodes_running=true
for i in $(seq 0 $((NUM_NODES-1))); do
    pid_file="$TESTNET_DIR/node$i/node.pid"
    rpc_port=$((RPC_BASE_PORT + i))
    
    if [ -f "$pid_file" ]; then
        pid=$(cat "$pid_file")
        if kill -0 "$pid" 2>/dev/null; then
            print_success "Node $i is running (PID: $pid)"
        else
            print_error "Node $i process not found"
            all_nodes_running=false
        fi
    else
        print_error "Node $i PID file not found"
        all_nodes_running=false
    fi
done

if [ "$all_nodes_running" = true ]; then
    print_success "All nodes are running"
else
    print_error "Some nodes are not running"
    exit 1
fi

# Test 2: RPC Connectivity
echo ""
echo "Test 2: RPC Connectivity"
echo "------------------------"

rpc_all_working=true
for i in $(seq 0 $((NUM_NODES-1))); do
    rpc_port=$((RPC_BASE_PORT + i))
    
    # Test basic connectivity
    if timeout 5 bash -c "echo > /dev/tcp/127.0.0.1/$rpc_port" 2>/dev/null; then
        print_success "Node $i RPC port $rpc_port is accessible"
        
        # Test RPC call (if we implement a simple status endpoint)
        # This would be replaced with actual RPC calls
        if curl -s "http://127.0.0.1:$rpc_port" >/dev/null 2>&1; then
            print_success "Node $i RPC is responding"
        else
            print_warning "Node $i RPC port open but not responding to HTTP"
        fi
    else
        print_error "Node $i RPC port $rpc_port is not accessible"
        rpc_all_working=false
    fi
done

if [ "$rpc_all_working" = true ]; then
    print_success "All RPC endpoints are accessible"
else
    print_warning "Some RPC endpoints have issues"
fi

# Test 3: P2P Connectivity
echo ""
echo "Test 3: P2P Network Connectivity"
echo "--------------------------------"

p2p_base_port=30333
p2p_all_working=true

for i in $(seq 0 $((NUM_NODES-1))); do
    p2p_port=$((p2p_base_port + i))
    
    if timeout 5 bash -c "echo > /dev/tcp/127.0.0.1/$p2p_port" 2>/dev/null; then
        print_success "Node $i P2P port $p2p_port is accessible"
    else
        print_error "Node $i P2P port $p2p_port is not accessible"
        p2p_all_working=false
    fi
done

if [ "$p2p_all_working" = true ]; then
    print_success "All P2P ports are accessible"
else
    print_error "Some P2P ports are not accessible"
fi

# Test 4: Log Analysis
echo ""
echo "Test 4: Log Analysis"
echo "-------------------"

error_count=0
warning_count=0

for i in $(seq 0 $((NUM_NODES-1))); do
    log_file="$TESTNET_DIR/node$i/node.log"
    
    if [ -f "$log_file" ]; then
        # Count errors and warnings in logs
        node_errors=$(grep -i "error" "$log_file" | wc -l || echo "0")
        node_warnings=$(grep -i "warn" "$log_file" | wc -l || echo "0")
        
        error_count=$((error_count + node_errors))
        warning_count=$((warning_count + node_warnings))
        
        if [ "$node_errors" -eq 0 ]; then
            print_success "Node $i has no errors in logs"
        else
            print_warning "Node $i has $node_errors errors in logs"
        fi
        
        if [ "$node_warnings" -le 5 ]; then
            print_success "Node $i has acceptable warning count ($node_warnings)"
        else
            print_warning "Node $i has high warning count ($node_warnings)"
        fi
        
        # Check for specific success indicators
        if grep -q "Node started successfully" "$log_file"; then
            print_success "Node $i started successfully"
        else
            print_warning "Node $i may not have started properly"
        fi
        
    else
        print_error "Node $i log file not found"
    fi
done

echo ""
print_info "Total errors across all nodes: $error_count"
print_info "Total warnings across all nodes: $warning_count"

# Test 5: Genesis Block Validation
echo ""
echo "Test 5: Genesis Block Validation"
echo "--------------------------------"

genesis_file="$TESTNET_DIR/genesis.json"
if [ -f "$genesis_file" ]; then
    print_success "Genesis block file exists"
    
    # Validate JSON format
    if jq empty "$genesis_file" 2>/dev/null; then
        print_success "Genesis block has valid JSON format"
        
        # Check required fields
        chain_id=$(jq -r '.chain_id' "$genesis_file")
        validators=$(jq -r '.initial_validators | length' "$genesis_file")
        
        if [ "$chain_id" != "null" ] && [ -n "$chain_id" ]; then
            print_success "Genesis block has valid chain ID: $chain_id"
        else
            print_error "Genesis block missing chain ID"
        fi
        
        if [ "$validators" -gt 0 ]; then
            print_success "Genesis block has $validators validators"
        else
            print_error "Genesis block has no validators"
        fi
        
    else
        print_error "Genesis block has invalid JSON format"
    fi
else
    print_error "Genesis block file not found"
fi

# Test 6: Configuration Validation
echo ""
echo "Test 6: Configuration Validation"
echo "--------------------------------"

config_all_valid=true
for i in $(seq 0 $((NUM_NODES-1))); do
    config_file="$TESTNET_DIR/node$i/config.toml"
    
    if [ -f "$config_file" ]; then
        print_success "Node $i config file exists"
        
        # Check for required sections
        if grep -q "\\[network\\]" "$config_file"; then
            print_success "Node $i has network configuration"
        else
            print_error "Node $i missing network configuration"
            config_all_valid=false
        fi
        
        if grep -q "\\[consensus\\]" "$config_file"; then
            print_success "Node $i has consensus configuration"
        else
            print_error "Node $i missing consensus configuration"
            config_all_valid=false
        fi
        
        if grep -q "\\[storage\\]" "$config_file"; then
            print_success "Node $i has storage configuration"
        else
            print_error "Node $i missing storage configuration"
            config_all_valid=false
        fi
        
    else
        print_error "Node $i config file not found"
        config_all_valid=false
    fi
done

if [ "$config_all_valid" = true ]; then
    print_success "All node configurations are valid"
else
    print_error "Some node configurations are invalid"
fi

# Test 7: Resource Usage Check
echo ""
echo "Test 7: Resource Usage Check"
echo "----------------------------"

total_cpu=0
total_memory=0

for i in $(seq 0 $((NUM_NODES-1))); do
    pid_file="$TESTNET_DIR/node$i/node.pid"
    
    if [ -f "$pid_file" ]; then
        pid=$(cat "$pid_file")
        
        if kill -0 "$pid" 2>/dev/null; then
            # Get CPU and memory usage (if ps supports it)
            if command -v ps >/dev/null 2>&1; then
                cpu_usage=$(ps -p "$pid" -o %cpu= 2>/dev/null | tr -d ' ' || echo "0")
                mem_usage=$(ps -p "$pid" -o %mem= 2>/dev/null | tr -d ' ' || echo "0")
                
                total_cpu=$(echo "$total_cpu + $cpu_usage" | bc -l 2>/dev/null || echo "$total_cpu")
                total_memory=$(echo "$total_memory + $mem_usage" | bc -l 2>/dev/null || echo "$total_memory")
                
                print_info "Node $i: CPU ${cpu_usage}%, Memory ${mem_usage}%"
            fi
        fi
    fi
done

print_info "Total CPU usage: ${total_cpu}%"
print_info "Total Memory usage: ${total_memory}%"

# Test 8: Network Security Validation
echo ""
echo "Test 8: Network Security Check"
echo "------------------------------"

# Check for open ports that shouldn't be open
print_info "Checking for unexpected open ports..."

# Check if only expected ports are open
expected_ports=""
for i in $(seq 0 $((NUM_NODES-1))); do
    p2p_port=$((30333 + i))
    rpc_port=$((9933 + i))
    expected_ports="$expected_ports $p2p_port $rpc_port"
done

if command -v netstat >/dev/null 2>&1; then
    open_ports=$(netstat -tlnp 2>/dev/null | grep LISTEN | grep -E ":30[0-9]{3}|:99[0-9]{2}" | wc -l)
    expected_count=$((NUM_NODES * 2))  # P2P + RPC per node
    
    if [ "$open_ports" -eq "$expected_count" ]; then
        print_success "Expected number of ports are open ($open_ports)"
    else
        print_warning "Unexpected number of open ports: $open_ports (expected: $expected_count)"
    fi
else
    print_warning "netstat not available, cannot check port status"
fi

# Final Summary
echo ""
echo "🏁 Validation Summary"
echo "===================="

if [ "$all_nodes_running" = true ] && [ "$rpc_all_working" = true ] && [ "$p2p_all_working" = true ] && [ "$config_all_valid" = true ]; then
    print_success "Testnet validation PASSED ✨"
    print_info "Your Nym testnet is running correctly!"
    echo ""
    echo "📊 Quick Stats:"
    echo "   • Nodes running: $NUM_NODES/$NUM_NODES"
    echo "   • Total errors: $error_count"
    echo "   • Total warnings: $warning_count"
    echo ""
    echo "🔗 RPC Endpoints:"
    for i in $(seq 0 $((NUM_NODES-1))); do
        rpc_port=$((RPC_BASE_PORT + i))
        echo "   • Node $i: http://127.0.0.1:$rpc_port"
    done
    echo ""
    echo "📝 Next steps:"
    echo "   • Monitor logs: tail -f $TESTNET_DIR/node*/node.log"
    echo "   • Test transactions: Use the nym-cli to send test transactions"
    echo "   • Check metrics: curl http://127.0.0.1:9933/metrics"
    
    exit 0
else
    print_error "Testnet validation FAILED ❌"
    print_info "Check the issues above and restart failed nodes"
    exit 1
fi