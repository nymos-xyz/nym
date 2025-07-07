#!/bin/bash

# Nym Testnet Setup Script
# This script sets up a local testnet with multiple nodes

set -e

# Configuration
TESTNET_DIR="./testnet"
CHAIN_ID="nym-testnet-local"
NUM_NODES=3
BASE_PORT=30333
RPC_BASE_PORT=9933

echo "Setting up Nym testnet..."
echo "Chain ID: $CHAIN_ID"
echo "Number of nodes: $NUM_NODES"
echo "Testnet directory: $TESTNET_DIR"

# Clean up existing testnet
if [ -d "$TESTNET_DIR" ]; then
    echo "Removing existing testnet directory..."
    rm -rf "$TESTNET_DIR"
fi

mkdir -p "$TESTNET_DIR"

# Generate genesis block
echo "Generating genesis block..."
cargo run --bin nym-node -- genesis \
    --output "$TESTNET_DIR/genesis.json" \
    --chain-id "$CHAIN_ID"

echo "Genesis block created:"
cat "$TESTNET_DIR/genesis.json" | jq .

# Create node directories and configurations
for i in $(seq 0 $((NUM_NODES-1))); do
    NODE_DIR="$TESTNET_DIR/node$i"
    mkdir -p "$NODE_DIR"
    
    echo "Setting up node $i..."
    
    # Calculate ports
    P2P_PORT=$((BASE_PORT + i))
    RPC_PORT=$((RPC_BASE_PORT + i))
    
    # Initialize node configuration
    cargo run --bin nym-node -- init \
        --data-dir "$NODE_DIR" \
        --testnet
    
    # Create custom config for this node
    cat > "$NODE_DIR/config.toml" << EOF
node_id = "node$i"

[network]
listen_addr = "0.0.0.0:$P2P_PORT"
max_peers = 50
enable_privacy_routing = true
mix_strategy = "random_delay"
cover_traffic_rate = 0.1

[storage]
data_dir = "$NODE_DIR/data"
max_storage_gb = 10
enable_pruning = true
pruning_interval_hours = 24
enable_archival = false

[consensus]
consensus_type = "Hybrid"
pow_enabled = true
pos_enabled = true
pow_weight = 0.5
pos_weight = 0.5
block_time_seconds = 5
finality_threshold = 67

[rpc]
enabled = true
listen_addr = "127.0.0.1:$RPC_PORT"
max_connections = 100
auth_enabled = false

[compute]
enabled = true
max_jobs = 5
supported_runtimes = ["wasm", "docker"]

[economics]
enable_adaptive_emissions = true
enable_fee_burning = true
min_stake_amount = 1000
validator_reward_percentage = 0.05

[logging]
level = "info"
format = "pretty"
EOF

    echo "Node $i configured:"
    echo "  - P2P Port: $P2P_PORT"
    echo "  - RPC Port: $RPC_PORT"
    echo "  - Data Directory: $NODE_DIR/data"
done

# Create bootstrap peers list for each node
for i in $(seq 0 $((NUM_NODES-1))); do
    NODE_CONFIG="$TESTNET_DIR/node$i/config.toml"
    
    # Add bootstrap peers (all other nodes)
    echo "bootstrap_peers = [" >> "$NODE_CONFIG"
    for j in $(seq 0 $((NUM_NODES-1))); do
        if [ $i -ne $j ]; then
            PEER_PORT=$((BASE_PORT + j))
            echo "  \"/ip4/127.0.0.1/tcp/$PEER_PORT\"," >> "$NODE_CONFIG"
        fi
    done
    echo "]" >> "$NODE_CONFIG"
done

# Create start script
cat > "$TESTNET_DIR/start-testnet.sh" << 'EOF'
#!/bin/bash

# Start all testnet nodes

TESTNET_DIR="$(dirname "$0")"
NUM_NODES=3

echo "Starting Nym testnet nodes..."

# Function to start a single node
start_node() {
    local node_id=$1
    local node_dir="$TESTNET_DIR/node$node_id"
    local log_file="$node_dir/node.log"
    
    echo "Starting node $node_id..."
    cd "$TESTNET_DIR/.."
    cargo run --bin nym-node -- start \
        --config "$node_dir/config.toml" \
        > "$log_file" 2>&1 &
    
    local pid=$!
    echo $pid > "$node_dir/node.pid"
    echo "Node $node_id started with PID $pid"
}

# Start all nodes
for i in $(seq 0 $((NUM_NODES-1))); do
    start_node $i
    sleep 2  # Small delay between node starts
done

echo "All nodes started!"
echo "Monitor logs:"
for i in $(seq 0 $((NUM_NODES-1))); do
    echo "  Node $i: tail -f $TESTNET_DIR/node$i/node.log"
done

echo ""
echo "RPC endpoints:"
for i in $(seq 0 $((NUM_NODES-1))); do
    rpc_port=$((9933 + i))
    echo "  Node $i: http://127.0.0.1:$rpc_port"
done

echo ""
echo "To stop all nodes: $TESTNET_DIR/stop-testnet.sh"
EOF

# Create stop script
cat > "$TESTNET_DIR/stop-testnet.sh" << 'EOF'
#!/bin/bash

# Stop all testnet nodes

TESTNET_DIR="$(dirname "$0")"
NUM_NODES=3

echo "Stopping Nym testnet nodes..."

for i in $(seq 0 $((NUM_NODES-1))); do
    node_dir="$TESTNET_DIR/node$i"
    pid_file="$node_dir/node.pid"
    
    if [ -f "$pid_file" ]; then
        pid=$(cat "$pid_file")
        echo "Stopping node $i (PID: $pid)..."
        kill $pid 2>/dev/null || echo "Node $i was not running"
        rm -f "$pid_file"
    else
        echo "Node $i PID file not found"
    fi
done

echo "All nodes stopped!"
EOF

# Create status script
cat > "$TESTNET_DIR/status-testnet.sh" << 'EOF'
#!/bin/bash

# Check status of all testnet nodes

TESTNET_DIR="$(dirname "$0")"
NUM_NODES=3

echo "Nym Testnet Status:"
echo "==================="

for i in $(seq 0 $((NUM_NODES-1))); do
    node_dir="$TESTNET_DIR/node$i"
    pid_file="$node_dir/node.pid"
    rpc_port=$((9933 + i))
    
    echo "Node $i:"
    
    # Check if process is running
    if [ -f "$pid_file" ]; then
        pid=$(cat "$pid_file")
        if kill -0 $pid 2>/dev/null; then
            echo "  Status: Running (PID: $pid)"
        else
            echo "  Status: Stopped (stale PID file)"
            rm -f "$pid_file"
        fi
    else
        echo "  Status: Stopped"
    fi
    
    # Check RPC endpoint
    if curl -s "http://127.0.0.1:$rpc_port" > /dev/null 2>&1; then
        echo "  RPC: Available at http://127.0.0.1:$rpc_port"
    else
        echo "  RPC: Not available"
    fi
    
    echo ""
done
EOF

# Make scripts executable
chmod +x "$TESTNET_DIR/start-testnet.sh"
chmod +x "$TESTNET_DIR/stop-testnet.sh"
chmod +x "$TESTNET_DIR/status-testnet.sh"

echo ""
echo "Testnet setup complete!"
echo ""
echo "Commands:"
echo "  Start testnet: $TESTNET_DIR/start-testnet.sh"
echo "  Stop testnet:  $TESTNET_DIR/stop-testnet.sh"
echo "  Check status:  $TESTNET_DIR/status-testnet.sh"
echo ""
echo "Genesis block: $TESTNET_DIR/genesis.json"
echo ""
echo "Node configurations:"
for i in $(seq 0 $((NUM_NODES-1))); do
    echo "  Node $i: $TESTNET_DIR/node$i/config.toml"
done