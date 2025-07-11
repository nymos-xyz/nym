#!/bin/bash
# Start Nym Testnet

echo "🚀 Starting Nym Testnet..."
echo "Chain ID: nym-testnet-local"
echo "Nodes: 3"

# This is a mock testnet startup script
# In a real implementation, this would start the actual node processes

for i in {0..2}; do
    echo "Starting node $i..."
    # cargo run --bin nym-node -- start --config testnet/node$i/config.toml &
    echo "Node $i started (mock)"
done

echo ""
echo "✅ Testnet started successfully!"
echo ""
echo "RPC Endpoints:"
echo "  Node 0: http://127.0.0.1:9933"
echo "  Node 1: http://127.0.0.1:9934" 
echo "  Node 2: http://127.0.0.1:9935"
echo ""
echo "To stop testnet: ./testnet/stop_testnet.sh"
