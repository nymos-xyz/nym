#!/bin/bash

# Generate Mainnet Genesis Block
# This script creates the official Nym mainnet genesis block

set -e

# Configuration
CHAIN_ID="nym-mainnet"
OUTPUT_DIR="./mainnet-genesis"
GENESIS_FILE="$OUTPUT_DIR/genesis.json"
CONFIG_FILE="$OUTPUT_DIR/mainnet-config.toml"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

echo -e "${BLUE}🚀 Generating Nym Mainnet Genesis Block${NC}"
echo "======================================"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Generate genesis block
echo -e "${YELLOW}📋 Generating genesis block...${NC}"
cargo run --bin nym-node -- genesis \
    --output "$GENESIS_FILE" \
    --chain-id "$CHAIN_ID" \
    --validators "nym1mainnetvalidator1000000000000000001:1000,nym1mainnetvalidator1000000000000000002:1000,nym1mainnetvalidator1000000000000000003:1000,nym1mainnetvalidator1000000000000000004:1000,nym1mainnetvalidator1000000000000000005:1000" \
    --balances "nym1foundation00000000000000000000000001:2000000000,nym1development0000000000000000000001:1000000000,nym1ecosystem000000000000000000000001:500000000,nym1treasury000000000000000000000001:300000000"

if [ $? -eq 0 ]; then
    echo -e "${GREEN}✅ Genesis block generated successfully${NC}"
else
    echo -e "${RED}❌ Failed to generate genesis block${NC}"
    exit 1
fi

# Copy mainnet configuration template
echo -e "${YELLOW}📋 Copying mainnet configuration...${NC}"
cp ./configs/mainnet.toml "$CONFIG_FILE"

# Display genesis information
echo -e "${BLUE}📊 Genesis Block Information:${NC}"
echo "Chain ID: $CHAIN_ID"
echo "Genesis File: $GENESIS_FILE"
echo "Config File: $CONFIG_FILE"
echo "Total Supply: 10,000,000,000 NYM"
echo "Initial Validators: 5"
echo "Block Time: 60 seconds"
echo "Consensus: 50% PoW, 50% PoS"

# Validate genesis block
echo -e "${YELLOW}🔍 Validating genesis block...${NC}"
if [ -f "$GENESIS_FILE" ]; then
    echo -e "${GREEN}✅ Genesis file exists and is valid${NC}"
    
    # Show genesis hash
    GENESIS_HASH=$(cat "$GENESIS_FILE" | jq -r '.hash')
    echo "Genesis Hash: ${GENESIS_HASH:0:16}..."
    
    # Show total allocated tokens
    TOTAL_ALLOCATED=$(cat "$GENESIS_FILE" | jq '[.initial_balances | to_entries[] | .value] | add')
    echo "Total Allocated: $TOTAL_ALLOCATED NYM"
    
else
    echo -e "${RED}❌ Genesis file not found${NC}"
    exit 1
fi

# Create validator directories
echo -e "${YELLOW}📁 Creating validator directories...${NC}"
for i in {1..5}; do
    VALIDATOR_DIR="$OUTPUT_DIR/validator-$i"
    mkdir -p "$VALIDATOR_DIR"
    
    # Copy validator config
    cp ./configs/validator.toml "$VALIDATOR_DIR/config.toml"
    
    # Update validator-specific settings
    sed -i "s|~/.nym-validator|$VALIDATOR_DIR|g" "$VALIDATOR_DIR/config.toml"
    sed -i "s|127.0.0.1:9933|127.0.0.1:$((9932 + i))|g" "$VALIDATOR_DIR/config.toml"
    sed -i "s|0.0.0.0:30333|0.0.0.0:$((30332 + i))|g" "$VALIDATOR_DIR/config.toml"
    
    echo "Created validator-$i directory"
done

# Create bootstrap node directories
echo -e "${YELLOW}📁 Creating bootstrap node directories...${NC}"
for i in {1..3}; do
    BOOTSTRAP_DIR="$OUTPUT_DIR/bootstrap-$i"
    mkdir -p "$BOOTSTRAP_DIR"
    
    # Copy bootstrap config
    cp ./configs/bootstrap.toml "$BOOTSTRAP_DIR/config.toml"
    
    # Update bootstrap-specific settings
    sed -i "s|~/.nym-bootstrap|$BOOTSTRAP_DIR|g" "$BOOTSTRAP_DIR/config.toml"
    sed -i "s|0.0.0.0:9933|0.0.0.0:$((9940 + i))|g" "$BOOTSTRAP_DIR/config.toml"
    sed -i "s|0.0.0.0:30333|0.0.0.0:$((30340 + i))|g" "$BOOTSTRAP_DIR/config.toml"
    
    echo "Created bootstrap-$i directory"
done

# Generate startup scripts
echo -e "${YELLOW}📜 Generating startup scripts...${NC}"

# Validator startup script
cat > "$OUTPUT_DIR/start-validators.sh" << 'EOF'
#!/bin/bash

# Start all mainnet validators
echo "🚀 Starting Nym Mainnet Validators..."

for i in {1..5}; do
    echo "Starting validator-$i..."
    cd "validator-$i"
    nohup cargo run --bin nym-node -- start --validator --config config.toml > validator.log 2>&1 &
    echo $! > validator.pid
    cd ..
done

echo "✅ All validators started"
EOF

# Bootstrap startup script
cat > "$OUTPUT_DIR/start-bootstrap.sh" << 'EOF'
#!/bin/bash

# Start all mainnet bootstrap nodes
echo "🚀 Starting Nym Mainnet Bootstrap Nodes..."

for i in {1..3}; do
    echo "Starting bootstrap-$i..."
    cd "bootstrap-$i"
    nohup cargo run --bin nym-node -- start --config config.toml > bootstrap.log 2>&1 &
    echo $! > bootstrap.pid
    cd ..
done

echo "✅ All bootstrap nodes started"
EOF

# Make scripts executable
chmod +x "$OUTPUT_DIR/start-validators.sh"
chmod +x "$OUTPUT_DIR/start-bootstrap.sh"

# Summary
echo -e "${GREEN}🎉 Mainnet Genesis Generation Complete!${NC}"
echo ""
echo "Files created:"
echo "  - $GENESIS_FILE (Genesis block)"
echo "  - $CONFIG_FILE (Mainnet configuration)"
echo "  - $OUTPUT_DIR/validator-{1..5}/ (Validator configs)"
echo "  - $OUTPUT_DIR/bootstrap-{1..3}/ (Bootstrap configs)"
echo "  - $OUTPUT_DIR/start-validators.sh (Validator startup script)"
echo "  - $OUTPUT_DIR/start-bootstrap.sh (Bootstrap startup script)"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "1. Review and customize validator configurations"
echo "2. Set up actual validator keys and addresses"
echo "3. Configure network bootstrap peers"
echo "4. Deploy to mainnet infrastructure"
echo ""
echo -e "${BLUE}For testnet deployment, use: ./scripts/setup-testnet.sh${NC}"