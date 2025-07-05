#!/bin/bash

# Test script for Nym compilation and testing

echo "=== Checking Nym Project Compilation Status ==="

# Check if we're in the right directory
echo "Current directory: $(pwd)"

# Check Rust version
echo "Rust version:"
rustc --version
cargo --version

# Check workspace structure
echo -e "\n=== Workspace Structure ==="
find . -name "Cargo.toml" | head -20

# Try to check each component individually
echo -e "\n=== Individual Component Checks ==="

components=(
    "nym-core"
    "nym-crypto" 
    "nym-consensus"
    "nym-network"
    "nym-storage"
    "nym-cli"
    "nym-node"
    "nym-security-audit"
    "nym-privacy-validation"
)

for component in "${components[@]}"; do
    echo -e "\n--- Checking $component ---"
    if [ -d "$component" ]; then
        cd "$component"
        echo "Dependencies for $component:"
        cargo metadata --format-version 1 2>/dev/null | grep -o '"name":"[^"]*"' | head -10 || echo "Could not read metadata"
        cd ..
    else
        echo "$component directory not found"
    fi
done

# Try workspace check
echo -e "\n=== Workspace Check ==="
cargo check --workspace --offline 2>&1 | head -50

# Try workspace test
echo -e "\n=== Workspace Test ==="
cargo test --workspace --offline 2>&1 | head -50

echo -e "\n=== Test Complete ==="