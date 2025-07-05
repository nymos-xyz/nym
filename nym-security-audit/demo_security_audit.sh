#!/bin/bash

# Demo script for Nym Security Audit System
# Demonstrates key features of the security audit binaries

echo "🛡️ Nym Security Audit System Demo"
echo "================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

print_step() {
    echo -e "${BLUE}Step $1:${NC} $2"
}

print_info() {
    echo -e "${YELLOW}ℹ️  $1${NC}"
}

print_success() {
    echo -e "${GREEN}✅ $1${NC}"
}

# Step 1: Build the binaries
print_step "1" "Building security audit binaries"
print_info "Building audit_runner and fuzzing_harness..."
cargo build --bins --release
if [ $? -eq 0 ]; then
    print_success "Binaries built successfully"
else
    echo "❌ Failed to build binaries"
    exit 1
fi
echo ""

# Step 2: Show help for audit runner
print_step "2" "Audit Runner Features"
print_info "Available audit runner commands:"
./target/release/audit_runner --help
echo ""

# Step 3: Show help for fuzzing harness
print_step "3" "Fuzzing Harness Features"
print_info "Available fuzzing harness commands:"
./target/release/fuzzing_harness --help
echo ""

# Step 4: Demonstrate quick audit (with timeout for demo)
print_step "4" "Quick Security Audit Demo"
print_info "Running a quick security audit (limited time for demo)..."
timeout 30 ./target/release/audit_runner quick --format text 2>/dev/null || echo "Demo timeout reached"
echo ""

# Step 5: Demonstrate component-specific audit
print_step "5" "Component-Specific Audit Demo"
print_info "Running cryptographic component audit..."
timeout 15 ./target/release/audit_runner component crypto --format text 2>/dev/null || echo "Demo timeout reached"
echo ""

# Step 6: Demonstrate fuzzing
print_step "6" "Fuzzing Demo"
print_info "Running short cryptographic fuzzing test..."
timeout 10 ./target/release/fuzzing_harness crypto --duration 5 --output-dir demo_fuzzing 2>/dev/null || echo "Demo timeout reached"
if [ -d "demo_fuzzing" ]; then
    print_success "Fuzzing output directory created"
    ls -la demo_fuzzing/ 2>/dev/null || echo "No files created in short demo"
fi
echo ""

# Step 7: Show configuration options
print_step "7" "Custom Configuration Demo"
print_info "Example custom audit configuration:"
echo "  ./target/release/audit_runner custom \\"
echo "    --fuzzing-duration 600 \\"
echo "    --timing-iterations 50000 \\"
echo "    --enable-fuzzing true \\"
echo "    --enable-timing true \\"
echo "    --enable-dos true \\"
echo "    --enable-memory true \\"
echo "    --format json \\"
echo "    --output comprehensive_audit.json"
echo ""

# Step 8: Show continuous fuzzing example
print_step "8" "Continuous Fuzzing Demo"
print_info "Example continuous fuzzing setup:"
echo "  # Start continuous fuzzing in background"
echo "  nohup ./target/release/fuzzing_harness continuous \\"
echo "    --report-interval 3600 \\"
echo "    --output-dir /var/log/nym-fuzzing > fuzzing.log 2>&1 &"
echo ""
echo "  # Monitor for critical issues"
echo "  tail -f fuzzing.log | grep -i \"critical\\|crash\\|vulnerability\""
echo ""

# Step 9: Security coverage overview
print_step "9" "Security Coverage Overview"
print_info "The security audit system covers:"
echo "  🔐 Cryptographic Security:"
echo "    - ML-DSA quantum-resistant signatures"
echo "    - SHAKE256 hash functions"
echo "    - zk-STARK zero-knowledge proofs"
echo "    - Key derivation security"
echo "    - Timing attack resistance"
echo "    - Side-channel resistance"
echo ""
echo "  🌐 Network Security:"
echo "    - P2P protocol security"
echo "    - Message integrity"
echo "    - Peer authentication"
echo "    - DoS resistance"
echo "    - Eclipse/Sybil attack resistance"
echo ""
echo "  💾 Storage Security:"
echo "    - Encryption at rest"
echo "    - Access control"
echo "    - Backup security"
echo "    - Recovery systems"
echo "    - Data integrity"
echo "    - Privacy preservation"
echo ""
echo "  🔗 QuID Integration:"
echo "    - Authentication integration"
echo "    - Identity management"
echo "    - Recovery integration"
echo "    - Cross-component privacy"
echo "    - Key derivation"
echo ""
echo "  ⚡ Attack Resistance:"
echo "    - Comprehensive fuzzing"
echo "    - DoS resistance testing"
echo "    - Timing attack analysis"
echo "    - Memory safety validation"
echo ""

# Step 10: Production recommendations
print_step "10" "Production Recommendations"
print_info "Recommended security audit schedule:"
echo "  • Daily: Quick audit (5 minutes)"
echo "  • Weekly: Full comprehensive audit (30+ minutes)"
echo "  • Continuous: Fuzzing harness running in background"
echo "  • Before releases: Full audit + extended fuzzing"
echo ""

# Cleanup
print_info "Cleaning up demo files..."
rm -rf demo_fuzzing
print_success "Demo completed successfully!"
echo ""
echo "🚀 The Nym Security Audit System is ready for production use!"
echo ""
echo "📚 For detailed usage instructions, see:"
echo "   - README_BINARIES.md"
echo "   - Source code in src/bin/"
echo "   - Individual module documentation"
echo ""
echo "🔧 To get started:"
echo "   1. cargo build --bins --release"
echo "   2. ./target/release/audit_runner quick"
echo "   3. ./target/release/fuzzing_harness crypto --duration 60"