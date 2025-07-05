# Makefile for Nym Security Audit System
# Provides convenient targets for building and running security audits

.PHONY: all build clean audit-quick audit-full audit-crypto audit-network audit-storage audit-quid fuzz-crypto fuzz-network fuzz-storage fuzz-all fuzz-continuous test demo help

# Default target
all: build

# Build all binaries
build:
	@echo "🔨 Building security audit binaries..."
	cargo build --bins --release
	@echo "✅ Build complete. Binaries available in target/release/"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	cargo clean
	rm -rf fuzzing_output audit_results.json *.log

# Security audit targets
audit-quick:
	@echo "🛡️ Running quick security audit..."
	./target/release/audit_runner quick --format text

audit-full:
	@echo "🛡️ Running full comprehensive security audit..."
	./target/release/audit_runner full --format json --output audit_results.json

audit-crypto:
	@echo "🔐 Running cryptographic security audit..."
	./target/release/audit_runner component crypto --format text

audit-network:
	@echo "🌐 Running network security audit..."
	./target/release/audit_runner component network --format text

audit-storage:
	@echo "💾 Running storage security audit..."
	./target/release/audit_runner component storage --format text

audit-quid:
	@echo "🔗 Running QuID integration security audit..."
	./target/release/audit_runner component quid --format text

audit-timing:
	@echo "⏱️ Running timing attack analysis..."
	./target/release/audit_runner component timing --format text

audit-memory:
	@echo "🧠 Running memory safety audit..."
	./target/release/audit_runner component memory --format text

audit-dos:
	@echo "⚡ Running DoS resistance audit..."
	./target/release/audit_runner component dos --format text

audit-custom:
	@echo "🔧 Running custom security audit..."
	./target/release/audit_runner custom \
		--fuzzing-duration 300 \
		--timing-iterations 10000 \
		--enable-fuzzing true \
		--enable-timing true \
		--enable-dos true \
		--enable-memory true \
		--format json \
		--output custom_audit_results.json

# Fuzzing targets
fuzz-crypto:
	@echo "🔍 Running cryptographic fuzzing..."
	./target/release/fuzzing_harness crypto --duration 300 --output-dir fuzzing_output

fuzz-network:
	@echo "🔍 Running network protocol fuzzing..."
	./target/release/fuzzing_harness network --duration 300 --output-dir fuzzing_output

fuzz-storage:
	@echo "🔍 Running storage system fuzzing..."
	./target/release/fuzzing_harness storage --duration 300 --output-dir fuzzing_output

fuzz-all:
	@echo "🔍 Running comprehensive fuzzing..."
	./target/release/fuzzing_harness all --duration 600 --output-dir fuzzing_output

fuzz-continuous:
	@echo "🔍 Starting continuous fuzzing (Ctrl+C to stop)..."
	./target/release/fuzzing_harness continuous --report-interval 60 --output-dir fuzzing_output

fuzz-quick:
	@echo "🔍 Running quick fuzzing test..."
	./target/release/fuzzing_harness crypto --duration 30 --output-dir fuzzing_output

# Testing and validation
test:
	@echo "🧪 Running security audit tests..."
	cargo test --workspace

bench:
	@echo "📊 Running timing analysis benchmarks..."
	cargo bench

check:
	@echo "🔍 Checking code quality..."
	cargo check --bins
	cargo clippy --bins -- -D warnings
	cargo fmt -- --check

# Demo and documentation
demo:
	@echo "🎬 Running security audit system demo..."
	@chmod +x demo_security_audit.sh
	./demo_security_audit.sh

help:
	@echo "Nym Security Audit System - Available targets:"
	@echo ""
	@echo "🔨 Building:"
	@echo "  build         - Build all security audit binaries"
	@echo "  clean         - Clean build artifacts"
	@echo "  check         - Check code quality (check, clippy, fmt)"
	@echo ""
	@echo "🛡️ Security Audits:"
	@echo "  audit-quick   - Quick security audit (5 minutes)"
	@echo "  audit-full    - Full comprehensive audit (30+ minutes)"
	@echo "  audit-crypto  - Cryptographic security audit"
	@echo "  audit-network - Network security audit"
	@echo "  audit-storage - Storage security audit"
	@echo "  audit-quid    - QuID integration security audit"
	@echo "  audit-timing  - Timing attack analysis"
	@echo "  audit-memory  - Memory safety audit"
	@echo "  audit-dos     - DoS resistance audit"
	@echo "  audit-custom  - Custom audit configuration"
	@echo ""
	@echo "🔍 Fuzzing:"
	@echo "  fuzz-crypto   - Cryptographic fuzzing"
	@echo "  fuzz-network  - Network protocol fuzzing"
	@echo "  fuzz-storage  - Storage system fuzzing"
	@echo "  fuzz-all      - Comprehensive fuzzing"
	@echo "  fuzz-continuous - Continuous fuzzing (never stops)"
	@echo "  fuzz-quick    - Quick fuzzing test"
	@echo ""
	@echo "🧪 Testing:"
	@echo "  test          - Run security audit tests"
	@echo "  bench         - Run timing analysis benchmarks"
	@echo ""
	@echo "📚 Documentation:"
	@echo "  demo          - Run interactive demo"
	@echo "  help          - Show this help message"
	@echo ""
	@echo "🚀 Quick start:"
	@echo "  make build && make audit-quick"
	@echo "  make fuzz-quick"
	@echo "  make demo"

# CI/CD targets
ci-audit:
	@echo "🏗️ Running CI security audit..."
	./target/release/audit_runner full --format json --output ci_audit_results.json
	@if [ -f ci_audit_results.json ]; then \
		echo "✅ CI audit completed. Results in ci_audit_results.json"; \
	else \
		echo "❌ CI audit failed"; \
		exit 1; \
	fi

ci-fuzz:
	@echo "🏗️ Running CI fuzzing tests..."
	./target/release/fuzzing_harness all --duration 120 --output-dir ci_fuzzing_output
	@if [ -d ci_fuzzing_output ]; then \
		echo "✅ CI fuzzing completed. Results in ci_fuzzing_output/"; \
	else \
		echo "❌ CI fuzzing failed"; \
		exit 1; \
	fi

# Security checks for pre-commit
pre-commit: build audit-quick fuzz-quick
	@echo "✅ Pre-commit security checks passed"

# Full security validation
security-validation: build audit-full fuzz-all
	@echo "🛡️ Full security validation completed"
	@echo "📊 Check audit_results.json and fuzzing_output/ for detailed results"