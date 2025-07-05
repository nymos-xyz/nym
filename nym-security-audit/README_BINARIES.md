# Nym Security Audit Binaries

This document describes the security audit runner binaries for the Nym cryptocurrency project, implementing comprehensive security testing for Week 19-20 of the roadmap.

## Overview

The Nym security audit system provides two main binary executables:

1. **`audit_runner`** - Comprehensive security audit runner
2. **`fuzzing_harness`** - Dedicated fuzzing harness for continuous security testing

## Building

Build the binaries using Cargo:

```bash
cargo build --bins --release
```

The binaries will be available in `target/release/`:
- `target/release/audit_runner`
- `target/release/fuzzing_harness`

## Binary 1: Security Audit Runner (`audit_runner`)

### Purpose
Comprehensive security audit runner that executes all security tests across the Nym system.

### Features
- **Multiple audit modes**: Quick, Full, Custom, Component-specific
- **Comprehensive coverage**: Cryptographic, Network, Storage, QuID integration security
- **Attack resistance testing**: Fuzzing, DoS resistance, timing attacks, memory safety
- **Flexible output**: JSON and text formats
- **Report generation**: Generate reports from previous audit results

### Usage

#### Quick Security Audit (5 minutes)
```bash
./target/release/audit_runner quick
```

#### Full Comprehensive Audit (30+ minutes)
```bash
./target/release/audit_runner full
```

#### Custom Audit Configuration
```bash
./target/release/audit_runner custom \
    --fuzzing-duration 600 \
    --timing-iterations 50000 \
    --enable-fuzzing true \
    --enable-timing true \
    --enable-dos true \
    --enable-memory true \
    --parallel true \
    --comprehensive true
```

#### Component-Specific Audit
```bash
# Audit specific components
./target/release/audit_runner component crypto
./target/release/audit_runner component network
./target/release/audit_runner component storage
./target/release/audit_runner component quid
./target/release/audit_runner component timing
./target/release/audit_runner component memory
./target/release/audit_runner component fuzzing
./target/release/audit_runner component dos
```

#### Output Formats
```bash
# JSON output
./target/release/audit_runner quick --format json --output audit_results.json

# Text output (default)
./target/release/audit_runner quick --format text

# Verbose logging
./target/release/audit_runner quick --verbose
```

#### Generate Report from Results
```bash
./target/release/audit_runner report audit_results.json --format text
```

### Security Areas Covered

#### Cryptographic Security
- Quantum resistance validation (ML-DSA signatures)
- Key generation security
- Signature scheme security
- Hash function security (SHAKE256)
- zk-STARK proof security
- Timing attack resistance
- Side-channel resistance

#### Network Security
- P2P protocol security
- Message integrity validation
- Peer authentication security
- DoS resistance
- Eclipse attack resistance
- Sybil attack resistance

#### Storage Security
- Encryption at rest
- Access control
- Backup security validation
- Recovery system security
- Data integrity protection
- Privacy preservation

#### QuID Integration Security
- Authentication integration
- Identity management
- Recovery integration
- Cross-component privacy
- Key derivation security

#### Integration Security
- Component isolation
- Data flow security
- Privilege escalation prevention
- Cross-component attack prevention

#### Attack Resistance
- Comprehensive fuzzing
- DoS resistance testing
- Timing attack analysis
- Memory safety validation

## Binary 2: Fuzzing Harness (`fuzzing_harness`)

### Purpose
Dedicated fuzzing harness for continuous security testing and vulnerability discovery.

### Features
- **Comprehensive fuzzing**: Cryptographic, Network, Storage systems
- **Continuous mode**: Never-ending fuzzing with periodic reports
- **Crash detection**: Automatic crash report generation
- **Vulnerability discovery**: Security issue identification
- **Detailed reporting**: JSON output with timestamps

### Usage

#### Comprehensive Fuzzing
```bash
./target/release/fuzzing_harness all --duration 1800 --output-dir fuzzing_results
```

#### Cryptographic Fuzzing
```bash
# All crypto operations
./target/release/fuzzing_harness crypto --duration 600

# Specific crypto operations
./target/release/fuzzing_harness crypto --operation ml-dsa
./target/release/fuzzing_harness crypto --operation shake256
./target/release/fuzzing_harness crypto --operation zk-stark
./target/release/fuzzing_harness crypto --operation key-derivation
```

#### Network Protocol Fuzzing
```bash
# All network components
./target/release/fuzzing_harness network --duration 600

# Specific network components
./target/release/fuzzing_harness network --component message-parsing
./target/release/fuzzing_harness network --component auth
./target/release/fuzzing_harness network --component connection
```

#### Storage System Fuzzing
```bash
# All storage components
./target/release/fuzzing_harness storage --duration 600

# Specific storage components
./target/release/fuzzing_harness storage --component database
./target/release/fuzzing_harness storage --component serialization
./target/release/fuzzing_harness storage --component file-ops
```

#### Continuous Fuzzing
```bash
# Run continuous fuzzing with 60-second reports
./target/release/fuzzing_harness continuous --report-interval 60 --output-dir continuous_fuzzing
```

#### Configuration Options
```bash
# Verbose logging
./target/release/fuzzing_harness all --verbose

# Custom duration and test case limits
./target/release/fuzzing_harness all --duration 3600 --max-cases 5000000

# Custom output directory
./target/release/fuzzing_harness all --output-dir custom_fuzzing_output
```

### Fuzzing Targets

#### Cryptographic Operations
- **ML-DSA Operations**: Key generation, signing, verification, malformed input handling
- **SHAKE256 Operations**: Hash computation with various input sizes
- **Key Derivation**: Master key derivation with different contexts
- **zk-STARK Operations**: Proof generation and verification

#### Network Protocols
- **Message Parsing**: Malformed headers, oversized messages, truncated messages
- **Peer Authentication**: Authentication mechanism robustness
- **Connection Handling**: Connection establishment and management

#### Storage Systems
- **Database Operations**: Insert, query, update, delete with invalid inputs
- **Serialization/Deserialization**: Malformed data handling
- **File Operations**: File system interaction security

### Output Files

The fuzzing harness generates several types of output files:

#### Results Files
- `fuzzing_results_<type>_<timestamp>.json` - Comprehensive fuzzing results
- `findings_<type>_<timestamp>.json` - Security findings and issues
- `crashes_<type>_<timestamp>.json` - Critical crash reports

#### Continuous Mode
- `iteration_<N>/` - Results for each fuzzing iteration
- Cumulative statistics across all iterations

## Security Audit Results

### Exit Codes
- **0**: All security tests passed
- **1**: Security vulnerabilities found

### Result Structure
```json
{
  "overall_secure": true,
  "component_results": {
    "cryptographic_security": { /* ... */ },
    "network_security": { /* ... */ },
    "storage_security": { /* ... */ },
    "quid_integration_security": { /* ... */ }
  },
  "integration_results": { /* ... */ },
  "attack_resistance_results": {
    "fuzzing_results": { /* ... */ },
    "dos_resistance": { /* ... */ },
    "timing_attack_resistance": { /* ... */ },
    "memory_safety_results": { /* ... */ }
  },
  "findings": [ /* Security findings array */ ],
  "audit_duration": "PT15M30S"
}
```

### Security Findings
Each finding includes:
- **Severity**: Critical, High, Medium, Low, Informational
- **Category**: Cryptographic, Network, Storage, Integration, Performance, MemorySafety, Configuration
- **Component**: Affected component
- **Description**: Issue description
- **Recommendation**: Fix recommendation
- **Exploitable**: Whether the issue is exploitable

## Integration with CI/CD

### GitHub Actions Example
```yaml
name: Security Audit
on: [push, pull_request]
jobs:
  security-audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Build audit tools
        run: cd nym-security-audit && cargo build --bins --release
      - name: Run security audit
        run: cd nym-security-audit && ./target/release/audit_runner full --format json --output audit_results.json
      - name: Upload audit results
        uses: actions/upload-artifact@v3
        with:
          name: security-audit-results
          path: nym-security-audit/audit_results.json
```

### Continuous Fuzzing Setup
```bash
# Start continuous fuzzing in the background
nohup ./target/release/fuzzing_harness continuous --report-interval 3600 --output-dir /var/log/nym-fuzzing > fuzzing.log 2>&1 &

# Monitor for critical issues
tail -f fuzzing.log | grep -i "critical\|crash\|vulnerability"
```

## Production Recommendations

### Security Audit Schedule
- **Daily**: Quick audit (5 minutes)
- **Weekly**: Full comprehensive audit (30+ minutes)
- **Continuous**: Fuzzing harness running in background
- **Before releases**: Full audit + extended fuzzing

### Monitoring
- Set up alerts for non-zero exit codes
- Monitor fuzzing output for crashes and vulnerabilities
- Regular review of security findings
- Track security metrics over time

### Integration Points
- **Pre-commit hooks**: Quick security checks
- **CI/CD pipeline**: Full security audit on major changes
- **Production monitoring**: Continuous fuzzing
- **Security reviews**: Regular comprehensive audits

## Troubleshooting

### Common Issues

#### Build Errors
```bash
# Install required dependencies
cargo install --force cargo-audit
sudo apt-get install librocksdb-dev  # For RocksDB support
```

#### Permission Errors
```bash
# Ensure proper permissions for output directories
chmod -R 755 fuzzing_output/
```

#### Timeout Issues
```bash
# Increase timeout for long-running audits
timeout 3600 ./target/release/audit_runner full
```

### Debug Mode
```bash
# Enable debug logging
RUST_LOG=debug ./target/release/audit_runner quick --verbose
```

## Contributing

When adding new security tests:

1. Add test implementation to appropriate module (`crypto_audit.rs`, `network_security.rs`, etc.)
2. Update fuzzing harness in `fuzzing.rs` 
3. Add CLI options to binaries if needed
4. Update documentation
5. Test with both binaries

## Security Considerations

- **Secure by default**: All tests assume worst-case scenarios
- **No false positives**: High confidence in reported issues
- **Comprehensive coverage**: All attack vectors considered
- **Production ready**: Suitable for production security auditing

---

*This security audit system provides comprehensive coverage of all security aspects of the Nym cryptocurrency system, supporting Week 19-20 roadmap objectives for security audit preparation.*