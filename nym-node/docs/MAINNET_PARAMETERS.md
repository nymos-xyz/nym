# Nym Mainnet Network Parameters

This document outlines the official parameters for the Nym mainnet launch.

## Network Configuration

### Chain Parameters
- **Chain ID**: `nym-mainnet`
- **Block Time**: 60 seconds
- **Max Block Size**: 2 MB
- **Max Transactions per Block**: 5,000
- **Finality Threshold**: 67% (2/3 majority)

### Consensus Parameters
- **Consensus Type**: Hybrid PoW/PoS
- **PoW Weight**: 50%
- **PoS Weight**: 50%
- **Mining Algorithm**: Quantum-resistant RandomX variant (SHA-3 based)
- **Difficulty Adjustment**: Every 2016 blocks (~33.6 hours)

### Economic Parameters
- **Total Supply**: 10,000,000,000 NYM
- **Initial Emission Rate**: 2% annually
- **Minimum Stake Amount**: 10,000 NYM
- **Validator Reward Percentage**: 3%
- **Fee Burning**: Enabled (adaptive)

## Initial Token Distribution

### Genesis Allocation (4.05B NYM, 40.5% of total supply)
- **Foundation**: 2,000,000,000 NYM (20%)
- **Development Fund**: 1,000,000,000 NYM (10%)
- **Ecosystem Fund**: 500,000,000 NYM (5%)
- **Community Treasury**: 300,000,000 NYM (3%)
- **Genesis Validators**: 250,000,000 NYM (2.5% - 50M each)

### Future Allocation (5.95B NYM, 59.5% of total supply)
- **Mining Rewards**: 3,000,000,000 NYM (30%)
- **Staking Rewards**: 1,500,000,000 NYM (15%)
- **Ecosystem Growth**: 1,000,000,000 NYM (10%)
- **Reserve Fund**: 450,000,000 NYM (4.5%)

## Genesis Validators

### Validator Requirements
- **Minimum Stake**: 50,000,000 NYM
- **Voting Power**: 1,000 each
- **Hardware Requirements**: 
  - 8 CPU cores
  - 16 GB RAM
  - 500 GB SSD storage
  - 100 Mbps internet connection

### Genesis Validator Addresses
1. `nym1mainnetvalidator1000000000000000001` - Genesis Validator 1
2. `nym1mainnetvalidator1000000000000000002` - Genesis Validator 2
3. `nym1mainnetvalidator1000000000000000003` - Genesis Validator 3
4. `nym1mainnetvalidator1000000000000000004` - Genesis Validator 4
5. `nym1mainnetvalidator1000000000000000005` - Genesis Validator 5

## Network Infrastructure

### Bootstrap Nodes
- `bootstrap1.nym.network:30333`
- `bootstrap2.nym.network:30333`
- `bootstrap3.nym.network:30333`
- `bootstrap4.nym.network:30333`
- `bootstrap5.nym.network:30333`

### RPC Endpoints
- `rpc1.nym.network:9933`
- `rpc2.nym.network:9933`
- `rpc3.nym.network:9933`

### Archive Nodes
- `archive1.nym.network:30333`
- `archive2.nym.network:30333`

## Privacy & Security Features

### Privacy Routing
- **Mix Network**: Enabled by default
- **Cover Traffic Rate**: 10% of bandwidth
- **Mixing Strategy**: Random delay (30-300ms)
- **Onion Routing**: 3-hop minimum

### Security Parameters
- **Cryptographic Hash**: SHA-3 (quantum-resistant)
- **Signature Scheme**: ML-DSA (post-quantum)
- **Key Exchange**: ML-KEM (post-quantum)
- **zk-STARK Proof System**: Enabled for privacy transactions

## Node Types & Configurations

### Validator Nodes
- **Purpose**: Participate in consensus
- **Stake Required**: 25,000+ NYM
- **Hardware**: High-performance servers
- **Uptime**: 99.9%+ required

### Bootstrap Nodes
- **Purpose**: Network discovery and initial sync
- **Stake Required**: 50,000+ NYM
- **Hardware**: High-bandwidth servers
- **Uptime**: 99.95%+ required

### Archive Nodes
- **Purpose**: Store complete blockchain history
- **Stake Required**: None
- **Hardware**: High-storage servers
- **Uptime**: 99%+ recommended

### Light Nodes
- **Purpose**: Lightweight participation
- **Stake Required**: None
- **Hardware**: Consumer devices
- **Uptime**: No requirement

## Governance Parameters

### Proposal System
- **Proposal Threshold**: 100,000 NYM
- **Quorum Threshold**: 10% of staked tokens
- **Voting Period**: 14 days
- **Execution Delay**: 48 hours

### Emergency Governance
- **Emergency Council**: 5 members
- **Emergency Threshold**: 3/5 signatures
- **Emergency Powers**: Parameter adjustment only

## Launch Timeline

### Phase 1: Genesis Block Creation
- **Duration**: 1 week
- **Activities**: Genesis block generation, validator setup

### Phase 2: Bootstrap Network
- **Duration**: 2 weeks
- **Activities**: Bootstrap node deployment, network initialization

### Phase 3: Validator Onboarding
- **Duration**: 4 weeks
- **Activities**: Validator registration, staking, testing

### Phase 4: Public Launch
- **Duration**: 1 week
- **Activities**: Public network access, exchange listings

## Monitoring & Metrics

### Network Health Indicators
- **Block Production**: Consistent 60-second intervals
- **Validator Participation**: >90% online
- **Network Latency**: <100ms average
- **Transaction Throughput**: 100+ TPS sustained

### Economic Health Indicators
- **Token Distribution**: Decentralized ownership
- **Staking Participation**: >50% of supply
- **Fee Market**: Stable transaction costs
- **Emission Rate**: Following schedule

## Upgrade & Governance

### Network Upgrades
- **Coordination**: Through governance proposals
- **Backward Compatibility**: Maintained where possible
- **Testing**: Extensive testnet validation

### Parameter Updates
- **Process**: Governance proposal → Voting → Execution
- **Limits**: Safety bounds on critical parameters
- **Monitoring**: Real-time parameter impact assessment

## Risk Management

### Technical Risks
- **Quantum Attacks**: Post-quantum cryptography
- **Network Attacks**: Multi-layer security
- **Scaling Issues**: Layer 2 solutions planned

### Economic Risks
- **Inflation Control**: Adaptive emission system
- **Centralization**: Decentralization incentives
- **Market Volatility**: Stable protocol parameters

### Governance Risks
- **Capture**: Quadratic voting, delegation limits
- **Deadlock**: Emergency governance procedures
- **Manipulation**: Transparent proposal process

---

**Document Version**: 1.0  
**Last Updated**: January 2025  
**Network Version**: 1  
**Status**: Pre-launch