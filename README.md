<div align="center">Oxidity Searcher

Ultra-low-latency, multi-strategy MEV infrastructure written in Rust

""Rust" (https://img.shields.io/badge/Rust-1.78%2B-000000?logo=rust&logoColor=white)" (https://www.rust-lang.org/)
""Ethereum" (https://img.shields.io/badge/Ethereum-Mainnet-627EEA?logo=ethereum&logoColor=white)" (https://ethereum.org/)
""EVM" (https://img.shields.io/badge/EVM-Compatible-3C3C3D)" (https://ethereum.org/en/developers/docs/evm/)


Stream pending transactions. Decode DEX activity. Generate opportunities. Simulate atomically. Submit privately.

"Features" (#key-features) ·
"Architecture" (#architecture) ·
"Quick Start" (#quick-start) ·
"Configuration" (#configuration) ·
"Documentation" (#documentation)

</div>---

«[!IMPORTANT]
Oxidity Searcher is advanced blockchain infrastructure.

It requires a locally operated execution client, a deployed executor contract, secure signer management, and a thorough understanding of transaction simulation, private order flow, smart-contract risk, and Ethereum execution semantics.»

«[!CAUTION]
Never commit ".env", private keys, relay signing keys, keystore files, or production configuration to source control. Use isolated signers with tightly limited funds and permissions.»

Overview

Oxidity Searcher is an ultra-low-latency, multi-strategy Maximal Extractable Value searcher built in Rust for Ethereum Mainnet and EVM-compatible networks.

It consumes pending transactions directly from local execution-node mempools, decodes multi-DEX interactions in real time, generates candidate execution bundles, evaluates profitability, pre-simulates execution against a local EVM endpoint, and submits signed atomic bundles to private block builders.

Core execution flow

Local Reth / Geth
        |
        v
Pending Transaction Stream
        |
        v
Parallel Decode and Classification
        |
        v
Strategy Candidate Generation
        |
        v
Optimal Trade-Sizing Solver
        |
        v
Safety and Toxicity Checks
        |
        v
Local Bundle Simulation
        |
        +-- Reverting / Unprofitable --> Drop
        |
        v
Private Builder Submission

Supported infrastructure

Layer| Integrations
Execution clients| Reth, Geth
Transport| HTTP JSON-RPC, WebSockets
Simulation| "eth_simulateV1", "debug_traceCall"
DEX protocols| Uniswap V2, Uniswap V3, Sushiswap, Balancer, Curve
Flash liquidity| Balancer V2, Aave V3
Private builders| Flashbots, BeaverBuild, Titan
Runtime| Tokio, Rayon
Storage| SQLite
Primary language| Rust

---

Key Features

High-throughput parallel pipeline

Built around Tokio and Rayon, with parallelized processing for:

- Pending-transaction ingestion
- Calldata decoding
- Swap classification
- Pool-state analysis
- Candidate generation
- Profitability evaluation
- Bundle construction
- Simulation and relay submission

The pipeline is designed for high-throughput local-node environments where latency directly affects execution viability.

Multi-strategy engine

Cross-DEX and triangular arbitrage

Searches multi-hop token graphs for profitable execution paths across supported liquidity venues.

Token A -> Token B -> Token C -> Token A

Supported route families include:

- Uniswap V2-compatible pools
- Uniswap V3 concentrated-liquidity pools
- Sushiswap
- Balancer
- Curve

Atomic transaction-ordering strategies

Constructs ordered, atomic bundles around qualifying pending swaps and evaluates the complete bundle locally before submission.

«[!WARNING]
Transaction-ordering strategies may be restricted by relay policies, application rules, contractual obligations, or applicable law. Operators are responsible for determining whether a strategy is permitted in their jurisdiction and execution environment.»

Uniswap V3 JIT liquidity

Evaluates temporary concentrated-liquidity positions around qualifying large swaps, including:

1. Liquidity minting
2. Target swap execution
3. Liquidity removal
4. Fee and profitability accounting

Adversarial transaction detection

Detects suspicious or weakly protected transaction patterns, including unusually permissive output constraints, and evaluates defensive or counter-execution opportunities.

Honeypot and toxic-token screening

Provides automated sell-path probes and toxicity caching through mechanisms such as:

probe_v2_sell_for_toxicity(...)
probe_v3_sell_for_toxicity(...)

Tokens that fail configured safety checks can be cached and excluded from later candidate generation.

Analytical trade sizing

The sizing solver estimates peak-profit trade sizes while respecting configured pool-impact constraints.

A simplified maximum-size bound is:

$$
S_{\max}

\frac{\text{max_bps} \cdot R_1}
{10000-\text{max_bps}}
$$

Where:

Symbol| Meaning
$S_{\max}$| Maximum permitted input size
$\text{max_bps}$| Configured price-impact limit
$R_1$| Relevant pool reserve
$S^*$| Estimated optimal profitable size

Candidate sizing is bounded by liquidity, price impact, flash-liquidity availability, gas cost, builder payment, and configured risk limits.

Atomic flash-liquidity integration

Supports flash-liquidity execution through:

- Balancer V2 Vault
- Aave V3 pools

This allows qualifying strategies to execute without requiring the operator to permanently hold the full trade principal.

«[!NOTE]
Flash liquidity does not remove execution risk. Profitability still depends on contract correctness, simulation accuracy, state freshness, builder inclusion, gas accounting, token behavior, and protocol-specific fees.»

Simulation-first execution gate

Every candidate bundle can be simulated locally before relay submission.

Bundles are rejected when simulation indicates:

- Transaction reversion
- Insufficient output
- Negative net profit
- Excessive gas usage
- Invalid nonce or state assumptions
- Failed token-safety checks
- Violated price-impact limits
- Insufficient builder-payment margin

Simulation substantially reduces avoidable execution failures, but it cannot guarantee inclusion, profitability, or protection from state changes.

Private builder submission

Signed atomic bundles can be submitted directly to configured private builder endpoints, including:

- Flashbots
- BeaverBuild
- Titan

Example endpoint:

https://relay.flashbots.net

Relay authentication is performed using a dedicated ECDSA bundle-signing key.

---

Architecture

+------------------------------------------------------------+
|                    Local Execution Client                  |
|                       Reth or Geth                          |
+------------------------------+-----------------------------+
                               |
                     HTTP / WebSocket RPC
                               |
+------------------------------v-----------------------------+
|                    Mempool Ingestion Layer                 |
|  Subscription management, reconnects, and deduplication   |
+------------------------------+-----------------------------+
                               |
+------------------------------v-----------------------------+
|                    Transaction Decoder                     |
|  Router detection, calldata decoding, swap classification |
+------------------------------+-----------------------------+
                               |
+------------------------------v-----------------------------+
|                    Strategy Engine                         |
|  Arbitrage, JIT liquidity, ordered bundles, screening     |
+------------------------------+-----------------------------+
                               |
+------------------------------v-----------------------------+
|                  Optimization and Risk Layer               |
|  Sizing, price impact, toxicity cache, profitability      |
+------------------------------+-----------------------------+
                               |
+------------------------------v-----------------------------+
|                    Executor Integration                    |
|  Calldata construction, flash liquidity, atomic actions   |
+------------------------------+-----------------------------+
                               |
+------------------------------v-----------------------------+
|                    Local EVM Simulation                    |
|        eth_simulateV1, debug_traceCall, validation        |
+------------------------------+-----------------------------+
                               |
+------------------------------v-----------------------------+
|                   Private Relay Submission                |
|           Flashbots, BeaverBuild, Titan builders          |
+------------------------------------------------------------+

---

System Requirements

Minimum software requirements

Component| Requirement
Operating system| Linux
Recommended distributions| Ubuntu 22.04 LTS+, Debian 12+
Rust toolchain| Rust 1.78 or newer
Build tools| "cargo", "rustc"
Execution node| Local Reth or performance-tuned Geth
Database| SQLite 3
Network| Stable low-latency connection
Time synchronization| NTP or equivalent

Required RPC endpoints

A typical local configuration exposes:

HTTP:      http://127.0.0.1:8545
WebSocket: ws://127.0.0.1:8546

The execution client should support the methods required by the enabled strategies, including:

eth_subscribe
eth_call
eth_getBlockByNumber
eth_getTransactionCount
eth_feeHistory
eth_simulateV1
debug_traceCall

«[!TIP]
Run the searcher and execution client on the same machine or local network whenever possible. Public RPC endpoints generally introduce too much latency, rate limiting, and inconsistent pending-transaction visibility for competitive searcher operation.»

Storage

SQLite is initialized automatically:

oxidity_searcher.db

---

Quick Start

1. Clone the repository

git clone https://github.com/John0n1/oxidity-searcher.git
cd oxidity-searcher

2. Build the release binary

cargo build --release

The compiled binary will be available at:

target/release/oxidity-searcher

3. Create the environment file

cp .env.example .env

Configure the required signer and contract values:

OXIDITY_WALLET_PRIVATE_KEY=0xYOUR_PRIVATE_KEY
OXIDITY_WALLET_ADDRESS=0xYOUR_WALLET_ADDRESS
OXIDITY_BUNDLE_PRIVATE_KEY=0xYOUR_BUNDLE_SIGNER_KEY
OXIDITY_FLASHLOAN_CONTRACT_ADDRESS=0xYOUR_DEPLOYED_EXECUTOR_ADDRESS

«[!CAUTION]
Use separate keys for transaction signing and relay authentication. Do not use a primary wallet, exchange wallet, or wallet containing unrelated funds.»

4. Restrict environment-file permissions

chmod 600 .env

5. Validate the configuration

target/release/oxidity-searcher \
  --config config.toml \
  --shadow-mode

---

Shadow Mode

Shadow mode monitors live Mainnet activity and evaluates opportunities without broadcasting production transactions.

CHAINS=1 \
target/release/oxidity-searcher \
  --config config.toml \
  --shadow-mode

Use shadow mode to validate:

- Mempool connectivity
- DEX decoding
- Pool discovery
- Strategy generation
- Sizing behavior
- Gas estimation
- Simulation success rates
- Profit calculations
- Builder configuration

«[!TIP]
Run shadow mode for an extended period before enabling live execution. Compare detected opportunities against actual block outcomes and inspect false positives, simulation mismatches, and stale-state failures.»

---

Production Mode

Before enabling live execution, verify that:

- The executor contract is deployed
- Contract ownership and access controls are correct
- Providers and pools are allowlisted
- The signer has sufficient gas and builder-payment capital
- Relay authentication is working
- Simulation succeeds against current Mainnet state
- Profit thresholds include gas and builder payments
- Emergency pause and withdrawal paths have been tested
- Monitoring and alerting are active

Example production configuration:

debug = false
shadow_mode = false
dry_run = false
flashloan_enabled = true

Launch the searcher:

CHAINS=1 \
target/release/oxidity-searcher \
  --config config.toml

«[!WARNING]
Start with strict limits and minimal signer capital. A successful simulation does not guarantee builder inclusion or identical execution state at the target block.»

---

Configuration

Oxidity Searcher uses both environment variables and "config.toml".

Environment variables

Variable| Purpose| Secret
"OXIDITY_WALLET_PRIVATE_KEY"| Transaction-signing key| Yes
"OXIDITY_WALLET_ADDRESS"| Executor wallet address| No
"OXIDITY_BUNDLE_PRIVATE_KEY"| Private-relay authentication key| Yes
"OXIDITY_FLASHLOAN_CONTRACT_ADDRESS"| Deployed executor contract| No
"CHAINS"| Enabled chain IDs| No

Operational modes

Mode| Broadcasts transactions| Uses live state| Recommended purpose
Shadow mode| No| Yes| Strategy observation
Dry run| No| Yes| End-to-end validation
Debug mode| Depends on configuration| Yes| Diagnostics
Production mode| Yes| Yes| Live execution

Example "config.toml"

debug = false
shadow_mode = true
dry_run = true
flashloan_enabled = false

Configuration fields and defaults are documented in:

docs/CONFIG.md

---

Testing

Run the complete Rust test suite:

cargo test --all

Run tests with release optimizations:

cargo test --release --all

Run Clippy with warnings treated as errors:

cargo clippy --all-targets --all-features -- -D warnings

Check formatting:

cargo fmt --all -- --check

Run a release build:

cargo build --release

For contract, fork, integration, and simulation testing, see:

- ""docs/TESTING.md"" (docs/TESTING.md)
- ""docs/CONTRACT_DEPLOYMENT.md"" (docs/CONTRACT_DEPLOYMENT.md)

---

Recommended Production Checks

Before each live deployment, confirm:

[ ] Execution node is fully synchronized
[ ] Pending-transaction subscription is healthy
[ ] System clock is synchronized
[ ] HTTP and WebSocket RPC endpoints are local
[ ] Executor bytecode matches the audited build
[ ] Contract ownership is correctly configured
[ ] Provider allowlists are enabled
[ ] Signer balances are intentionally limited
[ ] Relay credentials are valid
[ ] Simulation methods are available
[ ] Profit thresholds include all execution costs
[ ] Emergency pause functionality has been tested
[ ] Database backups and log rotation are configured
[ ] Metrics, alerts, and failure notifications are active

---

Documentation

Detailed documentation is available in the ""docs/"" (docs/) directory.

Document| Description
"Configuration Reference" (docs/CONFIG.md)| Complete configuration fields, defaults, and examples
"Contract Deployment Guide" (docs/CONTRACT_DEPLOYMENT.md)| Executor deployment and initialization
"Execution Client Setup" (docs/EXECUTION_CLIENT.md)| Local Reth and RPC configuration
"Testing and Verification" (docs/TESTING.md)| Unit, integration, fork, and simulation testing
"Contributing Guidelines" (CONTRIBUTING.md)| Development workflow and contribution standards

---

Security

This repository interacts with private keys, smart contracts, public mempools, private relays, flash-liquidity providers, and rapidly changing blockchain state.

Operators should assume that:

- Configuration mistakes may cause financial loss
- Tokens may contain malicious or non-standard behavior
- RPC state may become stale between simulation and execution
- Private bundles may not be included
- Builder behavior and policies may change
- Smart-contract vulnerabilities may bypass off-chain checks
- Flash-liquidity callbacks increase contract complexity
- Logging secrets may expose signer credentials
- Dependency compromise may affect transaction construction

Recommended key separation

+-----------------------------+
| Production Transaction Key  |
| Limited gas and bribe funds |
+-----------------------------+

+-----------------------------+
| Relay Authentication Key    |
| No custody funds required   |
+-----------------------------+

+-----------------------------+
| Contract Administration Key |
| Offline or hardware-backed  |
+-----------------------------+

«[!IMPORTANT]
Off-chain simulation is a safety layer, not a substitute for executor-contract auditing, strict access controls, bounded approvals, provider validation, emergency controls, and production monitoring.»

---

Contributing

Contributions should follow the repository guidelines:

CONTRIBUTING.md

Before submitting a pull request:

cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all
cargo build --release

Security-sensitive issues should not be disclosed through a public issue before maintainers have had an opportunity to review them privately.

---

Responsible Use

Oxidity Searcher is provided for research, infrastructure development, simulation, testing, and lawful blockchain execution.

Users are solely responsible for:

- Compliance with applicable laws and regulations
- Compliance with builder and relay policies
- Smart-contract review and deployment safety
- Key custody and infrastructure security
- Strategy configuration
- Financial and operational risk
- Effects on users and protocols

---

License

Copyright © 2026 John Hauger Mitander
Contact: "john@oxidity.io"

Licensed under the "MIT License" (LICENSE).

---

<div align="center">Built with Rust for low-latency EVM execution.

"Back to top" (#oxidity-searcher)

</div>