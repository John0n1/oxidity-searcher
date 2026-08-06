-- Authoritative execution lifecycle and realized-settlement ledger.
-- Pre-execution estimates are deliberately separated from realized P&L.

CREATE TABLE IF NOT EXISTS execution_estimates (
    estimate_id TEXT PRIMARY KEY,
    chain_id INTEGER NOT NULL,
    strategy TEXT NOT NULL,
    opportunity_id TEXT,
    planned_tx_hash TEXT,
    settlement_token TEXT NOT NULL,
    estimated_gross_wei TEXT NOT NULL,
    estimated_gas_wei TEXT NOT NULL,
    estimated_bribe_wei TEXT NOT NULL,
    estimated_flashloan_premium_wei TEXT NOT NULL,
    estimated_net_wei TEXT NOT NULL,
    simulation_block_number INTEGER,
    simulation_block_hash TEXT,
    status TEXT NOT NULL DEFAULT 'simulated'
        CHECK (status IN ('simulated', 'submitted', 'rejected', 'expired')),
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS execution_attempts (
    tx_hash TEXT PRIMARY KEY,
    estimate_id TEXT,
    chain_id INTEGER NOT NULL,
    strategy TEXT NOT NULL,
    submission_mode TEXT NOT NULL
        CHECK (submission_mode IN ('shadow', 'private_bundle', 'mev_share', 'public')),
    status TEXT NOT NULL
        CHECK (status IN ('shadow', 'submitted', 'included', 'reverted', 'dropped', 'reorged')),
    nonce INTEGER,
    target_block INTEGER,
    included_block_number INTEGER,
    included_block_hash TEXT,
    gas_used TEXT,
    effective_gas_price_wei TEXT,
    actual_gas_cost_wei TEXT,
    error TEXT,
    submitted_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (estimate_id) REFERENCES execution_estimates(estimate_id)
);

CREATE TABLE IF NOT EXISTS settlements (
    tx_hash TEXT PRIMARY KEY,
    chain_id INTEGER NOT NULL,
    strategy TEXT NOT NULL,
    settlement_token TEXT NOT NULL,
    realized_gross_delta_wei TEXT NOT NULL,
    actual_gas_cost_wei TEXT NOT NULL,
    realized_net_delta_wei TEXT NOT NULL,
    block_number INTEGER NOT NULL,
    block_hash TEXT NOT NULL,
    confirmations INTEGER NOT NULL DEFAULT 1,
    finalized BOOLEAN NOT NULL DEFAULT FALSE,
    liquid BOOLEAN NOT NULL DEFAULT TRUE,
    reusable BOOLEAN NOT NULL DEFAULT FALSE,
    created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (tx_hash) REFERENCES execution_attempts(tx_hash)
);

CREATE TABLE IF NOT EXISTS settlement_deltas (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_hash TEXT NOT NULL,
    account TEXT NOT NULL,
    asset TEXT NOT NULL,
    decimals INTEGER NOT NULL,
    balance_before TEXT NOT NULL,
    balance_after TEXT NOT NULL,
    delta_raw TEXT NOT NULL,
    liquid BOOLEAN NOT NULL DEFAULT TRUE,
    FOREIGN KEY (tx_hash) REFERENCES settlements(tx_hash),
    UNIQUE (tx_hash, account, asset)
);

CREATE INDEX IF NOT EXISTS idx_execution_estimates_strategy_created
    ON execution_estimates(chain_id, strategy, created_at);
CREATE INDEX IF NOT EXISTS idx_execution_attempts_status_updated
    ON execution_attempts(chain_id, status, updated_at);
CREATE INDEX IF NOT EXISTS idx_settlements_reusable
    ON settlements(chain_id, reusable, updated_at);
CREATE INDEX IF NOT EXISTS idx_settlement_deltas_tx
    ON settlement_deltas(tx_hash);
