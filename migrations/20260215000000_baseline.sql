-- Squashed baseline migration for fresh databases.
-- Historical migrations are preserved in ./migrations_legacy for existing DBs.

CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_hash TEXT NOT NULL UNIQUE,
    chain_id INTEGER NOT NULL,
    block_number INTEGER,
    from_address TEXT NOT NULL,
    to_address TEXT,
    value_wei TEXT NOT NULL,
    gas_used INTEGER,
    gas_price_wei TEXT,
    status BOOLEAN,
    strategy TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    execution_time_ms REAL
);

CREATE TABLE IF NOT EXISTS profit_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_hash TEXT NOT NULL,
    chain_id INTEGER NOT NULL,
    strategy TEXT NOT NULL,
    profit_eth REAL NOT NULL,
    gas_cost_eth REAL NOT NULL,
    net_profit_eth REAL NOT NULL,
    profit_wei TEXT,
    gas_cost_wei TEXT,
    net_profit_wei TEXT,
    bribe_wei TEXT NOT NULL DEFAULT '0',
    flashloan_premium_wei TEXT NOT NULL DEFAULT '0',
    effective_cost_wei TEXT NOT NULL DEFAULT '0',
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS market_prices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id INTEGER NOT NULL,
    symbol TEXT NOT NULL,
    price_usd REAL NOT NULL,
    source TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS nonce_state (
    chain_id INTEGER PRIMARY KEY,
    block_number INTEGER NOT NULL,
    next_nonce INTEGER NOT NULL,
    touched_pools TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS router_discovery (
    chain_id INTEGER NOT NULL,
    address TEXT NOT NULL,
    seen_count INTEGER NOT NULL DEFAULT 0,
    first_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    last_seen DATETIME DEFAULT CURRENT_TIMESTAMP,
    status TEXT NOT NULL DEFAULT 'pending',
    router_kind TEXT,
    last_source TEXT,
    last_reason TEXT,
    notes TEXT,
    PRIMARY KEY (chain_id, address)
);

CREATE INDEX IF NOT EXISTS idx_tx_hash ON transactions(tx_hash);
CREATE INDEX IF NOT EXISTS idx_profit_strategy ON profit_records(strategy);
CREATE INDEX IF NOT EXISTS idx_router_discovery_status ON router_discovery(status);
CREATE INDEX IF NOT EXISTS idx_router_discovery_last_seen ON router_discovery(last_seen);
