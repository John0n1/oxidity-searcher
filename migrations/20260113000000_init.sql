-- Transactions table
CREATE TABLE IF NOT EXISTS transactions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_hash TEXT NOT NULL UNIQUE,
    chain_id INTEGER NOT NULL,
    block_number INTEGER,
    from_address TEXT NOT NULL,
    to_address TEXT,
    value_wei TEXT NOT NULL,  -- Stored as TEXT to prevent overflow
    gas_used INTEGER,
    gas_price_wei TEXT,       -- Stored as TEXT
    status BOOLEAN,
    strategy TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
    execution_time_ms REAL
);

-- Profit tracking
CREATE TABLE IF NOT EXISTS profit_records (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tx_hash TEXT NOT NULL,
    chain_id INTEGER NOT NULL,
    strategy TEXT NOT NULL,
    profit_eth REAL NOT NULL,
    gas_cost_eth REAL NOT NULL,
    net_profit_eth REAL NOT NULL,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Market Prices (Snapshots)
CREATE TABLE IF NOT EXISTS market_prices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chain_id INTEGER NOT NULL,
    symbol TEXT NOT NULL,
    price_usd REAL NOT NULL,
    source TEXT,
    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_tx_hash ON transactions(tx_hash);
CREATE INDEX IF NOT EXISTS idx_profit_strategy ON profit_records(strategy);