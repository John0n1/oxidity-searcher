-- Persisted bundle state to avoid nonce reuse after restarts
CREATE TABLE IF NOT EXISTS nonce_state (
    chain_id INTEGER PRIMARY KEY,
    block_number INTEGER NOT NULL,
    next_nonce INTEGER NOT NULL,
    touched_pools TEXT NOT NULL,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
);
