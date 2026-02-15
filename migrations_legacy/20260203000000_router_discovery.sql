-- Router discovery (unknown routers seen in mempool/MEV-Share)
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

CREATE INDEX IF NOT EXISTS idx_router_discovery_status
    ON router_discovery(status);
CREATE INDEX IF NOT EXISTS idx_router_discovery_last_seen
    ON router_discovery(last_seen);
