-- Add explicit profit cost components for accurate net PnL accounting.
ALTER TABLE profit_records ADD COLUMN bribe_wei TEXT NOT NULL DEFAULT '0';
ALTER TABLE profit_records ADD COLUMN flashloan_premium_wei TEXT NOT NULL DEFAULT '0';
ALTER TABLE profit_records ADD COLUMN effective_cost_wei TEXT NOT NULL DEFAULT '0';
