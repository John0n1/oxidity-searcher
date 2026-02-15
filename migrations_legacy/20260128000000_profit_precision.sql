-- Add integer-weighted accounting fields to avoid float precision loss
ALTER TABLE profit_records ADD COLUMN profit_wei TEXT;
ALTER TABLE profit_records ADD COLUMN gas_cost_wei TEXT;
ALTER TABLE profit_records ADD COLUMN net_profit_wei TEXT;
