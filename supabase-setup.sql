-- ============================================================================
-- MCP Domain Lookup — Supabase Database Setup
-- Run this SQL in your Supabase SQL Editor (Dashboard → SQL Editor → New Query)
-- ============================================================================

-- 1. API Keys table
CREATE TABLE IF NOT EXISTS api_keys (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  api_key TEXT UNIQUE NOT NULL,
  email TEXT NOT NULL,
  tier TEXT NOT NULL DEFAULT 'starter' CHECK (tier IN ('starter', 'pro', 'unlimited')),
  monthly_limit INTEGER,
  requests_used INTEGER DEFAULT 0,
  billing_cycle_start TIMESTAMPTZ DEFAULT now(),
  created_at TIMESTAMPTZ DEFAULT now(),
  is_active BOOLEAN DEFAULT true,
  stripe_customer_id TEXT
);

-- 2. Request logs table
CREATE TABLE IF NOT EXISTS request_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  api_key_id UUID REFERENCES api_keys(id) ON DELETE SET NULL,
  ip_address TEXT,
  tool_name TEXT,
  domain_queried TEXT,
  created_at TIMESTAMPTZ DEFAULT now(),
  response_time_ms INTEGER
);

-- 3. Free tier usage table
CREATE TABLE IF NOT EXISTS free_tier_usage (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  ip_address TEXT NOT NULL,
  date DATE NOT NULL DEFAULT CURRENT_DATE,
  requests_used INTEGER DEFAULT 0,
  UNIQUE (ip_address, date)
);

-- ============================================================================
-- Indexes
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_api_keys_api_key ON api_keys (api_key);
CREATE INDEX IF NOT EXISTS idx_api_keys_email ON api_keys (email);
CREATE INDEX IF NOT EXISTS idx_request_logs_api_key_id ON request_logs (api_key_id);
CREATE INDEX IF NOT EXISTS idx_request_logs_created_at ON request_logs (created_at);
CREATE INDEX IF NOT EXISTS idx_request_logs_ip_address ON request_logs (ip_address);
CREATE INDEX IF NOT EXISTS idx_free_tier_usage_ip_date ON free_tier_usage (ip_address, date);

-- ============================================================================
-- Auto-reset function: resets requests_used when billing cycle > 30 days old
-- ============================================================================

CREATE OR REPLACE FUNCTION reset_billing_cycle()
RETURNS TRIGGER AS $$
BEGIN
  IF NEW.billing_cycle_start + INTERVAL '30 days' < now() THEN
    NEW.requests_used := 0;
    NEW.billing_cycle_start := now();
  END IF;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-reset on any update to the api_keys row
DROP TRIGGER IF EXISTS trg_reset_billing_cycle ON api_keys;
CREATE TRIGGER trg_reset_billing_cycle
  BEFORE UPDATE ON api_keys
  FOR EACH ROW
  EXECUTE FUNCTION reset_billing_cycle();

-- ============================================================================
-- API Key generation function
-- Generates a key with prefix "dk_live_" followed by 32 hex characters
-- ============================================================================

CREATE OR REPLACE FUNCTION generate_api_key(
  p_email TEXT,
  p_tier TEXT DEFAULT 'starter'
)
RETURNS TEXT AS $$
DECLARE
  v_key TEXT;
  v_limit INTEGER;
BEGIN
  -- Generate key: dk_live_ + 32 random hex chars
  v_key := 'dk_live_' || encode(gen_random_bytes(16), 'hex');

  -- Set monthly limit based on tier
  CASE p_tier
    WHEN 'starter' THEN v_limit := 500;
    WHEN 'pro' THEN v_limit := 5000;
    WHEN 'unlimited' THEN v_limit := NULL;
    ELSE RAISE EXCEPTION 'Invalid tier: %', p_tier;
  END CASE;

  INSERT INTO api_keys (api_key, email, tier, monthly_limit)
  VALUES (v_key, p_email, p_tier, v_limit);

  RETURN v_key;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Row Level Security
-- ============================================================================

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE request_logs ENABLE ROW LEVEL SECURITY;
ALTER TABLE free_tier_usage ENABLE ROW LEVEL SECURITY;

-- Service role (our server) can do everything
CREATE POLICY "Service role full access on api_keys"
  ON api_keys FOR ALL
  USING (true)
  WITH CHECK (true);

CREATE POLICY "Service role full access on request_logs"
  ON request_logs FOR ALL
  USING (true)
  WITH CHECK (true);

CREATE POLICY "Service role full access on free_tier_usage"
  ON free_tier_usage FOR ALL
  USING (true)
  WITH CHECK (true);

-- ============================================================================
-- Cleanup: delete free_tier_usage rows older than 7 days (run periodically)
-- ============================================================================

CREATE OR REPLACE FUNCTION cleanup_old_free_tier_usage()
RETURNS void AS $$
BEGIN
  DELETE FROM free_tier_usage WHERE date < CURRENT_DATE - INTERVAL '7 days';
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- Done! Your database is ready.
-- Next steps:
--   1. Copy your Supabase URL and service_role key
--   2. Set SUPABASE_URL and SUPABASE_SERVICE_KEY in your .env
--   3. Run: node generate-key.js --email you@example.com --tier starter
-- ============================================================================
