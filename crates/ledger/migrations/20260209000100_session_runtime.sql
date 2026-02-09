-- Session runtime persistence for restart-safe and multi-instance-safe session handling.
CREATE TABLE IF NOT EXISTS pecr_session_runtime (
  session_id TEXT PRIMARY KEY REFERENCES pecr_sessions(session_id) ON DELETE CASCADE,
  tenant_id TEXT NOT NULL,
  session_token_hash TEXT NOT NULL,
  session_token_expires_at_epoch_ms BIGINT NOT NULL,
  operator_calls_used BIGINT NOT NULL DEFAULT 0,
  bytes_used BIGINT NOT NULL DEFAULT 0,
  evidence_unit_ids_json JSONB NOT NULL DEFAULT '[]'::jsonb,
  finalized BOOLEAN NOT NULL DEFAULT false,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CHECK (operator_calls_used >= 0),
  CHECK (bytes_used >= 0),
  CHECK (jsonb_typeof(evidence_unit_ids_json) = 'array')
);

CREATE INDEX IF NOT EXISTS pecr_session_runtime_updated_at_idx
  ON pecr_session_runtime(updated_at);
