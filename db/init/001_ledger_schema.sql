-- PECR V1 baseline ledger schema.
--
-- Normative fields per SSOT:
--   - C:\Research\pcdr\spec\05_DATASTORE_AND_MIGRATIONS.md :: Ledger schema (V1 baseline)

-- 1) Policy snapshots (immutable)
CREATE TABLE pecr_policy_snapshots (
  policy_snapshot_id TEXT PRIMARY KEY,
  policy_snapshot_hash TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  as_of_time TIMESTAMPTZ NOT NULL,
  policy_bundle_hash TEXT NOT NULL,
  input_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX pecr_policy_snapshots_hash_idx
  ON pecr_policy_snapshots(policy_snapshot_hash);
CREATE INDEX pecr_policy_snapshots_principal_asof_idx
  ON pecr_policy_snapshots(principal_id, as_of_time DESC);

-- 2) Sessions
CREATE TABLE pecr_sessions (
  session_id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL,
  principal_id TEXT NOT NULL,
  policy_snapshot_id TEXT NOT NULL REFERENCES pecr_policy_snapshots(policy_snapshot_id),
  budget_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finalized_at TIMESTAMPTZ,
  terminal_mode TEXT
);

CREATE INDEX pecr_sessions_trace_id_idx ON pecr_sessions(trace_id);
CREATE INDEX pecr_sessions_policy_snapshot_id_idx ON pecr_sessions(policy_snapshot_id);
CREATE INDEX pecr_sessions_active_idx ON pecr_sessions(finalized_at) WHERE finalized_at IS NULL;

-- 3) Session runtime snapshot (restart-safe runtime state)
CREATE TABLE pecr_session_runtime (
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

CREATE INDEX pecr_session_runtime_updated_at_idx ON pecr_session_runtime(updated_at);
CREATE INDEX pecr_session_runtime_expires_at_idx
  ON pecr_session_runtime(session_token_expires_at_epoch_ms);
CREATE INDEX pecr_session_runtime_finalized_updated_idx
  ON pecr_session_runtime(finalized, updated_at);

-- 4) Append-only ledger events
CREATE TABLE pecr_ledger_events (
  event_id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL,
  session_id TEXT NOT NULL REFERENCES pecr_sessions(session_id),
  event_type TEXT NOT NULL,
  event_time TIMESTAMPTZ NOT NULL DEFAULT now(),
  principal_id TEXT NOT NULL,
  policy_snapshot_id TEXT NOT NULL,
  payload_json JSONB NOT NULL,
  payload_hash TEXT NOT NULL
);

CREATE INDEX pecr_ledger_events_trace_id_idx ON pecr_ledger_events(trace_id);
CREATE INDEX pecr_ledger_events_event_type_idx ON pecr_ledger_events(event_type);
CREATE INDEX pecr_ledger_events_trace_time_idx
  ON pecr_ledger_events(trace_id, event_time DESC);
CREATE INDEX pecr_ledger_events_session_time_idx
  ON pecr_ledger_events(session_id, event_time DESC);
CREATE INDEX pecr_ledger_events_policy_snapshot_id_idx
  ON pecr_ledger_events(policy_snapshot_id);

-- 5) Evidence units (metadata; payload optional)
CREATE TABLE pecr_evidence_units (
  evidence_unit_id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL,
  session_id TEXT NOT NULL REFERENCES pecr_sessions(session_id),
  source_system TEXT NOT NULL,
  object_id TEXT NOT NULL,
  version_id TEXT NOT NULL,
  span_or_row_spec_json JSONB NOT NULL,
  content_type TEXT NOT NULL,
  content_hash TEXT NOT NULL,
  as_of_time TIMESTAMPTZ NOT NULL,
  retrieved_at TIMESTAMPTZ NOT NULL,
  policy_snapshot_id TEXT NOT NULL,
  policy_snapshot_hash TEXT NOT NULL,
  transform_chain_json JSONB NOT NULL,
  payload_json JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX pecr_evidence_units_trace_id_idx ON pecr_evidence_units(trace_id);
CREATE INDEX pecr_evidence_units_object_id_idx ON pecr_evidence_units(object_id);
CREATE INDEX pecr_evidence_units_trace_created_at_idx
  ON pecr_evidence_units(trace_id, created_at DESC);
CREATE INDEX pecr_evidence_units_session_created_at_idx
  ON pecr_evidence_units(session_id, created_at DESC);
CREATE INDEX pecr_evidence_units_policy_snapshot_id_idx
  ON pecr_evidence_units(policy_snapshot_id);
CREATE INDEX pecr_evidence_units_object_version_idx
  ON pecr_evidence_units(object_id, version_id);

-- 6) Claim maps (finalization records)
CREATE TABLE pecr_claim_maps (
  claim_map_id TEXT PRIMARY KEY,
  trace_id TEXT NOT NULL,
  session_id TEXT NOT NULL REFERENCES pecr_sessions(session_id),
  terminal_mode TEXT NOT NULL,
  coverage_threshold DOUBLE PRECISION NOT NULL,
  coverage_observed DOUBLE PRECISION NOT NULL,
  claim_map_json JSONB NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX pecr_claim_maps_session_id_idx ON pecr_claim_maps(session_id);
CREATE INDEX pecr_claim_maps_trace_created_at_idx
  ON pecr_claim_maps(trace_id, created_at DESC);

-- Append-only enforcement for audit-grade tables.
CREATE OR REPLACE FUNCTION pecr_reject_update_delete() RETURNS trigger AS $$
BEGIN
  RAISE EXCEPTION 'append-only table: %', TG_TABLE_NAME;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS pecr_policy_snapshots_append_only ON pecr_policy_snapshots;
CREATE TRIGGER pecr_policy_snapshots_append_only
  BEFORE UPDATE OR DELETE ON pecr_policy_snapshots
  FOR EACH ROW EXECUTE FUNCTION pecr_reject_update_delete();

DROP TRIGGER IF EXISTS pecr_ledger_events_append_only ON pecr_ledger_events;
CREATE TRIGGER pecr_ledger_events_append_only
  BEFORE UPDATE OR DELETE ON pecr_ledger_events
  FOR EACH ROW EXECUTE FUNCTION pecr_reject_update_delete();

DROP TRIGGER IF EXISTS pecr_evidence_units_append_only ON pecr_evidence_units;
CREATE TRIGGER pecr_evidence_units_append_only
  BEFORE UPDATE OR DELETE ON pecr_evidence_units
  FOR EACH ROW EXECUTE FUNCTION pecr_reject_update_delete();

DROP TRIGGER IF EXISTS pecr_claim_maps_append_only ON pecr_claim_maps;
CREATE TRIGGER pecr_claim_maps_append_only
  BEFORE UPDATE OR DELETE ON pecr_claim_maps
  FOR EACH ROW EXECUTE FUNCTION pecr_reject_update_delete();
