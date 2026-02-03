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

-- 3) Append-only ledger events
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

-- 4) Evidence units (metadata; payload optional)
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

-- 5) Claim maps (finalization records)
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
