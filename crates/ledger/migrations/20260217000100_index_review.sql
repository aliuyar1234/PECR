-- Index review for long-term scale and trace/session-heavy read patterns.

CREATE INDEX IF NOT EXISTS pecr_policy_snapshots_hash_idx
  ON pecr_policy_snapshots(policy_snapshot_hash);
CREATE INDEX IF NOT EXISTS pecr_policy_snapshots_principal_asof_idx
  ON pecr_policy_snapshots(principal_id, as_of_time DESC);

CREATE INDEX IF NOT EXISTS pecr_sessions_trace_id_idx
  ON pecr_sessions(trace_id);
CREATE INDEX IF NOT EXISTS pecr_sessions_policy_snapshot_id_idx
  ON pecr_sessions(policy_snapshot_id);
CREATE INDEX IF NOT EXISTS pecr_sessions_active_idx
  ON pecr_sessions(finalized_at) WHERE finalized_at IS NULL;

CREATE INDEX IF NOT EXISTS pecr_session_runtime_expires_at_idx
  ON pecr_session_runtime(session_token_expires_at_epoch_ms);
CREATE INDEX IF NOT EXISTS pecr_session_runtime_finalized_updated_idx
  ON pecr_session_runtime(finalized, updated_at);

CREATE INDEX IF NOT EXISTS pecr_ledger_events_trace_time_idx
  ON pecr_ledger_events(trace_id, event_time DESC);
CREATE INDEX IF NOT EXISTS pecr_ledger_events_session_time_idx
  ON pecr_ledger_events(session_id, event_time DESC);
CREATE INDEX IF NOT EXISTS pecr_ledger_events_policy_snapshot_id_idx
  ON pecr_ledger_events(policy_snapshot_id);

CREATE INDEX IF NOT EXISTS pecr_evidence_units_trace_created_at_idx
  ON pecr_evidence_units(trace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS pecr_evidence_units_session_created_at_idx
  ON pecr_evidence_units(session_id, created_at DESC);
CREATE INDEX IF NOT EXISTS pecr_evidence_units_policy_snapshot_id_idx
  ON pecr_evidence_units(policy_snapshot_id);
CREATE INDEX IF NOT EXISTS pecr_evidence_units_object_version_idx
  ON pecr_evidence_units(object_id, version_id);

CREATE INDEX IF NOT EXISTS pecr_claim_maps_session_id_idx
  ON pecr_claim_maps(session_id);
CREATE INDEX IF NOT EXISTS pecr_claim_maps_trace_created_at_idx
  ON pecr_claim_maps(trace_id, created_at DESC);
