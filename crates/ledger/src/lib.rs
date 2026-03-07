use std::time::Duration;

use pecr_contracts::canonical;
use pecr_contracts::{Budget, ClaimMap, EvidenceUnit, PolicySnapshot, TerminalMode};
use sqlx::Row;
use sqlx::postgres::PgPoolOptions;
use ulid::Ulid;

#[derive(Debug)]
pub enum LedgerError {
    Timeout,
    InvalidInput(String),
    Sqlx(sqlx::Error),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::Timeout => write!(f, "ledger operation timed out"),
            LedgerError::InvalidInput(message) => write!(f, "ledger invalid input: {}", message),
            LedgerError::Sqlx(err) => write!(f, "ledger sql error: {}", err),
        }
    }
}

impl std::error::Error for LedgerError {}

impl From<sqlx::Error> for LedgerError {
    fn from(value: sqlx::Error) -> Self {
        LedgerError::Sqlx(value)
    }
}

#[derive(Clone)]
pub struct LedgerWriter {
    pool: sqlx::PgPool,
    write_timeout: Duration,
}

pub struct FinalizeResultRecord<'a> {
    pub trace_id: &'a str,
    pub session_id: &'a str,
    pub principal_id: &'a str,
    pub policy_snapshot_id: &'a str,
    pub policy_decision_reason: &'a str,
    pub claim_map: &'a ClaimMap,
    pub budget_counters: &'a serde_json::Value,
    pub request_id: &'a str,
    pub session_runtime: SessionRuntimeWrite<'a>,
}

pub struct OperatorResultRecord<'a> {
    pub trace_id: &'a str,
    pub session_id: &'a str,
    pub principal_id: &'a str,
    pub policy_snapshot_id: &'a str,
    pub policy_decision_reason: &'a str,
    pub op_name: &'a str,
    pub request_id: &'a str,
    pub params_hash: &'a str,
    pub cache_hit: bool,
    pub params_bytes: u64,
    pub result_bytes: u64,
    pub terminal_mode: TerminalMode,
    pub error_code: Option<&'a str>,
    pub evidence_units: &'a [EvidenceUnit],
    pub store_payload: bool,
    pub session_runtime: SessionRuntimeWrite<'a>,
}

pub struct SessionRuntimeWrite<'a> {
    pub session_id: &'a str,
    pub tenant_id: &'a str,
    pub session_token_hash: &'a str,
    pub session_token_expires_at_epoch_ms: i64,
    pub operator_calls_used: u32,
    pub bytes_used: u64,
    pub evidence_unit_ids: &'a [String],
    pub finalized: bool,
}

pub struct CreateSessionRecord<'a> {
    pub session_id: &'a str,
    pub trace_id: &'a str,
    pub principal_id: &'a str,
    pub budget: &'a Budget,
    pub policy_snapshot_id: &'a str,
    pub policy_snapshot: &'a PolicySnapshot,
    pub tenant_id: &'a str,
    pub session_token_hash: &'a str,
    pub session_token_expires_at_epoch_ms: i64,
}

#[derive(Debug, Clone)]
pub struct SessionRuntimeRecord {
    pub session_id: String,
    pub trace_id: String,
    pub principal_id: String,
    pub tenant_id: String,
    pub policy_snapshot_id: String,
    pub policy_snapshot_hash: String,
    pub as_of_time: String,
    pub budget: Budget,
    pub session_token_hash: String,
    pub session_token_expires_at_epoch_ms: i64,
    pub operator_calls_used: u32,
    pub bytes_used: u64,
    pub evidence_unit_ids: Vec<String>,
    pub finalized: bool,
}

impl LedgerWriter {
    pub async fn connect(db_url: &str, write_timeout: Duration) -> Result<Self, LedgerError> {
        let pool = tokio::time::timeout(
            Duration::from_secs(15),
            PgPoolOptions::new()
                .max_connections(8)
                .acquire_timeout(Duration::from_secs(10))
                .connect(db_url),
        )
        .await
        .map_err(|_| LedgerError::Timeout)??;

        Ok(Self {
            pool,
            write_timeout,
        })
    }

    pub async fn connect_and_migrate(
        db_url: &str,
        write_timeout: Duration,
    ) -> Result<Self, LedgerError> {
        let writer = Self::connect(db_url, write_timeout).await?;
        writer.migrate().await?;
        Ok(writer)
    }

    pub async fn migrate(&self) -> Result<(), LedgerError> {
        tokio::time::timeout(Duration::from_secs(30), migrate(&self.pool))
            .await
            .map_err(|_| LedgerError::Timeout)??;
        Ok(())
    }

    pub async fn ping(&self) -> Result<(), LedgerError> {
        tokio::time::timeout(
            self.write_timeout,
            sqlx::query("SELECT 1").execute(&self.pool),
        )
        .await
        .map_err(|_| LedgerError::Timeout)??;
        Ok(())
    }

    pub async fn create_session(&self, record: CreateSessionRecord<'_>) -> Result<(), LedgerError> {
        let budget_json =
            serde_json::to_value(record.budget).unwrap_or_else(|_| serde_json::json!({}));
        let input_json =
            serde_json::to_value(record.policy_snapshot).unwrap_or_else(|_| serde_json::json!({}));

        tokio::time::timeout(self.write_timeout, async {
            let mut tx = self.pool.begin().await?;

            sqlx::query(
                "INSERT INTO pecr_policy_snapshots (policy_snapshot_id, policy_snapshot_hash, principal_id, as_of_time, policy_bundle_hash, input_json) VALUES ($1, $2, $3, $4::timestamptz, $5, $6)",
            )
            .bind(record.policy_snapshot_id)
            .bind(&record.policy_snapshot.policy_snapshot_hash)
            .bind(record.principal_id)
            .bind(&record.policy_snapshot.as_of_time)
            .bind(&record.policy_snapshot.policy_bundle_hash)
            .bind(&input_json)
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "INSERT INTO pecr_sessions (session_id, trace_id, principal_id, policy_snapshot_id, budget_json) VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(record.session_id)
            .bind(record.trace_id)
            .bind(record.principal_id)
            .bind(record.policy_snapshot_id)
            .bind(&budget_json)
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "INSERT INTO pecr_session_runtime (session_id, tenant_id, session_token_hash, session_token_expires_at_epoch_ms, operator_calls_used, bytes_used, evidence_unit_ids_json, finalized, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now())",
            )
            .bind(record.session_id)
            .bind(record.tenant_id)
            .bind(record.session_token_hash)
            .bind(record.session_token_expires_at_epoch_ms)
            .bind(0_i64)
            .bind(0_i64)
            .bind(serde_json::json!([]))
            .bind(false)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;
            Ok::<(), sqlx::Error>(())
        })
        .await
        .map_err(|_| LedgerError::Timeout)??;

        Ok(())
    }

    pub async fn mark_session_finalized(
        &self,
        session_id: &str,
        terminal_mode: TerminalMode,
    ) -> Result<(), LedgerError> {
        let terminal_mode = terminal_mode.as_str();
        tokio::time::timeout(
            self.write_timeout,
            sqlx::query("UPDATE pecr_sessions SET finalized_at = now(), terminal_mode = $1 WHERE session_id = $2")
                .bind(terminal_mode)
                .bind(session_id)
                .execute(&self.pool),
        )
        .await
        .map_err(|_| LedgerError::Timeout)??;
        Ok(())
    }

    pub async fn append_event(
        &self,
        trace_id: &str,
        session_id: &str,
        event_type: &str,
        principal_id: &str,
        policy_snapshot_id: &str,
        payload_json: serde_json::Value,
    ) -> Result<String, LedgerError> {
        let event_id = Ulid::new().to_string();
        let payload_hash = canonical::hash_canonical_json(&payload_json);

        let execute_result = tokio::time::timeout(
            self.write_timeout,
            sqlx::query(
                "INSERT INTO pecr_ledger_events (event_id, trace_id, session_id, event_type, principal_id, policy_snapshot_id, payload_json, payload_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(&event_id)
            .bind(trace_id)
            .bind(session_id)
            .bind(event_type)
            .bind(principal_id)
            .bind(policy_snapshot_id)
            .bind(&payload_json)
            .bind(payload_hash)
            .execute(&self.pool),
        )
        .await;
        let execute_result = match execute_result {
            Ok(result) => result,
            Err(_) => {
                eprintln!(
                    "ledger.append_event_timed_out trace_id={} session_id={} event_type={}",
                    trace_id, session_id, event_type
                );
                return Err(LedgerError::Timeout);
            }
        };
        if let Err(err) = execute_result {
            eprintln!(
                "ledger.append_event_failed trace_id={} session_id={} event_type={} error={}",
                trace_id, session_id, event_type, err
            );
            return Err(LedgerError::Sqlx(err));
        }

        Ok(event_id)
    }

    pub async fn insert_evidence_unit(
        &self,
        trace_id: &str,
        session_id: &str,
        evidence: &EvidenceUnit,
        store_payload: bool,
    ) -> Result<(), LedgerError> {
        let transform_chain_json = serde_json::to_value(&evidence.transform_chain)
            .unwrap_or_else(|_| serde_json::json!([]));

        let payload_json = if store_payload {
            evidence.content.clone()
        } else {
            None
        };

        tokio::time::timeout(
            self.write_timeout,
            sqlx::query(
                "INSERT INTO pecr_evidence_units (evidence_unit_id, trace_id, session_id, source_system, object_id, version_id, span_or_row_spec_json, content_type, content_hash, as_of_time, retrieved_at, policy_snapshot_id, policy_snapshot_hash, transform_chain_json, payload_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::timestamptz,$11::timestamptz,$12,$13,$14,$15) ON CONFLICT (evidence_unit_id) DO NOTHING",
            )
            .bind(&evidence.evidence_unit_id)
            .bind(trace_id)
            .bind(session_id)
            .bind(&evidence.source_system)
            .bind(&evidence.object_id)
            .bind(&evidence.version_id)
            .bind(&evidence.span_or_row_spec)
            .bind(match evidence.content_type {
                pecr_contracts::EvidenceContentType::TextPlain => "text/plain",
                pecr_contracts::EvidenceContentType::ApplicationJson => "application/json",
            })
            .bind(&evidence.content_hash)
            .bind(&evidence.as_of_time)
            .bind(&evidence.retrieved_at)
            .bind(&evidence.policy_snapshot_id)
            .bind(&evidence.policy_snapshot_hash)
            .bind(&transform_chain_json)
            .bind(&payload_json)
            .execute(&self.pool),
        )
        .await
        .map_err(|_| LedgerError::Timeout)??;

        Ok(())
    }

    pub async fn insert_claim_map(
        &self,
        trace_id: &str,
        session_id: &str,
        claim_map: &ClaimMap,
    ) -> Result<(), LedgerError> {
        let claim_map_json =
            serde_json::to_value(claim_map).unwrap_or_else(|_| serde_json::json!({"claims": []}));

        tokio::time::timeout(
            self.write_timeout,
            sqlx::query(
                "INSERT INTO pecr_claim_maps (claim_map_id, trace_id, session_id, terminal_mode, coverage_threshold, coverage_observed, claim_map_json) VALUES ($1,$2,$3,$4,$5,$6,$7)",
            )
            .bind(&claim_map.claim_map_id)
            .bind(trace_id)
            .bind(session_id)
            .bind(claim_map.terminal_mode.as_str())
            .bind(claim_map.coverage_threshold)
            .bind(claim_map.coverage_observed)
            .bind(&claim_map_json)
            .execute(&self.pool),
        )
        .await
        .map_err(|_| LedgerError::Timeout)??;

        Ok(())
    }

    pub async fn record_finalize_result(
        &self,
        record: FinalizeResultRecord<'_>,
    ) -> Result<(), LedgerError> {
        let claim_map_json = serde_json::to_value(record.claim_map)
            .unwrap_or_else(|_| serde_json::json!({"claims": []}));
        let evidence_unit_ids_json = serde_json::to_value(record.session_runtime.evidence_unit_ids)
            .unwrap_or_else(|_| serde_json::json!([]));
        let bytes_used = checked_bigint_from_u64(record.session_runtime.bytes_used, "bytes_used")?;
        let policy_decision_payload = serde_json::json!({
            "decision": "allow",
            "reason": record.policy_decision_reason,
            "op_name": "finalize",
            "request_id": record.request_id,
        });
        let policy_decision_hash = canonical::hash_canonical_json(&policy_decision_payload);

        let payload_json = serde_json::json!({
            "terminal_mode": record.claim_map.terminal_mode.as_str(),
            "claim_map_id": record.claim_map.claim_map_id.clone(),
            "coverage_threshold": record.claim_map.coverage_threshold,
            "coverage_observed": record.claim_map.coverage_observed,
            "budget_counters": record.budget_counters,
            "request_id": record.request_id,
        });
        let payload_hash = canonical::hash_canonical_json(&payload_json);
        let policy_decision_event_id = canonical::hash_canonical_json(&serde_json::json!({
            "event_type": "POLICY_DECISION",
            "trace_id": record.trace_id,
            "session_id": record.session_id,
            "request_id": record.request_id,
            "policy_snapshot_id": record.policy_snapshot_id,
            "reason": record.policy_decision_reason,
        }));
        let event_id = canonical::hash_canonical_json(&serde_json::json!({
            "event_type": "FINALIZE_RESULT",
            "trace_id": record.trace_id,
            "session_id": record.session_id,
            "request_id": record.request_id,
            "claim_map_id": record.claim_map.claim_map_id,
        }));

        let mut last_error = None;
        for attempt in 0..3 {
            let policy_decision_event_id = policy_decision_event_id.clone();
            let policy_decision_payload = policy_decision_payload.clone();
            let policy_decision_hash = policy_decision_hash.clone();
            let claim_map_json = claim_map_json.clone();
            let event_id = event_id.clone();
            let payload_json = payload_json.clone();
            let payload_hash = payload_hash.clone();
            let evidence_unit_ids_json = evidence_unit_ids_json.clone();
            let execute_result = tokio::time::timeout(self.write_timeout, async {
                let mut tx = self.pool.begin().await?;

                sqlx::query(
                    "INSERT INTO pecr_ledger_events (event_id, trace_id, session_id, event_type, principal_id, policy_snapshot_id, payload_json, payload_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (event_id) DO NOTHING",
                )
                .bind(&policy_decision_event_id)
                .bind(record.trace_id)
                .bind(record.session_id)
                .bind("POLICY_DECISION")
                .bind(record.principal_id)
                .bind(record.policy_snapshot_id)
                .bind(&policy_decision_payload)
                .bind(policy_decision_hash)
                .execute(&mut *tx)
                .await?;

                sqlx::query(
                    "INSERT INTO pecr_claim_maps (claim_map_id, trace_id, session_id, terminal_mode, coverage_threshold, coverage_observed, claim_map_json) VALUES ($1,$2,$3,$4,$5,$6,$7) ON CONFLICT (claim_map_id) DO UPDATE SET terminal_mode = EXCLUDED.terminal_mode, coverage_threshold = EXCLUDED.coverage_threshold, coverage_observed = EXCLUDED.coverage_observed, claim_map_json = EXCLUDED.claim_map_json",
                )
                .bind(&record.claim_map.claim_map_id)
                .bind(record.trace_id)
                .bind(record.session_id)
                .bind(record.claim_map.terminal_mode.as_str())
                .bind(record.claim_map.coverage_threshold)
                .bind(record.claim_map.coverage_observed)
                .bind(&claim_map_json)
                .execute(&mut *tx)
                .await?;

                sqlx::query("UPDATE pecr_sessions SET finalized_at = now(), terminal_mode = $1 WHERE session_id = $2")
                    .bind(record.claim_map.terminal_mode.as_str())
                    .bind(record.session_id)
                    .execute(&mut *tx)
                    .await?;

                sqlx::query(
                    "INSERT INTO pecr_ledger_events (event_id, trace_id, session_id, event_type, principal_id, policy_snapshot_id, payload_json, payload_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (event_id) DO NOTHING",
                )
                .bind(&event_id)
                .bind(record.trace_id)
                .bind(record.session_id)
                .bind("FINALIZE_RESULT")
                .bind(record.principal_id)
                .bind(record.policy_snapshot_id)
                .bind(&payload_json)
                .bind(payload_hash)
                .execute(&mut *tx)
                .await?;

                sqlx::query(
                    "INSERT INTO pecr_session_runtime (session_id, tenant_id, session_token_hash, session_token_expires_at_epoch_ms, operator_calls_used, bytes_used, evidence_unit_ids_json, finalized, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now()) ON CONFLICT (session_id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id, session_token_hash = EXCLUDED.session_token_hash, session_token_expires_at_epoch_ms = EXCLUDED.session_token_expires_at_epoch_ms, operator_calls_used = EXCLUDED.operator_calls_used, bytes_used = EXCLUDED.bytes_used, evidence_unit_ids_json = EXCLUDED.evidence_unit_ids_json, finalized = EXCLUDED.finalized, updated_at = now()",
                )
                .bind(record.session_runtime.session_id)
                .bind(record.session_runtime.tenant_id)
                .bind(record.session_runtime.session_token_hash)
                .bind(record.session_runtime.session_token_expires_at_epoch_ms)
                .bind(i64::from(record.session_runtime.operator_calls_used))
                .bind(bytes_used)
                .bind(evidence_unit_ids_json)
                .bind(record.session_runtime.finalized)
                .execute(&mut *tx)
                .await?;

                tx.commit().await?;
                Ok::<(), sqlx::Error>(())
            })
            .await;
            match execute_result {
                Ok(Ok(())) => return Ok(()),
                Ok(Err(err)) => {
                    last_error = Some(LedgerError::Sqlx(err));
                }
                Err(_) => {
                    last_error = Some(LedgerError::Timeout);
                }
            }

            if attempt < 2 {
                tokio::time::sleep(Duration::from_millis(100 * (attempt + 1) as u64)).await;
            }
        }

        match last_error.unwrap_or(LedgerError::Timeout) {
            LedgerError::Timeout => {
                eprintln!(
                    "ledger.record_finalize_result_timed_out trace_id={} session_id={}",
                    record.trace_id, record.session_id
                );
                Err(LedgerError::Timeout)
            }
            LedgerError::Sqlx(err) => {
                eprintln!(
                    "ledger.record_finalize_result_failed trace_id={} session_id={} error={}",
                    record.trace_id, record.session_id, err
                );
                Err(LedgerError::Sqlx(err))
            }
            other => Err(other),
        }?;

        Ok(())
    }

    pub async fn record_operator_result(
        &self,
        record: OperatorResultRecord<'_>,
    ) -> Result<(), LedgerError> {
        let policy_decision_payload = serde_json::json!({
            "decision": "allow",
            "reason": record.policy_decision_reason,
            "op_name": record.op_name,
            "request_id": record.request_id,
        });
        let policy_decision_hash = canonical::hash_canonical_json(&policy_decision_payload);
        let evidence_unit_ids_json = serde_json::to_value(record.session_runtime.evidence_unit_ids)
            .unwrap_or_else(|_| serde_json::json!([]));
        let bytes_used = checked_bigint_from_u64(record.session_runtime.bytes_used, "bytes_used")?;
        let operator_event_payload = serde_json::json!({
            "op_name": record.op_name,
            "params_hash": record.params_hash,
            "cache_hit": record.cache_hit,
            "params_bytes": record.params_bytes,
            "result_bytes": record.result_bytes,
            "terminal_mode": record.terminal_mode.as_str(),
            "outcome": if record.error_code.is_none() { "success" } else { "error" },
            "error_code": record.error_code,
            "operator_calls_used": record.session_runtime.operator_calls_used,
            "bytes_used": record.session_runtime.bytes_used,
            "request_id": record.request_id,
        });

        let execute_result = tokio::time::timeout(self.write_timeout, async {
            let mut tx = self.pool.begin().await?;

            let policy_decision_event_id = Ulid::new().to_string();
            sqlx::query(
                "INSERT INTO pecr_ledger_events (event_id, trace_id, session_id, event_type, principal_id, policy_snapshot_id, payload_json, payload_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(&policy_decision_event_id)
            .bind(record.trace_id)
            .bind(record.session_id)
            .bind("POLICY_DECISION")
            .bind(record.principal_id)
            .bind(record.policy_snapshot_id)
            .bind(&policy_decision_payload)
            .bind(policy_decision_hash)
            .execute(&mut *tx)
            .await?;

            for evidence in record.evidence_units {
                let transform_chain_json = serde_json::to_value(&evidence.transform_chain)
                    .unwrap_or_else(|_| serde_json::json!([]));
                let payload_json = if record.store_payload {
                    evidence.content.clone()
                } else {
                    None
                };

                sqlx::query(
                    "INSERT INTO pecr_evidence_units (evidence_unit_id, trace_id, session_id, source_system, object_id, version_id, span_or_row_spec_json, content_type, content_hash, as_of_time, retrieved_at, policy_snapshot_id, policy_snapshot_hash, transform_chain_json, payload_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10::timestamptz,$11::timestamptz,$12,$13,$14,$15) ON CONFLICT (evidence_unit_id) DO NOTHING",
                )
                .bind(&evidence.evidence_unit_id)
                .bind(record.trace_id)
                .bind(record.session_id)
                .bind(&evidence.source_system)
                .bind(&evidence.object_id)
                .bind(&evidence.version_id)
                .bind(&evidence.span_or_row_spec)
                .bind(match evidence.content_type {
                    pecr_contracts::EvidenceContentType::TextPlain => "text/plain",
                    pecr_contracts::EvidenceContentType::ApplicationJson => "application/json",
                })
                .bind(&evidence.content_hash)
                .bind(&evidence.as_of_time)
                .bind(&evidence.retrieved_at)
                .bind(&evidence.policy_snapshot_id)
                .bind(&evidence.policy_snapshot_hash)
                .bind(&transform_chain_json)
                .bind(&payload_json)
                .execute(&mut *tx)
                .await?;

                let evidence_event_payload = serde_json::json!({
                    "evidence_unit_id": evidence.evidence_unit_id.as_str(),
                    "content_hash": evidence.content_hash.as_str(),
                    "source_system": evidence.source_system.as_str(),
                    "object_id": evidence.object_id.as_str(),
                    "version_id": evidence.version_id.as_str(),
                    "op_name": record.op_name,
                    "request_id": record.request_id,
                });
                let evidence_event_hash = canonical::hash_canonical_json(&evidence_event_payload);
                let evidence_event_id = Ulid::new().to_string();

                sqlx::query(
                    "INSERT INTO pecr_ledger_events (event_id, trace_id, session_id, event_type, principal_id, policy_snapshot_id, payload_json, payload_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
                )
                .bind(&evidence_event_id)
                .bind(record.trace_id)
                .bind(record.session_id)
                .bind("EVIDENCE_EMITTED")
                .bind(record.principal_id)
                .bind(record.policy_snapshot_id)
                .bind(&evidence_event_payload)
                .bind(evidence_event_hash)
                .execute(&mut *tx)
                .await?;
            }

            let operator_event_hash = canonical::hash_canonical_json(&operator_event_payload);
            let operator_event_id = Ulid::new().to_string();
            sqlx::query(
                "INSERT INTO pecr_ledger_events (event_id, trace_id, session_id, event_type, principal_id, policy_snapshot_id, payload_json, payload_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
            )
            .bind(&operator_event_id)
            .bind(record.trace_id)
            .bind(record.session_id)
            .bind("OPERATOR_CALL")
            .bind(record.principal_id)
            .bind(record.policy_snapshot_id)
            .bind(&operator_event_payload)
            .bind(operator_event_hash)
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "INSERT INTO pecr_session_runtime (session_id, tenant_id, session_token_hash, session_token_expires_at_epoch_ms, operator_calls_used, bytes_used, evidence_unit_ids_json, finalized, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now()) ON CONFLICT (session_id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id, session_token_hash = EXCLUDED.session_token_hash, session_token_expires_at_epoch_ms = EXCLUDED.session_token_expires_at_epoch_ms, operator_calls_used = EXCLUDED.operator_calls_used, bytes_used = EXCLUDED.bytes_used, evidence_unit_ids_json = EXCLUDED.evidence_unit_ids_json, finalized = EXCLUDED.finalized, updated_at = now()",
            )
            .bind(record.session_runtime.session_id)
            .bind(record.session_runtime.tenant_id)
            .bind(record.session_runtime.session_token_hash)
            .bind(record.session_runtime.session_token_expires_at_epoch_ms)
            .bind(i64::from(record.session_runtime.operator_calls_used))
            .bind(bytes_used)
            .bind(evidence_unit_ids_json)
            .bind(record.session_runtime.finalized)
            .execute(&mut *tx)
            .await?;

            tx.commit().await?;
            Ok::<(), sqlx::Error>(())
        })
        .await;
        let execute_result = match execute_result {
            Ok(result) => result,
            Err(_) => {
                eprintln!(
                    "ledger.record_operator_result_timed_out trace_id={} session_id={} op_name={}",
                    record.trace_id, record.session_id, record.op_name
                );
                return Err(LedgerError::Timeout);
            }
        };
        if let Err(err) = execute_result {
            eprintln!(
                "ledger.record_operator_result_failed trace_id={} session_id={} op_name={} error={}",
                record.trace_id, record.session_id, record.op_name, err
            );
            return Err(LedgerError::Sqlx(err));
        }

        Ok(())
    }

    pub async fn upsert_session_runtime(
        &self,
        record: SessionRuntimeWrite<'_>,
    ) -> Result<(), LedgerError> {
        let evidence_unit_ids_json = serde_json::to_value(record.evidence_unit_ids)
            .unwrap_or_else(|_| serde_json::json!([]));
        let bytes_used = checked_bigint_from_u64(record.bytes_used, "bytes_used")?;

        let execute_result = tokio::time::timeout(
            self.write_timeout,
            sqlx::query(
                "INSERT INTO pecr_session_runtime (session_id, tenant_id, session_token_hash, session_token_expires_at_epoch_ms, operator_calls_used, bytes_used, evidence_unit_ids_json, finalized, updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8, now()) ON CONFLICT (session_id) DO UPDATE SET tenant_id = EXCLUDED.tenant_id, session_token_hash = EXCLUDED.session_token_hash, session_token_expires_at_epoch_ms = EXCLUDED.session_token_expires_at_epoch_ms, operator_calls_used = EXCLUDED.operator_calls_used, bytes_used = EXCLUDED.bytes_used, evidence_unit_ids_json = EXCLUDED.evidence_unit_ids_json, finalized = EXCLUDED.finalized, updated_at = now()",
            )
            .bind(record.session_id)
            .bind(record.tenant_id)
            .bind(record.session_token_hash)
            .bind(record.session_token_expires_at_epoch_ms)
            .bind(i64::from(record.operator_calls_used))
            .bind(bytes_used)
            .bind(evidence_unit_ids_json)
            .bind(record.finalized)
            .execute(&self.pool),
        )
        .await;
        let execute_result = match execute_result {
            Ok(result) => result,
            Err(_) => {
                eprintln!(
                    "ledger.upsert_session_runtime_timed_out session_id={}",
                    record.session_id
                );
                return Err(LedgerError::Timeout);
            }
        };
        if let Err(err) = execute_result {
            eprintln!(
                "ledger.upsert_session_runtime_failed session_id={} error={}",
                record.session_id, err
            );
            return Err(LedgerError::Sqlx(err));
        }

        Ok(())
    }

    pub async fn load_session_runtime(
        &self,
        session_id: &str,
    ) -> Result<Option<SessionRuntimeRecord>, LedgerError> {
        let row = tokio::time::timeout(
            self.write_timeout,
            sqlx::query(
                "SELECT s.session_id, s.trace_id, s.principal_id, s.policy_snapshot_id, s.budget_json, ps.policy_snapshot_hash, to_char(ps.as_of_time AT TIME ZONE 'UTC', 'YYYY-MM-DD\"T\"HH24:MI:SS\"Z\"') as as_of_time, COALESCE(r.tenant_id, 'local') AS tenant_id, COALESCE(r.session_token_hash, '') AS session_token_hash, COALESCE(r.session_token_expires_at_epoch_ms, 0) AS session_token_expires_at_epoch_ms, COALESCE(r.operator_calls_used, 0) AS operator_calls_used, COALESCE(r.bytes_used, 0) AS bytes_used, COALESCE(r.evidence_unit_ids_json, '[]'::jsonb) AS evidence_unit_ids_json, (s.finalized_at IS NOT NULL OR COALESCE(r.finalized, false)) AS finalized FROM pecr_sessions s JOIN pecr_policy_snapshots ps ON ps.policy_snapshot_id = s.policy_snapshot_id LEFT JOIN pecr_session_runtime r ON r.session_id = s.session_id WHERE s.session_id = $1",
            )
            .bind(session_id)
            .fetch_optional(&self.pool),
        )
        .await
        .map_err(|_| LedgerError::Timeout)??;

        let Some(row) = row else {
            return Ok(None);
        };

        let budget_json: serde_json::Value = row.try_get("budget_json")?;
        let budget = parse_budget_json_value(budget_json)?;

        let evidence_unit_ids_json: serde_json::Value = row.try_get("evidence_unit_ids_json")?;
        let evidence_unit_ids = parse_evidence_unit_ids_value(evidence_unit_ids_json);

        let operator_calls_used = row.try_get::<i64, _>("operator_calls_used")?;
        let bytes_used = row.try_get::<i64, _>("bytes_used")?;

        Ok(Some(SessionRuntimeRecord {
            session_id: row.try_get("session_id")?,
            trace_id: row.try_get("trace_id")?,
            principal_id: row.try_get("principal_id")?,
            tenant_id: row.try_get("tenant_id")?,
            policy_snapshot_id: row.try_get("policy_snapshot_id")?,
            policy_snapshot_hash: row.try_get("policy_snapshot_hash")?,
            as_of_time: row.try_get("as_of_time")?,
            budget,
            session_token_hash: row.try_get("session_token_hash")?,
            session_token_expires_at_epoch_ms: row.try_get("session_token_expires_at_epoch_ms")?,
            operator_calls_used: checked_u32_from_i64(operator_calls_used, "operator_calls_used")?,
            bytes_used: checked_u64_from_i64(bytes_used, "bytes_used")?,
            evidence_unit_ids,
            finalized: row.try_get("finalized")?,
        }))
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }
}

pub async fn migrate(pool: &sqlx::PgPool) -> Result<(), sqlx::Error> {
    sqlx::migrate!("./migrations").run(pool).await?;
    Ok(())
}

pub async fn migrate_url(db_url: &str) -> Result<(), sqlx::Error> {
    let pool = sqlx::PgPool::connect(db_url).await?;
    migrate(&pool).await?;
    pool.close().await;
    Ok(())
}

fn parse_budget_json_value(value: serde_json::Value) -> Result<Budget, LedgerError> {
    serde_json::from_value::<Budget>(value).map_err(|err| {
        LedgerError::Sqlx(sqlx::Error::Decode(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid budget_json: {}", err),
        ))))
    })
}

fn parse_evidence_unit_ids_value(value: serde_json::Value) -> Vec<String> {
    match value {
        serde_json::Value::Array(items) => items
            .into_iter()
            .filter_map(|item| item.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>(),
        _ => Vec::new(),
    }
}

fn checked_bigint_from_u64(value: u64, field: &str) -> Result<i64, LedgerError> {
    i64::try_from(value)
        .map_err(|_| LedgerError::InvalidInput(format!("{field} exceeds BIGINT range")))
}

fn checked_u32_from_i64(value: i64, field: &str) -> Result<u32, LedgerError> {
    u32::try_from(value).map_err(|_| {
        LedgerError::Sqlx(sqlx::Error::Decode(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid {field}: expected non-negative u32"),
        ))))
    })
}

fn checked_u64_from_i64(value: i64, field: &str) -> Result<u64, LedgerError> {
    u64::try_from(value).map_err(|_| {
        LedgerError::Sqlx(sqlx::Error::Decode(Box::new(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            format!("invalid {field}: expected non-negative i64"),
        ))))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_budget_json_value_accepts_valid_budget() {
        let budget = parse_budget_json_value(serde_json::json!({
            "max_operator_calls": 5,
            "max_bytes": 1024,
            "max_wallclock_ms": 1000,
            "max_recursion_depth": 3,
            "max_parallelism": 2
        }))
        .expect("budget should parse");

        assert_eq!(budget.max_operator_calls, 5);
        assert_eq!(budget.max_bytes, 1024);
    }

    #[test]
    fn parse_budget_json_value_rejects_invalid_shape() {
        let err = parse_budget_json_value(serde_json::json!({ "oops": true })).unwrap_err();
        assert!(matches!(err, LedgerError::Sqlx(sqlx::Error::Decode(_))));
    }

    #[test]
    fn parse_evidence_unit_ids_value_filters_non_string_entries() {
        let ids = parse_evidence_unit_ids_value(serde_json::json!(["a", 1, null, "b"]));

        assert_eq!(ids, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn checked_bigint_from_u64_rejects_values_above_i64_max() {
        let err = checked_bigint_from_u64(i64::MAX as u64 + 1, "bytes_used").unwrap_err();

        assert!(matches!(err, LedgerError::InvalidInput(_)));
        assert_eq!(
            err.to_string(),
            "ledger invalid input: bytes_used exceeds BIGINT range"
        );
    }

    #[test]
    fn checked_u64_from_i64_rejects_negative_values() {
        let err = checked_u64_from_i64(-1, "bytes_used").unwrap_err();

        assert!(matches!(err, LedgerError::Sqlx(sqlx::Error::Decode(_))));
        assert!(err.to_string().contains("invalid bytes_used"));
    }
}
