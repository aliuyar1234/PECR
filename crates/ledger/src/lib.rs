use std::time::Duration;

use pecr_contracts::canonical;
use pecr_contracts::{Budget, ClaimMap, EvidenceUnit, PolicySnapshot, TerminalMode};
use sqlx::postgres::PgPoolOptions;
use ulid::Ulid;

#[derive(Debug)]
pub enum LedgerError {
    Timeout,
    Sqlx(sqlx::Error),
}

impl std::fmt::Display for LedgerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LedgerError::Timeout => write!(f, "ledger operation timed out"),
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
    pub claim_map: &'a ClaimMap,
    pub budget_counters: &'a serde_json::Value,
    pub request_id: &'a str,
}

impl LedgerWriter {
    pub async fn connect(db_url: &str, write_timeout: Duration) -> Result<Self, LedgerError> {
        let pool = tokio::time::timeout(
            Duration::from_secs(2),
            PgPoolOptions::new().max_connections(8).connect(db_url),
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
        tokio::time::timeout(Duration::from_secs(10), migrate(&self.pool))
            .await
            .map_err(|_| LedgerError::Timeout)??;
        Ok(())
    }

    pub async fn create_session(
        &self,
        session_id: &str,
        trace_id: &str,
        principal_id: &str,
        budget: &Budget,
        policy_snapshot_id: &str,
        policy_snapshot: &PolicySnapshot,
    ) -> Result<(), LedgerError> {
        let budget_json = serde_json::to_value(budget).unwrap_or_else(|_| serde_json::json!({}));
        let input_json =
            serde_json::to_value(policy_snapshot).unwrap_or_else(|_| serde_json::json!({}));

        tokio::time::timeout(self.write_timeout, async {
            let mut tx = self.pool.begin().await?;

            sqlx::query(
                "INSERT INTO pecr_policy_snapshots (policy_snapshot_id, policy_snapshot_hash, principal_id, as_of_time, policy_bundle_hash, input_json) VALUES ($1, $2, $3, $4::timestamptz, $5, $6)",
            )
            .bind(policy_snapshot_id)
            .bind(&policy_snapshot.policy_snapshot_hash)
            .bind(principal_id)
            .bind(&policy_snapshot.as_of_time)
            .bind(&policy_snapshot.policy_bundle_hash)
            .bind(&input_json)
            .execute(&mut *tx)
            .await?;

            sqlx::query(
                "INSERT INTO pecr_sessions (session_id, trace_id, principal_id, policy_snapshot_id, budget_json) VALUES ($1, $2, $3, $4, $5)",
            )
            .bind(session_id)
            .bind(trace_id)
            .bind(principal_id)
            .bind(policy_snapshot_id)
            .bind(&budget_json)
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

        tokio::time::timeout(
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
        .await
        .map_err(|_| LedgerError::Timeout)??;

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

        let payload_json = serde_json::json!({
            "terminal_mode": record.claim_map.terminal_mode.as_str(),
            "claim_map_id": record.claim_map.claim_map_id.clone(),
            "coverage_threshold": record.claim_map.coverage_threshold,
            "coverage_observed": record.claim_map.coverage_observed,
            "budget_counters": record.budget_counters,
            "request_id": record.request_id,
        });
        let payload_hash = canonical::hash_canonical_json(&payload_json);
        let event_id = Ulid::new().to_string();

        tokio::time::timeout(self.write_timeout, async {
            let mut tx = self.pool.begin().await?;

            sqlx::query(
                "INSERT INTO pecr_claim_maps (claim_map_id, trace_id, session_id, terminal_mode, coverage_threshold, coverage_observed, claim_map_json) VALUES ($1,$2,$3,$4,$5,$6,$7)",
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
                "INSERT INTO pecr_ledger_events (event_id, trace_id, session_id, event_type, principal_id, policy_snapshot_id, payload_json, payload_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
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

            tx.commit().await?;
            Ok::<(), sqlx::Error>(())
        })
        .await
        .map_err(|_| LedgerError::Timeout)??;

        Ok(())
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
