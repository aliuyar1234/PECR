use std::collections::HashSet;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::StatusCode;
use pecr_contracts::{Budget, TerminalMode};
use pecr_ledger::SessionRuntimeWrite;
use sqlx::{Postgres, Transaction};

use super::{ApiError, AppState, json_error};

#[derive(Debug, Clone)]
pub(super) struct Session {
    pub(super) session_id: String,
    pub(super) trace_id: String,
    pub(super) principal_id: String,
    pub(super) tenant_id: String,
    pub(super) policy_snapshot_id: String,
    pub(super) policy_snapshot_hash: String,
    pub(super) as_of_time: String,
    pub(super) budget: Budget,
    pub(super) session_token_hash: String,
    pub(super) session_token_expires_at_epoch_ms: i64,
    pub(super) operator_calls_used: u32,
    pub(super) bytes_used: u64,
    pub(super) evidence_unit_ids: HashSet<String>,
    pub(super) finalized: bool,
}

pub(super) fn unix_epoch_ms_now() -> i64 {
    let duration = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO);
    duration.as_millis().min(i64::MAX as u128) as i64
}

pub(super) async fn acquire_session_lock<'a>(
    state: &'a AppState,
    session_id: &str,
) -> Result<Transaction<'a, Postgres>, ApiError> {
    let timeout = Duration::from_millis(state.config.ledger_write_timeout_ms.max(200));
    let mut tx = tokio::time::timeout(timeout, state.pg_pool.begin())
        .await
        .map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_SOURCE_TIMEOUT",
                "session lock acquisition timed out".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })?
        .map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_DB_UNAVAILABLE",
                "failed to start session lock transaction".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })?;

    tokio::time::timeout(
        timeout,
        sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended($1, 0))")
            .bind(session_id)
            .execute(&mut *tx),
    )
    .await
    .map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_TIMEOUT",
            "session lock acquisition timed out".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?
    .map_err(|_| {
        json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_DB_UNAVAILABLE",
            "failed to acquire session lock".to_string(),
            TerminalMode::SourceUnavailable,
            true,
        )
    })?;

    Ok(tx)
}

pub(super) async fn persist_session_runtime(
    state: &AppState,
    session: &Session,
) -> Result<(), ApiError> {
    let mut evidence_unit_ids = session
        .evidence_unit_ids
        .iter()
        .cloned()
        .collect::<Vec<_>>();
    evidence_unit_ids.sort();
    evidence_unit_ids.dedup();

    state
        .ledger
        .upsert_session_runtime(SessionRuntimeWrite {
            session_id: session.session_id.as_str(),
            tenant_id: session.tenant_id.as_str(),
            session_token_hash: session.session_token_hash.as_str(),
            session_token_expires_at_epoch_ms: session.session_token_expires_at_epoch_ms,
            operator_calls_used: session.operator_calls_used,
            bytes_used: session.bytes_used,
            evidence_unit_ids: &evidence_unit_ids,
            finalized: session.finalized,
        })
        .await
        .map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_LEDGER_UNAVAILABLE",
                "ledger unavailable".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })
}

pub(super) async fn load_session_runtime(
    state: &AppState,
    session_id: &str,
) -> Result<Option<Session>, ApiError> {
    let record = state
        .ledger
        .load_session_runtime(session_id)
        .await
        .map_err(|_| {
            json_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "ERR_LEDGER_UNAVAILABLE",
                "ledger unavailable".to_string(),
                TerminalMode::SourceUnavailable,
                true,
            )
        })?;

    let Some(record) = record else {
        return Ok(None);
    };

    if record.budget.validate().is_err() {
        return Err(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_INTERNAL",
            "stored session budget is invalid".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        ));
    }

    let evidence_unit_ids = record.evidence_unit_ids.into_iter().collect::<HashSet<_>>();

    Ok(Some(Session {
        session_id: record.session_id,
        trace_id: record.trace_id,
        principal_id: record.principal_id,
        tenant_id: record.tenant_id,
        policy_snapshot_id: record.policy_snapshot_id,
        policy_snapshot_hash: record.policy_snapshot_hash,
        as_of_time: record.as_of_time,
        budget: record.budget,
        session_token_hash: record.session_token_hash,
        session_token_expires_at_epoch_ms: record.session_token_expires_at_epoch_ms,
        operator_calls_used: record.operator_calls_used,
        bytes_used: record.bytes_used,
        evidence_unit_ids,
        finalized: record.finalized,
    }))
}
