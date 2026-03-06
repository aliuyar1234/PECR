use std::sync::Arc;
use std::time::Duration;

use axum::http::StatusCode;
use axum::routing::{get, post};
use axum::{Json, Router};
use pecr_auth::OidcAuthenticator;
use pecr_ledger::LedgerWriter;
use serde::Serialize;
use sqlx::PgPool;
use tokio::sync::RwLock;

use crate::config::{AuthMode, GatewayConfig, StartupError};
use crate::opa::{OpaClient, OpaClientConfig};
use crate::operator_cache::OperatorCache;
use crate::rate_limit::RateLimiter;

mod auth;
mod diagnostics;
mod finalize;
mod operator;
mod operator_api;
mod policy;
mod policy_api;
mod runtime;
mod session;
mod session_api;

use self::diagnostics::{healthz, metrics, readyz};
use self::finalize::finalize;
use self::operator_api::call_operator;
use self::policy_api::{policy_capabilities, simulate_policy};
use self::runtime::{FsSearchIndexCache, FsVersionCache, validate_safeview_schema};
use self::session_api::create_session;

#[cfg(test)]
use self::finalize::finalize_gate;
#[cfg(test)]
use self::policy::{
    apply_field_redaction, apply_field_redaction_to_evidence_unit, compute_evidence_unit_id,
    parse_field_redaction,
};
#[cfg(test)]
use self::runtime::{missing_safeview_columns, safeview_spec, sha256_hex};
#[cfg(test)]
use self::session::{Session, unix_epoch_ms_now};
#[cfg(test)]
use pecr_contracts::{ClaimMap, ClaimStatus};
#[cfg(test)]
use pecr_policy::FieldRedaction;

#[derive(Clone)]
pub struct AppState {
    pub config: GatewayConfig,
    oidc: Option<OidcAuthenticator>,
    ledger: LedgerWriter,
    opa: OpaClient,
    operator_cache: OperatorCache,
    rate_limiter: RateLimiter,
    pg_pool: PgPool,
    fs_search_index: Arc<RwLock<FsSearchIndexCache>>,
    fs_versions: Arc<RwLock<FsVersionCache>>,
    pg_versions: Arc<RwLock<FsVersionCache>>,
}

type ApiError = (StatusCode, Json<ErrorResponse>);
type FilterEq = (String, String);

pub async fn router(config: GatewayConfig) -> Result<Router, StartupError> {
    let oidc = if config.auth_mode == AuthMode::Oidc {
        let oidc_config = config.oidc.clone().ok_or_else(|| StartupError {
            code: "ERR_INVALID_CONFIG",
            message: "oidc auth mode requires oidc config".to_string(),
        })?;

        Some(
            OidcAuthenticator::new(oidc_config)
                .await
                .map_err(|err| StartupError {
                    code: err.code,
                    message: err.message,
                })?,
        )
    } else {
        None
    };

    let ledger = LedgerWriter::connect_and_migrate(
        &config.db_url,
        Duration::from_millis(config.ledger_write_timeout_ms),
    )
    .await
    .map_err(|err| StartupError {
        code: "ERR_LEDGER_UNAVAILABLE",
        message: format!("failed to initialize ledger: {}", err),
    })?;

    let opa = OpaClient::new(OpaClientConfig {
        base_url: config.opa_url.clone(),
        timeout: Duration::from_millis(config.opa_timeout_ms),
        cache_max_entries: config.cache_max_entries,
        cache_ttl: Duration::from_millis(config.cache_ttl_ms),
        retry_max_attempts: config.opa_retry_max_attempts,
        retry_base_backoff: Duration::from_millis(config.opa_retry_base_backoff_ms),
        circuit_breaker_failure_threshold: config.opa_circuit_breaker_failure_threshold,
        circuit_breaker_open_for: Duration::from_millis(config.opa_circuit_breaker_open_ms),
    })
    .map_err(|_| StartupError {
        code: "ERR_OPA_UNAVAILABLE",
        message: "failed to initialize policy client".to_string(),
    })?;

    let pg_pool = PgPool::connect(&config.db_url)
        .await
        .map_err(|_| StartupError {
            code: "ERR_DB_UNAVAILABLE",
            message: "failed to initialize safe-view database pool".to_string(),
        })?;
    validate_safeview_schema(&pg_pool).await?;

    let operator_cache = OperatorCache::new(
        config.cache_max_entries,
        Duration::from_millis(config.cache_ttl_ms),
    );
    let rate_limiter = RateLimiter::new(
        Duration::from_secs(config.rate_limit_window_secs.max(1)),
        16_384,
    );

    let fs_versions = Arc::new(RwLock::new(FsVersionCache::new(
        config.fs_version_cache_max_bytes,
        config.fs_version_cache_max_versions_per_object,
    )));

    let fs_search_index = Arc::new(RwLock::new(FsSearchIndexCache::new(Duration::from_millis(
        config.cache_ttl_ms,
    ))));

    let pg_versions = Arc::new(RwLock::new(FsVersionCache::new(
        config.fs_version_cache_max_bytes,
        config.fs_version_cache_max_versions_per_object,
    )));

    let state = AppState {
        config,
        oidc,
        ledger,
        opa,
        operator_cache,
        rate_limiter,
        pg_pool,
        fs_search_index,
        fs_versions,
        pg_versions,
    };

    Ok(Router::new()
        .route("/healthz", get(healthz))
        .route("/readyz", get(readyz))
        .route("/metrics", get(metrics))
        .route("/v1/sessions", post(create_session))
        .route("/v1/policies/capabilities", get(policy_capabilities))
        .route("/v1/policies/simulate", post(simulate_policy))
        .route("/v1/operators/{op_name}", post(call_operator))
        .route("/v1/finalize", post(finalize))
        .with_state(state))
}

#[derive(Debug, Serialize)]
pub(super) struct ErrorResponse {
    code: String,
    message: String,
    terminal_mode_hint: pecr_contracts::TerminalMode,
    retryable: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    response_kind: Option<pecr_contracts::ClientResponseKind>,
    #[serde(skip_serializing_if = "Option::is_none")]
    what_failed: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    safe_alternative: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<serde_json::Value>,
}

#[derive(Clone, Copy)]
struct ErrorGuidance {
    what_failed: &'static str,
    safe_alternative: &'static str,
}

fn classify_error_response_kind(
    terminal_mode_hint: pecr_contracts::TerminalMode,
) -> Option<pecr_contracts::ClientResponseKind> {
    match terminal_mode_hint {
        pecr_contracts::TerminalMode::InsufficientPermission => {
            Some(pecr_contracts::ClientResponseKind::Blocked)
        }
        pecr_contracts::TerminalMode::SourceUnavailable => {
            Some(pecr_contracts::ClientResponseKind::SourceDown)
        }
        _ => None,
    }
}

fn default_error_guidance(
    code: &str,
    terminal_mode_hint: pecr_contracts::TerminalMode,
    retryable: bool,
) -> Option<ErrorGuidance> {
    match (code, terminal_mode_hint) {
        ("ERR_RATE_LIMITED", pecr_contracts::TerminalMode::InsufficientPermission) => {
            Some(ErrorGuidance {
                what_failed: "The gateway blocked the request because the caller exceeded the current rate limit.",
                safe_alternative: "Retry after the rate-limit window resets, or reduce request frequency for this principal.",
            })
        }
        ("ERR_POLICY_DENIED", pecr_contracts::TerminalMode::InsufficientPermission) => {
            Some(ErrorGuidance {
                what_failed: "The current principal is not allowed to access the requested session, operator, or finalize path.",
                safe_alternative: "Retry with a principal that has access, or narrow the request to a permitted operator or dataset.",
            })
        }
        (_, pecr_contracts::TerminalMode::InsufficientPermission) => Some(ErrorGuidance {
            what_failed: "The current principal could not complete this gateway request with its available permissions.",
            safe_alternative: "Retry with a principal that has the required access, or narrow the request to a permitted dataset.",
        }),
        (_, pecr_contracts::TerminalMode::SourceUnavailable) => Some(ErrorGuidance {
            what_failed: "A required policy, ledger, or source dependency was unavailable for this request.",
            safe_alternative: if retryable {
                "Retry the request after the dependency recovers, or try a narrower request that touches fewer sources."
            } else {
                "Check dependency health and retry once the unavailable source path is restored."
            },
        }),
        _ => None,
    }
}

fn with_actionable_guidance(mut err: ErrorResponse) -> ErrorResponse {
    if err.response_kind.is_none() {
        err.response_kind = classify_error_response_kind(err.terminal_mode_hint);
    }
    if let Some(guidance) =
        default_error_guidance(err.code.as_str(), err.terminal_mode_hint, err.retryable)
    {
        if err.what_failed.is_none() {
            err.what_failed = Some(guidance.what_failed.to_string());
        }
        if err.safe_alternative.is_none() {
            err.safe_alternative = Some(guidance.safe_alternative.to_string());
        }
    }
    err
}

pub(super) fn json_error(
    status: StatusCode,
    code: impl Into<String>,
    message: impl Into<String>,
    terminal_mode_hint: pecr_contracts::TerminalMode,
    retryable: bool,
) -> (StatusCode, Json<ErrorResponse>) {
    (
        status,
        Json(with_actionable_guidance(ErrorResponse {
            code: code.into(),
            message: message.into(),
            terminal_mode_hint,
            retryable,
            response_kind: None,
            what_failed: None,
            safe_alternative: None,
            detail: None,
        })),
    )
}

pub(super) fn opa_error_response(err: &crate::opa::OpaError) -> (StatusCode, Json<ErrorResponse>) {
    match err {
        crate::opa::OpaError::Timeout => json_error(
            StatusCode::GATEWAY_TIMEOUT,
            "ERR_SOURCE_TIMEOUT",
            "policy engine timeout".to_string(),
            pecr_contracts::TerminalMode::SourceUnavailable,
            true,
        ),
        crate::opa::OpaError::CircuitOpen => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "policy engine circuit breaker is open".to_string(),
            pecr_contracts::TerminalMode::SourceUnavailable,
            true,
        ),
        crate::opa::OpaError::InvalidResponse => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "policy engine invalid response".to_string(),
            pecr_contracts::TerminalMode::SourceUnavailable,
            true,
        ),
        crate::opa::OpaError::Http(_) | crate::opa::OpaError::BadStatus(_) => json_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "ERR_SOURCE_UNAVAILABLE",
            "policy engine unavailable".to_string(),
            pecr_contracts::TerminalMode::SourceUnavailable,
            true,
        ),
    }
}

#[cfg(test)]
mod tests;
