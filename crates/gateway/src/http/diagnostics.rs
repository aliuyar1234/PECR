use std::collections::BTreeMap;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use serde::Serialize;

use super::AppState;
use super::auth::extract_principal;

pub(super) async fn healthz() -> &'static str {
    "ok"
}

#[derive(Debug, Serialize)]
struct ReadyzResponse {
    status: &'static str,
    checks: BTreeMap<&'static str, bool>,
}

pub(super) async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let mut checks = BTreeMap::new();

    let ledger_ready = state.ledger.ping().await.is_ok();
    checks.insert("ledger", ledger_ready);

    let postgres_ready = tokio::time::timeout(
        Duration::from_millis(state.config.pg_safeview_query_timeout_ms.max(50)),
        sqlx::query("SELECT 1").execute(&state.pg_pool),
    )
    .await
    .is_ok_and(|res| res.is_ok());
    checks.insert("postgres", postgres_ready);

    let opa_ready = state.opa.ready().await.is_ok();
    checks.insert("opa", opa_ready);

    let all_ready = checks.values().all(|ok| *ok);
    let status = if all_ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(ReadyzResponse {
            status: if all_ready { "ready" } else { "not_ready" },
            checks,
        }),
    )
}

pub(super) async fn metrics(
    State(state): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if state.config.metrics_require_auth
        && let Err(err) = extract_principal(&state, &headers).await
    {
        return err.into_response();
    }

    match crate::metrics::render() {
        Ok((body, content_type)) => {
            let mut headers = HeaderMap::new();
            if let Ok(value) = HeaderValue::from_str(content_type.as_str()) {
                headers.insert(header::CONTENT_TYPE, value);
            }
            (headers, body).into_response()
        }
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}
