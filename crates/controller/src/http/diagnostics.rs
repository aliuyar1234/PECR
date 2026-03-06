use std::collections::BTreeMap;
use std::time::Duration;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, HeaderValue, StatusCode, header};
use axum::response::IntoResponse;
use serde::Serialize;

use super::{AppState, extract_principal, run_replay_store_io};
use crate::config::AuthMode;

pub(super) async fn healthz() -> &'static str {
    "ok"
}

#[derive(Debug, Serialize)]
struct ReadyzResponse {
    status: &'static str,
    checks: BTreeMap<&'static str, bool>,
}

pub(super) async fn readyz(State(state): State<AppState>) -> impl IntoResponse {
    let gateway_ready = {
        let url = format!("{}/readyz", state.config.gateway_url.trim_end_matches('/'));
        tokio::time::timeout(Duration::from_secs(2), state.http.get(url).send())
            .await
            .is_ok_and(|resp| resp.map(|r| r.status().is_success()).unwrap_or(false))
    };

    let auth_ready = match state.config.auth_mode {
        AuthMode::Local => true,
        AuthMode::Oidc => state.oidc.is_some(),
    };
    let replay_store_ready = run_replay_store_io(&state, |replay_store| {
        replay_store.readiness_check()?;
        Ok(())
    })
    .await
    .is_ok();

    let mut checks = BTreeMap::new();
    checks.insert("gateway", gateway_ready);
    checks.insert("auth", auth_ready);
    checks.insert("replay_store", replay_store_ready);

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
