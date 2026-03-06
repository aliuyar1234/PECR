use axum::Json;
use axum::http::{HeaderMap, StatusCode, header};
use pecr_auth::Principal;
use pecr_contracts::{TerminalMode, canonical};
use ulid::Ulid;

use super::{ApiError, AppState, ErrorResponse, json_error};
use crate::config::AuthMode;

pub(super) fn extract_authorization_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
}

pub(super) async fn extract_principal(
    state: &AppState,
    headers: &HeaderMap,
) -> Result<Principal, ApiError> {
    match state.config.auth_mode {
        AuthMode::Local => {
            validate_local_auth_shared_secret(
                headers,
                state.config.local_auth_shared_secret.as_deref(),
            )?;
            let principal_id = extract_principal_id(headers)?;
            Ok(Principal {
                principal_id,
                tenant_id: "local".to_string(),
                principal_roles: Vec::new(),
                principal_attrs_hash: canonical::hash_canonical_json(&serde_json::json!({})),
            })
        }
        AuthMode::Oidc => {
            let Some(auth) = state.oidc.as_ref() else {
                return Err(json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ERR_INTERNAL",
                    "oidc authenticator is not initialized".to_string(),
                    TerminalMode::SourceUnavailable,
                    false,
                ));
            };

            auth.authenticate(headers)
                .await
                .map_err(|err| match err.code {
                    "ERR_AUTH_UNAVAILABLE" => json_error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        err.code,
                        err.message,
                        TerminalMode::SourceUnavailable,
                        true,
                    ),
                    "ERR_AUTH_REQUIRED" | "ERR_AUTH_INVALID" => json_error(
                        StatusCode::UNAUTHORIZED,
                        err.code,
                        err.message,
                        TerminalMode::InsufficientPermission,
                        false,
                    ),
                    _ => json_error(
                        StatusCode::UNAUTHORIZED,
                        err.code,
                        err.message,
                        TerminalMode::InsufficientPermission,
                        false,
                    ),
                })
        }
    }
}

pub(super) fn apply_gateway_auth(
    builder: reqwest::RequestBuilder,
    principal_id: &str,
    authz_header: Option<&str>,
    local_auth_shared_secret: Option<&str>,
) -> reqwest::RequestBuilder {
    match authz_header {
        Some(authz_header) => builder.header(reqwest::header::AUTHORIZATION, authz_header),
        None => {
            let builder = builder.header("x-pecr-principal-id", principal_id);
            if let Some(secret) = local_auth_shared_secret {
                builder.header("x-pecr-local-auth-secret", secret)
            } else {
                builder
            }
        }
    }
}

fn validate_local_auth_shared_secret(
    headers: &HeaderMap,
    expected_secret: Option<&str>,
) -> Result<(), ApiError> {
    let Some(expected_secret) = expected_secret else {
        return Ok(());
    };

    let provided_secret = headers
        .get("x-pecr-local-auth-secret")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "ERR_AUTH_REQUIRED",
                "missing local auth secret".to_string(),
                TerminalMode::InsufficientPermission,
                false,
            )
        })?;

    if provided_secret != expected_secret {
        return Err(json_error(
            StatusCode::UNAUTHORIZED,
            "ERR_AUTH_INVALID",
            "invalid local auth secret".to_string(),
            TerminalMode::InsufficientPermission,
            false,
        ));
    }

    Ok(())
}

fn extract_principal_id(headers: &HeaderMap) -> Result<String, (StatusCode, Json<ErrorResponse>)> {
    let principal_id = headers
        .get("x-pecr-principal-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .map(|v| v.to_string())
        .ok_or_else(|| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "ERR_POLICY_DENIED",
                "missing x-pecr-principal-id header".to_string(),
                TerminalMode::InsufficientPermission,
                false,
            )
        })?;

    Ok(principal_id)
}

pub(super) fn extract_request_id(headers: &HeaderMap) -> String {
    headers
        .get("x-pecr-request-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .and_then(sanitize_request_id)
        .unwrap_or_else(|| Ulid::new().to_string())
}

pub(super) fn extract_trace_id(headers: &HeaderMap) -> String {
    headers
        .get("x-pecr-trace-id")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .and_then(|v| v.parse::<Ulid>().ok())
        .map(|u| u.to_string())
        .unwrap_or_else(|| Ulid::new().to_string())
}

fn sanitize_request_id(raw: &str) -> Option<String> {
    const MAX_LEN: usize = 64;
    let mut out = String::with_capacity(raw.len().min(MAX_LEN));

    for ch in raw.chars() {
        if out.len() >= MAX_LEN {
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.') {
            out.push(ch);
        }
    }

    (!out.is_empty()).then_some(out)
}
