use axum::http::{HeaderMap, StatusCode};
use pecr_auth::Principal;
use pecr_contracts::{TerminalMode, canonical};
use ulid::Ulid;

use super::{ApiError, AppState, json_error};
use crate::config::AuthMode;

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

pub(super) fn extract_session_token(headers: &HeaderMap) -> Result<String, ApiError> {
    let token = headers
        .get("x-pecr-session-token")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| {
            json_error(
                StatusCode::UNAUTHORIZED,
                "ERR_POLICY_DENIED",
                "missing or invalid session token".to_string(),
                TerminalMode::InsufficientPermission,
                false,
            )
        })?;

    Ok(token.to_string())
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

pub(super) fn parse_optional_sha256_hash(
    raw: Option<&str>,
    field_name: &str,
) -> Result<Option<String>, ApiError> {
    let Some(value) = raw
        .map(|value| value.trim())
        .filter(|value| !value.is_empty())
    else {
        return Ok(None);
    };

    if canonical::is_sha256_hex(value) {
        return Ok(Some(value.to_string()));
    }

    Err(json_error(
        StatusCode::BAD_REQUEST,
        "ERR_INVALID_PARAMS",
        format!("{} must be sha256 hex", field_name),
        TerminalMode::InsufficientEvidence,
        false,
    ))
}

pub(super) fn sanitize_as_of_time(raw: &str) -> Option<String> {
    const LEN: usize = 20;
    let raw = raw.trim();
    if raw.len() != LEN {
        return None;
    }

    let bytes = raw.as_bytes();
    let digit = |idx: usize| bytes.get(idx).is_some_and(|b| b.is_ascii_digit());

    if !digit(0)
        || !digit(1)
        || !digit(2)
        || !digit(3)
        || bytes.get(4) != Some(&b'-')
        || !digit(5)
        || !digit(6)
        || bytes.get(7) != Some(&b'-')
        || !digit(8)
        || !digit(9)
        || bytes.get(10) != Some(&b'T')
        || !digit(11)
        || !digit(12)
        || bytes.get(13) != Some(&b':')
        || !digit(14)
        || !digit(15)
        || bytes.get(16) != Some(&b':')
        || !digit(17)
        || !digit(18)
        || bytes.get(19) != Some(&b'Z')
    {
        return None;
    }

    Some(raw.to_string())
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

fn extract_principal_id(headers: &HeaderMap) -> Result<String, ApiError> {
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
