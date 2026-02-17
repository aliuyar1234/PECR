use std::time::{Duration, Instant};

use axum::http::StatusCode;
use pecr_contracts::{Budget, EvidenceUnit, EvidenceUnitRef, TerminalMode};
use serde::{Deserialize, Serialize};
use tracing::Instrument;

use super::budget::remaining_wallclock;
use super::{ApiError, AppState, apply_gateway_auth, json_error};

#[cfg(feature = "rlm")]
use std::path::PathBuf;
#[cfg(feature = "rlm")]
use std::process::Stdio;
#[cfg(feature = "rlm")]
use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

#[derive(Debug, Serialize)]
struct OperatorCallRequest {
    session_id: String,
    params: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct OperatorCallResponse {
    terminal_mode: TerminalMode,
    result: serde_json::Value,
}

#[derive(Debug)]
pub(super) struct ContextLoopResult {
    pub(super) terminal_mode: TerminalMode,
    pub(super) response_text: Option<String>,
    #[allow(dead_code)]
    pub(super) evidence_refs: Vec<EvidenceUnitRef>,
    #[allow(dead_code)]
    pub(super) evidence_units: Vec<EvidenceUnit>,
    #[allow(dead_code)]
    pub(super) operator_calls_used: u32,
    #[allow(dead_code)]
    pub(super) bytes_used: u64,
    #[allow(dead_code)]
    pub(super) depth_used: u32,
}

#[derive(Debug, Deserialize)]
struct GatewayErrorResponse {
    terminal_mode_hint: TerminalMode,
}

#[derive(Debug)]
struct OperatorCallOutcome {
    terminal_mode_hint: TerminalMode,
    body: Option<OperatorCallResponse>,
    bytes_len: usize,
}

#[derive(Clone, Copy)]
pub(super) struct GatewayCallContext<'a> {
    pub(super) principal_id: &'a str,
    pub(super) authz_header: Option<&'a str>,
    pub(super) local_auth_shared_secret: Option<&'a str>,
    pub(super) request_id: &'a str,
    pub(super) trace_id: &'a str,
    pub(super) session_token: &'a str,
    pub(super) session_id: &'a str,
}

async fn call_operator(
    state: &AppState,
    ctx: GatewayCallContext<'_>,
    op_name: &str,
    params: serde_json::Value,
    timeout: Duration,
) -> Result<OperatorCallOutcome, ApiError> {
    let params_bytes = serde_json::to_vec(&params)
        .map(|v| v.len() as u64)
        .unwrap_or(0);

    let span = match op_name {
        "search" => tracing::info_span!(
            "operator.search",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "search",
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
        "fetch_span" => tracing::info_span!(
            "operator.fetch_span",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "fetch_span",
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
        "fetch_rows" => tracing::info_span!(
            "operator.fetch_rows",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "fetch_rows",
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
        "aggregate" => tracing::info_span!(
            "operator.aggregate",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "aggregate",
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
        "list_versions" => tracing::info_span!(
            "operator.list_versions",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "list_versions",
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
        "diff" => tracing::info_span!(
            "operator.diff",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "diff",
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
        "redact" => tracing::info_span!(
            "operator.redact",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = "redact",
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
        _ => tracing::info_span!(
            "operator.unknown",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            principal_id = %ctx.principal_id,
            operator_name = %op_name,
            params_bytes,
            result_bytes = tracing::field::Empty,
            status_code = tracing::field::Empty,
            terminal_mode = tracing::field::Empty,
            latency_ms = tracing::field::Empty,
            outcome = tracing::field::Empty,
        ),
    };
    let started = Instant::now();
    async move {
        let url = format!(
            "{}/v1/operators/{}",
            state.config.gateway_url.trim_end_matches('/'),
            op_name
        );

        let send_fut = async {
            let builder = state
                .http
                .post(url)
                .header("x-pecr-request-id", ctx.request_id)
                .header("x-pecr-trace-id", ctx.trace_id)
                .header("x-pecr-session-token", ctx.session_token);

            let response = apply_gateway_auth(
                builder,
                ctx.principal_id,
                ctx.authz_header,
                ctx.local_auth_shared_secret,
            )
            .json(&OperatorCallRequest {
                session_id: ctx.session_id.to_string(),
                params,
            })
            .send()
            .await
            .map_err(|_| {
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "ERR_SOURCE_UNAVAILABLE",
                    "gateway request failed".to_string(),
                    TerminalMode::SourceUnavailable,
                    true,
                )
            })?;

            let status = response.status();
            let bytes = response.bytes().await.map_err(|_| {
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "ERR_SOURCE_UNAVAILABLE",
                    "gateway response read failed".to_string(),
                    TerminalMode::SourceUnavailable,
                    true,
                )
            })?;

            Ok::<_, ApiError>((status, bytes))
        };

        let timed = tokio::time::timeout(timeout, send_fut).await;
        let (status, bytes) = match timed {
            Ok(res) => res?,
            Err(_) => {
                let latency_ms = started.elapsed().as_millis() as u64;
                tracing::Span::current().record("latency_ms", latency_ms);
                tracing::Span::current().record("outcome", "timeout");
                return Ok(OperatorCallOutcome {
                    terminal_mode_hint: TerminalMode::SourceUnavailable,
                    body: None,
                    bytes_len: 0,
                });
            }
        };

        let bytes_len = bytes.len();
        let status_code = status.as_u16();
        let result_bytes = bytes_len as u64;
        tracing::Span::current().record("status_code", status_code);
        tracing::Span::current().record("result_bytes", result_bytes);

        if status.is_success() {
            let body = serde_json::from_slice::<OperatorCallResponse>(&bytes).map_err(|_| {
                json_error(
                    StatusCode::BAD_GATEWAY,
                    "ERR_INTERNAL",
                    "failed to parse gateway response".to_string(),
                    TerminalMode::SourceUnavailable,
                    false,
                )
            })?;

            let terminal_mode = body.terminal_mode.as_str();
            let latency_ms = started.elapsed().as_millis() as u64;
            tracing::Span::current().record("terminal_mode", terminal_mode);
            tracing::Span::current().record("latency_ms", latency_ms);
            tracing::Span::current().record("outcome", "ok");

            return Ok(OperatorCallOutcome {
                terminal_mode_hint: body.terminal_mode,
                body: Some(body),
                bytes_len,
            });
        }

        let terminal_mode_hint = serde_json::from_slice::<GatewayErrorResponse>(&bytes)
            .map_or(TerminalMode::SourceUnavailable, |e| e.terminal_mode_hint);
        let terminal_mode = terminal_mode_hint.as_str();
        let latency_ms = started.elapsed().as_millis() as u64;
        tracing::Span::current().record("terminal_mode", terminal_mode);
        tracing::Span::current().record("latency_ms", latency_ms);
        tracing::Span::current().record("outcome", "error");

        Ok(OperatorCallOutcome {
            terminal_mode_hint,
            body: None,
            bytes_len,
        })
    }
    .instrument(span)
    .await
}

pub(super) async fn run_context_loop(
    state: &AppState,
    ctx: GatewayCallContext<'_>,
    query: &str,
    budget: &Budget,
) -> Result<ContextLoopResult, ApiError> {
    use crate::config::BaselinePlanStep;

    let loop_start = Instant::now();
    let query_trimmed = query.trim();

    let mut terminal_mode = TerminalMode::InsufficientEvidence;
    let mut operator_calls_used: u32 = 0;
    let mut bytes_used: u64 = 0;
    let mut depth_used: u32 = 0;
    let mut stop_reason: &'static str = "unknown";
    let mut budget_violation = false;

    let mut evidence_refs = Vec::<EvidenceUnitRef>::new();
    let mut evidence_units = Vec::<EvidenceUnit>::new();
    let mut search_refs = Vec::<EvidenceUnitRef>::new();

    'plan_loop: for step in &state.config.baseline_plan {
        if depth_used >= budget.max_recursion_depth {
            stop_reason = "budget_max_recursion_depth";
            budget_violation = true;
            break;
        }

        crate::metrics::inc_loop_iteration();
        if operator_calls_used >= budget.max_operator_calls {
            stop_reason = "budget_max_operator_calls";
            budget_violation = true;
            break;
        }

        let Some(timeout) = remaining_wallclock(budget, loop_start) else {
            stop_reason = "budget_max_wallclock_ms";
            budget_violation = true;
            break;
        };

        depth_used = depth_used.saturating_add(1);

        match step {
            BaselinePlanStep::Operator { op_name, params } => {
                if op_name == "search" && query_trimmed.is_empty() {
                    continue;
                }

                let rendered_params = render_plan_params(params, query_trimmed);
                let outcome =
                    call_operator(state, ctx, op_name.as_str(), rendered_params, timeout).await?;
                operator_calls_used = operator_calls_used.saturating_add(1);
                bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                let Some(body) = outcome.body else {
                    terminal_mode = outcome.terminal_mode_hint;
                    stop_reason = "operator_error";
                    break;
                };

                if op_name == "search"
                    && let Some(refs_value) = body.result.get("refs").cloned()
                    && let Ok(refs) = serde_json::from_value::<Vec<EvidenceUnitRef>>(refs_value)
                {
                    search_refs = refs;
                    evidence_refs = search_refs.clone();
                }

                if let Ok(units) = serde_json::from_value::<Vec<EvidenceUnit>>(body.result.clone())
                {
                    evidence_units.extend(units);
                } else if let Ok(unit) = serde_json::from_value::<EvidenceUnit>(body.result) {
                    evidence_units.push(unit);
                }
            }
            BaselinePlanStep::SearchRefFetchSpan { max_refs } => {
                for r in search_refs.iter().take(*max_refs) {
                    if operator_calls_used >= budget.max_operator_calls {
                        stop_reason = "budget_max_operator_calls";
                        budget_violation = true;
                        break 'plan_loop;
                    }
                    let Some(timeout) = remaining_wallclock(budget, loop_start) else {
                        stop_reason = "budget_max_wallclock_ms";
                        budget_violation = true;
                        break 'plan_loop;
                    };

                    let outcome = call_operator(
                        state,
                        ctx,
                        "fetch_span",
                        serde_json::json!({ "object_id": r.object_id }),
                        timeout,
                    )
                    .await?;
                    operator_calls_used = operator_calls_used.saturating_add(1);
                    bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                    let Some(body) = outcome.body else {
                        terminal_mode = outcome.terminal_mode_hint;
                        stop_reason = "operator_error";
                        break 'plan_loop;
                    };

                    if let Ok(unit) = serde_json::from_value::<EvidenceUnit>(body.result) {
                        evidence_units.push(unit);
                    }
                }
            }
        }

        if bytes_used > budget.max_bytes {
            terminal_mode = TerminalMode::InsufficientEvidence;
            stop_reason = "budget_max_bytes";
            budget_violation = true;
            break;
        }
    }

    if stop_reason == "unknown" {
        stop_reason = "plan_complete";
    }
    if budget_violation {
        crate::metrics::inc_budget_violation();
    }

    tracing::info!(
        request_id = %ctx.request_id,
        trace_id = %ctx.trace_id,
        principal_id = %ctx.principal_id,
        session_id = %ctx.session_id,
        terminal_mode = %terminal_mode.as_str(),
        stop_reason = %stop_reason,
        budget_violation,
        operator_calls_used,
        depth_used,
        bytes_used,
        "controller.context_loop_completed"
    );

    Ok(ContextLoopResult {
        terminal_mode,
        response_text: None,
        evidence_refs,
        evidence_units,
        operator_calls_used,
        bytes_used,
        depth_used,
    })
}

fn render_plan_params(params: &serde_json::Value, query: &str) -> serde_json::Value {
    match params {
        serde_json::Value::String(value) if value == "$query" => {
            serde_json::Value::String(query.to_string())
        }
        serde_json::Value::Array(values) => serde_json::Value::Array(
            values
                .iter()
                .map(|value| render_plan_params(value, query))
                .collect(),
        ),
        serde_json::Value::Object(map) => {
            let mut out = serde_json::Map::with_capacity(map.len());
            for (key, value) in map {
                out.insert(key.clone(), render_plan_params(value, query));
            }
            serde_json::Value::Object(out)
        }
        _ => params.clone(),
    }
}

#[cfg(feature = "rlm")]
pub(super) async fn run_context_loop_rlm(
    state: &AppState,
    ctx: GatewayCallContext<'_>,
    query: &str,
    budget: &Budget,
) -> Result<ContextLoopResult, ApiError> {
    let loop_start = Instant::now();

    let mut terminal_mode = TerminalMode::InsufficientEvidence;
    let mut operator_calls_used: u32 = 0;
    let mut bytes_used: u64 = 0;
    let mut depth_used: u32 = 0;
    let stop_reason: Option<&'static str>;
    let mut budget_violation = false;

    let mut evidence_refs = Vec::<EvidenceUnitRef>::new();
    let mut evidence_units = Vec::<EvidenceUnit>::new();

    let python = std::env::var("PECR_RLM_PYTHON")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| {
            if cfg!(windows) {
                "python".to_string()
            } else {
                "python3".to_string()
            }
        });

    let script_path = std::env::var("PECR_RLM_SCRIPT_PATH")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .map(PathBuf::from)
        .or_else(|| {
            let candidates = [
                PathBuf::from("/usr/local/share/pecr/pecr_rlm_bridge.py"),
                PathBuf::from("scripts/rlm/pecr_rlm_bridge.py"),
            ];
            candidates.into_iter().find(|p| p.exists())
        })
        .ok_or_else(|| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_RLM_BRIDGE_SCRIPT_NOT_FOUND",
                "rlm bridge script not found; set PECR_RLM_SCRIPT_PATH or ensure scripts/rlm/pecr_rlm_bridge.py is present"
                    .to_string(),
                TerminalMode::SourceUnavailable,
                false,
            )
        })?;

    let mut child = tokio::process::Command::new(&python)
        .arg(&script_path)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|_| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_RLM_BRIDGE_SPAWN_FAILED",
                format!(
                    "failed to spawn rlm bridge (python={}, script={})",
                    python,
                    script_path.display()
                ),
                TerminalMode::SourceUnavailable,
                false,
            )
        })?;

    let mut child_stdin = child.stdin.take().ok_or_else(|| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_RLM_BRIDGE_INTERNAL",
            "failed to open rlm bridge stdin".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;
    let child_stdout = child.stdout.take().ok_or_else(|| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_RLM_BRIDGE_INTERNAL",
            "failed to open rlm bridge stdout".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;
    let child_stderr = child.stderr.take().ok_or_else(|| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_RLM_BRIDGE_INTERNAL",
            "failed to open rlm bridge stderr".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;

    let trace_id = ctx.trace_id.to_string();
    let request_id = ctx.request_id.to_string();
    tokio::spawn(async move {
        let mut lines = tokio::io::BufReader::new(child_stderr).lines();
        while let Ok(Some(line)) = lines.next_line().await {
            tracing::warn!(
                trace_id = %trace_id,
                request_id = %request_id,
                line = %line,
                "rlm.bridge.stderr"
            );
        }
    });

    let start_msg = serde_json::json!({
        "type": "start",
        "query": query,
        "budget": budget,
    });
    let start_line = serde_json::to_string(&start_msg).map_err(|_| {
        json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_RLM_BRIDGE_INTERNAL",
            "failed to serialize rlm bridge start message".to_string(),
            TerminalMode::SourceUnavailable,
            false,
        )
    })?;
    child_stdin
        .write_all(format!("{}\n", start_line).as_bytes())
        .await
        .map_err(|_| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_RLM_BRIDGE_PROTOCOL",
                "failed to write rlm bridge start message".to_string(),
                TerminalMode::SourceUnavailable,
                false,
            )
        })?;

    let mut stdout_lines = tokio::io::BufReader::new(child_stdout).lines();
    let mut response_text: Option<String> = None;

    loop {
        let Some(timeout) = remaining_wallclock(budget, loop_start) else {
            stop_reason = Some("budget_max_wallclock_ms");
            budget_violation = true;
            break;
        };

        let next_line = tokio::time::timeout(timeout, stdout_lines.next_line()).await;
        let line = match next_line {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => {
                stop_reason = Some("bridge_eof");
                budget_violation = false;
                break;
            }
            Ok(Err(_)) => {
                stop_reason = Some("bridge_read_error");
                budget_violation = false;
                break;
            }
            Err(_) => {
                stop_reason = Some("budget_max_wallclock_ms");
                budget_violation = true;
                break;
            }
        };

        let msg = serde_json::from_str::<serde_json::Value>(&line).map_err(|_| {
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ERR_RLM_BRIDGE_PROTOCOL",
                "rlm bridge emitted invalid json".to_string(),
                TerminalMode::SourceUnavailable,
                false,
            )
        })?;
        let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or_default();

        match msg_type {
            "call_operator" => {
                let id = msg
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let depth = msg.get("depth").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let op_name = msg
                    .get("op_name")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let params = msg.get("params").cloned().unwrap_or(serde_json::json!({}));

                if id.is_empty() {
                    stop_reason = Some("bridge_invalid_message");
                    break;
                }
                if depth >= budget.max_recursion_depth {
                    stop_reason = Some("budget_max_recursion_depth");
                    budget_violation = true;
                    break;
                }
                depth_used = depth_used.max(depth.saturating_add(1));

                if operator_calls_used >= budget.max_operator_calls {
                    stop_reason = Some("budget_max_operator_calls");
                    budget_violation = true;
                    break;
                }

                let allowed = matches!(
                    op_name.as_str(),
                    "search"
                        | "fetch_span"
                        | "fetch_rows"
                        | "aggregate"
                        | "list_versions"
                        | "diff"
                        | "redact"
                );
                if !allowed {
                    stop_reason = Some("bridge_operator_not_allowlisted");
                    break;
                }

                let outcome = call_operator(state, ctx, op_name.as_str(), params, timeout).await?;
                operator_calls_used = operator_calls_used.saturating_add(1);
                bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                if let Some(body) = outcome.body {
                    let terminal_mode_for_resp = body.terminal_mode;
                    let result = body.result;
                    if op_name == "search" {
                        if let Some(refs_value) = result.get("refs").cloned()
                            && let Ok(refs) =
                                serde_json::from_value::<Vec<EvidenceUnitRef>>(refs_value)
                        {
                            evidence_refs = refs;
                        }
                    }

                    if let Ok(units) = serde_json::from_value::<Vec<EvidenceUnit>>(result.clone()) {
                        evidence_units.extend(units);
                    } else if let Ok(unit) = serde_json::from_value::<EvidenceUnit>(result.clone())
                    {
                        evidence_units.push(unit);
                    }

                    let resp = serde_json::json!({
                        "type": "operator_result",
                        "id": id,
                        "ok": true,
                        "terminal_mode": terminal_mode_for_resp.as_str(),
                        "result": result,
                        "bytes_len": outcome.bytes_len,
                    });
                    let resp_line = serde_json::to_string(&resp).map_err(|_| {
                        json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "ERR_RLM_BRIDGE_INTERNAL",
                            "failed to serialize rlm bridge response".to_string(),
                            TerminalMode::SourceUnavailable,
                            false,
                        )
                    })?;
                    child_stdin
                        .write_all(format!("{}\n", resp_line).as_bytes())
                        .await
                        .map_err(|_| {
                            json_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "ERR_RLM_BRIDGE_PROTOCOL",
                                "failed to write rlm bridge response".to_string(),
                                TerminalMode::SourceUnavailable,
                                false,
                            )
                        })?;
                } else {
                    terminal_mode = outcome.terminal_mode_hint;
                    stop_reason = Some("operator_error");

                    let resp = serde_json::json!({
                        "type": "operator_result",
                        "id": id,
                        "ok": false,
                        "terminal_mode": outcome.terminal_mode_hint.as_str(),
                        "result": serde_json::Value::Null,
                        "bytes_len": outcome.bytes_len,
                    });
                    let resp_line = serde_json::to_string(&resp).map_err(|_| {
                        json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "ERR_RLM_BRIDGE_INTERNAL",
                            "failed to serialize rlm bridge response".to_string(),
                            TerminalMode::SourceUnavailable,
                            false,
                        )
                    })?;
                    let _ = child_stdin
                        .write_all(format!("{}\n", resp_line).as_bytes())
                        .await;
                    break;
                }

                if bytes_used > budget.max_bytes {
                    stop_reason = Some("budget_max_bytes");
                    budget_violation = true;
                    break;
                }
            }
            "done" => {
                response_text = msg
                    .get("final_answer")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                stop_reason = Some("rlm_done");
                break;
            }
            _ => {
                stop_reason = Some("bridge_unknown_message");
                break;
            }
        }
    }

    if budget_violation {
        crate::metrics::inc_budget_violation();
    }

    let stop_reason = stop_reason.unwrap_or("unknown");
    let stop_is_bridge_failure = matches!(
        stop_reason,
        "bridge_eof"
            | "bridge_read_error"
            | "bridge_invalid_message"
            | "bridge_operator_not_allowlisted"
            | "bridge_unknown_message"
    );

    let status = if stop_reason == "rlm_done" {
        tokio::time::timeout(Duration::from_millis(250), child.wait())
            .await
            .ok()
            .and_then(Result::ok)
    } else {
        let _ = child.kill();
        let _ = tokio::time::timeout(Duration::from_millis(250), child.wait()).await;
        None
    };

    if stop_is_bridge_failure || status.is_some_and(|s| !s.success()) {
        return Err(json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "ERR_RLM_BRIDGE_FAILED",
            format!("rlm bridge failed (reason={})", stop_reason),
            TerminalMode::SourceUnavailable,
            false,
        ));
    }

    tracing::info!(
        request_id = %ctx.request_id,
        trace_id = %ctx.trace_id,
        principal_id = %ctx.principal_id,
        session_id = %ctx.session_id,
        terminal_mode = %terminal_mode.as_str(),
        stop_reason = %stop_reason,
        budget_violation,
        operator_calls_used,
        depth_used,
        bytes_used,
        "controller.context_loop_completed"
    );

    Ok(ContextLoopResult {
        terminal_mode,
        response_text,
        evidence_refs,
        evidence_units,
        operator_calls_used,
        bytes_used,
        depth_used,
    })
}

#[cfg(not(feature = "rlm"))]
pub(super) async fn run_context_loop_rlm(
    _state: &AppState,
    _ctx: GatewayCallContext<'_>,
    _query: &str,
    _budget: &Budget,
) -> Result<ContextLoopResult, ApiError> {
    Err(json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "ERR_RLM_FEATURE_DISABLED",
        "rlm controller engine is not enabled in this build".to_string(),
        TerminalMode::InsufficientEvidence,
        false,
    ))
}
