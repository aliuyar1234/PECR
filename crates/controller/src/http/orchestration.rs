use std::time::{Duration, Instant};

use axum::http::StatusCode;
use futures_util::stream::{FuturesUnordered, StreamExt};
use pecr_contracts::{Budget, EvidenceUnit, EvidenceUnitRef, TerminalMode};
use serde::{Deserialize, Serialize};
use tracing::Instrument;

use super::budget::{BudgetScheduler, BudgetStopReason};
use super::{ApiError, AppState, apply_gateway_auth, json_error};

#[cfg(feature = "rlm")]
use std::collections::{HashMap, VecDeque};
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

struct InflightOpsGuard;

impl InflightOpsGuard {
    fn new() -> Self {
        crate::metrics::inc_inflight_ops();
        Self
    }
}

impl Drop for InflightOpsGuard {
    fn drop(&mut self) {
        crate::metrics::dec_inflight_ops();
    }
}

#[cfg(feature = "rlm")]
#[derive(Debug, Deserialize)]
struct BatchBridgeCall {
    op_name: String,
    #[serde(default)]
    params: serde_json::Value,
}

#[cfg(feature = "rlm")]
#[derive(Debug)]
struct PendingBatchCall {
    idx: usize,
    params: serde_json::Value,
}

#[cfg(feature = "rlm")]
const RLM_BRIDGE_PROTOCOL_MIN_VERSION: u32 = 1;
#[cfg(feature = "rlm")]
const RLM_BRIDGE_PROTOCOL_MAX_VERSION: u32 = 1;

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

#[cfg(feature = "rlm")]
fn allowed_operator(op_name: &str) -> bool {
    matches!(
        op_name,
        "search" | "fetch_span" | "fetch_rows" | "aggregate" | "list_versions" | "diff" | "redact"
    )
}

#[cfg(feature = "rlm")]
fn record_operator_result(
    op_name: &str,
    result: &serde_json::Value,
    evidence_refs: &mut Vec<EvidenceUnitRef>,
    evidence_units: &mut Vec<EvidenceUnit>,
) {
    if op_name == "search"
        && let Some(refs_value) = result.get("refs").cloned()
        && let Ok(refs) = serde_json::from_value::<Vec<EvidenceUnitRef>>(refs_value)
    {
        *evidence_refs = refs;
    }

    if let Ok(units) = serde_json::from_value::<Vec<EvidenceUnit>>(result.clone()) {
        evidence_units.extend(units);
    } else if let Ok(unit) = serde_json::from_value::<EvidenceUnit>(result.clone()) {
        evidence_units.push(unit);
    }
}

fn scheduler_parallelism(
    state: &AppState,
    scheduler: BudgetScheduler<'_>,
    operator_calls_used: u32,
    scheduled_calls: u32,
) -> usize {
    if state.config.adaptive_parallelism_enabled {
        scheduler.adaptive_parallelism(operator_calls_used, scheduled_calls)
    } else {
        scheduler.effective_parallelism()
    }
}

#[cfg(feature = "rlm")]
fn next_fair_batch_call(
    fairness_ring: &mut VecDeque<String>,
    pending_by_operator: &mut HashMap<String, VecDeque<PendingBatchCall>>,
    in_flight_by_operator: &mut HashMap<String, usize>,
    max_in_flight_by_operator: &HashMap<String, usize>,
) -> Option<(usize, String, serde_json::Value)> {
    let slots = fairness_ring.len();
    for _ in 0..slots {
        let op_name = fairness_ring.pop_front()?;
        fairness_ring.push_back(op_name.clone());

        let max_in_flight = max_in_flight_by_operator
            .get(op_name.as_str())
            .copied()
            .unwrap_or(usize::MAX);
        let in_flight = in_flight_by_operator
            .get(op_name.as_str())
            .copied()
            .unwrap_or(0);
        if in_flight >= max_in_flight {
            continue;
        }

        let Some(queue) = pending_by_operator.get_mut(op_name.as_str()) else {
            continue;
        };
        let Some(next_call) = queue.pop_front() else {
            continue;
        };

        in_flight_by_operator.insert(op_name.clone(), in_flight.saturating_add(1));
        return Some((next_call.idx, op_name, next_call.params));
    }

    None
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
        let _inflight = InflightOpsGuard::new();
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
    let scheduler = BudgetScheduler::new(budget, loop_start);

    'plan_loop: for step in &state.config.baseline_plan {
        let step_name = match step {
            BaselinePlanStep::Operator { op_name, .. } => op_name.as_str(),
            BaselinePlanStep::SearchRefFetchSpan { .. } => "search_ref_fetch_span",
        };
        let planner_span = tracing::info_span!(
            "planner.baseline_step",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            step = %step_name,
            depth_used,
            operator_calls_used,
            bytes_used,
        );
        tracing::debug!(parent: &planner_span, "planner.step_ready");

        let scheduler_span = tracing::info_span!(
            "scheduler.budget_gate",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            depth_used,
            operator_calls_used,
            bytes_used,
        );
        if let Err(reason) = scheduler_span.in_scope(|| scheduler.check_depth(depth_used)) {
            stop_reason = reason.as_str();
            budget_violation = true;
            break;
        }

        crate::metrics::inc_loop_iteration();
        if let Err(reason) =
            scheduler_span.in_scope(|| scheduler.check_operator_calls(operator_calls_used))
        {
            stop_reason = reason.as_str();
            budget_violation = true;
            break;
        }

        let Some(timeout) = scheduler.remaining_wallclock() else {
            stop_reason = BudgetStopReason::WallclockMs.as_str();
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
                let mut refs_to_fetch = search_refs
                    .iter()
                    .take(*max_refs)
                    .map(|r| r.object_id.clone());
                let mut in_flight = FuturesUnordered::new();
                let mut scheduled_calls: u32 = 0;

                loop {
                    let parallelism = scheduler_parallelism(
                        state,
                        scheduler,
                        operator_calls_used,
                        scheduled_calls,
                    );
                    while in_flight.len() < parallelism {
                        if let Err(reason) = scheduler.check_operator_calls_with_reserved(
                            operator_calls_used,
                            scheduled_calls,
                        ) {
                            stop_reason = reason.as_str();
                            budget_violation = true;
                            break 'plan_loop;
                        }

                        let Some(object_id) = refs_to_fetch.next() else {
                            break;
                        };
                        let Some(timeout) = scheduler.remaining_wallclock() else {
                            stop_reason = BudgetStopReason::WallclockMs.as_str();
                            budget_violation = true;
                            break 'plan_loop;
                        };

                        scheduled_calls = scheduled_calls.saturating_add(1);
                        let queued_at = Instant::now();
                        in_flight.push(async move {
                            crate::metrics::observe_operator_queue_wait(queued_at.elapsed());
                            call_operator(
                                state,
                                ctx,
                                "fetch_span",
                                serde_json::json!({ "object_id": object_id }),
                                timeout,
                            )
                            .await
                        });
                    }

                    let Some(outcome) = in_flight.next().await else {
                        break;
                    };
                    scheduled_calls = scheduled_calls.saturating_sub(1);

                    let outcome = outcome?;
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

                    if let Err(reason) = scheduler.check_bytes(bytes_used) {
                        terminal_mode = TerminalMode::InsufficientEvidence;
                        stop_reason = reason.as_str();
                        budget_violation = true;
                        break 'plan_loop;
                    }
                }
            }
        }

        if let Err(reason) = scheduler.check_bytes(bytes_used) {
            terminal_mode = TerminalMode::InsufficientEvidence;
            stop_reason = reason.as_str();
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
    crate::metrics::observe_budget_stop_reason(stop_reason);

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
    let scheduler = BudgetScheduler::new(budget, loop_start);

    let mut terminal_mode = TerminalMode::InsufficientEvidence;
    let mut operator_calls_used: u32 = 0;
    let mut bytes_used: u64 = 0;
    let mut depth_used: u32 = 0;
    let mut stop_reason: Option<&'static str> = None;
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
        "protocol": {
            "min_version": RLM_BRIDGE_PROTOCOL_MIN_VERSION,
            "max_version": RLM_BRIDGE_PROTOCOL_MAX_VERSION,
        },
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
    let mut pending_msg: Option<serde_json::Value> = None;

    if let Some(timeout) = scheduler.remaining_wallclock() {
        let next_line = tokio::time::timeout(timeout, stdout_lines.next_line()).await;
        let first_line = match next_line {
            Ok(Ok(Some(line))) => line,
            Ok(Ok(None)) => {
                stop_reason = Some("bridge_eof");
                String::new()
            }
            Ok(Err(_)) => {
                stop_reason = Some("bridge_read_error");
                String::new()
            }
            Err(_) => {
                stop_reason = Some(BudgetStopReason::WallclockMs.as_str());
                budget_violation = true;
                String::new()
            }
        };

        if stop_reason.is_none() {
            let first_msg =
                serde_json::from_str::<serde_json::Value>(&first_line).map_err(|_| {
                    json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "ERR_RLM_BRIDGE_PROTOCOL",
                        "rlm bridge emitted invalid json".to_string(),
                        TerminalMode::SourceUnavailable,
                        false,
                    )
                })?;
            let first_msg_type = first_msg
                .get("type")
                .and_then(|v| v.as_str())
                .unwrap_or_default();
            if first_msg_type == "start_ack" {
                let version = first_msg
                    .get("protocol_version")
                    .and_then(|v| v.as_u64())
                    .ok_or_else(|| {
                        json_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "ERR_RLM_BRIDGE_PROTOCOL",
                            "rlm bridge start_ack missing protocol_version".to_string(),
                            TerminalMode::SourceUnavailable,
                            false,
                        )
                    })? as u32;
                if !(RLM_BRIDGE_PROTOCOL_MIN_VERSION..=RLM_BRIDGE_PROTOCOL_MAX_VERSION)
                    .contains(&version)
                {
                    return Err(json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "ERR_RLM_BRIDGE_PROTOCOL",
                        format!(
                            "unsupported rlm bridge protocol_version={} (supported {}-{})",
                            version,
                            RLM_BRIDGE_PROTOCOL_MIN_VERSION,
                            RLM_BRIDGE_PROTOCOL_MAX_VERSION
                        ),
                        TerminalMode::SourceUnavailable,
                        false,
                    ));
                }
            } else {
                // Backward compatibility: older bridges start directly with protocol messages.
                pending_msg = Some(first_msg);
            }
        }
    } else {
        stop_reason = Some(BudgetStopReason::WallclockMs.as_str());
        budget_violation = true;
    }

    while stop_reason.is_none() {
        let Some(timeout) = scheduler.remaining_wallclock() else {
            stop_reason = Some(BudgetStopReason::WallclockMs.as_str());
            budget_violation = true;
            break;
        };

        let msg = if let Some(msg) = pending_msg.take() {
            msg
        } else {
            let next_line = tokio::time::timeout(timeout, stdout_lines.next_line()).await;
            let line = match next_line {
                Ok(Ok(Some(line))) => line,
                Ok(Ok(None)) => {
                    stop_reason = Some("bridge_eof");
                    break;
                }
                Ok(Err(_)) => {
                    stop_reason = Some("bridge_read_error");
                    break;
                }
                Err(_) => {
                    stop_reason = Some(BudgetStopReason::WallclockMs.as_str());
                    budget_violation = true;
                    break;
                }
            };
            serde_json::from_str::<serde_json::Value>(&line).map_err(|_| {
                json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "ERR_RLM_BRIDGE_PROTOCOL",
                    "rlm bridge emitted invalid json".to_string(),
                    TerminalMode::SourceUnavailable,
                    false,
                )
            })?
        };
        let msg_type = msg.get("type").and_then(|v| v.as_str()).unwrap_or_default();
        let bridge_depth = msg.get("depth").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
        let planner_span = tracing::info_span!(
            "planner.rlm_message",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            msg_type = %msg_type,
            bridge_depth,
            depth_used,
            operator_calls_used,
            bytes_used,
        );
        tracing::debug!(parent: &planner_span, "planner.message_ready");
        let scheduler_span = tracing::info_span!(
            "scheduler.budget_gate",
            trace_id = %ctx.trace_id,
            request_id = %ctx.request_id,
            session_id = %ctx.session_id,
            phase = "rlm_loop",
            msg_type = %msg_type,
            bridge_depth,
            depth_used,
            operator_calls_used,
            bytes_used,
        );

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
                if let Err(reason) = scheduler_span.in_scope(|| scheduler.check_depth(depth)) {
                    stop_reason = Some(reason.as_str());
                    budget_violation = true;
                    break;
                }
                depth_used = depth_used.max(depth.saturating_add(1));

                if let Err(reason) =
                    scheduler_span.in_scope(|| scheduler.check_operator_calls(operator_calls_used))
                {
                    stop_reason = Some(reason.as_str());
                    budget_violation = true;
                    break;
                }

                if !allowed_operator(op_name.as_str()) {
                    stop_reason = Some("bridge_operator_not_allowlisted");
                    break;
                }

                let outcome = call_operator(state, ctx, op_name.as_str(), params, timeout).await?;
                operator_calls_used = operator_calls_used.saturating_add(1);
                bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                if let Some(body) = outcome.body {
                    let terminal_mode_for_resp = body.terminal_mode;
                    let result = body.result;
                    record_operator_result(
                        op_name.as_str(),
                        &result,
                        &mut evidence_refs,
                        &mut evidence_units,
                    );

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

                if let Err(reason) = scheduler_span.in_scope(|| scheduler.check_bytes(bytes_used)) {
                    stop_reason = Some(reason.as_str());
                    budget_violation = true;
                    break;
                }
            }
            "call_operator_batch" => {
                let id = msg
                    .get("id")
                    .and_then(|v| v.as_str())
                    .unwrap_or_default()
                    .to_string();
                let depth = msg.get("depth").and_then(|v| v.as_u64()).unwrap_or(0) as u32;
                let calls = msg
                    .get("calls")
                    .cloned()
                    .and_then(|value| serde_json::from_value::<Vec<BatchBridgeCall>>(value).ok())
                    .unwrap_or_default();

                if id.is_empty() || calls.is_empty() {
                    stop_reason = Some("bridge_invalid_message");
                    break;
                }
                if let Err(reason) = scheduler_span.in_scope(|| scheduler.check_depth(depth)) {
                    stop_reason = Some(reason.as_str());
                    budget_violation = true;
                    break;
                }
                depth_used = depth_used.max(depth.saturating_add(1));

                let mut batch_results = vec![serde_json::Value::Null; calls.len()];
                let mut break_outer = false;

                if !state.config.batch_mode_enabled {
                    for (idx, call) in calls.iter().enumerate() {
                        if let Err(reason) = scheduler_span
                            .in_scope(|| scheduler.check_operator_calls(operator_calls_used))
                        {
                            stop_reason = Some(reason.as_str());
                            budget_violation = true;
                            break_outer = true;
                            break;
                        }

                        let op_name = call.op_name.trim();
                        if op_name.is_empty() || !allowed_operator(op_name) {
                            stop_reason = Some("bridge_operator_not_allowlisted");
                            break_outer = true;
                            break;
                        }

                        let Some(timeout) = scheduler.remaining_wallclock() else {
                            stop_reason = Some(BudgetStopReason::WallclockMs.as_str());
                            budget_violation = true;
                            break_outer = true;
                            break;
                        };

                        let outcome =
                            call_operator(state, ctx, op_name, call.params.clone(), timeout)
                                .await?;
                        operator_calls_used = operator_calls_used.saturating_add(1);
                        bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                        if let Some(body) = outcome.body {
                            let terminal_mode_for_resp = body.terminal_mode;
                            let result = body.result;
                            record_operator_result(
                                op_name,
                                &result,
                                &mut evidence_refs,
                                &mut evidence_units,
                            );
                            batch_results[idx] = serde_json::json!({
                                "ok": true,
                                "op_name": op_name,
                                "terminal_mode": terminal_mode_for_resp.as_str(),
                                "result": result,
                                "bytes_len": outcome.bytes_len,
                            });
                        } else {
                            terminal_mode = outcome.terminal_mode_hint;
                            stop_reason = Some("operator_error");
                            batch_results[idx] = serde_json::json!({
                                "ok": false,
                                "op_name": op_name,
                                "terminal_mode": outcome.terminal_mode_hint.as_str(),
                                "result": serde_json::Value::Null,
                                "bytes_len": outcome.bytes_len,
                            });
                            break_outer = true;
                            break;
                        }

                        if let Err(reason) =
                            scheduler_span.in_scope(|| scheduler.check_bytes(bytes_used))
                        {
                            stop_reason = Some(reason.as_str());
                            budget_violation = true;
                            break_outer = true;
                            break;
                        }
                    }
                } else {
                    let mut pending_by_operator: HashMap<String, VecDeque<PendingBatchCall>> =
                        HashMap::new();
                    let mut max_in_flight_by_operator: HashMap<String, usize> = HashMap::new();
                    let mut in_flight_by_operator: HashMap<String, usize> = HashMap::new();
                    let mut fairness_ring = VecDeque::<String>::new();

                    for (idx, call) in calls.iter().enumerate() {
                        let op_name = call.op_name.trim();
                        if op_name.is_empty() || !allowed_operator(op_name) {
                            stop_reason = Some("bridge_operator_not_allowlisted");
                            break_outer = true;
                            break;
                        }

                        if !pending_by_operator.contains_key(op_name) {
                            let policy = state.config.operator_concurrency_policies.get(op_name);
                            let fairness_weight =
                                policy.and_then(|p| p.fairness_weight).unwrap_or(1) as usize;
                            let max_in_flight =
                                policy.and_then(|p| p.max_in_flight).unwrap_or(usize::MAX);
                            let op_name_owned = op_name.to_string();
                            pending_by_operator.insert(op_name_owned.clone(), VecDeque::new());
                            max_in_flight_by_operator.insert(op_name_owned.clone(), max_in_flight);
                            in_flight_by_operator.insert(op_name_owned.clone(), 0);
                            for _ in 0..fairness_weight {
                                fairness_ring.push_back(op_name_owned.clone());
                            }
                        }

                        if let Some(queue) = pending_by_operator.get_mut(op_name) {
                            queue.push_back(PendingBatchCall {
                                idx,
                                params: call.params.clone(),
                            });
                        }
                    }

                    if break_outer {
                        break;
                    }
                    if fairness_ring.is_empty() {
                        stop_reason = Some("bridge_invalid_message");
                        break;
                    }

                    let mut in_flight = FuturesUnordered::new();
                    let mut scheduled_calls: u32 = 0;

                    'batch_loop: loop {
                        let parallelism = scheduler_parallelism(
                            state,
                            scheduler,
                            operator_calls_used,
                            scheduled_calls,
                        );
                        while in_flight.len() < parallelism {
                            if let Err(reason) = scheduler_span.in_scope(|| {
                                scheduler.check_operator_calls_with_reserved(
                                    operator_calls_used,
                                    scheduled_calls,
                                )
                            }) {
                                stop_reason = Some(reason.as_str());
                                budget_violation = true;
                                break_outer = true;
                                break 'batch_loop;
                            }

                            let has_pending_calls =
                                pending_by_operator.values().any(|queue| !queue.is_empty());
                            if !has_pending_calls {
                                break;
                            }

                            let Some((idx, op_name, params)) = next_fair_batch_call(
                                &mut fairness_ring,
                                &mut pending_by_operator,
                                &mut in_flight_by_operator,
                                &max_in_flight_by_operator,
                            ) else {
                                break;
                            };

                            let Some(timeout) = scheduler.remaining_wallclock() else {
                                stop_reason = Some(BudgetStopReason::WallclockMs.as_str());
                                budget_violation = true;
                                break_outer = true;
                                break 'batch_loop;
                            };

                            scheduled_calls = scheduled_calls.saturating_add(1);
                            let queued_at = Instant::now();
                            in_flight.push(async move {
                                crate::metrics::observe_operator_queue_wait(queued_at.elapsed());
                                (
                                    idx,
                                    op_name.clone(),
                                    call_operator(state, ctx, op_name.as_str(), params, timeout)
                                        .await,
                                )
                            });
                        }

                        if in_flight.is_empty() {
                            let has_pending_calls =
                                pending_by_operator.values().any(|queue| !queue.is_empty());
                            if !has_pending_calls {
                                break;
                            }
                            stop_reason = Some("bridge_invalid_message");
                            break_outer = true;
                            break;
                        }

                        let Some((idx, op_name, outcome)) = in_flight.next().await else {
                            break;
                        };
                        scheduled_calls = scheduled_calls.saturating_sub(1);
                        if let Some(in_flight) = in_flight_by_operator.get_mut(op_name.as_str()) {
                            *in_flight = in_flight.saturating_sub(1);
                        }

                        let outcome = outcome?;
                        operator_calls_used = operator_calls_used.saturating_add(1);
                        bytes_used = bytes_used.saturating_add(outcome.bytes_len as u64);

                        if let Some(body) = outcome.body {
                            let terminal_mode_for_resp = body.terminal_mode;
                            let result = body.result;
                            record_operator_result(
                                op_name.as_str(),
                                &result,
                                &mut evidence_refs,
                                &mut evidence_units,
                            );
                            batch_results[idx] = serde_json::json!({
                                "ok": true,
                                "op_name": op_name,
                                "terminal_mode": terminal_mode_for_resp.as_str(),
                                "result": result,
                                "bytes_len": outcome.bytes_len,
                            });
                        } else {
                            terminal_mode = outcome.terminal_mode_hint;
                            stop_reason = Some("operator_error");
                            batch_results[idx] = serde_json::json!({
                                "ok": false,
                                "op_name": op_name,
                                "terminal_mode": outcome.terminal_mode_hint.as_str(),
                                "result": serde_json::Value::Null,
                                "bytes_len": outcome.bytes_len,
                            });
                            break_outer = true;
                            break;
                        }

                        if let Err(reason) =
                            scheduler_span.in_scope(|| scheduler.check_bytes(bytes_used))
                        {
                            stop_reason = Some(reason.as_str());
                            budget_violation = true;
                            break_outer = true;
                            break;
                        }
                    }
                }

                if break_outer {
                    break;
                }

                let resp = serde_json::json!({
                    "type": "operator_batch_result",
                    "id": id,
                    "results": batch_results,
                });
                let resp_line = serde_json::to_string(&resp).map_err(|_| {
                    json_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "ERR_RLM_BRIDGE_INTERNAL",
                        "failed to serialize rlm bridge batch response".to_string(),
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
                            "failed to write rlm bridge batch response".to_string(),
                            TerminalMode::SourceUnavailable,
                            false,
                        )
                    })?;
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
    crate::metrics::observe_budget_stop_reason(stop_reason);
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
        let _ = child.kill().await;
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
