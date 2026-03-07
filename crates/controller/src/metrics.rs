use std::sync::OnceLock;
use std::time::Duration;

use prometheus::{
    Encoder, Histogram, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts,
    Registry, TextEncoder,
};

static REGISTRY: OnceLock<Registry> = OnceLock::new();
static HTTP_REQUESTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static HTTP_REQUEST_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static TERMINAL_MODES_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static LOOP_ITERATIONS_TOTAL: OnceLock<IntCounter> = OnceLock::new();
static BUDGET_VIOLATIONS_TOTAL: OnceLock<IntCounter> = OnceLock::new();
static BUDGET_STOP_REASONS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static INFLIGHT_OPS: OnceLock<IntGauge> = OnceLock::new();
static OPERATOR_QUEUE_WAIT_SECONDS: OnceLock<Histogram> = OnceLock::new();
static EVIDENCE_PACKS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static EVIDENCE_PACK_UNITS: OnceLock<Histogram> = OnceLock::new();
static EVIDENCE_COMPACTION_RATIO: OnceLock<Histogram> = OnceLock::new();
static CITATION_QUALITY: OnceLock<Histogram> = OnceLock::new();

fn registry() -> &'static Registry {
    REGISTRY.get_or_init(Registry::new)
}

fn register_collector<T>(collector: T) -> T
where
    T: prometheus::core::Collector + Clone + 'static,
{
    let _ = registry().register(Box::new(collector.clone()));
    collector
}

fn http_requests_total() -> &'static IntCounterVec {
    HTTP_REQUESTS_TOTAL.get_or_init(|| {
        register_collector(
            IntCounterVec::new(
                Opts::new(
                    "pecr_controller_http_requests_total",
                    "Controller HTTP request count.",
                ),
                &["route", "method", "status"],
            )
            .expect("create pecr_controller_http_requests_total"),
        )
    })
}

fn http_request_duration_seconds() -> &'static HistogramVec {
    HTTP_REQUEST_DURATION_SECONDS.get_or_init(|| {
        register_collector(
            HistogramVec::new(
                HistogramOpts::new(
                    "pecr_controller_http_request_duration_seconds",
                    "Controller HTTP request duration in seconds.",
                )
                .buckets(vec![
                    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ]),
                &["route", "method", "outcome"],
            )
            .expect("create pecr_controller_http_request_duration_seconds"),
        )
    })
}

fn terminal_modes_total() -> &'static IntCounterVec {
    TERMINAL_MODES_TOTAL.get_or_init(|| {
        register_collector(
            IntCounterVec::new(
                Opts::new(
                    "pecr_controller_terminal_modes_total",
                    "Controller terminal modes observed in responses.",
                ),
                &["route", "terminal_mode"],
            )
            .expect("create pecr_controller_terminal_modes_total"),
        )
    })
}

fn loop_iterations_total() -> &'static IntCounter {
    LOOP_ITERATIONS_TOTAL.get_or_init(|| {
        register_collector(
            IntCounter::new(
                "pecr_controller_loop_iterations_total",
                "Controller context loop iterations.",
            )
            .expect("create pecr_controller_loop_iterations_total"),
        )
    })
}

fn budget_violations_total() -> &'static IntCounter {
    BUDGET_VIOLATIONS_TOTAL.get_or_init(|| {
        register_collector(
            IntCounter::new(
                "pecr_controller_budget_violations_total",
                "Controller budget violations observed.",
            )
            .expect("create pecr_controller_budget_violations_total"),
        )
    })
}

fn budget_stop_reasons_total() -> &'static IntCounterVec {
    BUDGET_STOP_REASONS_TOTAL.get_or_init(|| {
        register_collector(
            IntCounterVec::new(
                Opts::new(
                    "pecr_controller_budget_stop_reasons_total",
                    "Controller context-loop stop reasons.",
                ),
                &["reason"],
            )
            .expect("create pecr_controller_budget_stop_reasons_total"),
        )
    })
}

fn inflight_ops() -> &'static IntGauge {
    INFLIGHT_OPS.get_or_init(|| {
        register_collector(
            IntGauge::new(
                "pecr_controller_inflight_ops",
                "Controller currently in-flight operator calls.",
            )
            .expect("create pecr_controller_inflight_ops"),
        )
    })
}

fn operator_queue_wait_seconds() -> &'static Histogram {
    OPERATOR_QUEUE_WAIT_SECONDS.get_or_init(|| {
        register_collector(
            Histogram::with_opts(
                HistogramOpts::new(
                    "pecr_controller_operator_queue_wait_seconds",
                    "Time an operator call spent queued before execution.",
                )
                .buckets(vec![
                    0.0005, 0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0,
                ]),
            )
            .expect("create pecr_controller_operator_queue_wait_seconds"),
        )
    })
}

fn evidence_packs_total() -> &'static IntCounterVec {
    EVIDENCE_PACKS_TOTAL.get_or_init(|| {
        register_collector(
            IntCounterVec::new(
                Opts::new(
                    "pecr_controller_evidence_packs_total",
                    "Controller finalize evidence packs by selected mode.",
                ),
                &["mode"],
            )
            .expect("create pecr_controller_evidence_packs_total"),
        )
    })
}

fn evidence_pack_units() -> &'static Histogram {
    EVIDENCE_PACK_UNITS.get_or_init(|| {
        register_collector(
            Histogram::with_opts(
                HistogramOpts::new(
                    "pecr_controller_evidence_pack_units",
                    "Selected evidence units per finalize evidence pack.",
                )
                .buckets(vec![1.0, 2.0, 3.0, 4.0, 6.0, 8.0, 12.0, 16.0]),
            )
            .expect("create pecr_controller_evidence_pack_units"),
        )
    })
}

fn evidence_compaction_ratio() -> &'static Histogram {
    EVIDENCE_COMPACTION_RATIO.get_or_init(|| {
        register_collector(
            Histogram::with_opts(
                HistogramOpts::new(
                    "pecr_controller_evidence_compaction_ratio",
                    "Packed evidence chars divided by raw evidence chars for finalize selection.",
                )
                .buckets(vec![0.05, 0.1, 0.2, 0.35, 0.5, 0.75, 1.0]),
            )
            .expect("create pecr_controller_evidence_compaction_ratio"),
        )
    })
}

fn citation_quality() -> &'static Histogram {
    CITATION_QUALITY.get_or_init(|| {
        register_collector(
            Histogram::with_opts(
                HistogramOpts::new(
                    "pecr_controller_citation_quality",
                    "Citation quality observed on finalized controller responses.",
                )
                .buckets(vec![0.0, 0.25, 0.5, 0.75, 0.9, 0.95, 1.0]),
            )
            .expect("create pecr_controller_citation_quality"),
        )
    })
}

pub fn observe_http_request(route: &str, method: &str, status: u16, duration: Duration) {
    let status_str = status.to_string();
    http_requests_total()
        .with_label_values(&[route, method, status_str.as_str()])
        .inc();

    let outcome = if (200..400).contains(&status) {
        "success"
    } else {
        "error"
    };
    http_request_duration_seconds()
        .with_label_values(&[route, method, outcome])
        .observe(duration.as_secs_f64());
}

pub fn observe_terminal_mode(route: &str, terminal_mode: &str) {
    terminal_modes_total()
        .with_label_values(&[route, terminal_mode])
        .inc();
}

pub fn inc_loop_iteration() {
    loop_iterations_total().inc();
}

pub fn inc_budget_violation() {
    budget_violations_total().inc();
}

pub fn observe_budget_stop_reason(reason: &str) {
    budget_stop_reasons_total()
        .with_label_values(&[reason])
        .inc();
}

pub fn inc_inflight_ops() {
    inflight_ops().inc();
}

pub fn dec_inflight_ops() {
    inflight_ops().dec();
}

pub fn observe_operator_queue_wait(duration: Duration) {
    operator_queue_wait_seconds().observe(duration.as_secs_f64());
}

pub fn observe_finalize_evidence_pack(
    mode: &str,
    _input_units: usize,
    packed_units: usize,
    input_chars: usize,
    packed_chars: usize,
) {
    evidence_packs_total().with_label_values(&[mode]).inc();
    evidence_pack_units().observe(packed_units as f64);
    if input_chars > 0 {
        evidence_compaction_ratio()
            .observe((packed_chars as f64 / input_chars as f64).clamp(0.0, 1.0));
    }
}

pub fn observe_citation_quality(score: f64) {
    citation_quality().observe(score.clamp(0.0, 1.0));
}

pub fn render() -> Result<(Vec<u8>, String), prometheus::Error> {
    let _ = budget_violations_total();
    let _ = budget_stop_reasons_total();
    let _ = inflight_ops();
    let _ = operator_queue_wait_seconds();
    let _ = evidence_packs_total();
    let _ = evidence_pack_units();
    let _ = evidence_compaction_ratio();
    let _ = citation_quality();

    let encoder = TextEncoder::new();
    let metric_families = registry().gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;
    Ok((buffer, encoder.format_type().to_string()))
}
