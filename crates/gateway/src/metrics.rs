use std::sync::OnceLock;
use std::time::Duration;

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts, Registry, TextEncoder,
};

static REGISTRY: OnceLock<Registry> = OnceLock::new();
static HTTP_REQUESTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static HTTP_REQUEST_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static TERMINAL_MODES_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static OPERATOR_CALLS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static BUDGET_VIOLATIONS_TOTAL: OnceLock<IntCounter> = OnceLock::new();
static STALENESS_ERRORS_TOTAL: OnceLock<IntCounter> = OnceLock::new();
static LEAKAGE_DETECTIONS_TOTAL: OnceLock<IntCounter> = OnceLock::new();

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
                    "pecr_gateway_http_requests_total",
                    "Gateway HTTP request count.",
                ),
                &["route", "method", "status"],
            )
            .expect("create pecr_gateway_http_requests_total"),
        )
    })
}

fn http_request_duration_seconds() -> &'static HistogramVec {
    HTTP_REQUEST_DURATION_SECONDS.get_or_init(|| {
        register_collector(
            HistogramVec::new(
                HistogramOpts::new(
                    "pecr_gateway_http_request_duration_seconds",
                    "Gateway HTTP request duration in seconds.",
                )
                .buckets(vec![
                    0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
                ]),
                &["route", "method", "outcome"],
            )
            .expect("create pecr_gateway_http_request_duration_seconds"),
        )
    })
}

fn terminal_modes_total() -> &'static IntCounterVec {
    TERMINAL_MODES_TOTAL.get_or_init(|| {
        register_collector(
            IntCounterVec::new(
                Opts::new(
                    "pecr_gateway_terminal_modes_total",
                    "Gateway terminal modes observed in responses.",
                ),
                &["route", "terminal_mode"],
            )
            .expect("create pecr_gateway_terminal_modes_total"),
        )
    })
}

fn operator_calls_total() -> &'static IntCounterVec {
    OPERATOR_CALLS_TOTAL.get_or_init(|| {
        register_collector(
            IntCounterVec::new(
                Opts::new(
                    "pecr_gateway_operator_calls_total",
                    "Gateway operator call count.",
                ),
                &["operator_name", "outcome"],
            )
            .expect("create pecr_gateway_operator_calls_total"),
        )
    })
}

fn budget_violations_total() -> &'static IntCounter {
    BUDGET_VIOLATIONS_TOTAL.get_or_init(|| {
        register_collector(
            IntCounter::new(
                "pecr_gateway_budget_violations_total",
                "Gateway budget violations observed.",
            )
            .expect("create pecr_gateway_budget_violations_total"),
        )
    })
}

fn staleness_errors_total() -> &'static IntCounter {
    STALENESS_ERRORS_TOTAL.get_or_init(|| {
        register_collector(
            IntCounter::new(
                "pecr_gateway_staleness_errors_total",
                "Gateway staleness errors observed.",
            )
            .expect("create pecr_gateway_staleness_errors_total"),
        )
    })
}

fn leakage_detections_total() -> &'static IntCounter {
    LEAKAGE_DETECTIONS_TOTAL.get_or_init(|| {
        register_collector(
            IntCounter::new(
                "pecr_gateway_leakage_detections_total",
                "Gateway leakage detections observed.",
            )
            .expect("create pecr_gateway_leakage_detections_total"),
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

pub fn observe_operator_call(operator_name: &str, outcome: &str) {
    operator_calls_total()
        .with_label_values(&[operator_name, outcome])
        .inc();
}

pub fn inc_budget_violation() {
    budget_violations_total().inc();
}

pub fn render() -> Result<(Vec<u8>, String), prometheus::Error> {
    let _ = staleness_errors_total();
    let _ = leakage_detections_total();

    let encoder = TextEncoder::new();
    let metric_families = registry().gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;
    Ok((buffer, encoder.format_type().to_string()))
}
