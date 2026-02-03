use std::sync::OnceLock;
use std::time::Duration;

use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, Opts, Registry, TextEncoder,
};

static REGISTRY: OnceLock<Registry> = OnceLock::new();
static HTTP_REQUESTS_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static HTTP_REQUEST_DURATION_SECONDS: OnceLock<HistogramVec> = OnceLock::new();
static TERMINAL_MODES_TOTAL: OnceLock<IntCounterVec> = OnceLock::new();
static LOOP_ITERATIONS_TOTAL: OnceLock<IntCounter> = OnceLock::new();

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

pub fn render() -> Result<(Vec<u8>, String), prometheus::Error> {
    let encoder = TextEncoder::new();
    let metric_families = registry().gather();
    let mut buffer = Vec::new();
    encoder.encode(&metric_families, &mut buffer)?;
    Ok((buffer, encoder.format_type().to_string()))
}
