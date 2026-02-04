use pecr_controller::{config, http};
use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;

#[tokio::main]
async fn main() {
    init_tracing("pecr-controller");

    let config = match config::ControllerConfig::load() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("STARTUP_ERROR {}", err);
            std::process::exit(1);
        }
    };

    let app = match http::router(config.clone()).await {
        Ok(app) => app,
        Err(err) => {
            eprintln!("STARTUP_ERROR {}", err);
            std::process::exit(1);
        }
    };

    let listener = match tokio::net::TcpListener::bind(config.bind_addr).await {
        Ok(listener) => listener,
        Err(_) => {
            eprintln!("STARTUP_ERROR ERR_BIND_FAILED failed to bind controller listener");
            std::process::exit(1);
        }
    };

    tracing::info!(
        trace_id = "startup",
        request_id = "startup",
        bind_addr = %config.bind_addr,
        "pecr-controller listening"
    );

    if let Err(err) = axum::serve(listener, app).await {
        eprintln!("STARTUP_ERROR ERR_SERVER_FAILED {}", err);
        std::process::exit(1);
    }
}

fn init_tracing(service_name: &'static str) {
    let env_filter = tracing_subscriber::EnvFilter::from_default_env();

    let otel_enabled = std::env::var("PECR_OTEL_ENABLED")
        .ok()
        .map(|v| matches!(v.trim(), "1" | "true" | "TRUE" | "yes" | "YES"))
        .unwrap_or(false);

    if otel_enabled {
        opentelemetry::global::set_text_map_propagator(
            opentelemetry_sdk::propagation::TraceContextPropagator::new(),
        );

        let exporter = match opentelemetry_otlp::SpanExporter::builder()
            .with_http()
            .build()
        {
            Ok(exporter) => exporter,
            Err(err) => {
                eprintln!("STARTUP_ERROR ERR_OTEL_INIT {}", err);
                tracing_subscriber::fmt()
                    .with_env_filter(env_filter)
                    .json()
                    .with_current_span(true)
                    .with_span_list(true)
                    .init();
                return;
            }
        };

        let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
            .with_batch_exporter(exporter)
            .with_resource(
                opentelemetry_sdk::Resource::builder()
                    .with_service_name(service_name)
                    .build(),
            )
            .build();

        let tracer = opentelemetry::trace::TracerProvider::tracer(&tracer_provider, service_name);
        let otel_layer = tracing_opentelemetry::layer().with_tracer(tracer);
        let fmt_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_current_span(true)
            .with_span_list(true);

        tracing_subscriber::registry()
            .with(env_filter)
            .with(fmt_layer)
            .with(otel_layer)
            .init();
    } else {
        tracing_subscriber::fmt()
            .with_env_filter(env_filter)
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .init();
    }
}
