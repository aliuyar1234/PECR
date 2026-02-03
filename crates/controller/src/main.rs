use pecr_controller::{config, http};

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();

    let config = match config::ControllerConfig::load() {
        Ok(cfg) => cfg,
        Err(err) => {
            eprintln!("STARTUP_ERROR {}", err);
            std::process::exit(1);
        }
    };

    let app = http::router(config.clone());

    let listener = match tokio::net::TcpListener::bind(config.bind_addr).await {
        Ok(listener) => listener,
        Err(_) => {
            eprintln!("STARTUP_ERROR ERR_BIND_FAILED failed to bind controller listener");
            std::process::exit(1);
        }
    };

    tracing::info!(bind_addr = %config.bind_addr, "pecr-controller listening");

    if let Err(err) = axum::serve(listener, app).await {
        eprintln!("STARTUP_ERROR ERR_SERVER_FAILED {}", err);
        std::process::exit(1);
    }
}
