use std::collections::HashMap;
use std::io::Write;
use std::net::SocketAddr;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use axum::Json;
use axum::Router;
use axum::http::StatusCode;
use axum::routing::post;
use hex::ToHex;
use sha2::Digest;
use sqlx::PgPool;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

fn test_db_url() -> Option<String> {
    std::env::var("PECR_TEST_DB_URL")
        .ok()
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smoke_controller_creates_session_calls_operator_and_finalizes() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping e2e smoke test; set PECR_TEST_DB_URL to enable");
        return;
    };

    let log_buf = init_test_tracing();
    log_buf
        .lock()
        .expect("log lock should be available")
        .clear();

    let request_id = "req_smoke_01";

    let restricted_canary = "PECR_CANARY_RESTRICTED_ALPHA_6b3b91c2a7b44a9f";
    let injection_canary = "PECR_CANARY_INJECTION_BETA_29a1e0d7a03d4d8c";
    let pg_admin_canary_1 = "PECR_CANARY_PG_ADMIN_DELTA_1f2d8c6f87f84b76";
    let pg_support_canary_1 = "PECR_CANARY_PG_SUPPORT_EPSILON_6c6f4f07c04f4f8f";
    let pg_admin_canary_2 = "PECR_CANARY_PG_ADMIN_DELTA_2a519d6b7f4348d4";
    let pg_support_canary_2 = "PECR_CANARY_PG_SUPPORT_EPSILON_8d77b9a9d9e24c2b";

    let fs_corpus_root = prepare_temp_fs_corpus();

    let restricted_text =
        std::fs::read_to_string(fs_corpus_root.join("restricted").join("restricted_1.txt"))
            .expect("restricted fixture should be readable");
    assert!(
        restricted_text.contains(restricted_canary),
        "restricted fixture must contain its canary"
    );

    let injection_text =
        std::fs::read_to_string(fs_corpus_root.join("injection").join("injection_1.txt"))
            .expect("injection fixture should be readable");
    assert!(
        injection_text.contains(injection_canary),
        "injection fixture must contain its canary"
    );

    let pg_fixtures_sql = std::fs::read_to_string(
        workspace_root()
            .join("db")
            .join("init")
            .join("002_safeview_fixtures.sql"),
    )
    .expect("postgres fixture SQL should be readable");
    for canary in [
        pg_admin_canary_1,
        pg_support_canary_1,
        pg_admin_canary_2,
        pg_support_canary_2,
    ] {
        assert!(
            pg_fixtures_sql.contains(canary),
            "postgres fixture SQL must contain canary {}",
            canary
        );
    }

    apply_pg_fixtures(&db_url, &pg_fixtures_sql).await;

    let fs_corpus_path = fs_corpus_root.to_string_lossy().to_string();

    let opa_app = Router::new().route("/v1/data/pecr/authz/decision", post(opa_decision));
    let (opa_addr, opa_shutdown, opa_task) = spawn_server(opa_app).await;

    let gateway_config = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), db_url.clone()),
        ("PECR_OPA_URL".to_string(), format!("http://{}", opa_addr)),
        (
            "PECR_POLICY_BUNDLE_HASH".to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ),
        ("PECR_FS_CORPUS_PATH".to_string(), fs_corpus_path.clone()),
        (
            "PECR_AS_OF_TIME_DEFAULT".to_string(),
            "1970-01-01T00:00:00Z".to_string(),
        ),
    ]))
    .expect("gateway config should be valid");

    let (gateway_addr, gateway_shutdown, gateway_task) = spawn_server(
        pecr_gateway::http::router(gateway_config)
            .await
            .expect("gateway router should init"),
    )
    .await;

    let controller_config = pecr_controller::config::ControllerConfig::from_kv(&HashMap::from([
        ("PECR_CONTROLLER_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        (
            "PECR_GATEWAY_URL".to_string(),
            format!("http://{}", gateway_addr),
        ),
        ("PECR_MODEL_PROVIDER".to_string(), "mock".to_string()),
        (
            "PECR_BUDGET_DEFAULTS".to_string(),
            r#"{"max_operator_calls":10,"max_bytes":1048576,"max_wallclock_ms":10000,"max_recursion_depth":5,"max_parallelism":4}"#
                .to_string(),
        ),
    ]))
    .expect("controller config should be valid");

    let (controller_addr, controller_shutdown, controller_task) =
        spawn_server(pecr_controller::http::router(controller_config)).await;

    let client = reqwest::Client::new();
    wait_for_healthz(&client, controller_addr).await;

    let response = client
        .post(format!("http://{}/v1/run", controller_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", request_id)
        .json(&serde_json::json!({"query":"smoke"}))
        .send()
        .await
        .expect("request should succeed");

    assert!(
        response.status().is_success(),
        "expected 2xx, got {}",
        response.status()
    );

    let body = response
        .json::<serde_json::Value>()
        .await
        .expect("response should be valid JSON");

    assert_eq!(
        body.get("terminal_mode").and_then(|v| v.as_str()),
        Some("INSUFFICIENT_EVIDENCE")
    );
    let trace_id = body
        .get("trace_id")
        .and_then(|v| v.as_str())
        .expect("trace_id should exist");

    // Verify list_versions determinism directly against the gateway.
    let object_ids = ["restricted/restricted_1.txt", "injection/injection_1.txt"];

    let session_response = client
        .post(format!("http://{}/v1/sessions", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", request_id)
        .json(&serde_json::json!({"budget":{"max_operator_calls":10,"max_bytes":1024,"max_wallclock_ms":1000,"max_recursion_depth":3}}))
        .send()
        .await
        .expect("gateway session request should succeed");

    assert!(
        session_response.status().is_success(),
        "expected gateway session 2xx, got {}",
        session_response.status()
    );

    let session_token = session_response
        .headers()
        .get("x-pecr-session-token")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .expect("gateway must return x-pecr-session-token header")
        .to_string();

    let session = session_response
        .json::<serde_json::Value>()
        .await
        .expect("gateway session response should be JSON");

    let session_id = session
        .get("session_id")
        .and_then(|v| v.as_str())
        .expect("session_id should exist");

    for object_id in object_ids {
        let expected_version_id = sha256_hex(
            &std::fs::read(fs_corpus_root.join(object_id)).expect("fixture file should exist"),
        );

        let op_response = client
            .post(format!(
                "http://{}/v1/operators/list_versions",
                gateway_addr
            ))
            .header("x-pecr-principal-id", "dev")
            .header("x-pecr-request-id", request_id)
            .header("x-pecr-session-token", &session_token)
            .json(
                &serde_json::json!({"session_id": session_id, "params": {"object_id": object_id}}),
            )
            .send()
            .await
            .expect("gateway operator call should succeed")
            .json::<serde_json::Value>()
            .await
            .expect("gateway operator response should be JSON");

        let version_id = op_response
            .pointer("/result/versions/0/version_id")
            .and_then(|v| v.as_str())
            .expect("version_id should exist");

        assert_eq!(version_id, expected_version_id);
    }

    // Verify diff between two known versions in a temporary corpus.
    let public_object_id = "public/public_1.txt";
    let public_path = fs_corpus_root.join("public").join("public_1.txt");
    let public_v1 = sha256_hex(&std::fs::read(&public_path).expect("public fixture should exist"));

    let public_versions_before = client
        .post(format!(
            "http://{}/v1/operators/list_versions",
            gateway_addr
        ))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", request_id)
        .header("x-pecr-session-token", &session_token)
        .json(&serde_json::json!({
            "session_id": session_id,
            "params": { "object_id": public_object_id }
        }))
        .send()
        .await
        .expect("gateway list_versions call should succeed")
        .json::<serde_json::Value>()
        .await
        .expect("gateway list_versions response should be JSON");

    let versions_before = public_versions_before
        .pointer("/result/versions")
        .and_then(|v| v.as_array())
        .expect("list_versions must return result.versions array");
    assert!(
        versions_before
            .iter()
            .any(|v| v.get("version_id").and_then(|id| id.as_str()) == Some(public_v1.as_str())),
        "expected list_versions to include v1"
    );

    let marker = "DIFF_MARKER_ALPHA";
    let original_public =
        std::fs::read_to_string(&public_path).expect("public fixture should be readable as UTF-8");
    std::fs::write(&public_path, format!("{}\n{}\n", original_public, marker))
        .expect("public fixture should be writable in temp corpus");

    let public_v2 = sha256_hex(&std::fs::read(&public_path).expect("public fixture should exist"));

    let public_versions_after = client
        .post(format!(
            "http://{}/v1/operators/list_versions",
            gateway_addr
        ))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", request_id)
        .header("x-pecr-session-token", &session_token)
        .json(&serde_json::json!({
            "session_id": session_id,
            "params": { "object_id": public_object_id }
        }))
        .send()
        .await
        .expect("gateway list_versions call should succeed")
        .json::<serde_json::Value>()
        .await
        .expect("gateway list_versions response should be JSON");

    let versions_after = public_versions_after
        .pointer("/result/versions")
        .and_then(|v| v.as_array())
        .expect("list_versions must return result.versions array");
    let mut version_ids = versions_after
        .iter()
        .filter_map(|v| v.get("version_id").and_then(|id| id.as_str()))
        .collect::<Vec<_>>();
    version_ids.sort();
    version_ids.dedup();
    assert!(
        version_ids.contains(&public_v1.as_str()) && version_ids.contains(&public_v2.as_str()),
        "expected list_versions to include both v1 and v2"
    );

    let diff_resp = client
        .post(format!("http://{}/v1/operators/diff", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", request_id)
        .header("x-pecr-session-token", &session_token)
        .json(&serde_json::json!({
            "session_id": session_id,
            "params": { "object_id": public_object_id, "v1": public_v1, "v2": public_v2 }
        }))
        .send()
        .await
        .expect("gateway diff call should succeed")
        .json::<serde_json::Value>()
        .await
        .expect("gateway diff response should be JSON");

    let diff_evidence = diff_resp
        .get("result")
        .and_then(|v| v.as_array())
        .expect("diff must return result array");
    let first = diff_evidence
        .first()
        .expect("diff must return at least one EvidenceUnit");
    assert_eq!(
        first.get("version_id").and_then(|v| v.as_str()),
        Some(public_v2.as_str()),
        "diff evidence must be bound to v2"
    );
    let diff_content = first
        .get("content")
        .and_then(|v| v.as_str())
        .expect("diff must return content string");
    assert!(
        diff_content.contains(marker),
        "diff output should include the appended marker"
    );

    let search_resp = client
        .post(format!("http://{}/v1/operators/search", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", request_id)
        .header("x-pecr-session-token", &session_token)
        .json(&serde_json::json!({
            "session_id": session_id,
            "params": { "query": restricted_canary, "limit": 5 }
        }))
        .send()
        .await
        .expect("gateway search call should succeed")
        .json::<serde_json::Value>()
        .await
        .expect("gateway search response should be JSON");

    let refs = search_resp
        .pointer("/result/refs")
        .and_then(|v| v.as_array())
        .expect("search must return result.refs array");
    assert!(
        refs.iter().any(|v| {
            v.get("object_id").and_then(|o| o.as_str()) == Some("restricted/restricted_1.txt")
        }),
        "expected search to return restricted object_id ref"
    );

    let fetch_span_resp = client
        .post(format!("http://{}/v1/operators/fetch_span", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", request_id)
        .header("x-pecr-session-token", &session_token)
        .json(&serde_json::json!({"session_id": session_id, "params": {"object_id": "restricted/restricted_1.txt"}}))
        .send()
        .await
        .expect("gateway fetch_span call should succeed")
        .json::<serde_json::Value>()
        .await
        .expect("gateway fetch_span response should be JSON");

    let evidence_unit_id = fetch_span_resp
        .pointer("/result/evidence_unit_id")
        .and_then(|v| v.as_str())
        .expect("fetch_span must return evidence_unit_id");
    assert_eq!(evidence_unit_id.len(), 64);
    assert!(evidence_unit_id.chars().all(|c| c.is_ascii_hexdigit()));

    let evidence_content = fetch_span_resp
        .pointer("/result/content")
        .and_then(|v| v.as_str())
        .expect("fetch_span must return content");
    assert!(
        evidence_content.contains(restricted_canary),
        "fetch_span must return restricted content including canary"
    );

    let fetch_rows_resp = client
        .post(format!("http://{}/v1/operators/fetch_rows", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", request_id)
        .header("x-pecr-session-token", &session_token)
        .json(&serde_json::json!({
            "session_id": session_id,
            "params": {
                "view_id": "safe_customer_view_admin",
                "fields": ["admin_note"]
            }
        }))
        .send()
        .await
        .expect("gateway fetch_rows call should succeed")
        .json::<serde_json::Value>()
        .await
        .expect("gateway fetch_rows response should be JSON");

    let row_evidence = fetch_rows_resp
        .get("result")
        .and_then(|v| v.as_array())
        .expect("fetch_rows must return result array");
    assert!(!row_evidence.is_empty(), "fetch_rows must return rows");
    assert!(
        row_evidence.iter().any(|v| {
            v.pointer("/span_or_row_spec/type").and_then(|t| t.as_str()) == Some("db_row")
                && v.pointer("/span_or_row_spec/view_id")
                    .and_then(|t| t.as_str())
                    == Some("safe_customer_view_admin")
        }),
        "fetch_rows must emit db_row EvidenceUnits with view_id"
    );
    assert!(
        row_evidence.iter().any(|v| {
            v.pointer("/content/admin_note")
                .and_then(|c| c.as_str())
                .is_some_and(|c| c.contains(pg_admin_canary_1) || c.contains(pg_admin_canary_2))
        }),
        "fetch_rows must return admin_note canaries in response"
    );

    let aggregate_resp = client
        .post(format!("http://{}/v1/operators/aggregate", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", request_id)
        .header("x-pecr-session-token", &session_token)
        .json(&serde_json::json!({
            "session_id": session_id,
            "params": {
                "view_id": "safe_customer_view_public",
                "group_by": ["plan_tier"],
                "metrics": [{"name":"count","field":"customer_id"}]
            }
        }))
        .send()
        .await
        .expect("gateway aggregate call should succeed")
        .json::<serde_json::Value>()
        .await
        .expect("gateway aggregate response should be JSON");

    assert_eq!(
        aggregate_resp
            .pointer("/result/span_or_row_spec/type")
            .and_then(|v| v.as_str()),
        Some("db_aggregate")
    );
    let filter_fingerprint = aggregate_resp
        .pointer("/result/span_or_row_spec/filter_fingerprint")
        .and_then(|v| v.as_str())
        .expect("aggregate must include filter_fingerprint");
    assert_eq!(filter_fingerprint.len(), 64);

    let mut counts_by_tier = std::collections::HashMap::<String, i64>::new();
    let rows = aggregate_resp
        .pointer("/result/content/rows")
        .and_then(|v| v.as_array())
        .expect("aggregate must return content.rows array");
    for row in rows {
        let tier = row
            .pointer("/group/plan_tier")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let count = row
            .pointer("/metrics/0/value")
            .and_then(|v| v.as_i64())
            .unwrap_or(0);
        if !tier.is_empty() {
            counts_by_tier.insert(tier, count);
        }
    }
    assert_eq!(counts_by_tier.get("free"), Some(&1));
    assert_eq!(counts_by_tier.get("enterprise"), Some(&1));

    let _ = client
        .post(format!("http://{}/v1/finalize", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", request_id)
        .header("x-pecr-session-token", &session_token)
        .json(&serde_json::json!({
            "session_id": session_id,
            "response_text": "INSUFFICIENT_EVIDENCE",
            "claim_map": {
                "claim_map_id": sha256_hex(session_id.as_bytes()),
                "terminal_mode": "INSUFFICIENT_EVIDENCE",
                "claims": [],
                "coverage_threshold": 0.95,
                "coverage_observed": 1.0
            }
        }))
        .send()
        .await
        .expect("gateway finalize call should succeed");

    // Shutdown servers.
    let _ = controller_shutdown.send(());
    let _ = gateway_shutdown.send(());
    let _ = opa_shutdown.send(());

    let _ = tokio::time::timeout(Duration::from_secs(3), controller_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), gateway_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), opa_task).await;

    let _ = std::fs::remove_dir_all(&fs_corpus_root);

    let logs = String::from_utf8(
        log_buf
            .lock()
            .expect("log lock should be available")
            .clone(),
    )
    .expect("logs should be valid utf-8");

    assert!(
        logs.lines().any(|line| {
            line.contains("trace_id=")
                && line.contains(trace_id)
                && line.contains("request_id=")
                && line.contains(request_id)
        }),
        "expected gateway logs to include trace_id and request_id; trace_id={}, request_id={}, logs:\n{}",
        trace_id,
        request_id,
        logs
    );

    for canary in [
        restricted_canary,
        injection_canary,
        pg_admin_canary_1,
        pg_support_canary_1,
        pg_admin_canary_2,
        pg_support_canary_2,
    ] {
        assert!(
            !logs.contains(canary),
            "logs must not contain evidence canary {}; logs:\n{}",
            canary,
            logs
        );
    }
}

async fn apply_pg_fixtures(db_url: &str, sql: &str) {
    let pool = PgPool::connect(db_url)
        .await
        .expect("db should be reachable for fixtures");

    for statement in sql.split(';') {
        let stmt = statement.trim();
        if stmt.is_empty() {
            continue;
        }

        sqlx::query(stmt)
            .execute(&pool)
            .await
            .expect("fixture statement should execute");
    }
}

async fn spawn_server(
    app: Router,
) -> (SocketAddr, oneshot::Sender<()>, tokio::task::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind should succeed");
    let addr = listener.local_addr().expect("local_addr should succeed");

    let (shutdown_tx, shutdown_rx) = oneshot::channel::<()>();
    let handle = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(async {
                let _ = shutdown_rx.await;
            })
            .await;
    });

    (addr, shutdown_tx, handle)
}

async fn wait_for_healthz(client: &reqwest::Client, addr: SocketAddr) {
    let url = format!("http://{}/healthz", addr);

    for _ in 0..50 {
        if let Ok(response) = client.get(&url).send().await
            && response.status().is_success()
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!("server did not become ready at {}", url);
}

fn prepare_temp_fs_corpus() -> PathBuf {
    static COUNTER: AtomicUsize = AtomicUsize::new(0);
    let suffix = COUNTER.fetch_add(1, Ordering::Relaxed);

    let dst =
        std::env::temp_dir().join(format!("pecr_fs_corpus_{}_{}", std::process::id(), suffix));
    let src = workspace_root().join("fixtures").join("fs_corpus");

    copy_dir_recursive(&src, &dst);
    dst
}

fn copy_dir_recursive(src: &Path, dst: &Path) {
    std::fs::create_dir_all(dst).expect("temp fixture dir create should succeed");

    for entry in std::fs::read_dir(src).expect("read_dir should succeed") {
        let entry = entry.expect("dir entry should succeed");
        let ty = entry.file_type().expect("file type should be readable");
        let path = entry.path();
        let target = dst.join(entry.file_name());

        if ty.is_dir() {
            copy_dir_recursive(&path, &target);
        } else if ty.is_file() {
            std::fs::copy(&path, &target).expect("file copy should succeed");
        }
    }
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    hasher.finalize().encode_hex::<String>()
}

async fn opa_decision(
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let input = body.get("input").cloned().unwrap_or(serde_json::json!({}));
    let action = input
        .get("action")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    let principal_id = input
        .get("principal_id")
        .and_then(|v| v.as_str())
        .unwrap_or_default();

    let allow = match action {
        "health" | "create_session" | "finalize" => principal_id == "dev",
        "operator_call" => {
            let op_name = input.get("op_name").and_then(|v| v.as_str()).unwrap_or("");
            principal_id == "dev"
                && matches!(
                    op_name,
                    "list_versions" | "fetch_span" | "search" | "fetch_rows" | "aggregate" | "diff"
                )
        }
        _ => false,
    };

    let cacheable = matches!(action, "operator_call");

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "result": {
                "allow": allow,
                "cacheable": cacheable,
                "reason": if allow { "test_allow" } else { "test_deny" },
                "redaction": {}
            }
        })),
    )
}

#[derive(Clone)]
struct TestWriter {
    buf: Arc<Mutex<Vec<u8>>>,
}

impl Write for TestWriter {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let mut lock = self
            .buf
            .lock()
            .map_err(|_| std::io::Error::other("log mutex poisoned"))?;
        lock.extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fn init_test_tracing() -> Arc<Mutex<Vec<u8>>> {
    static LOG_BUF: OnceLock<Arc<Mutex<Vec<u8>>>> = OnceLock::new();

    LOG_BUF
        .get_or_init(|| {
            let buf = Arc::new(Mutex::new(Vec::new()));
            let make_writer = {
                let buf = buf.clone();
                move || TestWriter { buf: buf.clone() }
            };

            let subscriber = tracing_subscriber::fmt()
                .with_env_filter(tracing_subscriber::EnvFilter::new("info"))
                .with_ansi(false)
                .with_writer(make_writer)
                .finish();

            tracing::subscriber::set_global_default(subscriber)
                .expect("global tracing subscriber should be set once");

            buf
        })
        .clone()
}
