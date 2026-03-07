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
use axum::routing::{get, post};
use hex::ToHex;
use sha2::Digest;
use sqlx::PgPool;
use tokio::net::TcpListener;
use tokio::sync::oneshot;

static TEST_COUNTER: AtomicUsize = AtomicUsize::new(0);

fn test_db_url() -> Option<String> {
    let db_url = std::env::var("PECR_TEST_DB_URL")
        .ok()
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let require_db_url = std::env::var("PECR_E2E_REQUIRE_DB_URL")
        .ok()
        .is_some_and(|value| matches!(value.trim(), "1" | "true" | "TRUE" | "yes" | "YES"));

    if require_db_url && db_url.is_none() {
        panic!("PECR_TEST_DB_URL must be set when PECR_E2E_REQUIRE_DB_URL is enabled");
    }

    db_url
}

fn next_suffix() -> usize {
    TEST_COUNTER.fetch_add(1, Ordering::Relaxed)
}

fn schema_db_url(base: &str, schema: &str) -> String {
    let separator = if base.contains('?') { "&" } else { "?" };
    format!("{base}{separator}options=-csearch_path%3D{schema}")
}

async fn create_test_schema(base_db_url: &str) -> (PgPool, String, String) {
    let schema = format!("pecr_test_{}_{}", std::process::id(), next_suffix());
    let pool = PgPool::connect(base_db_url)
        .await
        .expect("db should be reachable for schema create");

    let create_schema = format!("CREATE SCHEMA {}", schema);
    sqlx::query(&create_schema)
        .execute(&pool)
        .await
        .expect("create schema should succeed");

    let schema_url = schema_db_url(base_db_url, &schema);
    (pool, schema, schema_url)
}

async fn drop_test_schema(pool: &PgPool, schema: &str) {
    let drop_schema = format!("DROP SCHEMA {} CASCADE", schema);
    let _ = sqlx::query(&drop_schema).execute(pool).await;
}

fn log_snapshot(buf: &Arc<Mutex<Vec<u8>>>) -> usize {
    buf.lock().expect("log lock should be available").len()
}

fn logs_since(buf: &Arc<Mutex<Vec<u8>>>, start: usize) -> String {
    let bytes = buf
        .lock()
        .expect("log lock should be available")
        .iter()
        .skip(start)
        .cloned()
        .collect::<Vec<u8>>();

    String::from_utf8(bytes).expect("logs should be valid utf-8")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn smoke_controller_creates_session_calls_operator_and_finalizes() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping e2e smoke test; set PECR_TEST_DB_URL to enable");
        return;
    };

    let log_buf = init_test_tracing();
    let log_start = log_snapshot(&log_buf);

    let request_id = format!("req_smoke_{}_{}", std::process::id(), next_suffix());

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

    let (schema_pool, schema_name, schema_url) = create_test_schema(&db_url).await;
    apply_pg_fixtures(&schema_url, &pg_fixtures_sql).await;

    let fs_corpus_path = fs_corpus_root.to_string_lossy().to_string();

    let opa_app = Router::new()
        .route("/health", get(opa_health))
        .route("/v1/data/pecr/authz/decision", post(opa_decision));
    let (opa_addr, opa_shutdown, opa_task) = spawn_server(opa_app).await;

    let gateway_config = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
        ("PECR_OPA_URL".to_string(), format!("http://{}", opa_addr)),
        (
            "PECR_LEDGER_WRITE_TIMEOUT_MS".to_string(),
            "20000".to_string(),
        ),
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

    let (controller_addr, controller_shutdown, controller_task) = spawn_server(
        pecr_controller::http::router(controller_config)
            .await
            .expect("controller router should init"),
    )
    .await;

    let client = reqwest::Client::new();
    wait_for_healthz(&client, controller_addr).await;

    let response = client
        .post(format!("http://{}/v1/run", controller_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
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
        Some("SUPPORTED")
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
        .header("x-pecr-request-id", &request_id)
        .json(&serde_json::json!({"budget":{"max_operator_calls":10,"max_bytes":1048576,"max_wallclock_ms":1000,"max_recursion_depth":3}}))
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
            .header("x-pecr-request-id", &request_id)
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
        .header("x-pecr-request-id", &request_id)
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
        .header("x-pecr-request-id", &request_id)
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
        .header("x-pecr-request-id", &request_id)
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
        .header("x-pecr-request-id", &request_id)
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
        .header("x-pecr-request-id", &request_id)
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
        .header("x-pecr-request-id", &request_id)
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
        .header("x-pecr-request-id", &request_id)
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
        .header("x-pecr-request-id", &request_id)
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

    let logs = logs_since(&log_buf, log_start);

    assert!(
        logs.lines().any(|line| {
            line.contains("trace_id=")
                && line.contains(trace_id)
                && line.contains("request_id=")
                && line.contains(request_id.as_str())
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

    drop_test_schema(&schema_pool, &schema_name).await;
    schema_pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn leakage_suite_role_matrix_canaries() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping leakage suite; set PECR_TEST_DB_URL to enable");
        return;
    };

    let log_buf = init_test_tracing();
    let log_start = log_snapshot(&log_buf);

    let request_id = format!("req_leakage_{}_{}", std::process::id(), next_suffix());

    let restricted_canary = "PECR_CANARY_RESTRICTED_ALPHA_6b3b91c2a7b44a9f";
    let injection_canary = "PECR_CANARY_INJECTION_BETA_29a1e0d7a03d4d8c";
    let pg_admin_canary_1 = "PECR_CANARY_PG_ADMIN_DELTA_1f2d8c6f87f84b76";
    let pg_support_canary_1 = "PECR_CANARY_PG_SUPPORT_EPSILON_6c6f4f07c04f4f8f";
    let pg_admin_canary_2 = "PECR_CANARY_PG_ADMIN_DELTA_2a519d6b7f4348d4";
    let pg_support_canary_2 = "PECR_CANARY_PG_SUPPORT_EPSILON_8d77b9a9d9e24c2b";

    let fs_corpus_root = prepare_temp_fs_corpus();
    let fs_corpus_path = fs_corpus_root.to_string_lossy().to_string();

    let (schema_pool, schema_name, schema_url) = create_test_schema(&db_url).await;

    let pg_fixtures_sql = std::fs::read_to_string(
        workspace_root()
            .join("db")
            .join("init")
            .join("002_safeview_fixtures.sql"),
    )
    .expect("postgres fixture SQL should be readable");
    apply_pg_fixtures(&schema_url, &pg_fixtures_sql).await;

    let opa_app = Router::new()
        .route("/health", get(opa_health))
        .route("/v1/data/pecr/authz/decision", post(opa_decision));
    let (opa_addr, opa_shutdown, opa_task) = spawn_server(opa_app).await;

    let gateway_config = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
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

    let client = reqwest::Client::new();
    wait_for_healthz(&client, gateway_addr).await;

    let (admin_session_id, admin_session_token, admin_trace_id, _admin_policy_snapshot_id) =
        gateway_create_session(&client, gateway_addr, "dev", &request_id).await;

    let admin_fetch_span = client
        .post(format!("http://{}/v1/operators/fetch_span", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &admin_session_token)
        .json(&serde_json::json!({
            "session_id": admin_session_id,
            "params": { "object_id": "restricted/restricted_1.txt" }
        }))
        .send()
        .await
        .expect("admin fetch_span request should succeed");
    assert!(admin_fetch_span.status().is_success());
    let admin_fetch_span_body = admin_fetch_span
        .json::<serde_json::Value>()
        .await
        .expect("admin fetch_span response should be JSON");
    let admin_restricted_content = admin_fetch_span_body
        .pointer("/result/content")
        .and_then(|v| v.as_str())
        .expect("fetch_span must return content");
    assert!(
        admin_restricted_content.contains(restricted_canary),
        "admin must be able to read restricted canary via fetch_span"
    );

    let admin_fetch_rows = client
        .post(format!("http://{}/v1/operators/fetch_rows", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &admin_session_token)
        .json(&serde_json::json!({
            "session_id": admin_session_id,
            "params": {
                "view_id": "safe_customer_view_admin",
                "fields": ["admin_note"]
            }
        }))
        .send()
        .await
        .expect("admin fetch_rows request should succeed");
    assert!(admin_fetch_rows.status().is_success());
    let admin_fetch_rows_body = admin_fetch_rows
        .json::<serde_json::Value>()
        .await
        .expect("admin fetch_rows response should be JSON");
    let admin_rows = admin_fetch_rows_body
        .get("result")
        .and_then(|v| v.as_array())
        .expect("fetch_rows must return result array");
    assert!(
        admin_rows.iter().any(|v| {
            v.pointer("/content/admin_note")
                .and_then(|c| c.as_str())
                .is_some_and(|c| c.contains(pg_admin_canary_1) || c.contains(pg_admin_canary_2))
        }),
        "admin must be able to read admin canary via fetch_rows"
    );

    let (support_session_id, support_session_token, support_trace_id, _support_policy_snapshot_id) =
        gateway_create_session(&client, gateway_addr, "support", &request_id).await;

    let support_fetch_span = client
        .post(format!("http://{}/v1/operators/fetch_span", gateway_addr))
        .header("x-pecr-principal-id", "support")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &support_session_token)
        .json(&serde_json::json!({
            "session_id": support_session_id,
            "params": { "object_id": "restricted/restricted_1.txt" }
        }))
        .send()
        .await
        .expect("support fetch_span request should succeed");
    assert_eq!(support_fetch_span.status(), StatusCode::FORBIDDEN);
    let support_fetch_span_json = support_fetch_span
        .json::<serde_json::Value>()
        .await
        .expect("support fetch_span response should be JSON");
    assert_eq!(
        support_fetch_span_json.get("code").and_then(|v| v.as_str()),
        Some("ERR_POLICY_DENIED")
    );
    let support_fetch_span_text = serde_json::to_string(&support_fetch_span_json)
        .expect("support fetch_span error should serialize");
    assert!(
        !support_fetch_span_text.contains(restricted_canary),
        "restricted canary must not leak via error payload"
    );

    let support_fetch_rows_admin = client
        .post(format!("http://{}/v1/operators/fetch_rows", gateway_addr))
        .header("x-pecr-principal-id", "support")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &support_session_token)
        .json(&serde_json::json!({
            "session_id": support_session_id,
            "params": {
                "view_id": "safe_customer_view_admin",
                "fields": ["admin_note"]
            }
        }))
        .send()
        .await
        .expect("support fetch_rows request should succeed");
    assert_eq!(support_fetch_rows_admin.status(), StatusCode::FORBIDDEN);

    let support_fetch_rows_support = client
        .post(format!("http://{}/v1/operators/fetch_rows", gateway_addr))
        .header("x-pecr-principal-id", "support")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &support_session_token)
        .json(&serde_json::json!({
            "session_id": support_session_id,
            "params": {
                "view_id": "safe_customer_view_support",
                "fields": ["support_note"]
            }
        }))
        .send()
        .await
        .expect("support fetch_rows request should succeed");
    assert!(support_fetch_rows_support.status().is_success());
    let support_fetch_rows_body = support_fetch_rows_support
        .json::<serde_json::Value>()
        .await
        .expect("support fetch_rows response should be JSON");
    let support_rows = support_fetch_rows_body
        .get("result")
        .and_then(|v| v.as_array())
        .expect("fetch_rows must return result array");
    assert!(
        support_rows.iter().any(|v| {
            v.pointer("/content/support_note")
                .and_then(|c| c.as_str())
                .is_some_and(|c| c.contains(pg_support_canary_1) || c.contains(pg_support_canary_2))
        }),
        "support must be able to read support canary via fetch_rows"
    );

    let (guest_session_id, guest_session_token, guest_trace_id, _guest_policy_snapshot_id) =
        gateway_create_session(&client, gateway_addr, "guest", &request_id).await;

    let guest_search = client
        .post(format!("http://{}/v1/operators/search", gateway_addr))
        .header("x-pecr-principal-id", "guest")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &guest_session_token)
        .json(&serde_json::json!({
            "session_id": guest_session_id,
            "params": { "query": "public", "limit": 1 }
        }))
        .send()
        .await
        .expect("guest search request should succeed");
    assert_eq!(guest_search.status(), StatusCode::FORBIDDEN);

    // Shutdown servers.
    let _ = gateway_shutdown.send(());
    let _ = opa_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(3), gateway_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), opa_task).await;

    let _ = std::fs::remove_dir_all(&fs_corpus_root);

    let scoped_pool = PgPool::connect(&schema_url)
        .await
        .expect("db should be reachable for leakage verification");

    let leak_events: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM pecr_ledger_events WHERE event_type = 'LEAK_DETECTED' AND trace_id = ANY($1)",
    )
    .bind(vec![admin_trace_id, support_trace_id, guest_trace_id])
    .fetch_one(&scoped_pool)
    .await
    .expect("query leak events should succeed");
    assert_eq!(leak_events, 0, "expected leakage events to be zero");

    scoped_pool.close().await;

    let logs = logs_since(&log_buf, log_start);
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

    drop_test_schema(&schema_pool, &schema_name).await;
    schema_pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn injection_suite_context_as_malware_tool_steering() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping injection suite; set PECR_TEST_DB_URL to enable");
        return;
    };

    struct OperatorCallCtx<'a> {
        client: &'a reqwest::Client,
        gateway_addr: SocketAddr,
        principal_id: &'a str,
        request_id: &'a str,
        session_token: &'a str,
        session_id: &'a str,
    }

    async fn assert_deterministic_error(
        ctx: &OperatorCallCtx<'_>,
        op_name: &str,
        params: serde_json::Value,
        expected_status: StatusCode,
        expected_message: &str,
    ) {
        let mut last: Option<String> = None;

        for attempt in 0..2 {
            let response = ctx
                .client
                .post(format!(
                    "http://{}/v1/operators/{}",
                    ctx.gateway_addr, op_name
                ))
                .header("x-pecr-principal-id", ctx.principal_id)
                .header("x-pecr-request-id", ctx.request_id)
                .header("x-pecr-session-token", ctx.session_token)
                .json(&serde_json::json!({
                    "session_id": ctx.session_id,
                    "params": params.clone(),
                }))
                .send()
                .await
                .expect("operator request should succeed");
            assert_eq!(
                response.status(),
                expected_status,
                "expected deterministic status on attempt {}",
                attempt
            );
            let body = response
                .json::<serde_json::Value>()
                .await
                .expect("error response should be JSON");
            assert_eq!(
                body.get("code").and_then(|v| v.as_str()),
                Some("ERR_INVALID_PARAMS")
            );
            assert_eq!(
                body.get("message").and_then(|v| v.as_str()),
                Some(expected_message)
            );
            assert_eq!(
                body.get("terminal_mode_hint").and_then(|v| v.as_str()),
                Some("INSUFFICIENT_EVIDENCE")
            );

            let serialized = serde_json::to_string(&body).expect("error must be serializable");
            if let Some(prev) = &last {
                assert_eq!(
                    prev, &serialized,
                    "error response must be deterministic for op_name {}",
                    op_name
                );
            } else {
                last = Some(serialized);
            }
        }
    }

    let log_buf = init_test_tracing();
    let log_start = log_snapshot(&log_buf);

    let request_id = format!("req_injection_{}_{}", std::process::id(), next_suffix());

    let injection_canary = "PECR_CANARY_INJECTION_BETA_29a1e0d7a03d4d8c";

    let fs_corpus_root = prepare_temp_fs_corpus();
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
    assert!(
        pg_fixtures_sql.contains("safe_customer_view_injection"),
        "postgres fixture SQL must contain injection view"
    );

    let (schema_pool, schema_name, schema_url) = create_test_schema(&db_url).await;
    apply_pg_fixtures(&schema_url, &pg_fixtures_sql).await;

    let fs_corpus_path = fs_corpus_root.to_string_lossy().to_string();

    let opa_app = Router::new()
        .route("/health", get(opa_health))
        .route("/v1/data/pecr/authz/decision", post(opa_decision));
    let (opa_addr, opa_shutdown, opa_task) = spawn_server(opa_app).await;

    let gateway_config = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
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

    let client = reqwest::Client::new();
    wait_for_healthz(&client, gateway_addr).await;

    let (session_id, session_token, _trace_id, _policy_snapshot_id) =
        gateway_create_session(&client, gateway_addr, "dev", &request_id).await;

    let op_ctx = OperatorCallCtx {
        client: &client,
        gateway_addr,
        principal_id: "dev",
        request_id: &request_id,
        session_token: &session_token,
        session_id: &session_id,
    };

    let injection_fetch_span = client
        .post(format!("http://{}/v1/operators/fetch_span", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &session_token)
        .json(&serde_json::json!({
            "session_id": session_id,
            "params": { "object_id": "injection/injection_1.txt" }
        }))
        .send()
        .await
        .expect("dev injection fetch_span request should succeed");
    assert!(injection_fetch_span.status().is_success());
    let injection_fetch_span_body = injection_fetch_span
        .json::<serde_json::Value>()
        .await
        .expect("dev injection fetch_span response should be JSON");
    let injection_content = injection_fetch_span_body
        .pointer("/result/content")
        .and_then(|v| v.as_str())
        .expect("fetch_span must return content");
    assert!(
        injection_content.contains(injection_canary),
        "dev must be able to retrieve injection canary content"
    );

    let injection_fetch_rows = client
        .post(format!("http://{}/v1/operators/fetch_rows", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &session_token)
        .json(&serde_json::json!({
            "session_id": session_id,
            "params": {
                "view_id": "safe_customer_view_injection",
                "filter_spec": { "customer_id": "cust_restricted_1" },
                "fields": ["injection_note"]
            }
        }))
        .send()
        .await
        .expect("dev injection fetch_rows request should succeed");
    assert!(injection_fetch_rows.status().is_success());
    let injection_fetch_rows_body = injection_fetch_rows
        .json::<serde_json::Value>()
        .await
        .expect("dev injection fetch_rows response should be JSON");
    let injection_rows = injection_fetch_rows_body
        .get("result")
        .and_then(|v| v.as_array())
        .expect("fetch_rows must return result array");
    assert!(
        injection_rows.iter().any(|v| {
            v.pointer("/content/injection_note")
                .and_then(|c| c.as_str())
                .is_some_and(|c| c.contains("safe_customer_view"))
        }),
        "injection rows should contain tool-steering strings"
    );

    // Injection attempts: forbidden operator call + unsafe parameters. Gateway must reject deterministically.
    assert_deterministic_error(
        &op_ctx,
        "drop_database",
        serde_json::json!({}),
        StatusCode::BAD_REQUEST,
        "operator not allowlisted",
    )
    .await;

    assert_deterministic_error(
        &op_ctx,
        "fetch_span",
        serde_json::json!({ "object_id": "../restricted/restricted_1.txt" }),
        StatusCode::BAD_REQUEST,
        "invalid params.object_id: resource_id must not contain parent traversal segments",
    )
    .await;

    assert_deterministic_error(
        &op_ctx,
        "fetch_rows",
        serde_json::json!({
            "view_id": "safe_customer_view",
            "fields": ["admin_note"],
            "filter_spec": { "customer_id": "cust_public_1" },
        }),
        StatusCode::BAD_REQUEST,
        "view_id not allowlisted",
    )
    .await;

    assert_deterministic_error(
        &op_ctx,
        "fetch_rows",
        serde_json::json!({
            "view_id": "safe_customer_view_public",
            "fields": ["admin_note"],
            "filter_spec": { "customer_id": "cust_public_1" },
        }),
        StatusCode::BAD_REQUEST,
        "field not allowlisted: admin_note",
    )
    .await;

    assert_deterministic_error(
        &op_ctx,
        "fetch_rows",
        serde_json::json!({
            "view_id": "safe_customer_view_public",
            "fields": ["status"],
            "filter_spec": { "admin_note": "x" },
        }),
        StatusCode::BAD_REQUEST,
        "filter field not allowlisted: admin_note",
    )
    .await;

    assert_deterministic_error(
        &op_ctx,
        "diff",
        serde_json::json!({
            "object_id": "public/public_1.txt",
            "v1": "not-a-sha",
            "v2": "also-not-a-sha",
        }),
        StatusCode::BAD_REQUEST,
        "v1 and v2 must be sha256 hex version ids",
    )
    .await;

    // Shutdown servers.
    let _ = gateway_shutdown.send(());
    let _ = opa_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(3), gateway_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), opa_task).await;

    let _ = std::fs::remove_dir_all(&fs_corpus_root);

    let logs = logs_since(&log_buf, log_start);
    assert!(
        !logs.contains(injection_canary),
        "logs must not contain injection canary {}; logs:\n{}",
        injection_canary,
        logs
    );

    drop_test_schema(&schema_pool, &schema_name).await;
    schema_pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn redaction_policy_suite_denies_fields_in_fetch_rows_results() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping redaction policy suite; set PECR_TEST_DB_URL to enable");
        return;
    };

    let request_id = format!(
        "req_redaction_policy_{}_{}",
        std::process::id(),
        next_suffix()
    );

    let fs_corpus_root = prepare_temp_fs_corpus();
    let fs_corpus_path = fs_corpus_root.to_string_lossy().to_string();

    let pg_fixtures_sql = std::fs::read_to_string(
        workspace_root()
            .join("db")
            .join("init")
            .join("002_safeview_fixtures.sql"),
    )
    .expect("postgres fixture SQL should be readable");

    let (schema_pool, schema_name, schema_url) = create_test_schema(&db_url).await;
    apply_pg_fixtures(&schema_url, &pg_fixtures_sql).await;

    let opa_app = Router::new()
        .route("/health", get(opa_health))
        .route("/v1/data/pecr/authz/decision", post(opa_decision));
    let (opa_addr, opa_shutdown, opa_task) = spawn_server(opa_app).await;

    let gateway_config = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
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

    let client = reqwest::Client::new();

    let (session_id, session_token, _trace_id, _policy_snapshot_id) =
        gateway_create_session(&client, gateway_addr, "redacted", &request_id).await;

    let fetch_rows = client
        .post(format!("http://{}/v1/operators/fetch_rows", gateway_addr))
        .header("x-pecr-principal-id", "redacted")
        .header("x-pecr-request-id", &request_id)
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
        .expect("fetch_rows request should succeed");
    assert!(fetch_rows.status().is_success());

    let fetch_rows_body = fetch_rows
        .json::<serde_json::Value>()
        .await
        .expect("fetch_rows response should be JSON");

    let units = fetch_rows_body
        .get("result")
        .and_then(|v| v.as_array())
        .expect("fetch_rows must return result array");
    assert!(!units.is_empty(), "fetch_rows must return rows");

    assert!(
        units
            .iter()
            .all(|unit| unit.pointer("/content/admin_note").is_none()),
        "expected policy redaction to remove content.admin_note from all units"
    );

    assert!(
        units.iter().all(|unit| {
            let Some(fields) = unit
                .pointer("/span_or_row_spec/fields")
                .and_then(|v| v.as_array())
            else {
                return false;
            };
            !fields
                .iter()
                .any(|v| v.as_str().is_some_and(|s| s == "admin_note"))
        }),
        "expected policy redaction to remove admin_note from span_or_row_spec.fields"
    );

    assert!(
        units.iter().all(|unit| {
            unit.pointer("/transform_chain")
                .and_then(|v| v.as_array())
                .is_some_and(|chain| {
                    chain.iter().any(|step| {
                        step.get("transform_type")
                            .and_then(|v| v.as_str())
                            .is_some_and(|t| t == "redaction")
                    })
                })
        }),
        "expected policy redaction to append a redaction transform step"
    );

    // Shutdown servers.
    let _ = gateway_shutdown.send(());
    let _ = opa_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(3), gateway_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), opa_task).await;

    let _ = std::fs::remove_dir_all(&fs_corpus_root);

    drop_test_schema(&schema_pool, &schema_name).await;
    schema_pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn staleness_suite_as_of_selects_fs_snapshot() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping staleness suite; set PECR_TEST_DB_URL to enable");
        return;
    };

    let log_buf = init_test_tracing();
    let log_start = log_snapshot(&log_buf);

    let request_id = format!("req_staleness_{}_{}", std::process::id(), next_suffix());

    let fs_corpus_root = prepare_temp_fs_corpus();
    let object_id = "public/public_1.txt";
    let public_path = fs_corpus_root.join("public").join("public_1.txt");
    let v1_text = std::fs::read_to_string(&public_path).expect("public fixture should be readable");

    let v2_marker = format!(
        "PECR_STALENESS_V2_MARKER_{}_{}",
        std::process::id(),
        next_suffix()
    );
    let v2_text = format!("{v1_text}\n\n{v2_marker}\n");

    let pg_fixtures_sql = std::fs::read_to_string(
        workspace_root()
            .join("db")
            .join("init")
            .join("002_safeview_fixtures.sql"),
    )
    .expect("postgres fixture SQL should be readable");

    let (schema_pool, schema_name, schema_url) = create_test_schema(&db_url).await;
    apply_pg_fixtures(&schema_url, &pg_fixtures_sql).await;

    let fs_corpus_path = fs_corpus_root.to_string_lossy().to_string();

    let opa_app = Router::new()
        .route("/health", get(opa_health))
        .route("/v1/data/pecr/authz/decision", post(opa_decision));
    let (opa_addr, opa_shutdown, opa_task) = spawn_server(opa_app).await;

    let gateway_config = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
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

    let client = reqwest::Client::new();
    wait_for_healthz(&client, gateway_addr).await;

    let t1 = "2026-01-01T00:00:00Z";
    let t2 = "2026-02-01T00:00:00Z";

    let (session_1, token_1, _trace_1, _policy_snapshot_1) =
        gateway_create_session_at(&client, gateway_addr, "dev", &request_id, Some(t1)).await;

    let list_v1 = client
        .post(format!(
            "http://{}/v1/operators/list_versions",
            gateway_addr
        ))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &token_1)
        .json(&serde_json::json!({
            "session_id": session_1,
            "params": { "object_id": object_id }
        }))
        .send()
        .await
        .expect("list_versions v1 request should succeed");
    assert!(list_v1.status().is_success());
    let list_v1_body = list_v1
        .json::<serde_json::Value>()
        .await
        .expect("list_versions v1 response should be JSON");
    let v1_versions = list_v1_body
        .pointer("/result/versions")
        .and_then(|v| v.as_array())
        .expect("list_versions must return result.versions array");
    assert_eq!(v1_versions.len(), 1, "expected one version before update");
    let v1_version_id = v1_versions[0]
        .get("version_id")
        .and_then(|v| v.as_str())
        .expect("version_id must be present")
        .to_string();

    let fetch_v1 = client
        .post(format!("http://{}/v1/operators/fetch_span", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &token_1)
        .json(&serde_json::json!({
            "session_id": session_1,
            "params": { "object_id": object_id }
        }))
        .send()
        .await
        .expect("fetch_span v1 request should succeed");
    assert!(fetch_v1.status().is_success());
    let fetch_v1_body = fetch_v1
        .json::<serde_json::Value>()
        .await
        .expect("fetch_span v1 response should be JSON");
    assert_eq!(
        fetch_v1_body
            .pointer("/result/version_id")
            .and_then(|v| v.as_str()),
        Some(v1_version_id.as_str()),
        "expected fetch_span at t1 to return v1 version_id"
    );
    let v1_content = fetch_v1_body
        .pointer("/result/content")
        .and_then(|v| v.as_str())
        .expect("fetch_span must return content");
    assert!(v1_content.contains("Public fixture document (public_1)."));
    assert!(
        !v1_content.contains(&v2_marker),
        "v1 content must not include v2 marker"
    );

    std::fs::write(&public_path, v2_text).expect("public fixture should be writable");

    let (session_2, token_2, _trace_2, _policy_snapshot_2) =
        gateway_create_session_at(&client, gateway_addr, "dev", &request_id, Some(t2)).await;

    let list_v2 = client
        .post(format!(
            "http://{}/v1/operators/list_versions",
            gateway_addr
        ))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &token_2)
        .json(&serde_json::json!({
            "session_id": session_2,
            "params": { "object_id": object_id }
        }))
        .send()
        .await
        .expect("list_versions v2 request should succeed");
    assert!(list_v2.status().is_success());
    let list_v2_body = list_v2
        .json::<serde_json::Value>()
        .await
        .expect("list_versions v2 response should be JSON");
    let v2_versions = list_v2_body
        .pointer("/result/versions")
        .and_then(|v| v.as_array())
        .expect("list_versions must return result.versions array");
    assert!(
        v2_versions.len() >= 2,
        "expected at least two versions after update"
    );
    let version_ids = v2_versions
        .iter()
        .filter_map(|v| v.get("version_id").and_then(|v| v.as_str()))
        .collect::<Vec<_>>();
    assert!(
        version_ids.contains(&v1_version_id.as_str()),
        "expected list_versions after update to include v1 version_id"
    );
    let v2_version_id = version_ids
        .iter()
        .find(|v| **v != v1_version_id.as_str())
        .expect("expected a second version_id after update")
        .to_string();

    let fetch_v2 = client
        .post(format!("http://{}/v1/operators/fetch_span", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &token_2)
        .json(&serde_json::json!({
            "session_id": session_2,
            "params": { "object_id": object_id }
        }))
        .send()
        .await
        .expect("fetch_span v2 request should succeed");
    assert!(fetch_v2.status().is_success());
    let fetch_v2_body = fetch_v2
        .json::<serde_json::Value>()
        .await
        .expect("fetch_span v2 response should be JSON");
    assert_eq!(
        fetch_v2_body
            .pointer("/result/version_id")
            .and_then(|v| v.as_str()),
        Some(v2_version_id.as_str()),
        "expected fetch_span at t2 to return v2 version_id"
    );
    let v2_content = fetch_v2_body
        .pointer("/result/content")
        .and_then(|v| v.as_str())
        .expect("fetch_span must return content");
    assert!(
        v2_content.contains(&v2_marker),
        "v2 content must include v2 marker"
    );

    let (session_1_again, token_1_again, _trace_1_again, _policy_snapshot_1_again) =
        gateway_create_session_at(&client, gateway_addr, "dev", &request_id, Some(t1)).await;

    let fetch_v1_again = client
        .post(format!("http://{}/v1/operators/fetch_span", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &token_1_again)
        .json(&serde_json::json!({
            "session_id": session_1_again,
            "params": { "object_id": object_id }
        }))
        .send()
        .await
        .expect("fetch_span v1 again request should succeed");
    let fetch_v1_again_status = fetch_v1_again.status();
    let fetch_v1_again_body = fetch_v1_again
        .json::<serde_json::Value>()
        .await
        .expect("fetch_span v1 again response should be JSON");
    assert!(
        fetch_v1_again_status.is_success(),
        "fetch_span v1 again unexpected status {}; body: {}",
        fetch_v1_again_status,
        fetch_v1_again_body
    );
    assert_eq!(
        fetch_v1_again_body
            .pointer("/result/version_id")
            .and_then(|v| v.as_str()),
        Some(v1_version_id.as_str()),
        "expected fetch_span at t1 (after update) to return v1 version_id"
    );
    let v1_again_content = fetch_v1_again_body
        .pointer("/result/content")
        .and_then(|v| v.as_str())
        .expect("fetch_span must return content");
    assert!(
        !v1_again_content.contains(&v2_marker),
        "as_of_time selection must not return v2 content for t1"
    );

    // Shutdown servers.
    let _ = gateway_shutdown.send(());
    let _ = opa_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(3), gateway_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), opa_task).await;

    let _ = std::fs::remove_dir_all(&fs_corpus_root);

    let logs = logs_since(&log_buf, log_start);
    assert!(
        !logs.contains(&v2_marker),
        "logs must not contain v2 marker; logs:\n{}",
        logs
    );

    drop_test_schema(&schema_pool, &schema_name).await;
    schema_pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn staleness_suite_as_of_selects_pg_snapshot() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping staleness suite; set PECR_TEST_DB_URL to enable");
        return;
    };

    let log_buf = init_test_tracing();
    let log_start = log_snapshot(&log_buf);

    let request_id = format!("req_staleness_pg_{}_{}", std::process::id(), next_suffix());

    let fs_corpus_root = prepare_temp_fs_corpus();

    let pg_fixtures_sql = std::fs::read_to_string(
        workspace_root()
            .join("db")
            .join("init")
            .join("002_safeview_fixtures.sql"),
    )
    .expect("postgres fixture SQL should be readable");

    let (schema_pool, schema_name, schema_url) = create_test_schema(&db_url).await;
    apply_pg_fixtures(&schema_url, &pg_fixtures_sql).await;

    let fs_corpus_path = fs_corpus_root.to_string_lossy().to_string();

    let opa_app = Router::new()
        .route("/health", get(opa_health))
        .route("/v1/data/pecr/authz/decision", post(opa_decision));
    let (opa_addr, opa_shutdown, opa_task) = spawn_server(opa_app).await;

    let gateway_config = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
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

    let client = reqwest::Client::new();
    wait_for_healthz(&client, gateway_addr).await;

    let t1 = "2026-01-01T00:00:00Z";
    let t2 = "2026-02-01T00:00:00Z";

    let v2_marker = format!(
        "PECR_STALENESS_PG_V2_MARKER_{}_{}",
        std::process::id(),
        next_suffix()
    );

    let (session_1, token_1, _trace_1, _policy_snapshot_1) =
        gateway_create_session_at(&client, gateway_addr, "dev", &request_id, Some(t1)).await;

    let fetch_v1 = client
        .post(format!("http://{}/v1/operators/fetch_rows", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &token_1)
        .json(&serde_json::json!({
            "session_id": session_1,
            "params": {
                "view_id": "safe_customer_view_public",
                "fields": ["status"],
                "filter_spec": {"customer_id": "cust_public_1"}
            }
        }))
        .send()
        .await
        .expect("fetch_rows v1 request should succeed");
    assert!(fetch_v1.status().is_success());
    let fetch_v1_body = fetch_v1
        .json::<serde_json::Value>()
        .await
        .expect("fetch_rows v1 response should be JSON");
    let v1_version_id = fetch_v1_body
        .pointer("/result/0/version_id")
        .and_then(|v| v.as_str())
        .expect("fetch_rows must return result[0].version_id")
        .to_string();
    let v1_status = fetch_v1_body
        .pointer("/result/0/content/status")
        .and_then(|v| v.as_str())
        .expect("fetch_rows must return result[0].content.status")
        .to_string();
    assert!(
        !v1_status.contains(&v2_marker),
        "expected v1 content to exclude v2 marker"
    );

    let admin_pool = PgPool::connect(&schema_url)
        .await
        .expect("schema should be reachable for updates");
    sqlx::query(
        "UPDATE pecr_fixture_customers SET status = $1, updated_at = $2::timestamptz WHERE tenant_id = 'local' AND customer_id = 'cust_public_1'",
    )
    .bind(&v2_marker)
    .bind(t2)
    .execute(&admin_pool)
    .await
    .expect("fixture update should succeed");
    admin_pool.close().await;

    let (session_2, token_2, _trace_2, _policy_snapshot_2) =
        gateway_create_session_at(&client, gateway_addr, "dev", &request_id, Some(t2)).await;

    let fetch_v2 = client
        .post(format!("http://{}/v1/operators/fetch_rows", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &token_2)
        .json(&serde_json::json!({
            "session_id": session_2,
            "params": {
                "view_id": "safe_customer_view_public",
                "fields": ["status"],
                "filter_spec": {"customer_id": "cust_public_1"}
            }
        }))
        .send()
        .await
        .expect("fetch_rows v2 request should succeed");
    assert!(fetch_v2.status().is_success());
    let fetch_v2_body = fetch_v2
        .json::<serde_json::Value>()
        .await
        .expect("fetch_rows v2 response should be JSON");
    let v2_version_id = fetch_v2_body
        .pointer("/result/0/version_id")
        .and_then(|v| v.as_str())
        .expect("fetch_rows must return result[0].version_id")
        .to_string();
    assert_ne!(
        v2_version_id, v1_version_id,
        "expected fetch_rows at t2 to return a new version_id"
    );
    let v2_status = fetch_v2_body
        .pointer("/result/0/content/status")
        .and_then(|v| v.as_str())
        .expect("fetch_rows must return result[0].content.status");
    assert!(
        v2_status.contains(&v2_marker),
        "expected v2 content to include v2 marker"
    );

    let (session_1_again, token_1_again, _trace_1_again, _policy_snapshot_1_again) =
        gateway_create_session_at(&client, gateway_addr, "dev", &request_id, Some(t1)).await;

    let fetch_v1_again = client
        .post(format!("http://{}/v1/operators/fetch_rows", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &token_1_again)
        .json(&serde_json::json!({
            "session_id": session_1_again,
            "params": {
                "view_id": "safe_customer_view_public",
                "fields": ["status"],
                "filter_spec": {"customer_id": "cust_public_1"}
            }
        }))
        .send()
        .await
        .expect("fetch_rows v1 again request should succeed");
    let fetch_v1_again_status = fetch_v1_again.status();
    let fetch_v1_again_body = fetch_v1_again
        .json::<serde_json::Value>()
        .await
        .expect("fetch_rows v1 again response should be JSON");
    assert!(
        fetch_v1_again_status.is_success(),
        "fetch_rows v1 again unexpected status {}; body: {}",
        fetch_v1_again_status,
        fetch_v1_again_body
    );
    assert_eq!(
        fetch_v1_again_body
            .pointer("/result/0/version_id")
            .and_then(|v| v.as_str()),
        Some(v1_version_id.as_str()),
        "expected fetch_rows at t1 (after update) to return v1 version_id"
    );
    let v1_again_status = fetch_v1_again_body
        .pointer("/result/0/content/status")
        .and_then(|v| v.as_str())
        .expect("fetch_rows must return result[0].content.status");
    assert_eq!(
        v1_again_status, v1_status,
        "expected fetch_rows at t1 (after update) to return v1 content"
    );
    assert!(
        !v1_again_status.contains(&v2_marker),
        "as_of_time selection must not return v2 content for t1"
    );

    // Shutdown servers.
    let _ = gateway_shutdown.send(());
    let _ = opa_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(3), gateway_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), opa_task).await;

    let _ = std::fs::remove_dir_all(&fs_corpus_root);

    let logs = logs_since(&log_buf, log_start);
    assert!(
        !logs.contains(&v2_marker),
        "logs must not contain v2 marker; logs:\n{}",
        logs
    );

    drop_test_schema(&schema_pool, &schema_name).await;
    schema_pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn claim_evidence_audit_suite_supported_claims_require_evidence() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping claim-evidence audit suite; set PECR_TEST_DB_URL to enable");
        return;
    };

    let log_buf = init_test_tracing();
    let log_start = log_snapshot(&log_buf);

    let request_id = format!("req_claim_audit_{}_{}", std::process::id(), next_suffix());

    let fs_corpus_root = prepare_temp_fs_corpus();
    let object_id = "public/public_1.txt";

    let pg_fixtures_sql = std::fs::read_to_string(
        workspace_root()
            .join("db")
            .join("init")
            .join("002_safeview_fixtures.sql"),
    )
    .expect("postgres fixture SQL should be readable");

    let (schema_pool, schema_name, schema_url) = create_test_schema(&db_url).await;
    apply_pg_fixtures(&schema_url, &pg_fixtures_sql).await;

    let fs_corpus_path = fs_corpus_root.to_string_lossy().to_string();

    let opa_app = Router::new()
        .route("/health", get(opa_health))
        .route("/v1/data/pecr/authz/decision", post(opa_decision));
    let (opa_addr, opa_shutdown, opa_task) = spawn_server(opa_app).await;

    let gateway_config = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
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

    let client = reqwest::Client::new();
    wait_for_healthz(&client, gateway_addr).await;

    // Case 1: SUPPORTED claim with emitted evidence -> finalize returns SUPPORTED.
    let (session_1, token_1, _trace_1, _policy_snapshot_1) =
        gateway_create_session(&client, gateway_addr, "dev", &request_id).await;

    let fetch_span = client
        .post(format!("http://{}/v1/operators/fetch_span", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &token_1)
        .json(&serde_json::json!({
            "session_id": session_1,
            "params": { "object_id": object_id }
        }))
        .send()
        .await
        .expect("fetch_span request should succeed");
    assert!(fetch_span.status().is_success());
    let fetch_span_body = fetch_span
        .json::<serde_json::Value>()
        .await
        .expect("fetch_span response should be JSON");
    let evidence_unit_id = fetch_span_body
        .pointer("/result/evidence_unit_id")
        .and_then(|v| v.as_str())
        .expect("fetch_span must return result.evidence_unit_id")
        .to_string();

    let claim_map_id = format!("cm_{}_{}", std::process::id(), next_suffix());
    let finalize_1 = client
        .post(format!("http://{}/v1/finalize", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &token_1)
        .json(&serde_json::json!({
            "session_id": session_1,
            "response_text": "ok",
            "claim_map": {
                "claim_map_id": claim_map_id,
                "terminal_mode": "SUPPORTED",
                "claims": [
                    {
                        "claim_id": "",
                        "claim_text": "public doc retrieved",
                        "status": "SUPPORTED",
                        "evidence_unit_ids": [evidence_unit_id]
                    }
                ],
                "coverage_threshold": 0.0,
                "coverage_observed": 0.0
            }
        }))
        .send()
        .await
        .expect("finalize request should succeed");
    assert!(finalize_1.status().is_success());
    let finalize_1_body = finalize_1
        .json::<serde_json::Value>()
        .await
        .expect("finalize response should be JSON");
    assert_eq!(
        finalize_1_body
            .pointer("/terminal_mode")
            .and_then(|v| v.as_str()),
        Some("SUPPORTED"),
        "expected SUPPORTED finalize when a SUPPORTED claim has evidence"
    );
    let coverage_observed = finalize_1_body
        .pointer("/claim_map/coverage_observed")
        .and_then(|v| v.as_f64())
        .expect("claim_map.coverage_observed must be present");
    let coverage_threshold = finalize_1_body
        .pointer("/claim_map/coverage_threshold")
        .and_then(|v| v.as_f64())
        .expect("claim_map.coverage_threshold must be present");
    assert!(
        coverage_observed >= coverage_threshold,
        "coverage must meet threshold for SUPPORTED"
    );

    // Case 2: SUPPORTED claim without evidence -> finalize must not return SUPPORTED.
    let (session_2, token_2, _trace_2, _policy_snapshot_2) =
        gateway_create_session(&client, gateway_addr, "dev", &request_id).await;
    let claim_map_id_2 = format!("cm_{}_{}", std::process::id(), next_suffix());
    let finalize_2 = client
        .post(format!("http://{}/v1/finalize", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &token_2)
        .json(&serde_json::json!({
            "session_id": session_2,
            "response_text": "no evidence",
            "claim_map": {
                "claim_map_id": claim_map_id_2,
                "terminal_mode": "SUPPORTED",
                "claims": [
                    {
                        "claim_id": "",
                        "claim_text": "unsupported claim",
                        "status": "SUPPORTED",
                        "evidence_unit_ids": []
                    }
                ],
                "coverage_threshold": 0.0,
                "coverage_observed": 0.0
            }
        }))
        .send()
        .await
        .expect("finalize request should succeed");
    assert!(finalize_2.status().is_success());
    let finalize_2_body = finalize_2
        .json::<serde_json::Value>()
        .await
        .expect("finalize response should be JSON");
    assert_eq!(
        finalize_2_body
            .pointer("/terminal_mode")
            .and_then(|v| v.as_str()),
        Some("INSUFFICIENT_EVIDENCE"),
        "expected INSUFFICIENT_EVIDENCE finalize when SUPPORTED claims have no evidence"
    );

    // Shutdown servers.
    let _ = gateway_shutdown.send(());
    let _ = opa_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(3), gateway_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), opa_task).await;

    let _ = std::fs::remove_dir_all(&fs_corpus_root);

    let logs = logs_since(&log_buf, log_start);
    assert!(
        !logs.contains(&evidence_unit_id),
        "logs must not contain raw evidence ids; logs:\n{}",
        logs
    );

    drop_test_schema(&schema_pool, &schema_name).await;
    schema_pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn cache_bleed_suite_cross_principal_reuse_is_zero() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping cache bleed suite; set PECR_TEST_DB_URL to enable");
        return;
    };

    let log_buf = init_test_tracing();
    let log_start = log_snapshot(&log_buf);

    let request_id = format!("req_cache_bleed_{}_{}", std::process::id(), next_suffix());

    let fs_corpus_root = prepare_temp_fs_corpus();

    let pg_fixtures_sql = std::fs::read_to_string(
        workspace_root()
            .join("db")
            .join("init")
            .join("002_safeview_fixtures.sql"),
    )
    .expect("postgres fixture SQL should be readable");

    let (schema_pool, schema_name, schema_url) = create_test_schema(&db_url).await;
    apply_pg_fixtures(&schema_url, &pg_fixtures_sql).await;

    let fs_corpus_path = fs_corpus_root.to_string_lossy().to_string();

    let opa_app = Router::new()
        .route("/health", get(opa_health))
        .route("/v1/data/pecr/authz/decision", post(opa_decision));
    let (opa_addr, opa_shutdown, opa_task) = spawn_server(opa_app).await;

    let gateway_config = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
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
        ("PECR_CACHE_MAX_ENTRIES".to_string(), "128".to_string()),
        ("PECR_CACHE_TTL_MS".to_string(), "60000".to_string()),
    ]))
    .expect("gateway config should be valid");

    let (gateway_addr, gateway_shutdown, gateway_task) = spawn_server(
        pecr_gateway::http::router(gateway_config)
            .await
            .expect("gateway router should init"),
    )
    .await;

    let client = reqwest::Client::new();
    wait_for_healthz(&client, gateway_addr).await;

    let (dev_session, dev_token, _dev_trace, _dev_policy_snapshot) =
        gateway_create_session(&client, gateway_addr, "dev", &request_id).await;
    let (support_session, support_token, _support_trace, _support_policy_snapshot) =
        gateway_create_session(&client, gateway_addr, "support", &request_id).await;

    async fn search_map(
        client: &reqwest::Client,
        gateway_addr: SocketAddr,
        principal_id: &str,
        request_id: &str,
        session_token: &str,
        session_id: &str,
        query: &str,
    ) -> HashMap<String, String> {
        let response = client
            .post(format!("http://{}/v1/operators/search", gateway_addr))
            .header("x-pecr-principal-id", principal_id)
            .header("x-pecr-request-id", request_id)
            .header("x-pecr-session-token", session_token)
            .json(&serde_json::json!({
                "session_id": session_id,
                "params": { "query": query, "limit": 50 }
            }))
            .send()
            .await
            .expect("search request should succeed");
        assert!(response.status().is_success());

        let body = response
            .json::<serde_json::Value>()
            .await
            .expect("search response should be JSON");

        let refs = body
            .pointer("/result/refs")
            .and_then(|v| v.as_array())
            .expect("search must return result.refs array");

        let mut out = HashMap::new();
        for r in refs {
            let object_id = r
                .get("object_id")
                .and_then(|v| v.as_str())
                .expect("ref must include object_id");
            let evidence_unit_id = r
                .get("evidence_unit_id")
                .and_then(|v| v.as_str())
                .expect("ref must include evidence_unit_id");
            out.insert(object_id.to_string(), evidence_unit_id.to_string());
        }
        out
    }

    let query = "Restricted fixture document";

    let dev_refs_1 = search_map(
        &client,
        gateway_addr,
        "dev",
        &request_id,
        &dev_token,
        &dev_session,
        query,
    )
    .await;
    let dev_refs_2 = search_map(
        &client,
        gateway_addr,
        "dev",
        &request_id,
        &dev_token,
        &dev_session,
        query,
    )
    .await;
    assert_eq!(dev_refs_1, dev_refs_2, "dev repeated search must be stable");

    let support_refs_1 = search_map(
        &client,
        gateway_addr,
        "support",
        &request_id,
        &support_token,
        &support_session,
        query,
    )
    .await;
    let support_refs_2 = search_map(
        &client,
        gateway_addr,
        "support",
        &request_id,
        &support_token,
        &support_session,
        query,
    )
    .await;
    assert_eq!(
        support_refs_1, support_refs_2,
        "support repeated search must be stable"
    );

    assert!(
        !dev_refs_1.is_empty(),
        "expected search to return at least one ref"
    );
    assert_eq!(
        dev_refs_1.len(),
        support_refs_1.len(),
        "expected search to return same object_ids across principals"
    );
    for (object_id, dev_evidence_unit_id) in &dev_refs_1 {
        let support_evidence_unit_id = support_refs_1
            .get(object_id)
            .expect("support must include same object_id");
        assert_ne!(
            dev_evidence_unit_id, support_evidence_unit_id,
            "cross-principal reuse detected for {}; cache keys must include principal+policy_snapshot_hash+as_of_time",
            object_id
        );
    }

    let metrics = client
        .get(format!("http://{}/metrics", gateway_addr))
        .send()
        .await
        .expect("metrics request should succeed")
        .text()
        .await
        .expect("metrics should be readable");
    let search_hits = metrics
        .lines()
        .find(|line| {
            line.starts_with("pecr_gateway_operator_cache_hits_total{operator_name=\"search\"}")
        })
        .expect("cache hit metric must be present");
    let hits: u64 = search_hits
        .split_whitespace()
        .nth(1)
        .expect("metric must include value")
        .parse()
        .expect("metric value must parse");
    assert!(
        hits >= 2,
        "expected at least 2 cache hits for search (dev+support second call); metrics:\n{}",
        metrics
    );

    // Shutdown servers.
    let _ = gateway_shutdown.send(());
    let _ = opa_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(3), gateway_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), opa_task).await;

    let _ = std::fs::remove_dir_all(&fs_corpus_root);

    let logs = logs_since(&log_buf, log_start);
    let restricted_canary = "PECR_CANARY_RESTRICTED_ALPHA_6b3b91c2a7b44a9f";
    assert!(
        !logs.contains(restricted_canary),
        "logs must not contain restricted canary {}; logs:\n{}",
        restricted_canary,
        logs
    );

    drop_test_schema(&schema_pool, &schema_name).await;
    schema_pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn telemetry_leakage_suite_no_canaries_in_logs_or_metrics() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping telemetry leakage suite; set PECR_TEST_DB_URL to enable");
        return;
    };

    let log_buf = init_test_tracing();
    let log_start = log_snapshot(&log_buf);

    let request_id = format!(
        "req_telemetry_leakage_{}_{}",
        std::process::id(),
        next_suffix()
    );

    let fs_corpus_root = prepare_temp_fs_corpus();

    let pg_fixtures_sql = std::fs::read_to_string(
        workspace_root()
            .join("db")
            .join("init")
            .join("002_safeview_fixtures.sql"),
    )
    .expect("postgres fixture SQL should be readable");

    let (schema_pool, schema_name, schema_url) = create_test_schema(&db_url).await;
    apply_pg_fixtures(&schema_url, &pg_fixtures_sql).await;

    let fs_corpus_path = fs_corpus_root.to_string_lossy().to_string();

    let opa_app = Router::new()
        .route("/health", get(opa_health))
        .route("/v1/data/pecr/authz/decision", post(opa_decision));
    let (opa_addr, opa_shutdown, opa_task) = spawn_server(opa_app).await;

    let gateway_config = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
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

    let client = reqwest::Client::new();
    wait_for_healthz(&client, gateway_addr).await;

    let (session, token, _trace, _policy_snapshot) =
        gateway_create_session(&client, gateway_addr, "dev", &request_id).await;

    let fetch_restricted = client
        .post(format!("http://{}/v1/operators/fetch_span", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &token)
        .json(&serde_json::json!({
            "session_id": session,
            "params": { "object_id": "restricted/restricted_1.txt" }
        }))
        .send()
        .await
        .expect("fetch_span restricted request should succeed");
    assert!(fetch_restricted.status().is_success());

    let fetch_injection = client
        .post(format!("http://{}/v1/operators/fetch_span", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &token)
        .json(&serde_json::json!({
            "session_id": session,
            "params": { "object_id": "injection/injection_1.txt" }
        }))
        .send()
        .await
        .expect("fetch_span injection request should succeed");
    assert!(fetch_injection.status().is_success());

    let fetch_admin_note = client
        .post(format!("http://{}/v1/operators/fetch_rows", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &token)
        .json(&serde_json::json!({
            "session_id": session,
            "params": {
                "view_id": "safe_customer_view_admin",
                "fields": ["admin_note"],
                "filter_spec": {"customer_id": "cust_public_1"}
            }
        }))
        .send()
        .await
        .expect("fetch_rows admin_note request should succeed");
    assert!(fetch_admin_note.status().is_success());

    let fetch_support_note = client
        .post(format!("http://{}/v1/operators/fetch_rows", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &token)
        .json(&serde_json::json!({
            "session_id": session,
            "params": {
                "view_id": "safe_customer_view_support",
                "fields": ["support_note"],
                "filter_spec": {"customer_id": "cust_public_1"}
            }
        }))
        .send()
        .await
        .expect("fetch_rows support_note request should succeed");
    assert!(fetch_support_note.status().is_success());

    let metrics = client
        .get(format!("http://{}/metrics", gateway_addr))
        .send()
        .await
        .expect("metrics request should succeed")
        .text()
        .await
        .expect("metrics should be readable");

    // Shutdown servers.
    let _ = gateway_shutdown.send(());
    let _ = opa_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(3), gateway_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), opa_task).await;

    let _ = std::fs::remove_dir_all(&fs_corpus_root);

    let logs = logs_since(&log_buf, log_start);
    let forbidden_tokens = [
        "PECR_CANARY_RESTRICTED_ALPHA_6b3b91c2a7b44a9f",
        "PECR_CANARY_INJECTION_BETA_29a1e0d7a03d4d8c",
        "PECR_CANARY_PG_ADMIN_DELTA_1f2d8c6f87f84b76",
        "PECR_CANARY_PG_SUPPORT_EPSILON_6c6f4f07c04f4f8f",
        "Restricted fixture document (restricted_1).",
        "Injection fixture document (injection_1).",
    ];

    for token in forbidden_tokens {
        assert!(
            !logs.contains(token),
            "logs must not contain {}; logs:\n{}",
            token,
            logs
        );
        assert!(
            !metrics.contains(token),
            "metrics must not contain {}; metrics:\n{}",
            token,
            metrics
        );
    }

    drop_test_schema(&schema_pool, &schema_name).await;
    schema_pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn observability_coverage_suite_required_signals_exist() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping observability coverage suite; set PECR_TEST_DB_URL to enable");
        return;
    };

    let log_buf = init_test_tracing();
    let log_start = log_snapshot(&log_buf);

    let request_id = format!("req_observability_{}_{}", std::process::id(), next_suffix());

    let fs_corpus_root = prepare_temp_fs_corpus();

    let pg_fixtures_sql = std::fs::read_to_string(
        workspace_root()
            .join("db")
            .join("init")
            .join("002_safeview_fixtures.sql"),
    )
    .expect("postgres fixture SQL should be readable");

    let (schema_pool, schema_name, schema_url) = create_test_schema(&db_url).await;
    apply_pg_fixtures(&schema_url, &pg_fixtures_sql).await;

    let fs_corpus_path = fs_corpus_root.to_string_lossy().to_string();

    let opa_app = Router::new()
        .route("/health", get(opa_health))
        .route("/v1/data/pecr/authz/decision", post(opa_decision));
    let (opa_addr, opa_shutdown, opa_task) = spawn_server(opa_app).await;

    let gateway_config = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
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

    let (controller_addr, controller_shutdown, controller_task) = spawn_server(
        pecr_controller::http::router(controller_config)
            .await
            .expect("controller router should init"),
    )
    .await;

    let client = reqwest::Client::new();
    wait_for_http_status(
        &client,
        format!("http://{}/readyz", gateway_addr).as_str(),
        StatusCode::OK,
    )
    .await;
    wait_for_http_status(
        &client,
        format!("http://{}/readyz", controller_addr).as_str(),
        StatusCode::OK,
    )
    .await;

    let response = client
        .post(format!("http://{}/v1/run", controller_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
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
    let trace_id = body
        .get("trace_id")
        .and_then(|v| v.as_str())
        .expect("trace_id should exist");
    assert_eq!(
        body.get("terminal_mode").and_then(|v| v.as_str()),
        Some("SUPPORTED"),
        "controller run should produce SUPPORTED terminal_mode: {}",
        body
    );
    assert!(
        body.get("response_text")
            .and_then(|v| v.as_str())
            .is_some_and(|text| text.contains("SUPPORTED:")),
        "response_text should include SUPPORTED claims: {}",
        body
    );
    let claims = body
        .get("claim_map")
        .and_then(|v| v.get("claims"))
        .and_then(|v| v.as_array())
        .expect("claim_map.claims should exist");
    assert!(
        claims.iter().any(|claim| {
            claim.get("status").and_then(|v| v.as_str()) == Some("SUPPORTED")
                && claim
                    .get("evidence_unit_ids")
                    .and_then(|v| v.as_array())
                    .is_some_and(|ids| !ids.is_empty())
        }),
        "claim_map should contain a supported claim with evidence: {}",
        body
    );

    let replay_list = wait_for_replay_list_contains_traces(
        &client,
        controller_addr,
        "dev",
        &[trace_id.to_string()],
    )
    .await;
    let replays = replay_list
        .get("replays")
        .and_then(|v| v.as_array())
        .expect("replay list should include replays array");
    assert!(
        replays
            .iter()
            .any(|replay| replay.get("trace_id").and_then(|v| v.as_str()) == Some(trace_id)),
        "replay metadata should contain the completed run trace_id {}; replays:\n{}",
        trace_id,
        replay_list
    );

    let gateway_metrics = client
        .get(format!("http://{}/metrics", gateway_addr))
        .send()
        .await
        .expect("gateway metrics request should succeed")
        .text()
        .await
        .expect("gateway metrics should be readable");

    for required in [
        "pecr_gateway_terminal_modes_total{",
        "pecr_gateway_operator_calls_total{",
        "pecr_gateway_budget_violations_total ",
        "pecr_gateway_staleness_errors_total ",
        "pecr_gateway_leakage_detections_total ",
        "pecr_gateway_http_request_duration_seconds_bucket{",
    ] {
        assert!(
            gateway_metrics.contains(required),
            "gateway metrics missing {}; metrics:\n{}",
            required,
            gateway_metrics
        );
    }

    let controller_metrics = client
        .get(format!("http://{}/metrics", controller_addr))
        .send()
        .await
        .expect("controller metrics request should succeed")
        .text()
        .await
        .expect("controller metrics should be readable");

    for required in [
        "pecr_controller_terminal_modes_total{",
        "pecr_controller_loop_iterations_total ",
        "pecr_controller_budget_violations_total ",
        "pecr_controller_http_request_duration_seconds_bucket{",
    ] {
        assert!(
            controller_metrics.contains(required),
            "controller metrics missing {}; metrics:\n{}",
            required,
            controller_metrics
        );
    }

    // Shutdown servers.
    let _ = controller_shutdown.send(());
    let _ = gateway_shutdown.send(());
    let _ = opa_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(3), controller_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), gateway_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), opa_task).await;

    let _ = std::fs::remove_dir_all(&fs_corpus_root);

    let logs = logs_since(&log_buf, log_start);
    assert!(
        logs.contains(&request_id),
        "logs must include request_id {}; logs:\n{}",
        request_id,
        logs
    );
    assert!(
        logs.contains(trace_id),
        "logs must include trace_id {}; logs:\n{}",
        trace_id,
        logs
    );
    assert!(
        logs.contains("stop_reason="),
        "logs must include a controller stopping reason; logs:\n{}",
        logs
    );
    for field in ["session_id=", "principal_id=", "policy_snapshot_id="] {
        assert!(
            logs.contains(field),
            "logs must include correlation field {}; logs:\n{}",
            field,
            logs
        );
    }

    let scoped_pool = PgPool::connect(&schema_url)
        .await
        .expect("db should be reachable for observability verification");
    for event_type in [
        "POLICY_DECISION",
        "OPERATOR_CALL",
        "EVIDENCE_EMITTED",
        "FINALIZE_RESULT",
    ] {
        let count: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM pecr_ledger_events WHERE event_type = $1 AND trace_id = $2",
        )
        .bind(event_type)
        .bind(trace_id)
        .fetch_one(&scoped_pool)
        .await
        .expect("query ledger events should succeed");
        assert!(
            count > 0,
            "expected at least one {} ledger event for trace_id {}; count={}",
            event_type,
            trace_id,
            count
        );
    }
    scoped_pool.close().await;

    drop_test_schema(&schema_pool, &schema_name).await;
    schema_pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failure_mode_suite_policy_deny_and_budget_exhaustion() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping failure mode suite; set PECR_TEST_DB_URL to enable");
        return;
    };

    let request_id = format!("req_failure_modes_{}_{}", std::process::id(), next_suffix());
    let fs_corpus_root = prepare_temp_fs_corpus();
    let fs_corpus_path = fs_corpus_root.to_string_lossy().to_string();

    let pg_fixtures_sql = std::fs::read_to_string(
        workspace_root()
            .join("db")
            .join("init")
            .join("002_safeview_fixtures.sql"),
    )
    .expect("postgres fixture SQL should be readable");

    let (schema_pool, schema_name, schema_url) = create_test_schema(&db_url).await;
    apply_pg_fixtures(&schema_url, &pg_fixtures_sql).await;

    let opa_app = Router::new()
        .route("/health", get(opa_health))
        .route("/v1/data/pecr/authz/decision", post(opa_decision));
    let (opa_addr, opa_shutdown, opa_task) = spawn_server(opa_app).await;

    let gateway_config = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
        ("PECR_OPA_URL".to_string(), format!("http://{}", opa_addr)),
        (
            "PECR_POLICY_BUNDLE_HASH".to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ),
        ("PECR_FS_CORPUS_PATH".to_string(), fs_corpus_path),
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

    let client = reqwest::Client::new();
    wait_for_healthz(&client, gateway_addr).await;

    // Policy deny path: guest principal is denied for operator_call by test OPA policy.
    let (guest_session, guest_token, _, _) =
        gateway_create_session(&client, gateway_addr, "guest", &request_id).await;

    let denied = client
        .post(format!("http://{}/v1/operators/fetch_rows", gateway_addr))
        .header("x-pecr-principal-id", "guest")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &guest_token)
        .json(&serde_json::json!({
            "session_id": guest_session,
            "params": {
                "view_id": "safe_customer_view_public",
                "fields": ["status"],
                "filter_spec": {"customer_id": "cust_public_1"}
            }
        }))
        .send()
        .await
        .expect("guest operator call should return a response");

    assert_eq!(denied.status(), StatusCode::FORBIDDEN);
    let denied_body = denied
        .json::<serde_json::Value>()
        .await
        .expect("deny response should be JSON");
    assert_eq!(
        denied_body
            .get("terminal_mode_hint")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "INSUFFICIENT_PERMISSION"
    );

    // Budget exhaustion path: max_operator_calls=1 allows first call and rejects second call.
    let budget_session_response = client
        .post(format!("http://{}/v1/sessions", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .json(&serde_json::json!({
            "budget": {
                "max_operator_calls": 1,
                "max_bytes": 1048576,
                "max_wallclock_ms": 10000,
                "max_recursion_depth": 3
            }
        }))
        .send()
        .await
        .expect("budget session request should succeed");
    assert!(budget_session_response.status().is_success());

    let budget_token = budget_session_response
        .headers()
        .get("x-pecr-session-token")
        .and_then(|v| v.to_str().ok())
        .expect("budget session must return token")
        .to_string();

    let budget_session_body = budget_session_response
        .json::<serde_json::Value>()
        .await
        .expect("budget session body should be JSON");
    let budget_session_id = budget_session_body
        .get("session_id")
        .and_then(|v| v.as_str())
        .expect("budget session_id should exist")
        .to_string();

    let first = client
        .post(format!(
            "http://{}/v1/operators/list_versions",
            gateway_addr
        ))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &budget_token)
        .json(&serde_json::json!({
            "session_id": budget_session_id,
            "params": {"object_id": "public/public_1.txt"}
        }))
        .send()
        .await
        .expect("first list_versions call should succeed");
    assert!(first.status().is_success());

    let second = client
        .post(format!("http://{}/v1/operators/list_versions", gateway_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &budget_token)
        .json(&serde_json::json!({
            "session_id": budget_session_body.get("session_id").and_then(|v| v.as_str()).unwrap_or_default(),
            "params": {"object_id": "public/public_1.txt"}
        }))
        .send()
        .await
        .expect("second list_versions call should return a response");
    assert_eq!(second.status(), StatusCode::TOO_MANY_REQUESTS);
    let second_body = second
        .json::<serde_json::Value>()
        .await
        .expect("second response should be JSON");
    assert_eq!(
        second_body
            .get("terminal_mode_hint")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "INSUFFICIENT_EVIDENCE"
    );

    let _ = gateway_shutdown.send(());
    let _ = opa_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(3), gateway_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), opa_task).await;

    let _ = std::fs::remove_dir_all(&fs_corpus_root);
    drop_test_schema(&schema_pool, &schema_name).await;
    schema_pool.close().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn failure_mode_suite_source_unavailable_and_timeout() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping source unavailable suite; set PECR_TEST_DB_URL to enable");
        return;
    };

    let request_id = format!(
        "req_source_unavailable_{}_{}",
        std::process::id(),
        next_suffix()
    );
    let fs_corpus_root = prepare_temp_fs_corpus();
    let fs_corpus_path = fs_corpus_root.to_string_lossy().to_string();

    let pg_fixtures_sql = std::fs::read_to_string(
        workspace_root()
            .join("db")
            .join("init")
            .join("002_safeview_fixtures.sql"),
    )
    .expect("postgres fixture SQL should be readable");

    let (schema_pool, schema_name, schema_url) = create_test_schema(&db_url).await;
    apply_pg_fixtures(&schema_url, &pg_fixtures_sql).await;

    // OPA unreachable -> source unavailable.
    let unreachable_gateway = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
        ("PECR_OPA_URL".to_string(), "http://127.0.0.1:9".to_string()),
        ("PECR_OPA_TIMEOUT_MS".to_string(), "100".to_string()),
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
    .expect("unreachable gateway config should be valid");

    let (unreachable_addr, unreachable_shutdown, unreachable_task) = spawn_server(
        pecr_gateway::http::router(unreachable_gateway)
            .await
            .expect("unreachable gateway router should init"),
    )
    .await;

    let client = reqwest::Client::new();
    wait_for_healthz(&client, unreachable_addr).await;

    let unavailable_response = client
        .post(format!("http://{}/v1/sessions", unreachable_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .json(&serde_json::json!({
            "budget": {
                "max_operator_calls": 10,
                "max_bytes": 1048576,
                "max_wallclock_ms": 1000,
                "max_recursion_depth": 3
            }
        }))
        .send()
        .await
        .expect("unavailable request should return a response");

    assert!(matches!(
        unavailable_response.status(),
        StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
    ));

    let _ = unreachable_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(3), unreachable_task).await;

    // OPA timeout path -> gateway timeout.
    let slow_opa_app = Router::new()
        .route("/health", get(opa_health))
        .route("/v1/data/pecr/authz/decision", post(opa_decision_slow));
    let (slow_opa_addr, slow_opa_shutdown, slow_opa_task) = spawn_server(slow_opa_app).await;

    let timeout_gateway = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
        (
            "PECR_OPA_URL".to_string(),
            format!("http://{}", slow_opa_addr),
        ),
        ("PECR_OPA_TIMEOUT_MS".to_string(), "25".to_string()),
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
    .expect("timeout gateway config should be valid");

    let (timeout_addr, timeout_shutdown, timeout_task) = spawn_server(
        pecr_gateway::http::router(timeout_gateway)
            .await
            .expect("timeout gateway router should init"),
    )
    .await;

    wait_for_healthz(&client, timeout_addr).await;

    let timeout_response = client
        .post(format!("http://{}/v1/sessions", timeout_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .json(&serde_json::json!({
            "budget": {
                "max_operator_calls": 10,
                "max_bytes": 1048576,
                "max_wallclock_ms": 1000,
                "max_recursion_depth": 3
            }
        }))
        .send()
        .await
        .expect("timeout request should return a response");

    assert_eq!(timeout_response.status(), StatusCode::GATEWAY_TIMEOUT);

    let _ = timeout_shutdown.send(());
    let _ = slow_opa_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(3), timeout_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), slow_opa_task).await;

    // PG statement-timeout path -> source unavailable.
    let pg_timeout_opa_app = Router::new()
        .route("/health", get(opa_health))
        .route("/v1/data/pecr/authz/decision", post(opa_decision));
    let (pg_timeout_opa_addr, pg_timeout_opa_shutdown, pg_timeout_opa_task) =
        spawn_server(pg_timeout_opa_app).await;

    let pg_timeout_gateway = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
        (
            "PECR_OPA_URL".to_string(),
            format!("http://{}", pg_timeout_opa_addr),
        ),
        (
            "PECR_POLICY_BUNDLE_HASH".to_string(),
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".to_string(),
        ),
        (
            "PECR_PG_SAFEVIEW_QUERY_TIMEOUT_MS".to_string(),
            "25".to_string(),
        ),
        ("PECR_FS_CORPUS_PATH".to_string(), fs_corpus_path.clone()),
        (
            "PECR_AS_OF_TIME_DEFAULT".to_string(),
            "1970-01-01T00:00:00Z".to_string(),
        ),
    ]))
    .expect("pg-timeout gateway config should be valid");

    let (pg_timeout_addr, pg_timeout_shutdown, pg_timeout_task) = spawn_server(
        pecr_gateway::http::router(pg_timeout_gateway)
            .await
            .expect("pg-timeout gateway router should init"),
    )
    .await;

    wait_for_healthz(&client, pg_timeout_addr).await;

    let (pg_timeout_session, pg_timeout_token, _, _) =
        gateway_create_session(&client, pg_timeout_addr, "dev", &request_id).await;

    let pg_timeout_response = client
        .post(format!(
            "http://{}/v1/operators/fetch_rows",
            pg_timeout_addr
        ))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .header("x-pecr-session-token", &pg_timeout_token)
        .json(&serde_json::json!({
            "session_id": pg_timeout_session,
            "params": {
                "view_id": "safe_customer_view_public_slow",
                "fields": ["status"],
                "filter_spec": {"customer_id": "cust_public_1"}
            }
        }))
        .send()
        .await
        .expect("pg-timeout fetch_rows request should return a response");

    assert_eq!(
        pg_timeout_response.status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
    let pg_timeout_body = pg_timeout_response
        .json::<serde_json::Value>()
        .await
        .expect("pg-timeout response should be JSON");
    assert_eq!(
        pg_timeout_body
            .get("code")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "ERR_SOURCE_UNAVAILABLE"
    );
    assert_eq!(
        pg_timeout_body
            .get("terminal_mode_hint")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "SOURCE_UNAVAILABLE"
    );
    assert_eq!(
        pg_timeout_body.get("retryable").and_then(|v| v.as_bool()),
        Some(true)
    );

    let _ = pg_timeout_shutdown.send(());
    let _ = pg_timeout_opa_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(3), pg_timeout_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), pg_timeout_opa_task).await;

    // DB availability failure path -> source unavailable.
    let db_outage_opa_app = Router::new()
        .route("/health", get(opa_health))
        .route("/v1/data/pecr/authz/decision", post(opa_decision));
    let (db_outage_opa_addr, db_outage_opa_shutdown, db_outage_opa_task) =
        spawn_server(db_outage_opa_app).await;

    let db_outage_gateway = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
        (
            "PECR_OPA_URL".to_string(),
            format!("http://{}", db_outage_opa_addr),
        ),
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
    .expect("db-outage gateway config should be valid");

    let (db_outage_addr, db_outage_shutdown, db_outage_task) = spawn_server(
        pecr_gateway::http::router(db_outage_gateway)
            .await
            .expect("db-outage gateway router should init"),
    )
    .await;

    wait_for_healthz(&client, db_outage_addr).await;

    // Simulate source outage after startup by dropping the scoped schema that backs ledger + safe-view tables.
    drop_test_schema(&schema_pool, &schema_name).await;

    let db_outage_response = client
        .post(format!("http://{}/v1/sessions", db_outage_addr))
        .header("x-pecr-principal-id", "dev")
        .header("x-pecr-request-id", &request_id)
        .json(&serde_json::json!({
            "budget": {
                "max_operator_calls": 10,
                "max_bytes": 1048576,
                "max_wallclock_ms": 1000,
                "max_recursion_depth": 3
            }
        }))
        .send()
        .await
        .expect("db outage request should return a response");

    assert_eq!(db_outage_response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let db_outage_body = db_outage_response
        .json::<serde_json::Value>()
        .await
        .expect("db outage response should be JSON");
    let db_outage_code = db_outage_body
        .get("code")
        .and_then(|v| v.as_str())
        .unwrap_or_default();
    assert!(
        matches!(
            db_outage_code,
            "ERR_SOURCE_UNAVAILABLE" | "ERR_LEDGER_UNAVAILABLE" | "ERR_DB_UNAVAILABLE"
        ),
        "unexpected db outage error code: {}",
        db_outage_code
    );
    assert_eq!(
        db_outage_body
            .get("terminal_mode_hint")
            .and_then(|v| v.as_str())
            .unwrap_or_default(),
        "SOURCE_UNAVAILABLE"
    );
    assert_eq!(
        db_outage_body.get("retryable").and_then(|v| v.as_bool()),
        Some(true)
    );

    let _ = db_outage_shutdown.send(());
    let _ = db_outage_opa_shutdown.send(());
    let _ = tokio::time::timeout(Duration::from_secs(3), db_outage_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(3), db_outage_opa_task).await;

    let _ = std::fs::remove_dir_all(&fs_corpus_root);
    drop_test_schema(&schema_pool, &schema_name).await;
    schema_pool.close().await;
}

struct RealStack {
    schema_pool: PgPool,
    schema_name: String,
    fs_corpus_root: PathBuf,
    replay_store_dir: PathBuf,
    gateway_addr: SocketAddr,
    gateway_shutdown: Option<oneshot::Sender<()>>,
    gateway_task: Option<tokio::task::JoinHandle<()>>,
    controller_addr: SocketAddr,
    controller_shutdown: Option<oneshot::Sender<()>>,
    controller_task: Option<tokio::task::JoinHandle<()>>,
    opa_shutdown: Option<oneshot::Sender<()>>,
    opa_task: Option<tokio::task::JoinHandle<()>>,
}

async fn run_useful_real_stack_named_queries(
    client: &reqwest::Client,
    stack: &RealStack,
    request_prefix: &str,
    log_buf: &Arc<Mutex<Vec<u8>>>,
    log_start: usize,
) -> Vec<String> {
    struct UsefulScenario<'a> {
        scenario_id: &'a str,
        query: &'a str,
        expected_fragments: &'a [&'a str],
        expected_response_kind: Option<&'a str>,
        expected_note_substrings: &'a [&'a str],
    }

    let scenarios = [
        UsefulScenario {
            scenario_id: "customer-status",
            query: "What is the customer status and plan tier?",
            expected_fragments: &["status=active", "plan_tier=free"],
            expected_response_kind: None,
            expected_note_substrings: &[],
        },
        UsefulScenario {
            scenario_id: "support-policy-source",
            query: "Show the source text and evidence for the support policy",
            expected_fragments: &["Support policy", "approved safe-view records"],
            expected_response_kind: None,
            expected_note_substrings: &[],
        },
        UsefulScenario {
            scenario_id: "annual-refund-source",
            query: "Show the source text for annual refund terms",
            expected_fragments: &["Annual refund terms", "30 days"],
            expected_response_kind: None,
            expected_note_substrings: &[],
        },
        UsefulScenario {
            scenario_id: "billing-terms-policy",
            query: "Show evidence for the billing terms policy",
            expected_fragments: &["Billing terms policy", "15 days"],
            expected_response_kind: None,
            expected_note_substrings: &[],
        },
        UsefulScenario {
            scenario_id: "customer-counts-by-plan",
            query: "Compare customer counts by plan tier",
            expected_fragments: &[
                "plan_tier=enterprise",
                "plan_tier=free",
                "count(customer_id)=1",
            ],
            expected_response_kind: None,
            expected_note_substrings: &[],
        },
        UsefulScenario {
            scenario_id: "monthly-customer-trend",
            query: "Show monthly customer trend over time",
            expected_fragments: &["time_bucket=2026-01", "time_bucket=2026-02"],
            expected_response_kind: None,
            expected_note_substrings: &[],
        },
        UsefulScenario {
            scenario_id: "compare-and-billing-source",
            query: "Compare active customer counts by plan tier and show the source text for the billing terms policy",
            expected_fragments: &[
                "plan_tier=free",
                "count(customer_id)=1",
                "Billing terms policy",
                "15 days",
            ],
            expected_response_kind: None,
            expected_note_substrings: &[],
        },
    ];

    let mut trace_ids = Vec::new();
    for scenario in scenarios {
        let scenario_id = scenario.scenario_id;
        let request_id = format!("{request_prefix}_{scenario_id}");
        let body = controller_run_query_ok_with_logs(
            client,
            stack.controller_addr,
            "dev",
            &request_id,
            scenario.query,
            log_buf,
            log_start,
        )
        .await;
        assert_eq!(
            body.get("terminal_mode").and_then(|value| value.as_str()),
            Some("SUPPORTED"),
            "scenario {} should be supported: {}; logs: {}",
            scenario_id,
            body,
            logs_since(log_buf, log_start)
        );

        if let Some(expected_response_kind) = scenario.expected_response_kind {
            assert_eq!(
                body.get("response_kind").and_then(|value| value.as_str()),
                Some(expected_response_kind),
                "scenario {} should surface response_kind {}: {}",
                scenario_id,
                expected_response_kind,
                body
            );
        }

        let rendered = serde_json::to_string(&body).expect("response JSON should serialize");
        for fragment in scenario.expected_fragments {
            assert!(
                rendered.contains(fragment),
                "scenario {} missing fragment {:?}: {}",
                scenario_id,
                fragment,
                body
            );
        }
        let notes = body
            .pointer("/claim_map/notes")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        for substring in scenario.expected_note_substrings {
            assert!(
                notes.contains(substring),
                "scenario {} missing note fragment {:?}: {}",
                scenario_id,
                substring,
                body
            );
        }

        let claims = body
            .pointer("/claim_map/claims")
            .and_then(|value| value.as_array())
            .expect("claim_map.claims should exist");
        assert!(
            claims.iter().any(|claim| {
                claim.get("status").and_then(|value| value.as_str()) == Some("SUPPORTED")
                    && claim
                        .get("evidence_unit_ids")
                        .and_then(|value| value.as_array())
                        .is_some_and(|ids| !ids.is_empty())
                    && claim
                        .get("evidence_snippets")
                        .and_then(|value| value.as_array())
                        .is_some_and(|snippets| !snippets.is_empty())
            }),
            "scenario {} should include supported claims with evidence snippets: {}",
            scenario_id,
            body
        );

        trace_ids.push(
            body.get("trace_id")
                .and_then(|value| value.as_str())
                .expect("trace_id should exist")
                .to_string(),
        );
    }

    let replay_list_body =
        wait_for_replay_list_contains_traces(client, stack.controller_addr, "dev", &trace_ids)
            .await;
    let replays = replay_list_body
        .get("replays")
        .and_then(|value| value.as_array())
        .expect("replay list should contain replays");
    for trace_id in &trace_ids {
        assert!(
            replays.iter().any(
                |replay| replay.get("trace_id").and_then(|value| value.as_str())
                    == Some(trace_id.as_str())
            ),
            "replay list should contain trace_id {}: {}",
            trace_id,
            replay_list_body
        );
    }

    trace_ids
}

async fn submit_useful_real_stack_evaluation(
    client: &reqwest::Client,
    controller_addr: SocketAddr,
    evaluation_name: &str,
    engine_mode: Option<&str>,
) -> serde_json::Value {
    let mut request_body = serde_json::json!({
        "evaluation_name": evaluation_name,
        "min_quality_score": 80.0,
        "max_source_unavailable_rate": 0.0
    });
    if let Some(engine_mode) = engine_mode {
        request_body
            .as_object_mut()
            .expect("evaluation body should be an object")
            .insert("engine_mode".to_string(), serde_json::json!(engine_mode));
    }

    let evaluation = client
        .post(format!("http://{}/v1/evaluations", controller_addr))
        .header("x-pecr-principal-id", "dev")
        .json(&request_body)
        .send()
        .await
        .expect("evaluation request should succeed");
    assert!(evaluation.status().is_success());
    evaluation
        .json::<serde_json::Value>()
        .await
        .expect("evaluation response should be JSON")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn useful_real_stack_suite_exercises_named_queries() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping useful real-stack suite; set PECR_TEST_DB_URL to enable");
        return;
    };

    let log_buf = init_test_tracing();
    let log_start = log_snapshot(&log_buf);
    let request_prefix = format!("req_useful_suite_{}_{}", std::process::id(), next_suffix());
    let stack = spawn_real_stack(&db_url, None).await;
    let client = reqwest::Client::new();

    run_useful_real_stack_named_queries(&client, &stack, &request_prefix, &log_buf, log_start)
        .await;
    let evaluation_body = submit_useful_real_stack_evaluation(
        &client,
        stack.controller_addr,
        "useful-real-stack-suite",
        None,
    )
    .await;
    assert_eq!(
        evaluation_body
            .get("overall_pass")
            .and_then(|value| value.as_bool()),
        Some(true),
        "useful real-stack evaluation should pass: {}",
        evaluation_body
    );
    assert!(
        evaluation_body
            .pointer("/scorecards/0/average_citation_quality")
            .and_then(|value| value.as_f64())
            .is_some_and(|value| value >= 0.9),
        "useful real-stack evaluation should report strong citation quality: {}",
        evaluation_body
    );

    shutdown_real_stack(stack).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn useful_rlm_real_stack_matches_or_beats_baseline_named_queries() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping useful rlm comparison suite; set PECR_TEST_DB_URL to enable");
        return;
    };

    let log_buf = init_test_tracing();
    let log_start = log_snapshot(&log_buf);
    let client = reqwest::Client::new();
    let shared_replay_store_dir = std::env::temp_dir().join(format!(
        "pecr_useful_compare_replays_{}_{}",
        std::process::id(),
        next_suffix()
    ));

    let mut baseline_stack = spawn_real_stack(&db_url, Some(shared_replay_store_dir.clone())).await;
    run_useful_real_stack_named_queries(
        &client,
        &baseline_stack,
        &format!(
            "req_useful_baseline_compare_{}_{}",
            std::process::id(),
            next_suffix()
        ),
        &log_buf,
        log_start,
    )
    .await;
    baseline_stack.replay_store_dir =
        std::env::temp_dir().join(format!("pecr_useful_compare_preserve_{}", next_suffix()));
    shutdown_real_stack(baseline_stack).await;

    let rlm_stack = spawn_real_stack_with_controller_overrides(
        &db_url,
        Some(shared_replay_store_dir.clone()),
        HashMap::from([("PECR_CONTROLLER_ENGINE".to_string(), "rlm".to_string())]),
    )
    .await;
    run_useful_real_stack_named_queries(
        &client,
        &rlm_stack,
        &format!(
            "req_useful_rlm_compare_{}_{}",
            std::process::id(),
            next_suffix()
        ),
        &log_buf,
        log_start,
    )
    .await;

    let evaluation_body = submit_useful_real_stack_evaluation(
        &client,
        rlm_stack.controller_addr,
        "useful-real-stack-engine-comparison",
        None,
    )
    .await;
    let scorecards = evaluation_body
        .get("scorecards")
        .and_then(|value| value.as_array())
        .expect("evaluation should include scorecards");
    let baseline_scorecard = scorecards
        .iter()
        .find(|scorecard| {
            scorecard
                .get("engine_mode")
                .and_then(|value| value.as_str())
                == Some("baseline")
        })
        .expect("baseline scorecard should exist");
    let rlm_scorecard = scorecards
        .iter()
        .find(|scorecard| {
            scorecard
                .get("engine_mode")
                .and_then(|value| value.as_str())
                == Some("rlm")
        })
        .expect("rlm scorecard should exist");

    let baseline_quality = baseline_scorecard
        .get("average_quality_score")
        .and_then(|value| value.as_f64())
        .expect("baseline average_quality_score should exist");
    let rlm_quality = rlm_scorecard
        .get("average_quality_score")
        .and_then(|value| value.as_f64())
        .expect("rlm average_quality_score should exist");
    // Quality scoring includes small response-shape penalties, so keep a narrow epsilon here
    // and rely on supported-rate plus citation-quality parity to catch real regressions.
    assert!(
        rlm_quality + 0.25 >= baseline_quality,
        "rlm should stay within the quality-score epsilon on the named usefulness benchmark: {}",
        evaluation_body
    );

    let baseline_supported_rate = baseline_scorecard
        .get("supported_rate")
        .and_then(|value| value.as_f64())
        .expect("baseline supported_rate should exist");
    let rlm_supported_rate = rlm_scorecard
        .get("supported_rate")
        .and_then(|value| value.as_f64())
        .expect("rlm supported_rate should exist");
    assert!(
        rlm_supported_rate + 0.0001 >= baseline_supported_rate,
        "rlm should preserve supported-answer rate on the named usefulness benchmark: {}",
        evaluation_body
    );

    let comparison = evaluation_body
        .get("engine_comparisons")
        .and_then(|value| value.as_array())
        .and_then(|comparisons| {
            comparisons.iter().find(|comparison| {
                let primary = comparison
                    .get("primary_engine_mode")
                    .and_then(|value| value.as_str());
                let secondary = comparison
                    .get("secondary_engine_mode")
                    .and_then(|value| value.as_str());
                matches!(
                    (primary, secondary),
                    (Some("baseline"), Some("rlm")) | (Some("rlm"), Some("baseline"))
                )
            })
        })
        .expect("evaluation should include a baseline vs rlm comparison");

    let primary_engine_mode = comparison
        .get("primary_engine_mode")
        .and_then(|value| value.as_str())
        .expect("primary_engine_mode should exist");
    let quality_delta = comparison
        .get("average_quality_score_delta")
        .and_then(|value| value.as_f64())
        .expect("average_quality_score_delta should exist");
    let rlm_minus_baseline_quality = if primary_engine_mode == "rlm" {
        quality_delta
    } else {
        -quality_delta
    };
    assert!(
        rlm_minus_baseline_quality >= -0.25,
        "rlm should stay within the quality-score epsilon on average quality score: {}",
        evaluation_body
    );
    assert_eq!(
        comparison
            .get("paired_query_count")
            .and_then(|value| value.as_u64()),
        Some(7),
        "all named usefulness scenarios should be paired across baseline and rlm: {}",
        evaluation_body
    );

    shutdown_real_stack(rlm_stack).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn useful_beam_planner_real_stack_falls_back_cleanly_when_planner_is_unavailable() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping beam planner real-stack suite; set PECR_TEST_DB_URL to enable");
        return;
    };

    let stack = spawn_real_stack_with_controller_overrides(
        &db_url,
        None,
        HashMap::from([
            (
                "PECR_CONTROLLER_ENGINE".to_string(),
                "beam_planner".to_string(),
            ),
            (
                "PECR_CONTROLLER_PLANNER_CLIENT".to_string(),
                "beam".to_string(),
            ),
            (
                "PECR_CONTROLLER_PLANNER_URL".to_string(),
                "http://127.0.0.1:9/plan".to_string(),
            ),
        ]),
    )
    .await;
    let client = reqwest::Client::new();

    let body = controller_run_query_ok(
        &client,
        stack.controller_addr,
        "dev",
        &format!("req_beam_planner_unavailable_{}", next_suffix()),
        "What is the customer status and plan tier?",
    )
    .await;
    assert_eq!(
        body.get("terminal_mode").and_then(|value| value.as_str()),
        Some("SUPPORTED"),
        "beam planner unavailability should still produce a supported answer: {}",
        body
    );
    let trace_id = body
        .get("trace_id")
        .and_then(|value| value.as_str())
        .expect("trace_id should exist")
        .to_string();
    let _replay_list_body =
        wait_for_replay_list_contains_traces(&client, stack.controller_addr, "dev", &[trace_id])
            .await;

    let evaluation = client
        .post(format!("http://{}/v1/evaluations", stack.controller_addr))
        .header("x-pecr-principal-id", "dev")
        .json(&serde_json::json!({
            "evaluation_name": "beam-planner-fallback-suite",
            "engine_mode": "beam_planner",
            "min_quality_score": 80.0,
            "max_source_unavailable_rate": 0.0
        }))
        .send()
        .await
        .expect("evaluation request should succeed");
    assert!(evaluation.status().is_success());
    let evaluation_body = evaluation
        .json::<serde_json::Value>()
        .await
        .expect("evaluation response should be JSON");
    assert_eq!(
        evaluation_body
            .pointer("/scorecards/0/engine_mode")
            .and_then(|value| value.as_str()),
        Some("beam_planner"),
        "evaluation should expose beam_planner scorecards: {}",
        evaluation_body
    );

    let replay_path = wait_for_replay_bundle_path(&stack.replay_store_dir).await;
    let replay_bundle = serde_json::from_str::<serde_json::Value>(
        &std::fs::read_to_string(&replay_path).expect("replay bundle should be readable"),
    )
    .expect("replay bundle should parse");

    assert_eq!(
        replay_bundle
            .pointer("/metadata/engine_mode")
            .and_then(|value| value.as_str()),
        Some("beam_planner"),
        "replay metadata should preserve beam_planner engine mode: {}",
        replay_bundle
    );
    assert!(
        replay_bundle
            .pointer("/planner_traces")
            .and_then(|value| value.as_array())
            .is_some_and(|traces| traces.iter().any(|trace| {
                trace
                    .pointer("/decision_summary/planner_source")
                    .and_then(|value| value.as_str())
                    == Some("beam_planner")
                    && trace
                        .pointer("/decision_summary/selected_for_execution")
                        .and_then(|value| value.as_bool())
                        == Some(false)
                    && trace
                        .pointer("/decision_summary/stop_reason")
                        .and_then(|value| value.as_str())
                        .is_some_and(|value| value.starts_with("ERR_PLANNER_CLIENT_"))
            })),
        "replay traces should show the beam planner fallback reason: {}",
        replay_bundle
    );
    assert!(
        replay_bundle
            .pointer("/planner_traces")
            .and_then(|value| value.as_array())
            .is_some_and(|traces| traces.iter().any(|trace| {
                trace
                    .pointer("/decision_summary/planner_source")
                    .and_then(|value| value.as_str())
                    == Some("rust_owned")
                    && trace
                        .pointer("/decision_summary/selected_for_execution")
                        .and_then(|value| value.as_bool())
                        == Some(true)
            })),
        "replay traces should show the rust-owned fallback execution path: {}",
        replay_bundle
    );

    shutdown_real_stack(stack).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn useful_fault_injection_suite_degrades_cleanly() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping useful fault suite; set PECR_TEST_DB_URL to enable");
        return;
    };

    let client = reqwest::Client::new();
    let useful_query = "What is the customer status and plan tier?";

    let mut opa_stack = spawn_real_stack(&db_url, None).await;
    let baseline = controller_run_query_ok(
        &client,
        opa_stack.controller_addr,
        "dev",
        &format!("req_fault_opa_baseline_{}", next_suffix()),
        useful_query,
    )
    .await;
    assert_eq!(
        baseline
            .get("terminal_mode")
            .and_then(|value| value.as_str()),
        Some("SUPPORTED")
    );

    stop_stack_opa(&mut opa_stack).await;
    wait_for_http_status(
        &client,
        format!("http://{}/readyz", opa_stack.gateway_addr).as_str(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;
    wait_for_http_status(
        &client,
        format!("http://{}/readyz", opa_stack.controller_addr).as_str(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;

    let opa_fault = controller_run_query(
        &client,
        opa_stack.controller_addr,
        "dev",
        &format!("req_fault_opa_{}", next_suffix()),
        useful_query,
    )
    .await;
    assert!(matches!(
        opa_fault.status(),
        StatusCode::SERVICE_UNAVAILABLE | StatusCode::GATEWAY_TIMEOUT
    ));
    let opa_fault_body = opa_fault
        .json::<serde_json::Value>()
        .await
        .expect("opa fault response should be JSON");
    assert_eq!(
        opa_fault_body
            .get("terminal_mode_hint")
            .and_then(|value| value.as_str()),
        Some("SOURCE_UNAVAILABLE"),
        "opa fault should degrade to source unavailable: {}",
        opa_fault_body
    );
    shutdown_real_stack(opa_stack).await;

    let source_stack = spawn_real_stack(&db_url, None).await;
    drop_test_schema(&source_stack.schema_pool, &source_stack.schema_name).await;

    let source_fault = controller_run_query(
        &client,
        source_stack.controller_addr,
        "dev",
        &format!("req_fault_source_{}", next_suffix()),
        useful_query,
    )
    .await;
    assert_eq!(source_fault.status(), StatusCode::SERVICE_UNAVAILABLE);
    let source_fault_body = source_fault
        .json::<serde_json::Value>()
        .await
        .expect("source fault response should be JSON");
    assert_eq!(
        source_fault_body
            .get("terminal_mode_hint")
            .and_then(|value| value.as_str()),
        Some("SOURCE_UNAVAILABLE"),
        "source fault should degrade to source unavailable: {}",
        source_fault_body
    );
    shutdown_real_stack(source_stack).await;

    let replay_store_dir = std::env::temp_dir().join(format!(
        "pecr_replay_fault_store_{}_{}",
        std::process::id(),
        next_suffix()
    ));
    let replay_stack = spawn_real_stack(&db_url, Some(replay_store_dir)).await;
    break_replay_store(&replay_stack.replay_store_dir);

    wait_for_http_status(
        &client,
        format!("http://{}/readyz", replay_stack.controller_addr).as_str(),
        StatusCode::SERVICE_UNAVAILABLE,
    )
    .await;

    let replay_fault = controller_run_query_ok(
        &client,
        replay_stack.controller_addr,
        "dev",
        &format!("req_fault_replay_{}", next_suffix()),
        useful_query,
    )
    .await;
    assert_eq!(
        replay_fault
            .get("terminal_mode")
            .and_then(|value| value.as_str()),
        Some("SUPPORTED"),
        "replay-store fault should not corrupt the answer itself: {}",
        replay_fault
    );

    let replay_list = client
        .get(format!(
            "http://{}/v1/replays",
            replay_stack.controller_addr
        ))
        .header("x-pecr-principal-id", "dev")
        .send()
        .await
        .expect("replay list request should return a response");
    assert_eq!(replay_list.status(), StatusCode::SERVICE_UNAVAILABLE);
    let replay_list_body = replay_list
        .json::<serde_json::Value>()
        .await
        .expect("replay fault response should be JSON");
    assert_eq!(
        replay_list_body
            .get("code")
            .and_then(|value| value.as_str()),
        Some("ERR_REPLAY_STORE"),
        "replay store fault should surface via replay APIs: {}",
        replay_list_body
    );

    shutdown_real_stack(replay_stack).await;
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

async fn gateway_create_session(
    client: &reqwest::Client,
    gateway_addr: SocketAddr,
    principal_id: &str,
    request_id: &str,
) -> (String, String, String, String) {
    gateway_create_session_at(client, gateway_addr, principal_id, request_id, None).await
}

async fn gateway_create_session_at(
    client: &reqwest::Client,
    gateway_addr: SocketAddr,
    principal_id: &str,
    request_id: &str,
    as_of_time: Option<&str>,
) -> (String, String, String, String) {
    let mut body = serde_json::json!({
        "budget": {
            "max_operator_calls": 10,
            "max_bytes": 1048576,
            "max_wallclock_ms": 1000,
            "max_recursion_depth": 3
        }
    });
    if let Some(as_of_time) = as_of_time {
        body.as_object_mut()
            .expect("session body must be object")
            .insert(
                "as_of_time".to_string(),
                serde_json::Value::String(as_of_time.to_string()),
            );
    }

    let response = {
        let mut attempt: u32 = 0;
        loop {
            let response = client
                .post(format!("http://{}/v1/sessions", gateway_addr))
                .header("x-pecr-principal-id", principal_id)
                .header("x-pecr-request-id", request_id)
                .json(&body)
                .send()
                .await
                .expect("gateway session request should succeed");

            if response.status().is_success() {
                break response;
            }

            // Gateway /healthz is intentionally shallow; the first authz/ledger call can race
            // startup in CI. Retry a few times on transient 503s to deflake the suites.
            let status = response.status();
            let body_text = response.text().await.unwrap_or_default();
            if status == StatusCode::SERVICE_UNAVAILABLE && attempt < 10 {
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(50 * attempt as u64)).await;
                continue;
            }

            panic!(
                "expected gateway session 2xx for principal {}, got {} (body={})",
                principal_id, status, body_text
            );
        }
    };

    let session_token = response
        .headers()
        .get("x-pecr-session-token")
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .expect("gateway must return x-pecr-session-token header")
        .to_string();

    let body = response
        .json::<serde_json::Value>()
        .await
        .expect("gateway session response should be JSON");

    let session_id = body
        .get("session_id")
        .and_then(|v| v.as_str())
        .expect("session_id should exist")
        .to_string();

    let trace_id = body
        .get("trace_id")
        .and_then(|v| v.as_str())
        .expect("trace_id should exist")
        .to_string();

    let policy_snapshot_id = body
        .get("policy_snapshot_id")
        .and_then(|v| v.as_str())
        .expect("policy_snapshot_id should exist")
        .to_string();

    (session_id, session_token, trace_id, policy_snapshot_id)
}

async fn spawn_real_stack(base_db_url: &str, replay_store_dir: Option<PathBuf>) -> RealStack {
    spawn_real_stack_with_controller_overrides(base_db_url, replay_store_dir, HashMap::new()).await
}

async fn spawn_real_stack_with_controller_overrides(
    base_db_url: &str,
    replay_store_dir: Option<PathBuf>,
    controller_overrides: HashMap<String, String>,
) -> RealStack {
    const E2E_LEDGER_WRITE_TIMEOUT_MS: &str = "20000";

    let fs_corpus_root = prepare_temp_fs_corpus();
    let fs_corpus_path = fs_corpus_root.to_string_lossy().to_string();

    let pg_fixtures_sql = std::fs::read_to_string(
        workspace_root()
            .join("db")
            .join("init")
            .join("002_safeview_fixtures.sql"),
    )
    .expect("postgres fixture SQL should be readable");

    let (schema_pool, schema_name, schema_url) = create_test_schema(base_db_url).await;
    apply_pg_fixtures(&schema_url, &pg_fixtures_sql).await;

    let replay_store_dir = replay_store_dir.unwrap_or_else(|| {
        std::env::temp_dir().join(format!(
            "pecr_e2e_replays_{}_{}",
            std::process::id(),
            next_suffix()
        ))
    });

    let opa_app = Router::new()
        .route("/health", get(opa_health))
        .route("/v1/data/pecr/authz/decision", post(opa_decision));
    let (opa_addr, opa_shutdown, opa_task) = spawn_server(opa_app).await;

    let gateway_config = pecr_gateway::config::GatewayConfig::from_kv(&HashMap::from([
        ("PECR_BIND_ADDR".to_string(), "127.0.0.1:0".to_string()),
        ("PECR_DB_URL".to_string(), schema_url.clone()),
        ("PECR_OPA_URL".to_string(), format!("http://{}", opa_addr)),
        (
            "PECR_LEDGER_WRITE_TIMEOUT_MS".to_string(),
            E2E_LEDGER_WRITE_TIMEOUT_MS.to_string(),
        ),
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

    let mut controller_env = HashMap::from([
        (
            "PECR_CONTROLLER_BIND_ADDR".to_string(),
            "127.0.0.1:0".to_string(),
        ),
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
        (
            "PECR_REPLAY_STORE_DIR".to_string(),
            replay_store_dir.to_string_lossy().to_string(),
        ),
    ]);
    controller_env.extend(controller_overrides);
    if controller_env
        .get("PECR_CONTROLLER_ENGINE")
        .is_some_and(|value| value == "rlm")
    {
        controller_env
            .entry("PECR_RLM_SANDBOX_ACK".to_string())
            .or_insert_with(|| "1".to_string());
        controller_env
            .entry("PECR_RLM_SCRIPT_PATH".to_string())
            .or_insert_with(|| {
                workspace_root()
                    .join("scripts")
                    .join("rlm")
                    .join("pecr_rlm_bridge.py")
                    .to_string_lossy()
                    .to_string()
            });
    }
    let controller_config = pecr_controller::config::ControllerConfig::from_kv(&controller_env)
        .expect("controller config should be valid");

    let (controller_addr, controller_shutdown, controller_task) = spawn_server(
        pecr_controller::http::router(controller_config)
            .await
            .expect("controller router should init"),
    )
    .await;

    let client = reqwest::Client::new();
    wait_for_http_status(
        &client,
        format!("http://{}/readyz", gateway_addr).as_str(),
        StatusCode::OK,
    )
    .await;
    wait_for_http_status(
        &client,
        format!("http://{}/readyz", controller_addr).as_str(),
        StatusCode::OK,
    )
    .await;

    RealStack {
        schema_pool,
        schema_name,
        fs_corpus_root,
        replay_store_dir,
        gateway_addr,
        gateway_shutdown: Some(gateway_shutdown),
        gateway_task: Some(gateway_task),
        controller_addr,
        controller_shutdown: Some(controller_shutdown),
        controller_task: Some(controller_task),
        opa_shutdown: Some(opa_shutdown),
        opa_task: Some(opa_task),
    }
}

async fn shutdown_real_stack(mut stack: RealStack) {
    if let Some(shutdown) = stack.controller_shutdown.take() {
        let _ = shutdown.send(());
    }
    if let Some(shutdown) = stack.gateway_shutdown.take() {
        let _ = shutdown.send(());
    }
    if let Some(shutdown) = stack.opa_shutdown.take() {
        let _ = shutdown.send(());
    }

    if let Some(task) = stack.controller_task.take() {
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }
    if let Some(task) = stack.gateway_task.take() {
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }
    if let Some(task) = stack.opa_task.take() {
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
    }

    remove_test_path(&stack.fs_corpus_root);
    remove_test_path(&stack.replay_store_dir);
    drop_test_schema(&stack.schema_pool, &stack.schema_name).await;
    stack.schema_pool.close().await;
}

async fn stop_stack_opa(stack: &mut RealStack) {
    if let Some(shutdown) = stack.opa_shutdown.take() {
        let _ = shutdown.send(());
    }
    if let Some(task) = stack.opa_task.take() {
        let _ = tokio::time::timeout(Duration::from_secs(3), task).await;
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

async fn wait_for_http_status(client: &reqwest::Client, url: &str, expected: StatusCode) {
    for _ in 0..50 {
        if let Ok(response) = client.get(url).send().await
            && response.status() == expected
        {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!("server did not reach status {} at {}", expected, url);
}

async fn wait_for_replay_list_contains_traces(
    client: &reqwest::Client,
    controller_addr: SocketAddr,
    principal_id: &str,
    trace_ids: &[String],
) -> serde_json::Value {
    let url = format!("http://{}/v1/replays", controller_addr);

    for _ in 0..50 {
        let response = client
            .get(&url)
            .header("x-pecr-principal-id", principal_id)
            .send()
            .await;
        if let Ok(response) = response
            && response.status().is_success()
        {
            let body = response
                .json::<serde_json::Value>()
                .await
                .expect("replay list response should be JSON");
            let replays = body
                .get("replays")
                .and_then(|value| value.as_array())
                .expect("replay list should include replays array");
            if trace_ids.iter().all(|trace_id| {
                replays.iter().any(|replay| {
                    replay.get("trace_id").and_then(|value| value.as_str()) == Some(trace_id)
                })
            }) {
                return body;
            }
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!(
        "replay list did not contain trace ids {:?} at {}",
        trace_ids, url
    );
}

async fn wait_for_replay_bundle_path(replay_store_dir: &Path) -> PathBuf {
    let replay_dir = replay_store_dir.join("replays");

    for _ in 0..50 {
        if let Ok(entries) = std::fs::read_dir(&replay_dir)
            && let Some(path) = entries
                .filter_map(Result::ok)
                .map(|entry| entry.path())
                .find(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        {
            return path;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }

    panic!(
        "replay bundle was not persisted under {}",
        replay_dir.display()
    );
}

async fn controller_run_query(
    client: &reqwest::Client,
    controller_addr: SocketAddr,
    principal_id: &str,
    request_id: &str,
    query: &str,
) -> reqwest::Response {
    client
        .post(format!("http://{}/v1/run", controller_addr))
        .header("x-pecr-principal-id", principal_id)
        .header("x-pecr-request-id", request_id)
        .json(&serde_json::json!({ "query": query }))
        .send()
        .await
        .expect("controller run request should return a response")
}

async fn controller_run_query_ok(
    client: &reqwest::Client,
    controller_addr: SocketAddr,
    principal_id: &str,
    request_id: &str,
    query: &str,
) -> serde_json::Value {
    let response =
        controller_run_query(client, controller_addr, principal_id, request_id, query).await;
    let status = response.status();
    let body = response
        .json::<serde_json::Value>()
        .await
        .expect("controller run response should be JSON");
    assert!(
        status.is_success(),
        "expected /v1/run success for query {:?}, got {} with body {}",
        query,
        status,
        body
    );
    body
}

async fn controller_run_query_ok_with_logs(
    client: &reqwest::Client,
    controller_addr: SocketAddr,
    principal_id: &str,
    request_id: &str,
    query: &str,
    log_buf: &Arc<Mutex<Vec<u8>>>,
    log_start: usize,
) -> serde_json::Value {
    let response =
        controller_run_query(client, controller_addr, principal_id, request_id, query).await;
    let status = response.status();
    let body = response
        .json::<serde_json::Value>()
        .await
        .expect("controller run response should be JSON");
    if !status.is_success() {
        let logs = logs_since(log_buf, log_start);
        panic!(
            "expected /v1/run success for principal {:?} query {:?}, got {} with body {}\nlogs:\n{}",
            principal_id, query, status, body, logs
        );
    }
    body
}

async fn opa_health() -> &'static str {
    "ok"
}

fn break_replay_store(root: &Path) {
    remove_test_path(root);
    if let Some(parent) = root.parent() {
        std::fs::create_dir_all(parent).expect("replay store parent should exist");
    }
    std::fs::write(root, b"blocked").expect("replay store fault file should be writable");
}

fn remove_test_path(path: &Path) {
    if path.is_dir() {
        let _ = std::fs::remove_dir_all(path);
    } else if path.exists() {
        let _ = std::fs::remove_file(path);
    }
}

fn prepare_temp_fs_corpus() -> PathBuf {
    let suffix = next_suffix();

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
        "health" => true,
        "create_session" | "finalize" => {
            matches!(principal_id, "dev" | "support" | "guest" | "redacted")
        }
        "operator_call" => match principal_id {
            "dev" => true,
            "support" => {
                let op_name = input.get("op_name").and_then(|v| v.as_str()).unwrap_or("");
                let object_id = input
                    .get("object_id")
                    .and_then(|v| v.as_str())
                    .unwrap_or("");
                let view_id = input.get("view_id").and_then(|v| v.as_str()).unwrap_or("");

                match op_name {
                    "search" => true,
                    "list_versions" | "fetch_span" | "diff" => {
                        object_id.starts_with("public/") || object_id.starts_with("injection/")
                    }
                    "fetch_rows" | "aggregate" => matches!(
                        view_id,
                        "safe_customer_view_public" | "safe_customer_view_support"
                    ),
                    _ => false,
                }
            }
            "redacted" => true,
            _ => false,
        },
        _ => false,
    };

    let cacheable = matches!(action, "operator_call");

    let redaction = if allow && action == "operator_call" && principal_id == "redacted" {
        serde_json::json!({"deny_fields": ["admin_note"]})
    } else {
        serde_json::json!({})
    };

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "result": {
                "allow": allow,
                "cacheable": cacheable,
                "reason": if allow { "test_allow" } else { "test_deny" },
                "redaction": redaction
            }
        })),
    )
}

async fn opa_decision_slow(
    Json(body): Json<serde_json::Value>,
) -> (StatusCode, Json<serde_json::Value>) {
    let input = body.get("input").cloned().unwrap_or(serde_json::json!({}));
    tokio::time::sleep(Duration::from_millis(250)).await;

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "result": {
                "allow": true,
                "cacheable": false,
                "reason": "slow_allow",
                "redaction": {},
                "input_echo_action": input.get("action").cloned().unwrap_or(serde_json::Value::Null)
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
