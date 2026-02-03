fn test_db_url() -> Option<String> {
    std::env::var("PECR_TEST_DB_URL")
        .ok()
        .or_else(|| std::env::var("DATABASE_URL").ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migrations_enforce_append_only_tables() {
    let Some(db_url) = test_db_url() else {
        eprintln!("skipping DB migration test; set PECR_TEST_DB_URL to enable");
        return;
    };

    let schema = format!("pecr_test_{}", ulid::Ulid::new());

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect(&db_url)
        .await
        .expect("DB connect should succeed");

    let create_schema = format!("CREATE SCHEMA {}", schema);
    sqlx::query(&create_schema)
        .execute(&pool)
        .await
        .expect("create schema should succeed");

    let set_search_path = format!("SET search_path TO {}", schema);
    sqlx::query(&set_search_path)
        .execute(&pool)
        .await
        .expect("set search_path should succeed");

    pecr_ledger::migrate(&pool)
        .await
        .expect("migrations should apply");
    pecr_ledger::migrate(&pool)
        .await
        .expect("migrations should be idempotent");

    let policy_snapshot_id = "ps1";
    let session_id = "s1";
    let trace_id = "t1";
    let event_id = "e1";
    let evidence_unit_id = "u1";
    let claim_map_id = "cm1";

    sqlx::query(
        "INSERT INTO pecr_policy_snapshots (policy_snapshot_id, policy_snapshot_hash, principal_id, as_of_time, policy_bundle_hash, input_json) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(policy_snapshot_id)
    .bind("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
    .bind("dev")
    .bind("1970-01-01T00:00:00Z")
    .bind("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")
    .bind(serde_json::json!({}))
    .execute(&pool)
    .await
    .expect("insert policy snapshot should succeed");

    sqlx::query(
        "INSERT INTO pecr_sessions (session_id, trace_id, principal_id, policy_snapshot_id, budget_json) VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(session_id)
    .bind(trace_id)
    .bind("dev")
    .bind(policy_snapshot_id)
    .bind(serde_json::json!({"max_operator_calls":1,"max_bytes":1,"max_wallclock_ms":1,"max_recursion_depth":1}))
    .execute(&pool)
    .await
    .expect("insert session should succeed");

    sqlx::query(
        "INSERT INTO pecr_ledger_events (event_id, trace_id, session_id, event_type, principal_id, policy_snapshot_id, payload_json, payload_hash) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(event_id)
    .bind(trace_id)
    .bind(session_id)
    .bind("test_event")
    .bind("dev")
    .bind(policy_snapshot_id)
    .bind(serde_json::json!({"k":"v"}))
    .bind("cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc")
    .execute(&pool)
    .await
    .expect("insert ledger event should succeed");

    sqlx::query(
        "INSERT INTO pecr_evidence_units (evidence_unit_id, trace_id, session_id, source_system, object_id, version_id, span_or_row_spec_json, content_type, content_hash, as_of_time, retrieved_at, policy_snapshot_id, policy_snapshot_hash, transform_chain_json) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)",
    )
    .bind(evidence_unit_id)
    .bind(trace_id)
    .bind(session_id)
    .bind("fs_corpus")
    .bind("public/public_1.txt")
    .bind("v1")
    .bind(serde_json::json!({"type":"text_span","start_byte":0,"end_byte":1}))
    .bind("text/plain")
    .bind("dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd")
    .bind("1970-01-01T00:00:00Z")
    .bind("1970-01-01T00:00:00Z")
    .bind(policy_snapshot_id)
    .bind("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")
    .bind(serde_json::json!([]))
    .execute(&pool)
    .await
    .expect("insert evidence unit should succeed");

    sqlx::query(
        "INSERT INTO pecr_claim_maps (claim_map_id, trace_id, session_id, terminal_mode, coverage_threshold, coverage_observed, claim_map_json) VALUES ($1,$2,$3,$4,$5,$6,$7)",
    )
    .bind(claim_map_id)
    .bind(trace_id)
    .bind(session_id)
    .bind("INSUFFICIENT_EVIDENCE")
    .bind(0.95_f64)
    .bind(0.0_f64)
    .bind(serde_json::json!({"claims":[]}))
    .execute(&pool)
    .await
    .expect("insert claim map should succeed");

    for (table, pk_col, pk_val) in [
        (
            "pecr_policy_snapshots",
            "policy_snapshot_id",
            policy_snapshot_id,
        ),
        ("pecr_ledger_events", "event_id", event_id),
        ("pecr_evidence_units", "evidence_unit_id", evidence_unit_id),
        ("pecr_claim_maps", "claim_map_id", claim_map_id),
    ] {
        let update_sql = format!("UPDATE {table} SET {pk_col} = {pk_col} WHERE {pk_col} = $1");
        let update_err = sqlx::query(&update_sql)
            .bind(pk_val)
            .execute(&pool)
            .await
            .expect_err("update must be rejected for append-only tables");
        assert!(
            format!("{update_err:?}").contains("append-only table"),
            "expected append-only error for {table} update, got: {update_err:?}"
        );

        let delete_sql = format!("DELETE FROM {table} WHERE {pk_col} = $1");
        let delete_err = sqlx::query(&delete_sql)
            .bind(pk_val)
            .execute(&pool)
            .await
            .expect_err("delete must be rejected for append-only tables");
        assert!(
            format!("{delete_err:?}").contains("append-only table"),
            "expected append-only error for {table} delete, got: {delete_err:?}"
        );
    }

    let drop_schema = format!("DROP SCHEMA {} CASCADE", schema);
    let _ = sqlx::query(&drop_schema).execute(&pool).await;

    pool.close().await;
}
