use std::time::Duration;

use http::HeaderMap;
use http::header;
use jsonwebtoken::{Algorithm, EncodingKey, Header, encode};
use pecr_auth::{OidcAuthenticator, OidcConfig};

#[tokio::test]
async fn authenticate_extracts_principal_from_valid_rs256_jwt() {
    let private_key_pem = include_bytes!("fixtures/test_rsa_private.pem");
    let jwks_json = include_str!("fixtures/test_jwks.json");

    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-kid".to_string());

    let claims = serde_json::json!({
        "iss": "https://issuer.example",
        "sub": "dev",
        "aud": "pecr",
        "exp": 2000000000,
        "iat": 1000000000,
        "tenant_id": "local",
        "groups": ["support", "dev"],
        "dept": "eng"
    });

    let token = encode(
        &header,
        &claims,
        &EncodingKey::from_rsa_pem(private_key_pem).expect("private key must parse"),
    )
    .expect("token encode should succeed");

    let auth = OidcAuthenticator::new(OidcConfig {
        issuer: "https://issuer.example".to_string(),
        audience: Some("pecr".to_string()),
        jwks_url: None,
        jwks_json: Some(jwks_json.to_string()),
        jwks_timeout: Duration::from_millis(2000),
        jwks_refresh_ttl: Duration::from_secs(300),
        clock_skew: Duration::from_secs(0),
        principal_id_claim: "sub".to_string(),
        tenant_claim: Some("tenant_id".to_string()),
        tenant_id_static: None,
        roles_claim: Some("groups".to_string()),
        abac_claims: vec!["dept".to_string()],
    })
    .await
    .expect("auth init should succeed");

    let mut headers = HeaderMap::new();
    headers.insert(
        header::AUTHORIZATION,
        format!("Bearer {}", token)
            .parse()
            .expect("authorization header must parse"),
    );

    let principal = auth
        .authenticate(&headers)
        .await
        .expect("authenticate should succeed");

    assert_eq!(principal.principal_id, "dev");
    assert_eq!(principal.tenant_id, "local");
    assert_eq!(principal.principal_roles, vec!["dev", "support"]);

    let expected_attrs_hash =
        pecr_contracts::canonical::hash_canonical_json(&serde_json::json!({"dept": "eng"}));
    assert_eq!(principal.principal_attrs_hash, expected_attrs_hash);
}
