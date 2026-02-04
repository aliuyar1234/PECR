use std::sync::Arc;
use std::time::{Duration, Instant};

use http::HeaderMap;
use http::header;
use jsonwebtoken::jwk::JwkSet;
use jsonwebtoken::{Algorithm, DecodingKey, Validation, decode, decode_header};
use pecr_contracts::canonical;
use serde_json::Value;
use tokio::sync::RwLock;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Principal {
    pub principal_id: String,
    pub tenant_id: String,
    pub principal_roles: Vec<String>,
    pub principal_attrs_hash: String,
}

#[derive(Debug, Clone)]
pub struct OidcConfig {
    pub issuer: String,
    pub audience: Option<String>,
    pub jwks_url: Option<String>,
    pub jwks_json: Option<String>,
    pub jwks_timeout: Duration,
    pub jwks_refresh_ttl: Duration,
    pub clock_skew: Duration,
    pub principal_id_claim: String,
    pub tenant_claim: Option<String>,
    pub tenant_id_static: Option<String>,
    pub roles_claim: Option<String>,
    pub abac_claims: Vec<String>,
}

#[derive(Debug, Clone)]
pub struct AuthError {
    pub code: &'static str,
    pub message: String,
}

impl std::fmt::Display for AuthError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.code, self.message)
    }
}

impl std::error::Error for AuthError {}

#[derive(Clone)]
pub struct OidcAuthenticator {
    config: OidcConfig,
    http: reqwest::Client,
    jwks: Arc<RwLock<JwksCache>>,
}

#[derive(Debug)]
struct JwksCache {
    jwks: Option<JwkSet>,
    fetched_at: Option<Instant>,
}

impl OidcAuthenticator {
    pub async fn new(config: OidcConfig) -> Result<Self, AuthError> {
        if config.issuer.trim().is_empty() {
            return Err(AuthError {
                code: "ERR_INVALID_CONFIG",
                message: "oidc issuer must be non-empty".to_string(),
            });
        }

        if config.principal_id_claim.trim().is_empty() {
            return Err(AuthError {
                code: "ERR_INVALID_CONFIG",
                message: "oidc principal_id_claim must be non-empty".to_string(),
            });
        }

        if config.tenant_id_static.is_none() && config.tenant_claim.is_none() {
            return Err(AuthError {
                code: "ERR_INVALID_CONFIG",
                message: "oidc requires tenant mapping via tenant_claim or tenant_id_static"
                    .to_string(),
            });
        }

        let http = reqwest::Client::builder()
            .timeout(config.jwks_timeout)
            .build()
            .map_err(|_| AuthError {
                code: "ERR_INTERNAL",
                message: "failed to initialize oidc http client".to_string(),
            })?;

        let mut cache = JwksCache {
            jwks: None,
            fetched_at: None,
        };
        cache.refresh(&http, &config).await?;

        Ok(Self {
            config,
            http,
            jwks: Arc::new(RwLock::new(cache)),
        })
    }

    pub async fn authenticate(&self, headers: &HeaderMap) -> Result<Principal, AuthError> {
        let token = bearer_token(headers)?;

        let header = decode_header(&token).map_err(|_| AuthError {
            code: "ERR_AUTH_INVALID",
            message: "invalid JWT header".to_string(),
        })?;

        if header.alg != Algorithm::RS256 {
            return Err(AuthError {
                code: "ERR_AUTH_INVALID",
                message: "unsupported JWT alg (expected RS256)".to_string(),
            });
        }

        let kid = header.kid.ok_or_else(|| AuthError {
            code: "ERR_AUTH_INVALID",
            message: "JWT header missing kid".to_string(),
        })?;

        let decoding_key = self.decoding_key_for_kid(&kid).await?;

        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(std::slice::from_ref(&self.config.issuer));
        if let Some(audience) = self.config.audience.as_ref() {
            validation.set_audience(std::slice::from_ref(audience));
        }
        validation.leeway = self.config.clock_skew.as_secs();

        let decoded =
            decode::<Value>(&token, &decoding_key, &validation).map_err(|_| AuthError {
                code: "ERR_AUTH_INVALID",
                message: "JWT validation failed".to_string(),
            })?;

        let claims = decoded.claims;

        let principal_id = claim_string(&claims, &self.config.principal_id_claim)?;

        let tenant_id = match self.config.tenant_id_static.as_ref() {
            Some(tenant_id) => tenant_id.clone(),
            None => {
                let claim = self.config.tenant_claim.as_ref().unwrap();
                claim_string(&claims, claim)?
            }
        };

        let roles = match self.config.roles_claim.as_ref() {
            Some(claim) => claim_string_vec(&claims, claim)?,
            None => Vec::new(),
        };

        let principal_attrs_hash = attrs_hash(&claims, &self.config.abac_claims);

        Ok(Principal {
            principal_id,
            tenant_id,
            principal_roles: roles,
            principal_attrs_hash,
        })
    }

    async fn decoding_key_for_kid(&self, kid: &str) -> Result<DecodingKey, AuthError> {
        {
            let cache = self.jwks.read().await;
            if let Some(jwk) = cache.jwk_for_kid(kid) {
                return DecodingKey::from_jwk(jwk).map_err(|_| AuthError {
                    code: "ERR_AUTH_INVALID",
                    message: "failed to parse JWK decoding key".to_string(),
                });
            }
        }

        {
            let mut cache = self.jwks.write().await;
            let refresh_needed = cache
                .fetched_at
                .map(|t| t.elapsed() > self.config.jwks_refresh_ttl)
                .unwrap_or(true);
            if refresh_needed {
                cache.refresh(&self.http, &self.config).await?;
            }

            if let Some(jwk) = cache.jwk_for_kid(kid) {
                return DecodingKey::from_jwk(jwk).map_err(|_| AuthError {
                    code: "ERR_AUTH_INVALID",
                    message: "failed to parse JWK decoding key".to_string(),
                });
            }
        }

        Err(AuthError {
            code: "ERR_AUTH_INVALID",
            message: "JWT kid not found in JWKS".to_string(),
        })
    }
}

impl JwksCache {
    fn jwk_for_kid(&self, kid: &str) -> Option<&jsonwebtoken::jwk::Jwk> {
        self.jwks.as_ref()?.find(kid)
    }

    async fn refresh(
        &mut self,
        http: &reqwest::Client,
        config: &OidcConfig,
    ) -> Result<(), AuthError> {
        let jwks = if let Some(jwks_json) = config.jwks_json.as_ref() {
            serde_json::from_str::<JwkSet>(jwks_json).map_err(|_| AuthError {
                code: "ERR_INVALID_CONFIG",
                message: "PECR_OIDC_JWKS_JSON is not valid JWKS JSON".to_string(),
            })?
        } else if let Some(url) = config.jwks_url.as_ref() {
            http.get(url)
                .send()
                .await
                .map_err(|_| AuthError {
                    code: "ERR_AUTH_UNAVAILABLE",
                    message: "failed to fetch JWKS".to_string(),
                })?
                .error_for_status()
                .map_err(|_| AuthError {
                    code: "ERR_AUTH_UNAVAILABLE",
                    message: "JWKS endpoint returned non-success status".to_string(),
                })?
                .json::<JwkSet>()
                .await
                .map_err(|_| AuthError {
                    code: "ERR_AUTH_UNAVAILABLE",
                    message: "failed to parse JWKS JSON".to_string(),
                })?
        } else {
            return Err(AuthError {
                code: "ERR_INVALID_CONFIG",
                message: "oidc requires jwks_url or jwks_json".to_string(),
            });
        };

        self.jwks = Some(jwks);
        self.fetched_at = Some(Instant::now());
        Ok(())
    }
}

fn bearer_token(headers: &HeaderMap) -> Result<String, AuthError> {
    let authz = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.trim())
        .filter(|v| !v.is_empty())
        .ok_or_else(|| AuthError {
            code: "ERR_AUTH_REQUIRED",
            message: "missing Authorization header".to_string(),
        })?;

    let token = authz
        .strip_prefix("Bearer ")
        .or_else(|| authz.strip_prefix("bearer "))
        .ok_or_else(|| AuthError {
            code: "ERR_AUTH_INVALID",
            message: "Authorization must be a Bearer token".to_string(),
        })?;

    if token.trim().is_empty() {
        return Err(AuthError {
            code: "ERR_AUTH_INVALID",
            message: "Bearer token is empty".to_string(),
        });
    }

    Ok(token.to_string())
}

fn claim_string(claims: &Value, claim: &str) -> Result<String, AuthError> {
    claims
        .get(claim)
        .and_then(|v| v.as_str())
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .ok_or_else(|| AuthError {
            code: "ERR_AUTH_INVALID",
            message: format!("required claim `{}` is missing or not a string", claim),
        })
}

fn claim_string_vec(claims: &Value, claim: &str) -> Result<Vec<String>, AuthError> {
    let Some(value) = claims.get(claim) else {
        return Ok(Vec::new());
    };

    match value {
        Value::String(s) => {
            let s = s.trim();
            if s.is_empty() {
                Ok(Vec::new())
            } else {
                Ok(vec![s.to_string()])
            }
        }
        Value::Array(items) => {
            let mut out = Vec::with_capacity(items.len());
            for item in items {
                let Some(s) = item.as_str() else {
                    return Err(AuthError {
                        code: "ERR_AUTH_INVALID",
                        message: format!("claim `{}` must be a string array", claim),
                    });
                };
                let s = s.trim();
                if !s.is_empty() {
                    out.push(s.to_string());
                }
            }
            out.sort();
            out.dedup();
            Ok(out)
        }
        _ => Err(AuthError {
            code: "ERR_AUTH_INVALID",
            message: format!("claim `{}` must be a string or a string array", claim),
        }),
    }
}

fn attrs_hash(claims: &Value, abac_claims: &[String]) -> String {
    let mut obj = serde_json::Map::new();
    for claim in abac_claims {
        let claim = claim.trim();
        if claim.is_empty() {
            continue;
        }
        if let Some(value) = claims.get(claim) {
            obj.insert(claim.to_string(), value.clone());
        }
    }
    canonical::hash_canonical_json(&Value::Object(obj))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bearer_token_rejects_missing_header() {
        let headers = HeaderMap::new();
        let err = bearer_token(&headers).unwrap_err();
        assert_eq!(err.code, "ERR_AUTH_REQUIRED");
    }

    #[test]
    fn claim_string_vec_accepts_string_and_array() {
        let claims = serde_json::json!({
            "groups": ["a", "b", "b", ""],
            "role": "admin",
        });

        let groups = claim_string_vec(&claims, "groups").unwrap();
        assert_eq!(groups, vec!["a".to_string(), "b".to_string()]);

        let role = claim_string_vec(&claims, "role").unwrap();
        assert_eq!(role, vec!["admin".to_string()]);

        let missing = claim_string_vec(&claims, "missing").unwrap();
        assert!(missing.is_empty());
    }
}
