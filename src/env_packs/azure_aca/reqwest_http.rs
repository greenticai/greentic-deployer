//! The live [`AzureHttp`]: `reqwest` plus the Entra client-credentials flow.
//! Not exercised against Azure (no credentials existed); the pure pieces it
//! uses (`token::parse_token_response`, `TokenCache`) are unit-tested.

use std::sync::Mutex;
use std::time::Instant;

use async_trait::async_trait;
use url::form_urlencoded;

use super::arm_http::{ArmRequest, ArmResponse, AzureHttp, HttpError, Method, TokenScope};
use super::token::{ClientCredentials, TokenCache, parse_token_response};

#[derive(Debug)]
pub(crate) struct ReqwestHttp {
    client: reqwest::Client,
    creds: ClientCredentials,
    cache: Mutex<TokenCache>,
}

impl ReqwestHttp {
    pub(crate) fn new(creds: ClientCredentials) -> Result<Self, HttpError> {
        let client = reqwest::Client::builder()
            .timeout(std::time::Duration::from_secs(120))
            .build()
            .map_err(|e| HttpError::Transport(e.to_string()))?;
        Ok(Self {
            client,
            creds,
            cache: Mutex::new(TokenCache::default()),
        })
    }

    async fn token(&self, scope: TokenScope) -> Result<String, HttpError> {
        let now = Instant::now();
        if let Ok(cache) = self.cache.lock()
            && let Some(t) = cache.get(scope, now)
        {
            return Ok(t);
        }
        let form = form_urlencoded::Serializer::new(String::new())
            .append_pair("grant_type", "client_credentials")
            .append_pair("client_id", &self.creds.client_id)
            .append_pair("client_secret", self.creds.expose_secret())
            .append_pair("scope", scope.scope_string())
            .finish();
        let resp = self
            .client
            .post(self.creds.token_url())
            .header("content-type", "application/x-www-form-urlencoded")
            .body(form)
            .send()
            .await
            // reqwest errors can embed the URL; the secret is only in the body.
            .map_err(|e| HttpError::Token(e.without_url().to_string()))?;
        let status = resp.status().as_u16();
        let bytes = resp
            .bytes()
            .await
            .map_err(|e| HttpError::Token(e.without_url().to_string()))?;
        let body: serde_json::Value =
            serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null);
        let (token, ttl) = parse_token_response(status, &body).map_err(HttpError::Token)?;
        if let Ok(mut cache) = self.cache.lock() {
            cache.put(scope, token.clone(), ttl, Instant::now());
        }
        Ok(token)
    }
}

#[async_trait]
impl AzureHttp for ReqwestHttp {
    async fn send(&self, req: ArmRequest) -> Result<ArmResponse, HttpError> {
        let token = self.token(req.scope).await?;
        let method = match req.method {
            Method::Get => reqwest::Method::GET,
            Method::Put => reqwest::Method::PUT,
            Method::Post => reqwest::Method::POST,
            Method::Patch => reqwest::Method::PATCH,
            Method::Delete => reqwest::Method::DELETE,
        };
        let mut builder = self.client.request(method, &req.url).bearer_auth(token);
        if let Some(body) = req.body {
            builder = builder
                .header("content-type", "application/json")
                .body(body);
        } else if matches!(req.method, Method::Post | Method::Put | Method::Patch) {
            builder = builder.header("content-length", "0");
        }
        let resp = builder
            .send()
            .await
            .map_err(|e| HttpError::Transport(e.without_url().to_string()))?;
        let status = resp.status().as_u16();
        let headers = resp
            .headers()
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v| (k.as_str().to_ascii_lowercase(), v.to_string()))
            })
            .collect();
        let body = resp
            .bytes()
            .await
            .map_err(|e| HttpError::Transport(e.without_url().to_string()))?;
        Ok(ArmResponse {
            status,
            headers,
            body: body.to_vec(),
        })
    }
}
