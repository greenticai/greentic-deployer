//! The ARM transport seam. The real transport attaches the bearer token; a
//! request never stores one, and a body (which may carry secrets) is never
//! printed by `Debug`.

use async_trait::async_trait;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Method {
    Get,
    Put,
    Post,
    Patch,
    Delete,
}

/// Which audience the transport mints a token for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum TokenScope {
    Arm,
}

impl TokenScope {
    pub(crate) fn scope_string(self) -> &'static str {
        match self {
            TokenScope::Arm => "https://management.azure.com/.default",
        }
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ArmRequest {
    pub method: Method,
    pub url: String,
    pub scope: TokenScope,
    pub body: Option<Vec<u8>>,
}

impl ArmRequest {
    pub(crate) fn new(method: Method, url: impl Into<String>) -> Self {
        Self {
            method,
            url: url.into(),
            scope: TokenScope::Arm,
            body: None,
        }
    }

    pub(crate) fn json(mut self, body: &serde_json::Value) -> Self {
        self.body = serde_json::to_vec(body).ok();
        self
    }
}

impl std::fmt::Debug for ArmRequest {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ArmRequest")
            .field("method", &self.method)
            .field("url", &self.url)
            .field(
                "body",
                &self.body.as_ref().map(|b| format!("<{} bytes>", b.len())),
            )
            .finish()
    }
}

#[derive(Clone, PartialEq, Eq)]
pub(crate) struct ArmResponse {
    pub status: u16,
    /// Header names lowercased.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl ArmResponse {
    #[cfg(test)]
    pub(crate) fn new(status: u16, body: &str) -> Self {
        Self {
            status,
            headers: Vec::new(),
            body: body.as_bytes().to_vec(),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_header(mut self, name: &str, value: &str) -> Self {
        self.headers
            .push((name.to_ascii_lowercase(), value.to_string()));
        self
    }

    pub(crate) fn header(&self, name: &str) -> Option<&str> {
        let n = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(k, _)| *k == n)
            .map(|(_, v)| v.as_str())
    }

    pub(crate) fn json(&self) -> Option<serde_json::Value> {
        serde_json::from_slice(&self.body).ok()
    }
}

impl std::fmt::Debug for ArmResponse {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "ArmResponse({}, <{} bytes>)",
            self.status,
            self.body.len()
        )
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum HttpError {
    #[error("transport error: {0}")]
    Transport(String),
    #[error("could not acquire an Entra token: {0}")]
    Token(String),
}

#[async_trait]
pub(crate) trait AzureHttp: std::fmt::Debug + Send + Sync {
    async fn send(&self, req: ArmRequest) -> Result<ArmResponse, HttpError>;
}

#[cfg(test)]
pub(crate) mod fake {
    //! Recording transport replaying scripted responses.
    use std::collections::VecDeque;
    use std::sync::Mutex;

    use super::*;

    #[derive(Debug, Default)]
    pub(crate) struct FakeHttp {
        pub requests: Mutex<Vec<ArmRequest>>,
        script: Mutex<VecDeque<Result<ArmResponse, String>>>,
    }

    impl FakeHttp {
        pub(crate) fn with(responses: Vec<ArmResponse>) -> Self {
            Self {
                requests: Mutex::default(),
                script: Mutex::new(responses.into_iter().map(Ok).collect()),
            }
        }

        pub(crate) fn seen(&self) -> Vec<ArmRequest> {
            self.requests.lock().map(|g| g.clone()).unwrap_or_default()
        }
    }

    #[async_trait]
    impl AzureHttp for FakeHttp {
        async fn send(&self, req: ArmRequest) -> Result<ArmResponse, HttpError> {
            if let Ok(mut g) = self.requests.lock() {
                g.push(req);
            }
            let next = self.script.lock().ok().and_then(|mut s| s.pop_front());
            match next {
                Some(Ok(r)) => Ok(r),
                Some(Err(e)) => Err(HttpError::Transport(e)),
                None => Err(HttpError::Transport("no scripted response".into())),
            }
        }
    }
}
