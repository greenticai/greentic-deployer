//! Retry and long-running-operation polling over an [`AzureHttp`] (pure logic).

use std::time::Duration;

use super::arm_http::{ArmRequest, ArmResponse, AzureHttp, HttpError, Method, TokenScope};

#[derive(Debug, Clone, Copy)]
pub(crate) struct Policy {
    /// Total attempts for a throttled (429 / 503) request.
    pub attempts: u32,
    /// Delay used when the server sends no `Retry-After`.
    pub default_delay: Duration,
    /// Polls of one operation.
    pub poll_attempts: u32,
    pub poll_interval: Duration,
}

impl Default for Policy {
    fn default() -> Self {
        Self {
            attempts: 5,
            default_delay: Duration::from_secs(2),
            poll_attempts: 120,
            poll_interval: Duration::from_secs(5),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum LroError {
    #[error(transparent)]
    Http(#[from] HttpError),
    #[error("operation failed: {0}")]
    Failed(String),
    #[error("operation did not finish within {0} polls")]
    TimedOut(u32),
}

fn retry_after(resp: &ArmResponse, default: Duration) -> Duration {
    resp.header("retry-after")
        .and_then(|v| v.trim().parse::<u64>().ok())
        .map(Duration::from_secs)
        .unwrap_or(default)
        .min(Duration::from_secs(60))
}

/// Send, retrying 429 / 503 with `Retry-After`. The last throttled response is
/// returned (not an error) once attempts are spent, so the caller reports it.
pub(crate) async fn send_with_retry(
    http: &dyn AzureHttp,
    req: ArmRequest,
    policy: &Policy,
) -> Result<ArmResponse, HttpError> {
    let mut attempt = 1;
    loop {
        let resp = http.send(req.clone()).await?;
        if !matches!(resp.status, 429 | 503) || attempt >= policy.attempts {
            return Ok(resp);
        }
        tokio::time::sleep(retry_after(&resp, policy.default_delay)).await;
        attempt += 1;
    }
}

/// Drive a long-running operation to its end and return the final response.
///
/// `Azure-AsyncOperation` is polled until its `status` is terminal; failing that,
/// a `Location` header on a 202 is polled until it stops answering 202. A
/// response with neither is already final.
pub(crate) async fn complete(
    http: &dyn AzureHttp,
    initial: ArmResponse,
    policy: &Policy,
) -> Result<ArmResponse, LroError> {
    let poll_url = initial
        .header("azure-asyncoperation")
        .map(|u| (u.to_string(), true))
        .or_else(|| {
            (initial.status == 202)
                .then(|| initial.header("location").map(|u| (u.to_string(), false)))
                .flatten()
        });
    let Some((url, is_async_op)) = poll_url else {
        return Ok(initial);
    };
    for _ in 0..policy.poll_attempts {
        tokio::time::sleep(policy.poll_interval).await;
        let req = ArmRequest {
            method: Method::Get,
            url: url.clone(),
            scope: TokenScope::Arm,
            body: None,
        };
        let resp = send_with_retry(http, req, policy).await?;
        if is_async_op {
            let status = resp
                .json()
                .and_then(|v| v.get("status").and_then(|s| s.as_str().map(str::to_string)));
            match status.as_deref() {
                Some("Succeeded") => return Ok(resp),
                Some("Failed") | Some("Canceled") => {
                    let detail = resp
                        .json()
                        .and_then(|v| {
                            v.pointer("/error/message")
                                .and_then(|m| m.as_str().map(str::to_string))
                        })
                        .unwrap_or_else(|| "no detail".to_string());
                    return Err(LroError::Failed(detail));
                }
                _ => {}
            }
        } else if resp.status != 202 {
            return Ok(resp);
        }
    }
    Err(LroError::TimedOut(policy.poll_attempts))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::env_packs::azure_aca::arm_http::fake::FakeHttp;

    fn fast() -> Policy {
        Policy {
            attempts: 3,
            default_delay: Duration::ZERO,
            poll_attempts: 4,
            poll_interval: Duration::ZERO,
        }
    }

    #[tokio::test]
    async fn a_429_is_retried_then_succeeds() {
        let http = FakeHttp::with(vec![
            ArmResponse::new(429, "{}").with_header("Retry-After", "0"),
            ArmResponse::new(200, "{}"),
        ]);
        let r = send_with_retry(&http, ArmRequest::new(Method::Get, "u"), &fast())
            .await
            .unwrap();
        assert_eq!(r.status, 200);
        assert_eq!(http.seen().len(), 2);
    }

    #[tokio::test]
    async fn a_persistent_429_surfaces_after_the_attempts() {
        let http = FakeHttp::with(vec![ArmResponse::new(429, "{}"); 3]);
        let r = send_with_retry(&http, ArmRequest::new(Method::Get, "u"), &fast())
            .await
            .unwrap();
        assert_eq!(r.status, 429);
        assert_eq!(http.seen().len(), 3);
    }

    #[tokio::test]
    async fn the_async_operation_is_polled_to_success_and_to_failure() {
        let initial = ArmResponse::new(201, "{}").with_header("Azure-AsyncOperation", "https://op");
        let http = FakeHttp::with(vec![
            ArmResponse::new(200, r#"{"status":"InProgress"}"#),
            ArmResponse::new(200, r#"{"status":"Succeeded"}"#),
        ]);
        assert!(complete(&http, initial.clone(), &fast()).await.is_ok());
        let http = FakeHttp::with(vec![ArmResponse::new(
            200,
            r#"{"status":"Failed","error":{"message":"boom"}}"#,
        )]);
        let e = complete(&http, initial.clone(), &fast()).await.unwrap_err();
        assert!(e.to_string().contains("boom"), "{e}");
        let http = FakeHttp::with(vec![ArmResponse::new(200, r#"{"status":"InProgress"}"#); 4]);
        assert!(matches!(
            complete(&http, initial, &fast()).await,
            Err(LroError::TimedOut(4))
        ));
    }

    #[tokio::test]
    async fn a_response_without_an_operation_is_final_and_location_polls_until_not_202() {
        let http = FakeHttp::default();
        assert_eq!(
            complete(&http, ArmResponse::new(200, "{}"), &fast())
                .await
                .unwrap()
                .status,
            200
        );
        assert!(http.seen().is_empty());
        let accepted = ArmResponse::new(202, "").with_header("Location", "https://loc");
        let http = FakeHttp::with(vec![ArmResponse::new(202, ""), ArmResponse::new(200, "{}")]);
        assert_eq!(
            complete(&http, accepted, &fast()).await.unwrap().status,
            200
        );
    }
}
