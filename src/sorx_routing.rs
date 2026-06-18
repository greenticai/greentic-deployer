//! Alias-aware routing layer for the bundled single-operator case (S3-deployer,
//! decision B1 / Option A).
//!
//! This module is the **verifiable core** of the deployer-owned thin
//! orchestrator/router. It consumes SoRX's routing-table
//! (`GET /v1/sorx/routing-table?tenant=&sor=`) and decides where an inbound
//! `/{tenant}/{sor}/{alias}/{rest}` request should be forwarded.
//!
//! ## What is in scope
//!
//! 1. [`AliasResolver`] — a TTL-cached resolver over a [`RoutingTableSource`]
//!    that maps `(tenant, sor, alias)` to a routable [`RouteRow`]
//!    (`deployment_id`, `base_path`, …). Stale-on-error: if a refetch fails,
//!    the last good table is served.
//! 2. [`route_request`] — a **pure** decision function: given a resolver, an
//!    injected [`UpstreamRegistry`], and the parts of an inbound HTTP request,
//!    it returns a [`ProxyOutcome`] (`Forward { upstream, rewritten_path }` or
//!    `NotFound`). It performs no network I/O, so the full routing logic is
//!    unit-testable without sockets.
//!
//! ## What is OUT of scope (documented boundary — deferred follow-up)
//!
//! The actual **N-process spawning** — starting one SoRX instance per
//! deployment and tracking its live `host:port` — is the infra-coupled part of
//! Option A and is *not* built here. Instead the live instance address is an
//! injected parameter: [`UpstreamRegistry::upstream_for`]. The v1
//! implementation is [`StaticUpstreamRegistry`] (a fixed map). A live
//! orchestrator registry (process spawner + health tracking) is the documented
//! follow-up; it slots in behind the same [`UpstreamRegistry`] trait without
//! touching the routing logic.
//!
//! Likewise, the real network forward (binding a listener, copying bytes) is a
//! thin wrapper around [`route_request`]; see [`describe_request`] for the
//! CLI-facing dry-run that exercises the decision layer without a listener.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

/// One row of the SoRX routing-table
/// (`GET /v1/sorx/routing-table` → `{ "schema": ..., "routes": [ … ] }`).
///
/// Field set mirrors the SoRX contract exactly; unknown future fields are
/// ignored on deserialize so a SoRX schema bump does not break the resolver.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteRow {
    pub tenant_id: String,
    pub sor_name: String,
    pub alias: String,
    pub deployment_id: String,
    pub pack_name: String,
    pub pack_version: String,
    /// Path prefix the upstream instance serves under (e.g. `/sor/customer`).
    pub base_path: String,
    pub state_namespace: String,
    pub visibility: String,
    /// Whether this row may currently receive traffic. Only `routable == true`
    /// rows are resolvable.
    pub routable: bool,
    /// Traffic split for this row, mirrored from the SoRX contract (SoRX emits
    /// `traffic` as an object, e.g. `{"mode":"all"}`, or omits it). Carried
    /// through for parity; weighted split across multiple routable rows for the
    /// same alias is a follow-up (v1 picks the first routable row). Optional and
    /// `#[serde(default)]` so an absent/`null`/extended traffic shape from a
    /// SoRX schema bump does not break alias resolution.
    #[serde(default)]
    pub traffic: Option<TrafficSplit>,
}

/// Traffic split descriptor mirrored from the SoRX routing-table contract
/// (`{ "mode": "all" | "percent" | …, "percent"?: u8, … }`). All fields are
/// `#[serde(default)]` and unknown ones are ignored, so SoRX can evolve the
/// traffic shape without breaking the deployer's decode. The deployer's v1
/// router does not yet act on the split (it picks the first routable row).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct TrafficSplit {
    #[serde(default)]
    pub mode: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub percent: Option<u8>,
}

/// Wire envelope for `GET /v1/sorx/routing-table`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RoutingTable {
    pub schema: String,
    pub routes: Vec<RouteRow>,
}

/// Source of routing-table rows. Sync by design: the deployer's HTTP stack is
/// `reqwest::blocking`, and the router runs off the request hot-path behind a
/// TTL cache, so a blocking fetch is appropriate and keeps the trait
/// object-safe and trivially fakeable in tests.
pub trait RoutingTableSource: Send + Sync {
    /// Fetch the routing-table from SoRX. `tenant` / `sor` are optional server
    /// side filters; passing `None` fetches the full table. Errors are
    /// returned as a `String` so the resolver can apply stale-on-error without
    /// coupling to a concrete error type.
    fn fetch(
        &self,
        sorx_base_url: &str,
        tenant: Option<&str>,
        sor: Option<&str>,
    ) -> Result<Vec<RouteRow>, String>;
}

/// Maps a resolved deployment to its live instance address. **Supplied by the
/// orchestrator (process spawner) — NOT resolved here.**
///
/// v1: a static map ([`StaticUpstreamRegistry`]). A live orchestrator registry
/// that tracks spawned SoRX processes is the documented follow-up; it
/// implements this same trait.
pub trait UpstreamRegistry: Send + Sync {
    /// The live `host:port` (e.g. `"127.0.0.1:8088"`) for a `deployment_id`, or
    /// `None` if no instance is currently registered/healthy.
    fn upstream_for(&self, deployment_id: &str) -> Option<String>;
}

/// v1 [`UpstreamRegistry`]: a fixed `deployment_id -> host:port` map injected
/// at construction (e.g. parsed from `--upstreams <json>`).
#[derive(Debug, Clone, Default)]
pub struct StaticUpstreamRegistry {
    map: HashMap<String, String>,
}

impl StaticUpstreamRegistry {
    pub fn new(map: HashMap<String, String>) -> Self {
        Self { map }
    }
}

impl UpstreamRegistry for StaticUpstreamRegistry {
    fn upstream_for(&self, deployment_id: &str) -> Option<String> {
        self.map.get(deployment_id).cloned()
    }
}

/// Cache key for a resolved table slice. The resolver caches per
/// `(tenant, sor)` fetch scope so different filter scopes do not clobber each
/// other.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
struct ScopeKey {
    tenant: Option<String>,
    sor: Option<String>,
}

struct CacheEntry {
    rows: Vec<RouteRow>,
    fetched_at: Instant,
}

/// Resolves `(tenant, sor, alias)` to a routable [`RouteRow`] from a TTL-cached
/// routing table. Stale-on-error: a failed refetch falls back to the last good
/// table for that scope.
pub struct AliasResolver {
    source: Box<dyn RoutingTableSource>,
    ttl: Duration,
    cache: Mutex<HashMap<ScopeKey, CacheEntry>>,
}

impl AliasResolver {
    pub fn new(source: Box<dyn RoutingTableSource>, ttl: Duration) -> Self {
        Self {
            source,
            ttl,
            cache: Mutex::new(HashMap::new()),
        }
    }

    /// Return the routable [`RouteRow`] for `(tenant, sor, alias)`, or `None`.
    ///
    /// The table is fetched (scoped to `tenant`/`sor`) and cached for `ttl`.
    /// Within the TTL the cache is reused; after expiry a refetch is attempted.
    /// If the refetch fails but a previous good table exists, the stale table
    /// is used (stale-on-error). Only `routable == true` rows match.
    pub fn resolve(
        &self,
        sorx_base_url: &str,
        tenant: &str,
        sor: &str,
        alias: &str,
    ) -> Option<RouteRow> {
        let rows = self.rows_for_scope(sorx_base_url, tenant, sor);
        select_routable(&rows, tenant, sor, alias)
    }

    /// Fetch-or-cache the rows for the `(tenant, sor)` scope, applying TTL and
    /// stale-on-error semantics. Always queries SoRX with both filters set so
    /// the returned slice is already scoped.
    fn rows_for_scope(&self, sorx_base_url: &str, tenant: &str, sor: &str) -> Vec<RouteRow> {
        let key = ScopeKey {
            tenant: Some(tenant.to_string()),
            sor: Some(sor.to_string()),
        };

        let mut cache = match self.cache.lock() {
            Ok(guard) => guard,
            // A poisoned lock means a previous holder panicked while mutating
            // the cache. Recover the guard rather than propagating a panic:
            // the router must keep serving, and the worst case is a re-fetch.
            Err(poisoned) => poisoned.into_inner(),
        };

        let fresh = cache
            .get(&key)
            .map(|entry| entry.fetched_at.elapsed() < self.ttl)
            .unwrap_or(false);

        if fresh {
            // Safe: `fresh` is only true when the entry exists.
            if let Some(entry) = cache.get(&key) {
                return entry.rows.clone();
            }
        }

        match self.source.fetch(sorx_base_url, Some(tenant), Some(sor)) {
            Ok(rows) => {
                cache.insert(
                    key,
                    CacheEntry {
                        rows: rows.clone(),
                        fetched_at: Instant::now(),
                    },
                );
                rows
            }
            Err(err) => {
                // Stale-on-error: serve the last good table if we have one.
                if let Some(entry) = cache.get(&key) {
                    tracing::warn!(
                        error = %err,
                        tenant,
                        sor,
                        "sorx routing-table refetch failed; serving stale cache"
                    );
                    entry.rows.clone()
                } else {
                    tracing::warn!(
                        error = %err,
                        tenant,
                        sor,
                        "sorx routing-table fetch failed and no cache available"
                    );
                    Vec::new()
                }
            }
        }
    }
}

/// Pure selection: first `routable` row matching `(tenant, sor, alias)`.
///
/// v1 picks the first routable match. Weighted traffic split across multiple
/// routable rows for the same alias (using `RouteRow::traffic`) is a follow-up.
fn select_routable(rows: &[RouteRow], tenant: &str, sor: &str, alias: &str) -> Option<RouteRow> {
    rows.iter()
        .find(|r| r.routable && r.tenant_id == tenant && r.sor_name == sor && r.alias == alias)
        .cloned()
}

/// Outcome of the pure routing decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProxyOutcome {
    /// Forward the request to `upstream` (`host:port`) at `rewritten_path`.
    Forward {
        upstream: String,
        rewritten_path: String,
        deployment_id: String,
    },
    /// The request cannot be served. `status` is the HTTP status the proxy
    /// should return (404 alias-unresolved / 503 no-upstream / 400 malformed).
    NotFound { status: u16, reason: String },
}

/// Parsed parts of an inbound `/{tenant}/{sor}/{alias}/{rest}` request path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestPath {
    pub tenant: String,
    pub sor: String,
    pub alias: String,
    /// Everything after the alias segment, **without** a leading slash. May be
    /// empty (the alias root was requested).
    pub rest: String,
}

/// Parse `/{tenant}/{sor}/{alias}/{rest}` from a request path.
///
/// Requires at least the three leading segments (`tenant`, `sor`, `alias`);
/// `rest` is optional. Any query string is stripped (the caller forwards it
/// separately). Returns `None` for malformed paths so the caller can answer
/// 400.
pub fn parse_request_path(path: &str) -> Option<RequestPath> {
    // Drop a query string if present; the decision layer routes on the path.
    let path = path.split('?').next().unwrap_or(path);
    let trimmed = path.trim_start_matches('/');
    let mut segments = trimmed.splitn(4, '/');

    let tenant = segments.next().filter(|s| !s.is_empty())?;
    let sor = segments.next().filter(|s| !s.is_empty())?;
    let alias = segments.next().filter(|s| !s.is_empty())?;
    // `rest` may be absent (alias root) — default to empty.
    let rest = segments.next().unwrap_or("");

    Some(RequestPath {
        tenant: tenant.to_string(),
        sor: sor.to_string(),
        alias: alias.to_string(),
        rest: rest.to_string(),
    })
}

/// Build the upstream forward path for a resolved route.
///
/// **Path-rewrite decision (v1):** the inbound `{tenant}/{sor}/{alias}` prefix
/// is stripped and the remaining `{rest}` is forwarded under the resolved
/// deployment's `base_path`, i.e. `{base_path}/{rest}`. Rationale: the alias is
/// a routing handle that does not exist on the upstream instance; the upstream
/// serves its own surface under `base_path`. Both `base_path` and `rest` are
/// normalized so the result has exactly one slash between them and a single
/// leading slash.
fn rewrite_path(base_path: &str, rest: &str) -> String {
    let base = base_path.trim_matches('/');
    let rest = rest.trim_matches('/');
    match (base.is_empty(), rest.is_empty()) {
        (true, true) => "/".to_string(),
        (true, false) => format!("/{rest}"),
        (false, true) => format!("/{base}"),
        (false, false) => format!("/{base}/{rest}"),
    }
}

/// The pure routing decision: resolve the alias, then look up its upstream.
///
/// No network I/O. `method`, `headers`, and `body` are accepted so the live
/// proxy wrapper can pass them straight through; the decision itself only
/// depends on the path. They are intentionally unused by the decision and are
/// forwarded verbatim by the network layer.
///
/// Returns:
/// - `Forward` when the alias resolves to a routable deployment **and** that
///   deployment has a registered upstream.
/// - `NotFound { status: 400 }` for a malformed path.
/// - `NotFound { status: 404 }` when the alias does not resolve to a routable
///   deployment.
/// - `NotFound { status: 503 }` when the alias resolves but no upstream is
///   registered for the deployment (instance not yet spawned/healthy).
pub fn route_request(
    resolver: &AliasResolver,
    upstreams: &dyn UpstreamRegistry,
    sorx_base_url: &str,
    _method: &str,
    path: &str,
    _headers: &[(String, String)],
    _body: &[u8],
) -> ProxyOutcome {
    let parsed = match parse_request_path(path) {
        Some(p) => p,
        None => {
            return ProxyOutcome::NotFound {
                status: 400,
                reason: format!(
                    "malformed path {path:?}: expected /{{tenant}}/{{sor}}/{{alias}}/{{rest}}"
                ),
            };
        }
    };

    let row = match resolver.resolve(sorx_base_url, &parsed.tenant, &parsed.sor, &parsed.alias) {
        Some(row) => row,
        None => {
            return ProxyOutcome::NotFound {
                status: 404,
                reason: format!(
                    "no routable deployment for tenant={} sor={} alias={}",
                    parsed.tenant, parsed.sor, parsed.alias
                ),
            };
        }
    };

    let upstream = match upstreams.upstream_for(&row.deployment_id) {
        Some(addr) => addr,
        None => {
            return ProxyOutcome::NotFound {
                status: 503,
                reason: format!(
                    "no live upstream registered for deployment_id={} \
                     (instance not spawned/healthy yet)",
                    row.deployment_id
                ),
            };
        }
    };

    ProxyOutcome::Forward {
        upstream,
        rewritten_path: rewrite_path(&row.base_path, &parsed.rest),
        deployment_id: row.deployment_id,
    }
}

/// CLI-facing dry-run: run the routing decision for a sample request and return
/// a JSON-serializable description. Used by the `sorx route --dry-run`
/// subcommand so the decision layer is exercisable without binding a listener
/// (the live listener is the documented follow-up).
#[derive(Debug, Clone, Serialize)]
pub struct RouteDecision {
    pub method: String,
    pub path: String,
    pub outcome: RouteDecisionOutcome,
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RouteDecisionOutcome {
    Forward {
        upstream: String,
        rewritten_path: String,
        deployment_id: String,
    },
    NotFound {
        status: u16,
        reason: String,
    },
}

/// Produce a [`RouteDecision`] for a sample `(method, path)` against the live
/// resolver + upstream registry. No request body/headers (dry-run).
pub fn describe_request(
    resolver: &AliasResolver,
    upstreams: &dyn UpstreamRegistry,
    sorx_base_url: &str,
    method: &str,
    path: &str,
) -> RouteDecision {
    let outcome = match route_request(resolver, upstreams, sorx_base_url, method, path, &[], &[]) {
        ProxyOutcome::Forward {
            upstream,
            rewritten_path,
            deployment_id,
        } => RouteDecisionOutcome::Forward {
            upstream,
            rewritten_path,
            deployment_id,
        },
        ProxyOutcome::NotFound { status, reason } => {
            RouteDecisionOutcome::NotFound { status, reason }
        }
    };
    RouteDecision {
        method: method.to_string(),
        path: path.to_string(),
        outcome,
    }
}

/// A [`RoutingTableSource`] backed by SoRX over `reqwest::blocking`.
///
/// This is the live source used by the CLI. The pure decision layer above does
/// not depend on it (tests use a fake source), so the routing logic stays
/// socket-free and fully unit-testable.
pub struct HttpRoutingTableSource {
    client: reqwest::blocking::Client,
}

impl HttpRoutingTableSource {
    /// Build with a default blocking client (3s connect timeout to keep the
    /// router responsive on a dead SoRX; stale-on-error covers the gap).
    pub fn new() -> Result<Self, String> {
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(Duration::from_secs(3))
            .timeout(Duration::from_secs(10))
            .build()
            .map_err(|e| format!("failed to build http client: {e}"))?;
        Ok(Self { client })
    }
}

impl RoutingTableSource for HttpRoutingTableSource {
    fn fetch(
        &self,
        sorx_base_url: &str,
        tenant: Option<&str>,
        sor: Option<&str>,
    ) -> Result<Vec<RouteRow>, String> {
        let base = sorx_base_url.trim_end_matches('/');
        let mut url = format!("{base}/v1/sorx/routing-table");
        let mut params: Vec<(&str, &str)> = Vec::new();
        if let Some(t) = tenant {
            params.push(("tenant", t));
        }
        if let Some(s) = sor {
            params.push(("sor", s));
        }

        let mut request = self.client.get(&url);
        if !params.is_empty() {
            request = request.query(&params);
        }
        // Keep `url` referenced for error messages even when query is appended
        // by reqwest internally.
        url = format!("{url}{}", render_query_suffix(&params));

        let response = request
            .send()
            .map_err(|e| format!("GET {url} failed: {e}"))?;
        let status = response.status();
        if !status.is_success() {
            let body = response.text().unwrap_or_default();
            return Err(format!("GET {url} returned {status}: {body}"));
        }
        let table: RoutingTable = response
            .json()
            .map_err(|e| format!("GET {url} returned undecodable routing-table: {e}"))?;
        Ok(table.routes)
    }
}

fn render_query_suffix(params: &[(&str, &str)]) -> String {
    if params.is_empty() {
        return String::new();
    }
    let joined = params
        .iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&");
    format!("?{joined}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn row(alias: &str, deployment_id: &str, routable: bool, base_path: &str) -> RouteRow {
        RouteRow {
            tenant_id: "acme".to_string(),
            sor_name: "customer".to_string(),
            alias: alias.to_string(),
            deployment_id: deployment_id.to_string(),
            pack_name: "pack".to_string(),
            pack_version: "1.0.0".to_string(),
            base_path: base_path.to_string(),
            state_namespace: "ns".to_string(),
            visibility: "public".to_string(),
            routable,
            traffic: Some(TrafficSplit {
                mode: "all".to_string(),
                percent: None,
            }),
        }
    }

    /// A fake source returning a fixed table and counting fetch calls.
    struct FakeSource {
        rows: Vec<RouteRow>,
        calls: Arc<AtomicUsize>,
    }
    impl RoutingTableSource for FakeSource {
        fn fetch(
            &self,
            _url: &str,
            _tenant: Option<&str>,
            _sor: Option<&str>,
        ) -> Result<Vec<RouteRow>, String> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(self.rows.clone())
        }
    }

    /// A fake source that succeeds once then errors, counting calls.
    struct FlakySource {
        rows: Vec<RouteRow>,
        calls: Arc<AtomicUsize>,
    }
    impl RoutingTableSource for FlakySource {
        fn fetch(
            &self,
            _url: &str,
            _tenant: Option<&str>,
            _sor: Option<&str>,
        ) -> Result<Vec<RouteRow>, String> {
            let n = self.calls.fetch_add(1, Ordering::SeqCst);
            if n == 0 {
                Ok(self.rows.clone())
            } else {
                Err("sorx unreachable".to_string())
            }
        }
    }

    fn upstreams(pairs: &[(&str, &str)]) -> StaticUpstreamRegistry {
        StaticUpstreamRegistry::new(
            pairs
                .iter()
                .map(|(k, v)| (k.to_string(), v.to_string()))
                .collect(),
        )
    }

    #[test]
    fn resolve_returns_routable_deployment() {
        let calls = Arc::new(AtomicUsize::new(0));
        let source = FakeSource {
            rows: vec![
                row("v1", "dep-old", false, "/sor/customer"),
                row("v1", "dep-new", true, "/sor/customer"),
                row("v2", "dep-x", false, "/sor/customer"),
            ],
            calls: calls.clone(),
        };
        let resolver = AliasResolver::new(Box::new(source), Duration::from_secs(60));

        // The routable row for alias `v1` wins over the non-routable one.
        let resolved = resolver
            .resolve("http://sorx", "acme", "customer", "v1")
            .expect("v1 should resolve to the routable deployment");
        assert_eq!(resolved.deployment_id, "dep-new");
        assert!(resolved.routable);

        // alias `v2` is only present as non-routable -> None.
        assert!(
            resolver
                .resolve("http://sorx", "acme", "customer", "v2")
                .is_none()
        );

        // Unknown alias -> None.
        assert!(
            resolver
                .resolve("http://sorx", "acme", "customer", "nope")
                .is_none()
        );
    }

    #[test]
    fn resolve_ttl_refetch() {
        let calls = Arc::new(AtomicUsize::new(0));
        let source = FakeSource {
            rows: vec![row("v1", "dep-1", true, "/sor/customer")],
            calls: calls.clone(),
        };
        // Tiny TTL so we can cross it deterministically.
        let resolver = AliasResolver::new(Box::new(source), Duration::from_millis(30));

        resolver.resolve("http://sorx", "acme", "customer", "v1");
        resolver.resolve("http://sorx", "acme", "customer", "v1");
        // Two resolves within TTL -> exactly one fetch.
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        std::thread::sleep(Duration::from_millis(50));
        resolver.resolve("http://sorx", "acme", "customer", "v1");
        // After TTL expiry -> a refetch.
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn resolve_stale_on_error() {
        let calls = Arc::new(AtomicUsize::new(0));
        let source = FlakySource {
            rows: vec![row("v1", "dep-1", true, "/sor/customer")],
            calls: calls.clone(),
        };
        let resolver = AliasResolver::new(Box::new(source), Duration::from_millis(10));

        // First resolve: fetch succeeds, cache populated.
        let first = resolver.resolve("http://sorx", "acme", "customer", "v1");
        assert_eq!(first.expect("first resolve ok").deployment_id, "dep-1");

        // Let the TTL expire so the next resolve attempts a refetch (which errs).
        std::thread::sleep(Duration::from_millis(20));
        let stale = resolver.resolve("http://sorx", "acme", "customer", "v1");
        // Stale-on-error: still resolves from the last good table.
        assert_eq!(stale.expect("stale resolve ok").deployment_id, "dep-1");
        // Two fetches attempted (first ok, second errored).
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn resolve_no_cache_and_error_returns_none() {
        let calls = Arc::new(AtomicUsize::new(0));
        // Errors from the very first call -> nothing to fall back on.
        struct AlwaysErr(Arc<AtomicUsize>);
        impl RoutingTableSource for AlwaysErr {
            fn fetch(
                &self,
                _u: &str,
                _t: Option<&str>,
                _s: Option<&str>,
            ) -> Result<Vec<RouteRow>, String> {
                self.0.fetch_add(1, Ordering::SeqCst);
                Err("down".to_string())
            }
        }
        let resolver =
            AliasResolver::new(Box::new(AlwaysErr(calls.clone())), Duration::from_secs(60));
        assert!(
            resolver
                .resolve("http://sorx", "acme", "customer", "v1")
                .is_none()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn route_request_forwards_to_upstream() {
        let calls = Arc::new(AtomicUsize::new(0));
        let source = FakeSource {
            rows: vec![row("v1", "dep-1", true, "/sor/customer")],
            calls,
        };
        let resolver = AliasResolver::new(Box::new(source), Duration::from_secs(60));
        let reg = upstreams(&[("dep-1", "127.0.0.1:8088")]);

        let outcome = route_request(
            &resolver,
            &reg,
            "http://sorx",
            "GET",
            "/acme/customer/v1/orders/42",
            &[],
            &[],
        );

        match outcome {
            ProxyOutcome::Forward {
                upstream,
                rewritten_path,
                deployment_id,
            } => {
                assert_eq!(upstream, "127.0.0.1:8088");
                // rest = "orders/42" forwarded under base_path "/sor/customer".
                assert_eq!(rewritten_path, "/sor/customer/orders/42");
                assert_eq!(deployment_id, "dep-1");
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn route_request_forwards_alias_root_under_base_path() {
        let calls = Arc::new(AtomicUsize::new(0));
        let source = FakeSource {
            rows: vec![row("v1", "dep-1", true, "/sor/customer")],
            calls,
        };
        let resolver = AliasResolver::new(Box::new(source), Duration::from_secs(60));
        let reg = upstreams(&[("dep-1", "127.0.0.1:8088")]);

        // No `rest` segment -> forward base_path only.
        let outcome = route_request(
            &resolver,
            &reg,
            "http://sorx",
            "GET",
            "/acme/customer/v1",
            &[],
            &[],
        );
        match outcome {
            ProxyOutcome::Forward { rewritten_path, .. } => {
                assert_eq!(rewritten_path, "/sor/customer");
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }

    #[test]
    fn route_request_unresolved_alias_404() {
        let calls = Arc::new(AtomicUsize::new(0));
        let source = FakeSource {
            rows: vec![row("v1", "dep-1", false, "/sor/customer")], // non-routable
            calls,
        };
        let resolver = AliasResolver::new(Box::new(source), Duration::from_secs(60));
        let reg = upstreams(&[("dep-1", "127.0.0.1:8088")]);

        let outcome = route_request(
            &resolver,
            &reg,
            "http://sorx",
            "GET",
            "/acme/customer/v1/orders",
            &[],
            &[],
        );
        match outcome {
            ProxyOutcome::NotFound { status, .. } => assert_eq!(status, 404),
            other => panic!("expected 404 NotFound, got {other:?}"),
        }
    }

    #[test]
    fn route_request_no_upstream_503() {
        let calls = Arc::new(AtomicUsize::new(0));
        let source = FakeSource {
            rows: vec![row("v1", "dep-1", true, "/sor/customer")],
            calls,
        };
        let resolver = AliasResolver::new(Box::new(source), Duration::from_secs(60));
        // Alias resolves, but no upstream registered for dep-1.
        let reg = upstreams(&[("dep-other", "127.0.0.1:9999")]);

        let outcome = route_request(
            &resolver,
            &reg,
            "http://sorx",
            "GET",
            "/acme/customer/v1/orders",
            &[],
            &[],
        );
        match outcome {
            ProxyOutcome::NotFound { status, .. } => assert_eq!(status, 503),
            other => panic!("expected 503 NotFound, got {other:?}"),
        }
    }

    #[test]
    fn route_request_rejects_malformed_path() {
        let calls = Arc::new(AtomicUsize::new(0));
        let source = FakeSource {
            rows: vec![row("v1", "dep-1", true, "/sor/customer")],
            calls,
        };
        let resolver = AliasResolver::new(Box::new(source), Duration::from_secs(60));
        let reg = upstreams(&[("dep-1", "127.0.0.1:8088")]);

        for bad in ["/", "/acme", "/acme/customer", ""] {
            let outcome = route_request(&resolver, &reg, "http://sorx", "GET", bad, &[], &[]);
            match outcome {
                ProxyOutcome::NotFound { status, .. } => {
                    assert_eq!(status, 400, "path {bad:?} should be 400")
                }
                other => panic!("expected 400 for {bad:?}, got {other:?}"),
            }
        }
    }

    #[test]
    fn parse_request_path_variants() {
        let p = parse_request_path("/acme/customer/v1/orders/42").unwrap();
        assert_eq!(p.tenant, "acme");
        assert_eq!(p.sor, "customer");
        assert_eq!(p.alias, "v1");
        assert_eq!(p.rest, "orders/42");

        // No rest.
        let p = parse_request_path("/acme/customer/v1").unwrap();
        assert_eq!(p.rest, "");

        // Query string stripped.
        let p = parse_request_path("/acme/customer/v1/orders?page=2").unwrap();
        assert_eq!(p.rest, "orders");

        // Too few segments.
        assert!(parse_request_path("/acme/customer").is_none());
    }

    #[test]
    fn rewrite_path_normalizes_slashes() {
        assert_eq!(
            rewrite_path("/sor/customer", "orders/42"),
            "/sor/customer/orders/42"
        );
        assert_eq!(
            rewrite_path("/sor/customer/", "/orders"),
            "/sor/customer/orders"
        );
        assert_eq!(rewrite_path("/sor/customer", ""), "/sor/customer");
        assert_eq!(rewrite_path("", "orders"), "/orders");
        assert_eq!(rewrite_path("", ""), "/");
    }

    #[test]
    fn describe_request_serializes_forward() {
        let calls = Arc::new(AtomicUsize::new(0));
        let source = FakeSource {
            rows: vec![row("v1", "dep-1", true, "/sor/customer")],
            calls,
        };
        let resolver = AliasResolver::new(Box::new(source), Duration::from_secs(60));
        let reg = upstreams(&[("dep-1", "127.0.0.1:8088")]);

        let decision = describe_request(
            &resolver,
            &reg,
            "http://sorx",
            "GET",
            "/acme/customer/v1/orders",
        );
        let json = serde_json::to_value(&decision).unwrap();
        assert_eq!(json["outcome"]["kind"], "forward");
        assert_eq!(json["outcome"]["upstream"], "127.0.0.1:8088");
        assert_eq!(json["outcome"]["rewritten_path"], "/sor/customer/orders");
    }

    #[test]
    fn routing_table_deserializes_with_unknown_fields() {
        // A SoRX schema bump (extra field) must not break decode.
        let raw = r#"{
            "schema": "sorx.routing-table.v1",
            "routes": [
                {
                    "tenant_id": "acme",
                    "sor_name": "customer",
                    "alias": "v1",
                    "deployment_id": "dep-1",
                    "pack_name": "pack",
                    "pack_version": "1.0.0",
                    "base_path": "/sor/customer",
                    "state_namespace": "ns",
                    "visibility": "public",
                    "routable": true,
                    "traffic": {"mode": "all"},
                    "future_field": "ignored"
                }
            ]
        }"#;
        let table: RoutingTable = serde_json::from_str(raw).unwrap();
        assert_eq!(table.routes.len(), 1);
        assert_eq!(table.routes[0].deployment_id, "dep-1");
    }

    #[test]
    fn routing_table_decodes_real_sorx_traffic_shapes() {
        // Regression: SoRX emits `traffic` as an OBJECT (`{"mode":"all"}`), not
        // a number, and may omit it or send `null`. The decoder must accept all
        // three; a previous `traffic: u32` field silently failed to decode the
        // real wire shape, which collapsed the routing-table to zero rows and
        // turned every Forward into a 404. Caught by a live e2e against a real
        // SoRX instance (the FakeSource unit tests fed a hand-built `u32`).
        let raw = r#"{
            "schema": "greentic.sorx.public-routes.v1",
            "routes": [
                {
                    "tenant_id": "acme", "sor_name": "landlord", "alias": "stable",
                    "deployment_id": "dep-obj", "pack_name": "p", "pack_version": "0.1.0",
                    "base_path": "/acme/landlord", "state_namespace": "ns",
                    "visibility": "private", "routable": true,
                    "traffic": {"mode": "all"}
                },
                {
                    "tenant_id": "acme", "sor_name": "landlord", "alias": "canary",
                    "deployment_id": "dep-null", "pack_name": "p", "pack_version": "0.2.0",
                    "base_path": "/acme/landlord", "state_namespace": "ns",
                    "visibility": "private", "routable": false,
                    "traffic": null
                },
                {
                    "tenant_id": "acme", "sor_name": "landlord", "alias": "absent",
                    "deployment_id": "dep-absent", "pack_name": "p", "pack_version": "0.3.0",
                    "base_path": "/acme/landlord", "state_namespace": "ns",
                    "visibility": "private", "routable": false
                }
            ]
        }"#;
        let table: RoutingTable = serde_json::from_str(raw).unwrap();
        assert_eq!(table.routes.len(), 3);
        assert_eq!(
            table.routes[0].traffic,
            Some(TrafficSplit {
                mode: "all".to_string(),
                percent: None
            })
        );
        assert_eq!(table.routes[1].traffic, None, "null traffic -> None");
        assert_eq!(table.routes[2].traffic, None, "absent traffic -> None");

        // And the row still resolves + forwards end-to-end.
        let source = FakeSource {
            rows: table.routes.clone(),
            calls: Arc::new(AtomicUsize::new(0)),
        };
        let resolver = AliasResolver::new(Box::new(source), Duration::from_secs(60));
        let reg = upstreams(&[("dep-obj", "127.0.0.1:9090")]);
        match route_request(
            &resolver,
            &reg,
            "http://sorx",
            "GET",
            "/acme/landlord/stable/v1/agent/tenancies/t-1",
            &[],
            &[],
        ) {
            ProxyOutcome::Forward {
                upstream,
                deployment_id,
                ..
            } => {
                assert_eq!(upstream, "127.0.0.1:9090");
                assert_eq!(deployment_id, "dep-obj");
            }
            other => panic!("expected Forward, got {other:?}"),
        }
    }
}
