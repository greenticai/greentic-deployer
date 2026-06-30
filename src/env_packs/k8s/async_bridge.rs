//! Sync→async bridge for the K8s env-pack.
//!
//! The deployer CLI is synchronous (the A8 contract lives at the HTTP edge,
//! not inside the CLI). The K8s credential probes and the `op env reconcile`
//! cluster calls are async, so they cross the boundary through a dedicated
//! thread running a fresh current-thread runtime.
//!
//! `tokio::task::block_in_place` PANICS on a current-thread parent runtime
//! (the prod cloud-deploy CLI uses one) and `Handle::block_on` self-deadlocks
//! inside any runtime — the dedicated-thread hop is the only flavor-agnostic
//! shape (B12a precedent). Shared by [`credentials`](super::credentials) and
//! the reconcile path so both bridge identically.

/// Run `fut` to completion on a dedicated thread with its own current-thread
/// runtime, returning its output. The scoped thread borrows non-`'static`
/// captures (e.g. `&Environment`), so callers need not clone the world in.
pub(crate) fn run_k8s_async<F, T>(fut: F) -> T
where
    F: std::future::Future<Output = T> + Send,
    T: Send,
{
    std::thread::scope(|scope| {
        scope
            .spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("build current-thread tokio runtime");
                rt.block_on(fut)
            })
            .join()
            .expect("K8s async bridge thread did not panic")
    })
}
