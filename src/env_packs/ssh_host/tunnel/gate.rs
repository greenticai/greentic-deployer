//! The destination gate.
//!
//! A helper's SOCKS5 port (ocproxy, wireproxy, tailscaled) connects to anything
//! its network can reach, and any process in the container can reach a loopback
//! port. So `ssh` never talks to the helper: its `ProxyCommand` goes to THIS
//! gate, an in-process SOCKS5 listener on its own random loopback port that
//! forwards exactly one destination, the VM (`host:port`), and refuses every
//! other CONNECT before anything is dialled. The gate then dials the upstream
//! (a helper's SOCKS5 port, or a customer's SOCKS5/HTTP proxy) itself.
//!
//! Residual risk, stated plainly: another process in the same container can
//! still ask the gate for the VM (which is all it can get) and can still reach
//! the helper's raw port directly. Isolation between tenants is the container's
//! job; this closes "the tunnel as a general-purpose pivot", not that.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use super::guard::TunnelGuard;
use super::support::{BasicAuth, http_connect, socks5_connect};

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(15);

/// Where the gate forwards the one permitted destination.
#[derive(Clone)]
pub enum Upstream {
    /// A SOCKS5 proxy (a helper's, or the customer's), optionally with RFC 1929 credentials.
    Socks5 {
        addr: SocketAddr,
        auth: Option<BasicAuth>,
    },
    /// An HTTP proxy that accepts `CONNECT`, optionally with Basic credentials.
    HttpConnect {
        addr: SocketAddr,
        auth: Option<BasicAuth>,
    },
}

impl Upstream {
    fn dial(&self, host: &str, port: u16) -> std::io::Result<TcpStream> {
        match self {
            Upstream::Socks5 { addr, auth } => {
                socks5_connect(*addr, host, port, auth.as_ref(), UPSTREAM_TIMEOUT)
            }
            Upstream::HttpConnect { addr, auth } => {
                http_connect(*addr, host, port, auth.as_ref(), UPSTREAM_TIMEOUT)
            }
        }
    }
}

/// Start the gate for `allowed_host:allowed_port`; its loopback port is returned
/// and its thread is stopped (and the listener closed) when `guard` drops.
pub fn start(
    upstream: Upstream,
    allowed_host: String,
    allowed_port: u16,
    guard: &mut TunnelGuard,
) -> std::io::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    let port = listener.local_addr()?.port();
    let stop = Arc::new(AtomicBool::new(false));
    let stop_thread = Arc::clone(&stop);
    let handle = std::thread::spawn(move || {
        for incoming in listener.incoming() {
            if stop_thread.load(Ordering::SeqCst) {
                return;
            }
            let Ok(client) = incoming else { continue };
            let upstream = upstream.clone();
            let host = allowed_host.clone();
            std::thread::spawn(move || {
                let _ = serve(client, &upstream, &host, allowed_port);
            });
        }
    });
    guard.on_drop(move || {
        stop.store(true, Ordering::SeqCst);
        // Wake the blocked `accept` so the thread sees the flag.
        let _ = TcpStream::connect((Ipv4Addr::LOCALHOST, port));
        let _ = handle.join();
    });
    Ok(port)
}

fn reply(client: &mut TcpStream, code: u8) -> std::io::Result<()> {
    client.write_all(&[5, code, 0, 1, 0, 0, 0, 0, 0, 0])
}

fn serve(mut client: TcpStream, upstream: &Upstream, host: &str, port: u16) -> std::io::Result<()> {
    client.set_read_timeout(Some(HANDSHAKE_TIMEOUT))?;
    client.set_write_timeout(Some(HANDSHAKE_TIMEOUT))?;
    let mut head = [0u8; 2];
    client.read_exact(&mut head)?;
    if head[0] != 5 {
        return Ok(());
    }
    let mut methods = vec![0u8; usize::from(head[1])];
    client.read_exact(&mut methods)?;
    if !methods.contains(&0) {
        client.write_all(&[5, 0xff])?;
        return Ok(());
    }
    client.write_all(&[5, 0])?;

    let mut req = [0u8; 4];
    client.read_exact(&mut req)?;
    if req[0] != 5 || req[1] != 1 {
        return reply(&mut client, 7); // command not supported
    }
    let asked_host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            client.read_exact(&mut a)?;
            Ipv4Addr::from(a).to_string()
        }
        3 => {
            let mut len = [0u8; 1];
            client.read_exact(&mut len)?;
            let mut name = vec![0u8; usize::from(len[0])];
            client.read_exact(&mut name)?;
            String::from_utf8_lossy(&name).into_owned()
        }
        _ => return reply(&mut client, 8), // address type not supported
    };
    let mut p = [0u8; 2];
    client.read_exact(&mut p)?;
    let asked_port = u16::from_be_bytes(p);

    if !asked_host.eq_ignore_ascii_case(host) || asked_port != port {
        return reply(&mut client, 2); // not allowed by ruleset
    }
    let remote = match upstream.dial(host, port) {
        Ok(r) => r,
        Err(_) => return reply(&mut client, 5), // connection refused
    };
    reply(&mut client, 0)?;
    client.set_read_timeout(None)?;
    remote.set_read_timeout(None)?;
    relay(client, remote)
}

fn relay(client: TcpStream, remote: TcpStream) -> std::io::Result<()> {
    let (mut c_read, mut c_write) = (client.try_clone()?, client);
    let (mut r_read, mut r_write) = (remote.try_clone()?, remote);
    let up = std::thread::spawn(move || {
        let _ = std::io::copy(&mut c_read, &mut r_write);
        let _ = r_write.shutdown(Shutdown::Write);
    });
    let _ = std::io::copy(&mut r_read, &mut c_write);
    let _ = c_write.shutdown(Shutdown::Write);
    let _ = up.join();
    Ok(())
}

/// The helper process whose early exit aborts the readiness wait, and how to
/// word that exit for the operator. `explain` must not quote helper output.
pub struct HelperWatch<'a> {
    pub index: usize,
    pub explain: Box<dyn Fn(std::process::ExitStatus) -> String + 'a>,
}

/// The last step of every helper-based provider: put the gate in front of
/// `upstream`, prove the tunnel carries traffic (SOCKS5 CONNECT through the gate
/// to the VM, answered by an `SSH-` banner) within `ctx.ready_timeout`, and
/// return the finished [`TunnelUp`]. `helper` names the adopted child whose early
/// exit should abort the wait. On failure `guard` is dropped, which
/// tears everything down.
pub fn publish(
    kind: &str,
    ctx: &super::TunnelContext<'_>,
    upstream: Upstream,
    mut guard: TunnelGuard,
    helper: Option<HelperWatch<'_>>,
) -> Result<super::TunnelUp, super::TunnelError> {
    let fail = |detail: String| super::TunnelError::up(kind, detail);
    let port = start(
        upstream,
        ctx.target_host.to_string(),
        ctx.target_port,
        &mut guard,
    )
    .map_err(|e| fail(format!("could not start the local gate ({})", e.kind())))?;
    let gate_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    super::support::wait_until_ssh_reachable(
        gate_addr,
        ctx.target_host,
        ctx.target_port,
        ctx.ready_timeout,
        || {
            let watch = helper.as_ref()?;
            guard
                .child_exit(watch.index)
                .map(|status| (watch.explain)(status))
        },
    )
    .map_err(fail)?;
    Ok(super::TunnelUp {
        proxy_command: Some(super::support::socks5_proxy_command(port)),
        guard,
    })
}
