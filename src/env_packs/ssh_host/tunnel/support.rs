//! Helpers shared by the providers. See the module docs of [`super`] for the
//! contract they implement.

use std::io::{Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use zeroize::Zeroizing;

use crate::env_packs::ssh_host::remote::shell_quote;

/// A currently free TCP port on `127.0.0.1`. Another process can take it before
/// the caller's helper binds it; the readiness check notices when it does.
pub fn free_loopback_port() -> std::io::Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
    Ok(listener.local_addr()?.port())
}

/// Spawn a helper with stdin, stdout and stderr on /dev/null, so it can never
/// block on an unread pipe and its output (which may echo a secret) goes
/// nowhere. Providers that need the output redirect stderr to a scratch file
/// instead and classify it, never quoting it.
pub fn spawn_silent(command: &mut Command) -> std::io::Result<Child> {
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
}

/// Quote and join an argv into the one string `ProxyCommand` takes.
pub fn shell_quote_all(argv: &[String]) -> String {
    argv.iter()
        .map(|a| shell_quote(a))
        .collect::<Vec<_>>()
        .join(" ")
}

/// The `ProxyCommand` that connects through a SOCKS5 proxy on
/// `127.0.0.1:<port>` (OpenBSD `nc`, `-X 5 -x host:port`). `%h` and `%p` are
/// expanded by ssh. The port is always the deployer's own gate, never a helper's.
pub fn socks5_proxy_command(port: u16) -> String {
    let argv: Vec<String> = [
        "nc",
        "-X",
        "5",
        "-x",
        &format!("127.0.0.1:{port}"),
        "%h",
        "%p",
    ]
    .iter()
    .map(|a| a.to_string())
    .collect();
    shell_quote_all(&argv)
}

/// Why an address may never be a tunnel's target or a customer proxy: it would
/// turn the deployer into a way to reach itself or its cloud's metadata service.
pub fn refused_address_class(ip: IpAddr) -> Option<&'static str> {
    match ip {
        IpAddr::V4(v4) => refused_v4(v4),
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => refused_v4(v4),
            None => refused_v6(v6),
        },
    }
}

fn refused_v4(ip: Ipv4Addr) -> Option<&'static str> {
    if ip.is_loopback() {
        Some("loopback")
    } else if ip.is_unspecified() {
        Some("unspecified")
    } else if ip.is_link_local() {
        Some("link-local (cloud metadata)")
    } else if ip.is_multicast() || ip.is_broadcast() {
        Some("multicast or broadcast")
    } else {
        None
    }
}

fn refused_v6(ip: Ipv6Addr) -> Option<&'static str> {
    if ip.is_loopback() {
        Some("loopback")
    } else if ip.is_unspecified() {
        Some("unspecified")
    } else if ip.is_multicast() {
        Some("multicast")
    } else if (ip.segments()[0] & 0xffc0) == 0xfe80 {
        Some("link-local")
    } else {
        None
    }
}

/// `Err(reason)` when `host` is a literal IP in a refused class. A name is not
/// resolved here: VPN providers resolve it on the far side, and the `proxy`
/// kind resolves and pins its own proxy address.
pub fn check_literal_target(host: &str) -> Result<(), String> {
    match host.parse::<IpAddr>() {
        Ok(ip) => match refused_address_class(ip) {
            Some(class) => Err(format!(
                "the target address is {class}, which a tunnel never reaches"
            )),
            None => Ok(()),
        },
        Err(_) => {
            // `inet_aton` spellings (`0x7f.1`, `2130706433`) are not IpAddr
            // literals but ssh would still read them as addresses.
            let numeric = host.starts_with(|c: char| c.is_ascii_digit())
                && (host.to_ascii_lowercase().contains("0x")
                    || host.chars().all(|c| c.is_ascii_digit() || c == '.'));
            if numeric && host.parse::<Ipv4Addr>().is_err() {
                return Err(
                    "the target looks like a non-canonical numeric address; write it as a.b.c.d"
                        .into(),
                );
            }
            Ok(())
        }
    }
}

/// Read a secret from the file whose PATH an operator set. On unix a file
/// readable by group or others is refused: the designer materialises these at
/// 0600 in a 0700 directory. Never echoes the path or the content.
pub fn read_secret_file(key: &str, path: &str) -> Result<Zeroizing<String>, String> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let meta = std::fs::metadata(path)
            .map_err(|e| format!("`{key}` cannot be read ({})", e.kind()))?;
        if !meta.is_file() {
            return Err(format!("`{key}` is not a file"));
        }
        if meta.permissions().mode() & 0o077 != 0 {
            return Err(format!(
                "`{key}` is readable by group or others; it must be mode 0600"
            ));
        }
    }
    let raw = std::fs::read_to_string(path)
        .map_err(|e| format!("`{key}` cannot be read ({})", e.kind()))?;
    let raw = Zeroizing::new(raw);
    let trimmed = raw.trim_end_matches(['\n', '\r']);
    if trimmed.is_empty() {
        return Err(format!("`{key}` is empty"));
    }
    if trimmed.contains(['\n', '\r', '\0']) {
        return Err(format!("`{key}` must hold a single line"));
    }
    Ok(Zeroizing::new(trimmed.to_string()))
}

// ---- SOCKS5 client (readiness probe and the gate's upstream) ---------------

const SOCKS_VERSION: u8 = 5;

/// What a SOCKS5/HTTP CONNECT attempt ended with.
pub type IoResult<T> = std::io::Result<T>;

fn invalid(msg: &str) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::InvalidData, msg.to_string())
}

/// Credentials for RFC 1929 username/password sub-negotiation.
#[derive(Clone)]
pub struct BasicAuth {
    pub user: Zeroizing<String>,
    pub password: Zeroizing<String>,
}

fn socks5_request(host: &str, port: u16) -> IoResult<Vec<u8>> {
    let mut req = vec![SOCKS_VERSION, 1, 0];
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            req.push(1);
            req.extend_from_slice(&v4.octets());
        }
        Ok(IpAddr::V6(v6)) => {
            req.push(4);
            req.extend_from_slice(&v6.octets());
        }
        Err(_) => {
            let len = u8::try_from(host.len()).map_err(|_| invalid("host name too long"))?;
            req.push(3);
            req.push(len);
            req.extend_from_slice(host.as_bytes());
        }
    }
    req.extend_from_slice(&port.to_be_bytes());
    Ok(req)
}

/// Connect to `proxy`, speak SOCKS5 and CONNECT to `host:port`. The returned
/// stream is the tunnel to the target.
pub fn socks5_connect(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    auth: Option<&BasicAuth>,
    timeout: Duration,
) -> IoResult<TcpStream> {
    let mut s = TcpStream::connect_timeout(&proxy, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    if auth.is_some() {
        s.write_all(&[SOCKS_VERSION, 2, 0x00, 0x02])?;
    } else {
        s.write_all(&[SOCKS_VERSION, 1, 0x00])?;
    }
    let mut choice = [0u8; 2];
    s.read_exact(&mut choice)?;
    if choice[0] != SOCKS_VERSION {
        return Err(invalid("not a SOCKS5 proxy"));
    }
    match (choice[1], auth) {
        (0x00, _) => {}
        (0x02, Some(a)) => {
            let (u, p) = (a.user.as_bytes(), a.password.as_bytes());
            let (ul, pl) = (
                u8::try_from(u.len()).map_err(|_| invalid("proxy user too long"))?,
                u8::try_from(p.len()).map_err(|_| invalid("proxy password too long"))?,
            );
            let mut msg = Zeroizing::new(vec![1u8, ul]);
            msg.extend_from_slice(u);
            msg.push(pl);
            msg.extend_from_slice(p);
            s.write_all(&msg)?;
            let mut reply = [0u8; 2];
            s.read_exact(&mut reply)?;
            if reply[1] != 0 {
                return Err(invalid("the proxy refused the credentials"));
            }
        }
        _ => {
            return Err(invalid(
                "the proxy wants an authentication method we do not offer",
            ));
        }
    }
    s.write_all(&socks5_request(host, port)?)?;
    let mut head = [0u8; 4];
    s.read_exact(&mut head)?;
    if head[0] != SOCKS_VERSION {
        return Err(invalid("malformed SOCKS5 reply"));
    }
    if head[1] != 0 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 CONNECT refused (code {})", head[1]),
        ));
    }
    let skip = match head[3] {
        1 => 4 + 2,
        4 => 16 + 2,
        3 => {
            let mut len = [0u8; 1];
            s.read_exact(&mut len)?;
            usize::from(len[0]) + 2
        }
        _ => return Err(invalid("malformed SOCKS5 reply")),
    };
    let mut rest = vec![0u8; skip];
    s.read_exact(&mut rest)?;
    Ok(s)
}

/// Connect through an HTTP proxy with `CONNECT host:port`.
pub fn http_connect(
    proxy: SocketAddr,
    host: &str,
    port: u16,
    auth: Option<&BasicAuth>,
    timeout: Duration,
) -> IoResult<TcpStream> {
    use base64::Engine as _;
    let mut s = TcpStream::connect_timeout(&proxy, timeout)?;
    s.set_read_timeout(Some(timeout))?;
    s.set_write_timeout(Some(timeout))?;
    let mut req = format!("CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n");
    if let Some(a) = auth {
        let token = Zeroizing::new(
            base64::engine::general_purpose::STANDARD
                .encode(format!("{}:{}", &*a.user, &*a.password)),
        );
        req.push_str(&format!("Proxy-Authorization: Basic {}\r\n", &*token));
    }
    req.push_str("\r\n");
    let req = Zeroizing::new(req);
    s.write_all(req.as_bytes())?;
    // Byte at a time: reading past the blank line would swallow tunnel data.
    let mut head = Vec::with_capacity(256);
    let mut byte = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() > 8192 {
            return Err(invalid("proxy reply too long"));
        }
        s.read_exact(&mut byte)?;
        head.push(byte[0]);
    }
    let line = head.split(|b| *b == b'\r').next().unwrap_or_default();
    let ok = line.starts_with(b"HTTP/1.") && line.get(8..12) == Some(b" 200".as_slice());
    if ok {
        Ok(s)
    } else {
        Err(std::io::Error::new(
            std::io::ErrorKind::ConnectionRefused,
            "the HTTP proxy refused CONNECT",
        ))
    }
}

/// One readiness attempt: SOCKS5 CONNECT through `gate`, then the target must
/// speak first with an `SSH-` banner. A listener that merely accepts proves
/// nothing (WireGuard's, Tailscale's and ocproxy's all come up before the
/// tunnel carries traffic).
pub fn probe_ssh_banner(
    gate: SocketAddr,
    host: &str,
    port: u16,
    timeout: Duration,
) -> Result<(), String> {
    let mut s = socks5_connect(gate, host, port, None, timeout).map_err(|e| e.to_string())?;
    let deadline = Instant::now() + timeout;
    let mut got = Vec::with_capacity(8);
    let mut buf = [0u8; 8];
    while got.len() < 4 {
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err("the target sent no banner in time".into());
        }
        s.set_read_timeout(Some(left)).map_err(|e| e.to_string())?;
        match s.read(&mut buf) {
            Ok(0) => return Err("the target closed the connection before a banner".into()),
            Ok(n) => got.extend_from_slice(&buf[..n]),
            Err(e) => return Err(e.to_string()),
        }
    }
    if got.starts_with(b"SSH-") {
        Ok(())
    } else {
        Err("the target did not answer with an SSH banner".into())
    }
}

/// Poll [`probe_ssh_banner`] until it passes, `alive` reports the helper gone,
/// or `timeout` runs out. `alive` returns `Some(reason)` when the helper died.
pub fn wait_until_ssh_reachable(
    gate: SocketAddr,
    host: &str,
    port: u16,
    timeout: Duration,
    mut helper_gone: impl FnMut() -> Option<String>,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut last = String::from("no attempt was made");
    loop {
        if let Some(reason) = helper_gone() {
            return Err(reason);
        }
        let left = deadline.saturating_duration_since(Instant::now());
        if left.is_zero() {
            return Err(format!(
                "the target did not become reachable within {}s ({last})",
                timeout.as_secs()
            ));
        }
        match probe_ssh_banner(gate, host, port, left.min(Duration::from_secs(8))) {
            Ok(()) => return Ok(()),
            Err(e) => last = e,
        }
        std::thread::sleep(Duration::from_millis(500).min(left));
    }
}

/// Whether `path` names an existing regular file (for non-secret inputs).
pub fn is_file(path: &str) -> bool {
    Path::new(path).is_file()
}
