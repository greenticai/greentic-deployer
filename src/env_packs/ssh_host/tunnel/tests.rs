//! Tunnel framework tests: registry, settings, guard, gate, `none`, `jump`,
//! `proxy` and the ssh argv. No test leaves loopback.

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::gate::{self, Upstream};
use super::support::{self, socks5_connect};
use super::*;
use crate::env_packs::ssh_host::remote::{
    RemoteTarget, shell_quote, ssh_args, ssh_invocation, upload_command,
};

pub(super) fn map(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
    pairs
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_string()))
        .collect()
}

fn config(kind: &str, pairs: &[(&str, &str)]) -> TunnelConfig {
    TunnelConfig {
        kind: kind.into(),
        settings: map(pairs),
    }
}

// ---- fakes: a SOCKS5 server and an HTTP CONNECT proxy on loopback ----------

/// Answers every SOCKS5 CONNECT with success and then an SSH banner, and records
/// what was asked for.
pub(super) struct FakeServer {
    pub port: u16,
    pub asked: Arc<Mutex<Vec<String>>>,
    stop: Arc<AtomicBool>,
}

impl Drop for FakeServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect((Ipv4Addr::LOCALHOST, self.port));
    }
}

fn spawn_server(port: u16, handler: fn(TcpStream, &Mutex<Vec<String>>)) -> FakeServer {
    try_spawn_server(port, handler).expect("bind a loopback port")
}

fn try_spawn_server(port: u16, handler: fn(TcpStream, &Mutex<Vec<String>>)) -> Option<FakeServer> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, port)).ok()?;
    let port = listener.local_addr().unwrap().port();
    let asked = Arc::new(Mutex::new(Vec::new()));
    let stop = Arc::new(AtomicBool::new(false));
    let (asked_t, stop_t) = (Arc::clone(&asked), Arc::clone(&stop));
    std::thread::spawn(move || {
        for conn in listener.incoming() {
            if stop_t.load(Ordering::SeqCst) {
                return;
            }
            if let Ok(conn) = conn {
                let asked = Arc::clone(&asked_t);
                std::thread::spawn(move || handler(conn, &asked));
            }
        }
    });
    Some(FakeServer { port, asked, stop })
}

fn socks_handler(mut c: TcpStream, asked: &Mutex<Vec<String>>) {
    let mut head = [0u8; 2];
    if c.read_exact(&mut head).is_err() {
        return;
    }
    let mut methods = vec![0u8; head[1] as usize];
    let _ = c.read_exact(&mut methods);
    let _ = c.write_all(&[5, 0]);
    let mut req = [0u8; 4];
    if c.read_exact(&mut req).is_err() {
        return;
    }
    let host = match req[3] {
        1 => {
            let mut a = [0u8; 4];
            let _ = c.read_exact(&mut a);
            Ipv4Addr::from(a).to_string()
        }
        _ => {
            let mut l = [0u8; 1];
            let _ = c.read_exact(&mut l);
            let mut n = vec![0u8; l[0] as usize];
            let _ = c.read_exact(&mut n);
            String::from_utf8_lossy(&n).into_owned()
        }
    };
    let mut p = [0u8; 2];
    let _ = c.read_exact(&mut p);
    asked
        .lock()
        .unwrap()
        .push(format!("{host}:{}", u16::from_be_bytes(p)));
    let _ = c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    let _ = c.write_all(b"SSH-2.0-fake\r\n");
    std::thread::sleep(Duration::from_millis(100));
}

fn http_handler(mut c: TcpStream, asked: &Mutex<Vec<String>>) {
    let mut head = Vec::new();
    let mut b = [0u8; 1];
    while !head.ends_with(b"\r\n\r\n") {
        if c.read_exact(&mut b).is_err() {
            return;
        }
        head.push(b[0]);
    }
    let text = String::from_utf8_lossy(&head).into_owned();
    let line = text.lines().next().unwrap_or_default().to_string();
    let auth = text
        .lines()
        .find(|l| l.starts_with("Proxy-Authorization"))
        .map_or(String::new(), |l| format!(" [{l}]"));
    asked.lock().unwrap().push(format!("{line}{auth}"));
    let _ = c.write_all(b"HTTP/1.1 200 Connection established\r\n\r\n");
    let _ = c.write_all(b"SSH-2.0-fake\r\n");
    std::thread::sleep(Duration::from_millis(100));
}

pub(super) fn fake_socks(port: u16) -> FakeServer {
    spawn_server(port, socks_handler)
}

/// For a port someone else chose (the provider's): another test may have taken
/// it in the moment between the provider releasing it and this bind.
pub(super) fn try_fake_socks(port: u16) -> Option<FakeServer> {
    try_spawn_server(port, socks_handler)
}

fn fake_http_proxy() -> FakeServer {
    spawn_server(0, http_handler)
}

pub(super) fn ctx<'a>(settings: &'a BTreeMap<String, String>, host: &'a str) -> TunnelContext<'a> {
    TunnelContext {
        settings,
        login_user: "greentic",
        target_host: host,
        target_port: 22,
        ready_timeout: Duration::from_secs(5),
    }
}

// ---- registry --------------------------------------------------------------

#[test]
fn the_registry_knows_every_kind_and_refuses_the_rest() {
    let registry = TunnelRegistry::builtin();
    for kind in [
        "none",
        "jump",
        "proxy",
        "openconnect",
        "wireguard",
        "tailscale",
        "openvpn",
        "ikev2",
        "zerotier",
    ] {
        assert!(registry.get(kind).is_ok(), "{kind}");
    }
    let err = registry.get("carrier-pigeon").unwrap_err();
    assert!(matches!(err, TunnelError::UnknownKind { .. }));
    assert!(err.to_string().contains("known kinds"), "{err}");
}

#[test]
fn an_unknown_kind_is_shown_escaped_and_bounded() {
    let err = TunnelRegistry::builtin()
        .get("x\n$(id)\u{1b}[31m-and-a-very-very-very-very-long-kind-name")
        .unwrap_err()
        .to_string();
    assert!(!err.contains('\n') && !err.contains('\u{1b}'), "{err:?}");
    assert!(!err.contains("very-long"), "{err}");
}

#[test]
fn none_takes_no_settings_and_brings_nothing_up() {
    let registry = TunnelRegistry::builtin();
    registry.validate(&config("none", &[])).unwrap();
    assert!(registry.validate(&config("none", &[("a", "b")])).is_err());
    let up = registry
        .up(&config("none", &[]), "greentic", "vm.example.com", 22)
        .unwrap();
    assert!(up.proxy_command.is_none());
    assert!(up.guard.is_empty());
}

#[test]
fn recognised_kinds_that_cannot_come_up_refuse_before_starting_anything() {
    let registry = TunnelRegistry::builtin();
    for kind in ["wireguard", "tailscale", "openvpn", "ikev2", "zerotier"] {
        let cfg = config(kind, &[("endpoint", "vpn.example.com")]);
        registry.validate(&cfg).unwrap();
        match registry.up(&cfg, "greentic", "vm.example.com", 22) {
            Err(TunnelError::NotImplemented { .. }) => {}
            other => panic!("{kind}: {other:?}"),
        }
    }
    let runner = registry
        .up(&config("openvpn", &[]), "greentic", "vm.example.com", 22)
        .unwrap_err()
        .to_string();
    assert!(runner.contains("runner"), "{runner}");
}

#[test]
fn the_registry_refuses_a_loopback_or_metadata_target_before_any_provider_runs() {
    let registry = TunnelRegistry::builtin();
    let cfg = config(
        "jump",
        &[
            ("jump_host", "bastion.example.com"),
            ("jump_known_hosts_file", "/etc/kh"),
        ],
    );
    for target in [
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "::1",
        "0x7f.1",
        "2130706433",
    ] {
        let err = registry.up(&cfg, "greentic", target, 22);
        assert!(err.is_err(), "{target} must be refused");
    }
    assert!(registry.up(&cfg, "greentic", "10.1.2.3", 22).is_ok());
}

#[test]
fn address_classes() {
    use std::net::IpAddr;
    for refused in [
        "127.0.0.1",
        "169.254.169.254",
        "0.0.0.0",
        "224.0.0.1",
        "::1",
        "fe80::1",
        "::ffff:127.0.0.1",
    ] {
        let ip: IpAddr = refused.parse().unwrap();
        assert!(support::refused_address_class(ip).is_some(), "{refused}");
    }
    for fine in ["10.0.0.5", "192.168.1.1", "203.0.113.9", "2001:db8::1"] {
        let ip: IpAddr = fine.parse().unwrap();
        assert!(support::refused_address_class(ip).is_none(), "{fine}");
    }
}

// ---- settings --------------------------------------------------------------

#[test]
fn jump_settings_reject_injection_in_every_field() {
    let good = [
        ("jump_host", "bastion.example.com"),
        ("jump_known_hosts_file", "/etc/kh"),
    ];
    let registry = TunnelRegistry::builtin();
    registry.validate(&config("jump", &good)).unwrap();
    let evil = [
        "a b",
        "a;b",
        "$(id)",
        "`id`",
        "a'b",
        "a\"b",
        "a\nb",
        "-oProxyCommand=x",
        "a/../b",
        "a|b",
        "a&b",
        "a>b",
        "a\\b",
        "",
    ];
    for field in [
        "jump_host",
        "jump_user",
        "jump_identity_file",
        "jump_known_hosts_file",
        "jump_port",
    ] {
        for value in evil {
            let mut s = map(&good);
            s.insert(field.into(), value.into());
            let cfg = TunnelConfig {
                kind: "jump".into(),
                settings: s,
            };
            assert!(
                registry.validate(&cfg).is_err(),
                "{field}={value:?} was accepted"
            );
        }
    }
    // A path must be absolute; `..` and empty segments are out.
    for value in ["relative/kh", "/etc//kh", "/etc/./kh", "/"] {
        let mut s = map(&good);
        s.insert("jump_known_hosts_file".into(), value.into());
        let cfg = TunnelConfig {
            kind: "jump".into(),
            settings: s,
        };
        assert!(registry.validate(&cfg).is_err(), "{value:?}");
    }
}

#[test]
fn settings_are_strict_about_unknown_and_missing_keys_and_never_echo_values() {
    let registry = TunnelRegistry::builtin();
    let err = registry
        .validate(&config("jump", &[("jump_host", "b.example.com")]))
        .unwrap_err()
        .to_string();
    assert!(
        err.contains("jump_known_hosts_file") && err.contains("required"),
        "{err}"
    );
    let err = registry
        .validate(&config(
            "jump",
            &[
                ("jump_host", "b.example.com"),
                ("jump_known_hosts_file", "/kh"),
                ("extra", "1"),
            ],
        ))
        .unwrap_err()
        .to_string();
    assert!(err.contains("unknown setting"), "{err}");
    let err = registry
        .validate(&config(
            "jump",
            &[
                ("jump_host", "SECRET;rm -rf"),
                ("jump_known_hosts_file", "/kh"),
            ],
        ))
        .unwrap_err()
        .to_string();
    assert!(!err.contains("SECRET"), "{err}");
    let dbg = format!(
        "{:?}",
        config("jump", &[("jump_identity_file", "/home/me/key")])
    );
    assert!(!dbg.contains("/home/me/key"), "{dbg}");
}

#[test]
fn a_jump_bastion_may_not_be_loopback_or_metadata() {
    let registry = TunnelRegistry::builtin();
    for host in ["127.0.0.1", "169.254.169.254"] {
        let cfg = config(
            "jump",
            &[("jump_host", host), ("jump_known_hosts_file", "/kh")],
        );
        assert!(registry.validate(&cfg).is_err(), "{host}");
    }
}

#[test]
fn pin_sha256_must_be_a_real_digest() {
    let b64 = format!("pin-sha256:{}=", "A".repeat(43));
    let hex = format!("pin-sha256:{}", "ab".repeat(32));
    for ok in [b64.as_str(), hex.as_str()] {
        assert!(
            super::settings::validate_settings(
                "t",
                &[SettingSpec::required("servercert", ValueKind::PinSha256)],
                &map(&[("servercert", ok)])
            )
            .is_ok()
        );
    }
    for bad in [
        "sha256:abc",
        "pin-sha256:",
        "pin-sha256:short",
        "pin-sha256:$(id)AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
        "AAAA",
    ] {
        assert!(
            super::settings::validate_settings(
                "t",
                &[SettingSpec::required("servercert", ValueKind::PinSha256)],
                &map(&[("servercert", bad)])
            )
            .is_err()
        );
    }
}

// ---- ssh argv --------------------------------------------------------------

fn target() -> RemoteTarget {
    RemoteTarget {
        host: "vm.example.com".into(),
        port: 22,
        user: "greentic".into(),
        identity_file: Some("/keys/id".into()),
        known_hosts_file: Some("/keys/kh".into()),
        connect_timeout_secs: 10,
        proxy_command: None,
    }
}

/// Golden: without a tunnel the argv is exactly what it was before tunnels.
#[test]
fn no_tunnel_leaves_the_ssh_argv_byte_identical() {
    let expected: Vec<String> = [
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ClearAllForwardings=yes",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "ConnectTimeout=10",
        "-o",
        "UserKnownHostsFile=/keys/kh",
        "-o",
        "IdentitiesOnly=yes",
        "-i",
        "/keys/id",
        "-p",
        "22",
        "--",
        "greentic@vm.example.com",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(ssh_args(&target()), expected);
    let mut with_command = expected;
    with_command.push("true".into());
    assert_eq!(ssh_invocation(&target(), "true"), with_command);
    assert_eq!(
        upload_command("/opt/greentic/x"),
        "umask 077 && cat > /opt/greentic/x"
    );
}

#[test]
fn a_proxy_command_is_one_option_before_the_destination_for_commands_and_uploads() {
    let t = target().with_proxy_command(Some("nc -X 5 -x 127.0.0.1:9 %h %p".into()));
    for args in [
        ssh_args(&t),
        ssh_invocation(&t, &upload_command("/opt/greentic/x")),
    ] {
        let pos = args
            .iter()
            .position(|a| a == "ProxyCommand=nc -X 5 -x 127.0.0.1:9 %h %p")
            .expect("ProxyCommand is present as ONE argument");
        assert_eq!(args[pos - 1], "-o");
        let dashdash = args.iter().position(|a| a == "--").unwrap();
        assert!(pos < dashdash, "ProxyCommand must precede `--`");
        assert_eq!(
            args.iter()
                .filter(|a| a.starts_with("ProxyCommand="))
                .count(),
            1
        );
    }
    assert!(!format!("{t:?}").contains("nc -X"));
}

// ---- jump ------------------------------------------------------------------

#[test]
fn jump_builds_a_strict_bastion_hop_and_defaults_to_the_login_user() {
    let s = map(&[
        ("jump_host", "bastion.example.com"),
        ("jump_known_hosts_file", "/keys/bastion_kh"),
    ]);
    let cmd = jump::proxy_command(&s, "greentic");
    assert_eq!(
        cmd,
        "ssh -o BatchMode=yes -o StrictHostKeyChecking=yes -o ConnectTimeout=10 -o \
         UserKnownHostsFile=/keys/bastion_kh -p 22 -W %h:%p -- greentic@bastion.example.com"
    );
    let s = map(&[
        ("jump_host", "bastion.example.com"),
        ("jump_known_hosts_file", "/keys/bastion_kh"),
        ("jump_user", "hop"),
        ("jump_port", "2200"),
        ("jump_identity_file", "/keys/hop"),
    ]);
    let cmd = jump::proxy_command(&s, "greentic");
    assert!(cmd.contains("-o IdentitiesOnly=yes -i /keys/hop"), "{cmd}");
    assert!(
        cmd.ends_with("-p 2200 -W %h:%p -- hop@bastion.example.com"),
        "{cmd}"
    );
    assert!(!cmd.contains("StrictHostKeyChecking=no"));
    assert!(!cmd.contains(" -J "));
}

#[test]
fn jump_requires_the_bastion_known_hosts_file() {
    let cfg = config("jump", &[("jump_host", "bastion.example.com")]);
    assert!(TunnelRegistry::builtin().validate(&cfg).is_err());
}

#[test]
fn jump_up_starts_nothing_and_is_a_proxy_command_only() {
    let cfg = config(
        "jump",
        &[
            ("jump_host", "bastion.example.com"),
            ("jump_known_hosts_file", "/keys/kh"),
        ],
    );
    let up = TunnelRegistry::builtin()
        .up(&cfg, "greentic", "10.1.2.3", 22)
        .unwrap();
    assert!(up.proxy_command.unwrap().contains("-W %h:%p"));
    assert!(up.guard.is_empty());
}

// ---- guard -----------------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_scratch_dir_is_private_and_its_secrets_are_0600_and_exclusive() {
    use std::os::unix::fs::PermissionsExt;
    let scratch = ScratchDir::new().unwrap();
    let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(scratch.path()), 0o700);
    let file = scratch.write_secret("seed", b"hunter2").unwrap();
    assert_eq!(mode(&file), 0o600);
    assert_eq!(std::fs::read(&file).unwrap(), b"hunter2");
    assert!(
        scratch.write_secret("seed", b"again").is_err(),
        "never replaced"
    );
    assert!(scratch.write_secret("../escape", b"x").is_err());
    assert!(scratch.write_secret("a/b", b"x").is_err());
}

#[cfg(unix)]
#[test]
fn dropping_the_guard_kills_the_children_runs_hooks_in_reverse_and_deletes_scratch() {
    let scratch = ScratchDir::new().unwrap();
    let dir = scratch.path().to_path_buf();
    let mut guard = TunnelGuard::empty();
    let mut command = std::process::Command::new("sleep");
    command.arg("60");
    let child = support::spawn_silent(&mut command).unwrap();
    let pid = child.id();
    let index = guard.adopt_child(child);
    let order = Arc::new(Mutex::new(Vec::new()));
    for n in 1..=2 {
        let order = Arc::clone(&order);
        guard.on_drop(move || order.lock().unwrap().push(n));
    }
    guard.adopt_scratch(scratch);
    assert!(guard.child_exit(index).is_none());
    assert!(dir.exists());
    drop(guard);
    assert_eq!(*order.lock().unwrap(), vec![2, 1]);
    assert!(!dir.exists(), "scratch directory removed");
    // The child was reaped: signalling its pid finds nothing of ours.
    let status = std::process::Command::new("kill")
        .args(["-0", &pid.to_string()])
        .output()
        .unwrap();
    assert!(!status.status.success(), "the helper must be gone");
}

#[cfg(unix)]
#[test]
fn a_group_leader_takes_its_grandchildren_with_it() {
    use std::os::unix::process::CommandExt;
    let dir = tempfile::tempdir().unwrap();
    let pidfile = dir.path().join("grandchild.pid");
    let mut command = std::process::Command::new("sh");
    command
        .args([
            "-c",
            &format!("sleep 60 & echo $! > {}; wait", pidfile.display()),
        ])
        .process_group(0);
    let child = support::spawn_silent(&mut command).unwrap();
    let mut guard = TunnelGuard::empty();
    guard.adopt_group_leader(child);
    for _ in 0..100 {
        if pidfile.exists() && !std::fs::read_to_string(&pidfile).unwrap().trim().is_empty() {
            break;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    let grandchild = std::fs::read_to_string(&pidfile)
        .unwrap()
        .trim()
        .to_string();
    drop(guard);
    std::thread::sleep(Duration::from_millis(100));
    let alive = std::process::Command::new("kill")
        .args(["-0", &grandchild])
        .output()
        .unwrap();
    assert!(!alive.status.success(), "the grandchild must be gone too");
}

// ---- gate ------------------------------------------------------------------

#[test]
fn the_gate_forwards_only_the_vm_and_dials_nothing_else() {
    let upstream = fake_socks(0);
    let mut guard = TunnelGuard::empty();
    let port = gate::start(
        Upstream::Socks5 {
            addr: SocketAddr::from((Ipv4Addr::LOCALHOST, upstream.port)),
            auth: None,
        },
        "vm.example.com".into(),
        22,
        &mut guard,
    )
    .unwrap();
    let gate_addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
    let t = Duration::from_secs(3);

    let mut ok = socks5_connect(gate_addr, "vm.example.com", 22, None, t).unwrap();
    let mut banner = [0u8; 4];
    ok.set_read_timeout(Some(t)).unwrap();
    ok.read_exact(&mut banner).unwrap();
    assert_eq!(&banner, b"SSH-");

    for (host, p) in [
        ("evil.example.com", 22),
        ("vm.example.com", 2222),
        ("169.254.169.254", 80),
        ("127.0.0.1", 22),
    ] {
        let err = socks5_connect(gate_addr, host, p, None, t);
        assert!(err.is_err(), "{host}:{p} must be refused by the gate");
    }
    assert_eq!(
        *upstream.asked.lock().unwrap(),
        vec!["vm.example.com:22".to_string()]
    );
    // Dropping the guard stops the gate's thread (joined in the guard's hook).
    drop(guard);
}

#[test]
fn readiness_needs_an_ssh_banner_not_just_a_listener() {
    // A listener that accepts and answers SOCKS5 but then says nothing useful.
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = listener.local_addr().unwrap();
    std::thread::spawn(move || {
        for c in listener.incoming().flatten() {
            let mut c = c;
            let mut b = [0u8; 3];
            let _ = c.read_exact(&mut b);
            let _ = c.write_all(&[5, 0]);
            let mut r = [0u8; 4];
            let _ = c.read_exact(&mut r);
            let mut rest = [0u8; 64];
            let _ = c.read(&mut rest);
            let _ = c.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
            let _ = c.write_all(b"HTTP/1.1 400\r\n");
        }
    });
    let err = support::probe_ssh_banner(addr, "10.1.2.3", 22, Duration::from_secs(2)).unwrap_err();
    assert!(err.contains("SSH banner"), "{err}");
    let good = fake_socks(0);
    support::probe_ssh_banner(
        SocketAddr::from((Ipv4Addr::LOCALHOST, good.port)),
        "10.1.2.3",
        22,
        Duration::from_secs(2),
    )
    .unwrap();
}

#[test]
fn a_helper_that_exits_early_aborts_the_wait_with_its_own_reason() {
    let nothing = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let addr = nothing.local_addr().unwrap();
    drop(nothing);
    let started = std::time::Instant::now();
    let err =
        support::wait_until_ssh_reachable(addr, "10.1.2.3", 22, Duration::from_secs(30), || {
            Some("the helper died".to_string())
        })
        .unwrap_err();
    assert_eq!(err, "the helper died");
    assert!(started.elapsed() < Duration::from_secs(5));
}

// ---- proxy -----------------------------------------------------------------

fn proxy_registry() -> TunnelRegistry {
    TunnelRegistry::with_providers(vec![Box::new(proxy::Proxy {
        allow_loopback: true,
    })])
}

#[test]
fn proxy_validation_pairs_the_user_with_a_password_file() {
    let base = [
        ("proxy_type", "socks5"),
        ("proxy_host", "proxy.example.com"),
        ("proxy_port", "1080"),
    ];
    let r = TunnelRegistry::builtin();
    r.validate(&config("proxy", &base)).unwrap();
    let mut with_user = base.to_vec();
    with_user.push(("proxy_user", "svc"));
    assert!(r.validate(&config("proxy", &with_user)).is_err());
    with_user.push(("proxy_password_file", "/keys/pw"));
    r.validate(&config("proxy", &with_user)).unwrap();
    assert!(
        r.validate(&config(
            "proxy",
            &[
                ("proxy_type", "ftp"),
                ("proxy_host", "p.example.com"),
                ("proxy_port", "1")
            ]
        ))
        .is_err()
    );
}

#[test]
fn proxy_never_uses_a_loopback_or_metadata_address_as_the_proxy() {
    let r = TunnelRegistry::builtin();
    for host in ["127.0.0.1", "169.254.169.254"] {
        let cfg = config(
            "proxy",
            &[
                ("proxy_type", "socks5"),
                ("proxy_host", host),
                ("proxy_port", "1080"),
            ],
        );
        let err = r
            .up(&cfg, "greentic", "10.1.2.3", 22)
            .unwrap_err()
            .to_string();
        assert!(err.contains("never used as a proxy"), "{host}: {err}");
    }
}

#[test]
fn proxy_socks5_reaches_the_vm_through_the_gate() {
    let fake = fake_socks(0);
    let cfg = config(
        "proxy",
        &[
            ("proxy_type", "socks5"),
            ("proxy_host", "127.0.0.1"),
            ("proxy_port", &fake.port.to_string()),
        ],
    );
    let up = proxy_registry()
        .up(&cfg, "greentic", "vm.example.com", 22)
        .unwrap();
    let cmd = up.proxy_command.clone().unwrap();
    assert!(cmd.starts_with("nc -X 5 -x 127.0.0.1:"), "{cmd}");
    assert!(cmd.ends_with("%h %p"), "{cmd}");
    assert!(
        !cmd.contains(&fake.port.to_string()),
        "ssh talks to the gate, never to the proxy"
    );
    assert_eq!(fake.asked.lock().unwrap()[0], "vm.example.com:22");
}

#[test]
fn proxy_http_connect_carries_basic_credentials_from_a_file_only_in_memory() {
    let fake = fake_http_proxy();
    let secrets = ScratchDir::new().unwrap();
    let pw = secrets.write_secret("pw", b"s3cret\n").unwrap();
    let cfg = config(
        "proxy",
        &[
            ("proxy_type", "http"),
            ("proxy_host", "127.0.0.1"),
            ("proxy_port", &fake.port.to_string()),
            ("proxy_user", "svc"),
            ("proxy_password_file", pw.to_str().unwrap()),
        ],
    );
    let up = proxy_registry()
        .up(&cfg, "greentic", "vm.example.com", 22)
        .unwrap();
    let asked = fake.asked.lock().unwrap()[0].clone();
    assert!(
        asked.starts_with("CONNECT vm.example.com:22 HTTP/1.1"),
        "{asked}"
    );
    // base64("svc:s3cret")
    assert!(asked.contains("Basic c3ZjOnMzY3JldA=="), "{asked}");
    let cmd = up.proxy_command.unwrap();
    assert!(!cmd.contains("s3cret") && !cmd.contains("svc"), "{cmd}");
}

#[cfg(unix)]
#[test]
fn a_secret_file_readable_by_others_is_refused_without_echoing_it() {
    use std::os::unix::fs::PermissionsExt;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("pw");
    std::fs::write(&path, "topsecret\n").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = support::read_secret_file("password_file", path.to_str().unwrap()).unwrap_err();
    assert!(err.contains("0600") && !err.contains("topsecret"), "{err}");
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        &*support::read_secret_file("password_file", path.to_str().unwrap()).unwrap(),
        "topsecret"
    );
    std::fs::write(&path, "a\nb\n").unwrap();
    assert!(support::read_secret_file("password_file", path.to_str().unwrap()).is_err());
}

#[test]
fn shell_quote_keeps_proxy_tokens_expandable_by_ssh() {
    assert_eq!(shell_quote("%h"), "%h");
    assert_eq!(
        support::socks5_proxy_command(1234),
        "nc -X 5 -x 127.0.0.1:1234 %h %p"
    );
}
