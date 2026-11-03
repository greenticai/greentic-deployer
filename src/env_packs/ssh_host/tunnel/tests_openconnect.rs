//! `openconnect` provider tests, driven by a stub `openconnect` shell script and
//! a fake SOCKS5 listener standing in for `ocproxy`. Nothing leaves loopback.

use std::path::Path;
use std::time::Duration;

use super::openconnect::{OpenConnect, argv, classify_failure, stdin_payload};
use super::tests::{ctx, fake_socks, map};
use super::*;
use std::collections::BTreeMap;

const PIN: &str = "pin-sha256:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";
const SEED: &str = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const NOW: u64 = 1_800_000_000;

fn fixed_clock() -> u64 {
    NOW
}

fn unset_clock() -> u64 {
    0
}

fn settings(password_file: &Path, extra: &[(&str, &str)]) -> BTreeMap<String, String> {
    let mut s = map(&[
        ("server", "vpn.example.com"),
        ("servercert", PIN),
        ("user", "svc-deploy"),
        ("password_file", password_file.to_str().unwrap()),
    ]);
    for (k, v) in extra {
        s.insert(k.to_string(), v.to_string());
    }
    s
}

/// A fake `openconnect`: records its argv, stdin and each invocation next to
/// itself, then behaves according to `mode.txt`.
#[cfg(unix)]
fn stub(dir: &Path, mode: &str) -> String {
    use std::os::unix::fs::PermissionsExt;
    let script = r#"#!/bin/sh
d=$(dirname "$0")
echo run >> "$d/calls.txt"
printf '%s\n' "$@" > "$d/argv.txt"
cat > "$d/stdin.txt"
for a in "$@"; do
  case "$a" in
    *"-D "*) echo "$a" | sed 's/.*-D \([0-9]*\).*/\1/' > "$d/port.txt";;
  esac
done
case "$(cat "$d/mode.txt")" in
  saml) echo "SAML authentication is required; use --external-browser" >&2; exit 2;;
  auth) echo "Failed to complete authentication" >&2; exit 1;;
  pin) echo "Server certificate verify failed: signer not found" >&2; exit 1;;
  *) exec sleep 60;;
esac
"#;
    let bin = dir.join("openconnect");
    std::fs::write(&bin, script).unwrap();
    std::fs::set_permissions(&bin, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(dir.join("mode.txt"), mode).unwrap();
    bin.to_str().unwrap().to_string()
}

fn calls(dir: &Path) -> usize {
    std::fs::read_to_string(dir.join("calls.txt")).map_or(0, |t| t.lines().count())
}

// ---- pure pieces -----------------------------------------------------------

#[test]
fn validation_demands_the_pin_and_the_account_and_only_anyconnect() {
    let r = TunnelRegistry::builtin();
    let good = [
        ("server", "vpn.example.com"),
        ("servercert", PIN),
        ("user", "svc"),
        ("password_file", "/keys/pw"),
    ];
    let cfg = |extra: &[(&str, &str)]| {
        let mut pairs = good.to_vec();
        pairs.extend_from_slice(extra);
        TunnelConfig {
            kind: "openconnect".into(),
            settings: map(&pairs),
        }
    };
    r.validate(&cfg(&[])).unwrap();
    r.validate(&cfg(&[
        ("totp_seed_file", "/keys/seed"),
        ("totp_mode", "append"),
    ]))
    .unwrap();
    for missing in ["servercert", "user", "password_file", "server"] {
        let pairs: Vec<_> = good
            .iter()
            .filter(|(k, _)| *k != missing)
            .cloned()
            .collect();
        let c = TunnelConfig {
            kind: "openconnect".into(),
            settings: map(&pairs),
        };
        let err = r.validate(&c).unwrap_err().to_string();
        assert!(err.contains(missing) && err.contains("required"), "{err}");
    }
    assert!(
        r.validate(&cfg(&[("protocol", "gp")])).is_err(),
        "only anyconnect for now"
    );
    assert!(
        r.validate(&cfg(&[("totp_mode", "append")])).is_err(),
        "needs a seed"
    );
    assert!(r.validate(&cfg(&[("servercert", "sha256:abc")])).is_err());
    for evil in ["a b", "a;b", "$(id)", "-x", "a\nb"] {
        assert!(
            r.validate(&cfg(&[("authgroup", evil)])).is_err(),
            "{evil:?}"
        );
        assert!(
            r.validate(&cfg(&[("usergroup", evil)])).is_err(),
            "{evil:?}"
        );
        assert!(r.validate(&cfg(&[("user", evil)])).is_err(), "{evil:?}");
    }
    assert!(r.validate(&cfg(&[("server", "127.0.0.1")])).is_err());
}

#[test]
fn the_argv_carries_the_pin_and_no_secret_and_no_password_flag() {
    let s = settings(
        Path::new("/keys/pw"),
        &[("authgroup", "Staff"), ("usergroup", "vm")],
    );
    let args = argv(&s, "ocproxy", 4242);
    let joined = args.join(" ");
    for needle in [
        "--protocol=anyconnect",
        "--non-inter",
        "--passwd-on-stdin",
        "--user=svc-deploy",
        &format!("--servercert={PIN}"),
        "--no-dtls",
        "--script-tun",
        "--authgroup=Staff",
    ] {
        assert!(joined.contains(needle), "{needle} in {joined}");
    }
    assert_eq!(args.last().unwrap(), "https://vpn.example.com/vm");
    let script = &args[args.iter().position(|a| a == "--script").unwrap() + 1];
    assert_eq!(script, "ocproxy -D 4242 -k 30");
    assert!(
        !joined.contains("--password") && !joined.contains("pw"),
        "{joined}"
    );
    assert!(!joined.contains("--token"), "no token secret in argv");
}

#[test]
fn the_stdin_payload_is_password_then_code_or_the_two_joined() {
    assert_eq!(&*stdin_payload("pw", None, false), "pw\n");
    assert_eq!(&*stdin_payload("pw", Some("123456"), false), "pw\n123456\n");
    assert_eq!(&*stdin_payload("pw", Some("123456"), true), "pw123456\n");
}

#[test]
fn failures_become_fixed_sentences_that_quote_nothing_and_name_the_way_out() {
    let saml = classify_failure(
        "POST https://x/\nSAML authentication required for user bob@corp",
        None,
    );
    assert!(
        saml.contains("single sign-on") && saml.contains("service account"),
        "{saml}"
    );
    assert!(!saml.contains("bob"));
    assert!(classify_failure("Duo push sent, waiting for approval", None).contains("push"));
    assert!(classify_failure("HostScan token required", None).contains("HostScan"));
    let refused = classify_failure("Failed to complete authentication", None);
    assert!(
        refused.contains("ONCE") && refused.contains("not retried"),
        "{refused}"
    );
    assert!(classify_failure("Server certificate verify failed", None).contains("servercert"));
    assert!(
        classify_failure("Failed to open HTTPS connection to vpn", None)
            .contains("could not be reached")
    );
    assert!(classify_failure("???", None).contains("stopped"));
}

// ---- driving the stub ------------------------------------------------------

#[cfg(unix)]
#[test]
fn a_good_login_sends_password_and_a_computed_code_on_stdin_and_waits_for_the_banner() {
    let secrets = ScratchDir::new().unwrap();
    let pw = secrets.write_secret("pw", b"hunter2\n").unwrap();
    let seed = secrets
        .write_secret("seed", format!("{SEED}\n").as_bytes())
        .unwrap();
    let stubs = tempfile::tempdir().unwrap();
    let bin = stub(stubs.path(), "serve");
    let provider = OpenConnect::with(&bin, "ocproxy", fixed_clock);
    let s = settings(&pw, &[("totp_seed_file", seed.to_str().unwrap())]);

    let worker = std::thread::spawn(move || provider.up(&ctx(&s, "vm.example.com")));
    // `ocproxy` would listen on the port openconnect was told; play its part.
    let port_file = stubs.path().join("port.txt");
    let mut port = None;
    for _ in 0..200 {
        if let Some(p) = std::fs::read_to_string(&port_file)
            .ok()
            .and_then(|t| t.trim().parse::<u16>().ok())
        {
            port = Some(p);
            break;
        }
        std::thread::sleep(Duration::from_millis(25));
    }
    let _ocproxy = fake_socks(port.expect("the stub reported the SOCKS port"));
    let up = worker.join().unwrap().expect("tunnel up");

    let cmd = up.proxy_command.clone().unwrap();
    assert!(
        cmd.starts_with("nc -X 5 -x 127.0.0.1:") && cmd.ends_with("%h %p"),
        "{cmd}"
    );
    let seed_bytes = totp::decode_base32(SEED).unwrap();
    let code = totp::code(&seed_bytes, NOW);
    assert_eq!(
        std::fs::read_to_string(stubs.path().join("stdin.txt")).unwrap(),
        format!("hunter2\n{}\n", &*code)
    );
    let recorded = std::fs::read_to_string(stubs.path().join("argv.txt")).unwrap();
    assert!(
        recorded.contains(&format!("--servercert={PIN}")),
        "{recorded}"
    );
    assert!(
        !recorded.contains("hunter2") && !recorded.contains(&*code),
        "secrets stay out of argv"
    );
    assert_eq!(calls(stubs.path()), 1);
    drop(up);
}

#[cfg(unix)]
#[test]
fn append_mode_sends_one_line() {
    let secrets = ScratchDir::new().unwrap();
    let pw = secrets.write_secret("pw", b"hunter2\n").unwrap();
    let seed = secrets.write_secret("seed", SEED.as_bytes()).unwrap();
    let stubs = tempfile::tempdir().unwrap();
    let bin = stub(stubs.path(), "auth");
    let provider = OpenConnect::with(&bin, "ocproxy", fixed_clock);
    let s = settings(
        &pw,
        &[
            ("totp_seed_file", seed.to_str().unwrap()),
            ("totp_mode", "append"),
        ],
    );
    let _ = provider.up(&ctx(&s, "vm.example.com"));
    let code = totp::code(&totp::decode_base32(SEED).unwrap(), NOW);
    assert_eq!(
        std::fs::read_to_string(stubs.path().join("stdin.txt")).unwrap(),
        format!("hunter2{}\n", &*code)
    );
}

#[cfg(unix)]
#[test]
fn a_refused_login_is_tried_exactly_once_and_explained_without_quoting_the_gateway() {
    let secrets = ScratchDir::new().unwrap();
    let pw = secrets.write_secret("pw", b"hunter2\n").unwrap();
    for (mode, needle) in [
        ("auth", "tried ONCE"),
        ("saml", "single sign-on"),
        ("pin", "servercert"),
    ] {
        let stubs = tempfile::tempdir().unwrap();
        let provider = OpenConnect::with(&stub(stubs.path(), mode), "ocproxy", fixed_clock);
        let s = settings(&pw, &[]);
        let started = std::time::Instant::now();
        let err = provider
            .up(&ctx(&s, "vm.example.com"))
            .unwrap_err()
            .to_string();
        assert!(err.contains(needle), "{mode}: {err}");
        assert!(
            !err.contains("external-browser") && !err.contains("hunter2"),
            "{err}"
        );
        assert_eq!(calls(stubs.path()), 1, "{mode}: no automatic retry");
        assert!(
            started.elapsed() < Duration::from_secs(10),
            "{mode}: fails fast, not after the timeout"
        );
    }
}

#[cfg(unix)]
#[test]
fn a_password_without_the_code_when_no_seed_is_configured() {
    let secrets = ScratchDir::new().unwrap();
    let pw = secrets.write_secret("pw", b"hunter2\n").unwrap();
    let stubs = tempfile::tempdir().unwrap();
    let provider = OpenConnect::with(&stub(stubs.path(), "auth"), "ocproxy", fixed_clock);
    let _ = provider.up(&ctx(&settings(&pw, &[]), "vm.example.com"));
    assert_eq!(
        std::fs::read_to_string(stubs.path().join("stdin.txt")).unwrap(),
        "hunter2\n"
    );
}

#[cfg(unix)]
#[test]
fn an_unset_clock_refuses_before_openconnect_is_started() {
    let secrets = ScratchDir::new().unwrap();
    let pw = secrets.write_secret("pw", b"hunter2\n").unwrap();
    let seed = secrets.write_secret("seed", SEED.as_bytes()).unwrap();
    let stubs = tempfile::tempdir().unwrap();
    let provider = OpenConnect::with(&stub(stubs.path(), "serve"), "ocproxy", unset_clock);
    let s = settings(&pw, &[("totp_seed_file", seed.to_str().unwrap())]);
    let err = provider
        .up(&ctx(&s, "vm.example.com"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("clock"), "{err}");
    assert_eq!(
        calls(stubs.path()),
        0,
        "no login attempt is spent on a code that cannot be right"
    );
}

#[cfg(unix)]
#[test]
fn a_bad_seed_a_loose_password_file_or_a_missing_binary_never_start_a_login() {
    use std::os::unix::fs::PermissionsExt;
    let secrets = ScratchDir::new().unwrap();
    let pw = secrets.write_secret("pw", b"hunter2\n").unwrap();
    let bad_seed = secrets
        .write_secret("bad", b"not base32 at all!!!!!!")
        .unwrap();
    let stubs = tempfile::tempdir().unwrap();
    let provider = OpenConnect::with(&stub(stubs.path(), "serve"), "ocproxy", fixed_clock);
    let s = settings(&pw, &[("totp_seed_file", bad_seed.to_str().unwrap())]);
    assert!(
        provider
            .up(&ctx(&s, "vm.example.com"))
            .unwrap_err()
            .to_string()
            .contains("base32")
    );

    let loose = secrets.write_secret("loose", b"hunter2\n").unwrap();
    std::fs::set_permissions(&loose, std::fs::Permissions::from_mode(0o644)).unwrap();
    let err = provider
        .up(&ctx(&settings(&loose, &[]), "vm.example.com"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("0600") && !err.contains("hunter2"), "{err}");
    assert_eq!(calls(stubs.path()), 0);

    let missing = OpenConnect::with("/nonexistent/openconnect", "ocproxy", fixed_clock);
    let err = missing
        .up(&ctx(&settings(&pw, &[]), "vm.example.com"))
        .unwrap_err()
        .to_string();
    assert!(err.contains("package installed"), "{err}");
}

#[cfg(unix)]
#[test]
fn a_tunnel_that_never_carries_traffic_times_out_and_cleans_up() {
    let secrets = ScratchDir::new().unwrap();
    let pw = secrets.write_secret("pw", b"hunter2\n").unwrap();
    let stubs = tempfile::tempdir().unwrap();
    // The stub stays alive but no `ocproxy` ever listens.
    let provider = OpenConnect::with(&stub(stubs.path(), "serve"), "ocproxy", fixed_clock);
    let s = settings(&pw, &[]);
    let mut c = ctx(&s, "vm.example.com");
    c.ready_timeout = Duration::from_secs(2);
    let err = provider.up(&c).unwrap_err().to_string();
    assert!(err.contains("did not become reachable within 2s"), "{err}");
}
