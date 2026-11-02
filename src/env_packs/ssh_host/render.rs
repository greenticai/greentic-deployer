//! Pure rendering for the ssh-host deployer: the systemd unit. No I/O, so it is
//! pinned by a golden test. (The store snapshot is in [`super::snapshot`].)

use greentic_deploy_spec::Environment;

use super::params::SshHostParams;

/// The unit file.
///
/// * `HOME` is a writable directory under the install dir: greentic-start
///   creates `$HOME/.greentic/environments` at startup.
/// * `--no-updates` stops the runtime self-updating the binary on the VM behind
///   the deployer's back; `--no-browser --nats off` match the proven invocation.
/// * The bind address and port are set both here and in the shipped
///   `runtime.json` (see `snapshot`), so whichever the runtime honours agrees.
///
/// `User=` is omitted for root so a root login runs the service
/// as root rather than naming it redundantly; a non-root login runs the service
/// as that same user, which owns the install dir and the synchronized store.
pub fn render_unit(env: &Environment, params: &SshHostParams) -> String {
    let env_id = env.environment_id.as_str();
    let dir = &params.install_dir;
    let user_line = if params.user == "root" {
        String::new()
    } else {
        format!("User={}\n", params.user)
    };
    format!(
        "[Unit]\n\
         Description=Greentic runtime ({env_id})\n\
         After=network-online.target\n\
         Wants=network-online.target\n\
         \n\
         [Service]\n\
         Type=simple\n\
         {user_line}\
         WorkingDirectory={dir}\n\
         Environment=HOME={dir}/home\n\
         Environment=GREENTIC_ENV_ID={env_id}\n\
         Environment=GREENTIC_GATEWAY_LISTEN_ADDR={bind}\n\
         Environment=GREENTIC_GATEWAY_PORT={port}\n\
         ExecStart={dir}/bin/greentic-start start --store-root {dir}/store --env {env_id} --no-browser --nats off --no-updates\n\
         Restart=on-failure\n\
         RestartSec=5\n\
         NoNewPrivileges=true\n\
         PrivateTmp=true\n\
         \n\
         [Install]\n\
         WantedBy=multi-user.target\n",
        bind = params.bind_addr(),
        port = params.listen_port,
    )
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::*;
    use crate::env_packs::deployer::conformance::build_fixture_env;

    fn params(user: &str) -> SshHostParams {
        SshHostParams::from_answers(
            &build_fixture_env(),
            &json!({"host": "vm.example.com", "user": user, "listen_port": 9090, "expose": true}),
        )
        .unwrap()
    }

    #[test]
    fn unit_for_a_non_root_login_matches_the_golden_text() {
        let unit = render_unit(&build_fixture_env(), &params("greentic"));
        assert_eq!(
            unit,
            "[Unit]\n\
             Description=Greentic runtime (conformance)\n\
             After=network-online.target\n\
             Wants=network-online.target\n\
             \n\
             [Service]\n\
             Type=simple\n\
             User=greentic\n\
             WorkingDirectory=/opt/greentic\n\
             Environment=HOME=/opt/greentic/home\n\
             Environment=GREENTIC_ENV_ID=conformance\n\
             Environment=GREENTIC_GATEWAY_LISTEN_ADDR=0.0.0.0\n\
             Environment=GREENTIC_GATEWAY_PORT=9090\n\
             ExecStart=/opt/greentic/bin/greentic-start start --store-root /opt/greentic/store --env conformance --no-browser --nats off --no-updates\n\
             Restart=on-failure\n\
             RestartSec=5\n\
             NoNewPrivileges=true\n\
             PrivateTmp=true\n\
             \n\
             [Install]\n\
             WantedBy=multi-user.target\n"
        );
    }

    #[test]
    fn unit_binds_loopback_unless_exposed() {
        let loopback =
            SshHostParams::from_answers(&build_fixture_env(), &json!({"host": "h", "user": "u"}))
                .unwrap();
        let unit = render_unit(&build_fixture_env(), &loopback);
        assert!(
            unit.contains("GREENTIC_GATEWAY_LISTEN_ADDR=127.0.0.1\n"),
            "{unit}"
        );
        assert!(unit.contains("GREENTIC_GATEWAY_PORT=8080\n"), "{unit}");
    }

    #[test]
    fn unit_for_root_omits_the_user_line() {
        let unit = render_unit(&build_fixture_env(), &params("root"));
        assert!(!unit.contains("User="), "{unit}");
    }
}
