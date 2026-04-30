use anyhow::Result;
use greentic_deployer::{BuiltinBackendHandlerId, resolve_builtin_backend_descriptor};

use crate::{
    BuiltinBackendCommand, run_aws, run_azure, run_gcp, run_helm, run_juju_k8s, run_juju_machine,
    run_k8s_raw, run_operator, run_serverless, run_snap, run_terraform,
};

#[derive(Clone, Copy)]
struct BuiltinExecutionHandlerRegistration {
    handler_id: BuiltinBackendHandlerId,
    dispatch: fn(BuiltinBackendCommand) -> Result<()>,
}

const BUILTIN_EXECUTION_HANDLER_REGISTRATIONS: &[BuiltinExecutionHandlerRegistration] = &[
    BuiltinExecutionHandlerRegistration {
        handler_id: BuiltinBackendHandlerId::Terraform,
        dispatch: dispatch_terraform_backend_command,
    },
    BuiltinExecutionHandlerRegistration {
        handler_id: BuiltinBackendHandlerId::K8sRaw,
        dispatch: dispatch_k8s_raw_backend_command,
    },
    BuiltinExecutionHandlerRegistration {
        handler_id: BuiltinBackendHandlerId::Helm,
        dispatch: dispatch_helm_backend_command,
    },
    BuiltinExecutionHandlerRegistration {
        handler_id: BuiltinBackendHandlerId::Aws,
        dispatch: dispatch_aws_backend_command,
    },
    BuiltinExecutionHandlerRegistration {
        handler_id: BuiltinBackendHandlerId::Azure,
        dispatch: dispatch_azure_backend_command,
    },
    BuiltinExecutionHandlerRegistration {
        handler_id: BuiltinBackendHandlerId::Gcp,
        dispatch: dispatch_gcp_backend_command,
    },
    BuiltinExecutionHandlerRegistration {
        handler_id: BuiltinBackendHandlerId::JujuK8s,
        dispatch: dispatch_juju_k8s_backend_command,
    },
    BuiltinExecutionHandlerRegistration {
        handler_id: BuiltinBackendHandlerId::JujuMachine,
        dispatch: dispatch_juju_machine_backend_command,
    },
    BuiltinExecutionHandlerRegistration {
        handler_id: BuiltinBackendHandlerId::Operator,
        dispatch: dispatch_operator_backend_command,
    },
    BuiltinExecutionHandlerRegistration {
        handler_id: BuiltinBackendHandlerId::Serverless,
        dispatch: dispatch_serverless_backend_command,
    },
    BuiltinExecutionHandlerRegistration {
        handler_id: BuiltinBackendHandlerId::Snap,
        dispatch: dispatch_snap_backend_command,
    },
];

fn resolve_builtin_execution_handler(
    handler_id: BuiltinBackendHandlerId,
) -> Option<fn(BuiltinBackendCommand) -> Result<()>> {
    BUILTIN_EXECUTION_HANDLER_REGISTRATIONS
        .iter()
        .find(|registration| registration.handler_id == handler_id)
        .map(|registration| registration.dispatch)
}

fn dispatch_terraform_backend_command(command: BuiltinBackendCommand) -> Result<()> {
    match command {
        BuiltinBackendCommand::Terraform(command) => run_terraform(command),
        other => Err(anyhow::anyhow!(
            "backend {:?} was routed to terraform dispatch but is not terraform",
            other.backend_id()
        )),
    }
}

fn dispatch_k8s_raw_backend_command(command: BuiltinBackendCommand) -> Result<()> {
    match command {
        BuiltinBackendCommand::K8sRaw(command) => run_k8s_raw(command),
        other => Err(anyhow::anyhow!(
            "backend {:?} was routed to k8s-raw dispatch but is not k8s-raw",
            other.backend_id()
        )),
    }
}

fn dispatch_helm_backend_command(command: BuiltinBackendCommand) -> Result<()> {
    match command {
        BuiltinBackendCommand::Helm(command) => run_helm(command),
        other => Err(anyhow::anyhow!(
            "backend {:?} was routed to helm dispatch but is not helm",
            other.backend_id()
        )),
    }
}

fn dispatch_aws_backend_command(command: BuiltinBackendCommand) -> Result<()> {
    match command {
        BuiltinBackendCommand::Aws(command) => run_aws(command),
        other => Err(anyhow::anyhow!(
            "backend {:?} was routed to aws dispatch but is not aws",
            other.backend_id()
        )),
    }
}

fn dispatch_azure_backend_command(command: BuiltinBackendCommand) -> Result<()> {
    match command {
        BuiltinBackendCommand::Azure(command) => run_azure(command),
        other => Err(anyhow::anyhow!(
            "backend {:?} was routed to azure dispatch but is not azure",
            other.backend_id()
        )),
    }
}

fn dispatch_gcp_backend_command(command: BuiltinBackendCommand) -> Result<()> {
    match command {
        BuiltinBackendCommand::Gcp(command) => run_gcp(command),
        other => Err(anyhow::anyhow!(
            "backend {:?} was routed to gcp dispatch but is not gcp",
            other.backend_id()
        )),
    }
}

fn dispatch_juju_k8s_backend_command(command: BuiltinBackendCommand) -> Result<()> {
    match command {
        BuiltinBackendCommand::JujuK8s(command) => run_juju_k8s(command),
        other => Err(anyhow::anyhow!(
            "backend {:?} was routed to juju-k8s dispatch but is not juju-k8s",
            other.backend_id()
        )),
    }
}

fn dispatch_juju_machine_backend_command(command: BuiltinBackendCommand) -> Result<()> {
    match command {
        BuiltinBackendCommand::JujuMachine(command) => run_juju_machine(command),
        other => Err(anyhow::anyhow!(
            "backend {:?} was routed to juju-machine dispatch but is not juju-machine",
            other.backend_id()
        )),
    }
}

fn dispatch_operator_backend_command(command: BuiltinBackendCommand) -> Result<()> {
    match command {
        BuiltinBackendCommand::Operator(command) => run_operator(command),
        other => Err(anyhow::anyhow!(
            "backend {:?} was routed to operator dispatch but is not operator",
            other.backend_id()
        )),
    }
}

fn dispatch_serverless_backend_command(command: BuiltinBackendCommand) -> Result<()> {
    match command {
        BuiltinBackendCommand::Serverless(command) => run_serverless(command),
        other => Err(anyhow::anyhow!(
            "backend {:?} was routed to serverless dispatch but is not serverless",
            other.backend_id()
        )),
    }
}

fn dispatch_snap_backend_command(command: BuiltinBackendCommand) -> Result<()> {
    match command {
        BuiltinBackendCommand::Snap(command) => run_snap(command),
        other => Err(anyhow::anyhow!(
            "backend {:?} was routed to snap dispatch but is not snap",
            other.backend_id()
        )),
    }
}

pub(crate) fn dispatch_builtin_backend_command(command: BuiltinBackendCommand) -> Result<()> {
    let backend_id = command.backend_id();
    let descriptor = resolve_builtin_backend_descriptor(backend_id).ok_or_else(|| {
        anyhow::anyhow!(
            "no built-in backend descriptor registered for {:?}",
            backend_id
        )
    })?;
    let handler = resolve_builtin_execution_handler(descriptor.handler_id).ok_or_else(|| {
        anyhow::anyhow!(
            "no built-in execution handler registered for {:?}",
            descriptor.handler_id
        )
    })?;
    handler(command)
}

#[cfg(test)]
mod tests {
    use clap::Parser;
    use greentic_deployer::BuiltinBackendHandlerId;

    use super::*;

    fn parse_builtin_command(args: &[&str]) -> BuiltinBackendCommand {
        let cli = crate::Cli::try_parse_from(
            std::iter::once("greentic-deployer").chain(args.iter().copied()),
        )
        .expect("parse builtin command");

        match cli.command {
            crate::TopLevelCommand::Aws(command) => BuiltinBackendCommand::Aws(command),
            crate::TopLevelCommand::Terraform(command) => BuiltinBackendCommand::Terraform(command),
            _ => panic!("unexpected parsed command"),
        }
    }

    #[test]
    fn resolve_builtin_execution_handler_registers_every_builtin_handler() {
        for handler_id in [
            BuiltinBackendHandlerId::Terraform,
            BuiltinBackendHandlerId::K8sRaw,
            BuiltinBackendHandlerId::Helm,
            BuiltinBackendHandlerId::Aws,
            BuiltinBackendHandlerId::Azure,
            BuiltinBackendHandlerId::Gcp,
            BuiltinBackendHandlerId::JujuK8s,
            BuiltinBackendHandlerId::JujuMachine,
            BuiltinBackendHandlerId::Operator,
            BuiltinBackendHandlerId::Serverless,
            BuiltinBackendHandlerId::Snap,
        ] {
            assert!(
                resolve_builtin_execution_handler(handler_id).is_some(),
                "missing handler for {handler_id:?}"
            );
        }
    }

    #[test]
    fn dispatch_functions_reject_commands_for_the_wrong_backend() {
        let aws_args = [
            "aws",
            "generate",
            "--tenant",
            "acme",
            "--bundle-pack",
            "bundle",
        ];
        let terraform_args = [
            "terraform",
            "generate",
            "--tenant",
            "acme",
            "--bundle-pack",
            "bundle",
        ];

        let err = dispatch_terraform_backend_command(parse_builtin_command(&aws_args)).unwrap_err();
        assert!(format!("{err}").contains("is not terraform"));

        let err =
            dispatch_k8s_raw_backend_command(parse_builtin_command(&terraform_args)).unwrap_err();
        assert!(format!("{err}").contains("is not k8s-raw"));

        let err =
            dispatch_helm_backend_command(parse_builtin_command(&terraform_args)).unwrap_err();
        assert!(format!("{err}").contains("is not helm"));

        let err = dispatch_aws_backend_command(parse_builtin_command(&terraform_args)).unwrap_err();
        assert!(format!("{err}").contains("is not aws"));

        let err =
            dispatch_azure_backend_command(parse_builtin_command(&terraform_args)).unwrap_err();
        assert!(format!("{err}").contains("is not azure"));

        let err = dispatch_gcp_backend_command(parse_builtin_command(&terraform_args)).unwrap_err();
        assert!(format!("{err}").contains("is not gcp"));

        let err =
            dispatch_juju_k8s_backend_command(parse_builtin_command(&terraform_args)).unwrap_err();
        assert!(format!("{err}").contains("is not juju-k8s"));

        let err = dispatch_juju_machine_backend_command(parse_builtin_command(&terraform_args))
            .unwrap_err();
        assert!(format!("{err}").contains("is not juju-machine"));

        let err =
            dispatch_operator_backend_command(parse_builtin_command(&terraform_args)).unwrap_err();
        assert!(format!("{err}").contains("is not operator"));

        let err = dispatch_serverless_backend_command(parse_builtin_command(&terraform_args))
            .unwrap_err();
        assert!(format!("{err}").contains("is not serverless"));

        let err =
            dispatch_snap_backend_command(parse_builtin_command(&terraform_args)).unwrap_err();
        assert!(format!("{err}").contains("is not snap"));
    }

    #[test]
    fn dispatch_builtin_backend_command_uses_registered_backend_handler() {
        let command = parse_builtin_command(&[
            "terraform",
            "generate",
            "--tenant",
            "acme",
            "--bundle-pack",
            "does-not-exist",
        ]);

        let err = dispatch_builtin_backend_command(command).unwrap_err();
        assert!(format!("{err}").contains("pack path does-not-exist does not exist"));
    }
}
