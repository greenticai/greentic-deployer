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

/// Resolve a non-builtin target-id through the extension registry.
///
/// **Phase A (PR#1) status:** Defined and tested-buildable but NOT yet
/// wired into the CLI dispatch path. PR#2 (`greentic-deployer-extensions`
/// sibling repo) will add the call site once `deploy-desktop` ships.
/// The function bails with a clear "PR#2 required" message on success path
/// to make this explicit at runtime.
#[cfg(feature = "extensions")]
#[allow(dead_code)] // wired in PR#2 — see deploy-extension-migration spec §11
pub(crate) fn maybe_dispatch_via_extensions(target_id: &str) -> anyhow::Result<()> {
    use std::str::FromStr;

    if greentic_deployer::extension::BuiltinBackendId::from_str(target_id).is_ok() {
        anyhow::bail!(
            "target '{}' is a built-in backend — use the dedicated subcommand",
            target_id
        );
    }

    let dir = greentic_deployer::ext::loader::resolve_extension_dir(None);
    let loaded = greentic_deployer::ext::loader::scan(&dir)
        .map_err(|e| anyhow::anyhow!("load extensions: {e}"))?;
    let reg = greentic_deployer::ext::registry::ExtensionRegistry::build(loaded);
    let resolved = reg
        .resolve(target_id)
        .map_err(|e| anyhow::anyhow!("resolve '{target_id}': {e}"))?;
    tracing::info!(
        target_id = %target_id,
        ext_id = %resolved.ext_id,
        "extension target resolved; wiring into execution is PR#2 scope"
    );
    anyhow::bail!(
        "extension-provided target '{target_id}' requires PR#2 (deploy-desktop); \
         see docs/superpowers/plans/2026-04-17-deploy-extension-pr1.md"
    )
}
