//! Adapter layer: translate extension dispatch → built-in backend execution.
//!
//! Mode A only. Mode B is rejected earlier in `dispatcher::dispatch_extension`.
//! Currently wired backends: Desktop (docker-compose/podman), SingleVm
//! (systemd/service). Other BuiltinBackendId variants return
//! `AdapterNotImplemented` — users see a clear message that the backend exists
//! but no execution adapter has been shipped yet.

use std::path::Path;

use crate::ext::errors::{ExtensionError, ExtensionResult};
use crate::extension::BuiltinBackendId;

/// Action to run against the resolved backend.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtAction {
    Apply,
    Destroy,
}

/// Dispatch to the appropriate backend `*_from_ext` entry point.
pub fn run(
    backend: BuiltinBackendId,
    handler: Option<&str>,
    action: ExtAction,
    creds_json: &str,
    config_json: &str,
    pack_path: Option<&Path>,
) -> ExtensionResult<()> {
    match (backend, action) {
        (BuiltinBackendId::Desktop, ExtAction::Apply) => {
            crate::desktop::apply_from_ext(handler, config_json, creds_json)
                .map_err(|e| ExtensionError::BackendExecutionFailed { backend, source: e })
        }
        (BuiltinBackendId::Desktop, ExtAction::Destroy) => {
            crate::desktop::destroy_from_ext(handler, config_json, creds_json)
                .map_err(|e| ExtensionError::BackendExecutionFailed { backend, source: e })
        }
        (BuiltinBackendId::SingleVm, ExtAction::Apply) => {
            crate::single_vm::apply_from_ext(config_json, creds_json, pack_path).map_err(|e| {
                ExtensionError::BackendExecutionFailed {
                    backend,
                    source: anyhow::Error::from(e),
                }
            })
        }
        (BuiltinBackendId::SingleVm, ExtAction::Destroy) => {
            crate::single_vm::destroy_from_ext(config_json, creds_json).map_err(|e| {
                ExtensionError::BackendExecutionFailed {
                    backend,
                    source: anyhow::Error::from(e),
                }
            })
        }
        (BuiltinBackendId::Aws, ExtAction::Apply) => {
            crate::aws::apply_from_ext(config_json, creds_json, pack_path)
                .map_err(|e| ExtensionError::BackendExecutionFailed { backend, source: e })
        }
        (BuiltinBackendId::Aws, ExtAction::Destroy) => {
            crate::aws::destroy_from_ext(config_json, creds_json, pack_path)
                .map_err(|e| ExtensionError::BackendExecutionFailed { backend, source: e })
        }
        (BuiltinBackendId::Gcp, ExtAction::Apply) => {
            crate::gcp::apply_from_ext(config_json, creds_json, pack_path)
                .map_err(|e| ExtensionError::BackendExecutionFailed { backend, source: e })
        }
        (BuiltinBackendId::Gcp, ExtAction::Destroy) => {
            crate::gcp::destroy_from_ext(config_json, creds_json, pack_path)
                .map_err(|e| ExtensionError::BackendExecutionFailed { backend, source: e })
        }
        (BuiltinBackendId::Azure, ExtAction::Apply) => {
            crate::azure::apply_from_ext(config_json, creds_json, pack_path)
                .map_err(|e| ExtensionError::BackendExecutionFailed { backend, source: e })
        }
        (BuiltinBackendId::Azure, ExtAction::Destroy) => {
            crate::azure::destroy_from_ext(config_json, creds_json, pack_path)
                .map_err(|e| ExtensionError::BackendExecutionFailed { backend, source: e })
        }
        _ => Err(ExtensionError::AdapterNotImplemented { backend }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unsupported_backend_returns_adapter_not_implemented_apply() {
        let err = run(
            BuiltinBackendId::Terraform,
            None,
            ExtAction::Apply,
            "{}",
            "{}",
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::AdapterNotImplemented {
                backend: BuiltinBackendId::Terraform
            }
        ));
    }

    #[test]
    fn unsupported_backend_returns_adapter_not_implemented_destroy() {
        let err = run(
            BuiltinBackendId::Terraform,
            None,
            ExtAction::Destroy,
            "{}",
            "{}",
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::AdapterNotImplemented {
                backend: BuiltinBackendId::Terraform
            }
        ));
    }

    #[test]
    fn gcp_invalid_config_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::Gcp,
            None,
            ExtAction::Apply,
            "{}",
            "not json",
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::BackendExecutionFailed {
                backend: BuiltinBackendId::Gcp,
                ..
            }
        ));
    }

    #[test]
    fn gcp_destroy_invalid_config_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::Gcp,
            None,
            ExtAction::Destroy,
            "{}",
            "not json",
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::BackendExecutionFailed {
                backend: BuiltinBackendId::Gcp,
                ..
            }
        ));
    }

    #[test]
    fn desktop_invalid_handler_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::Desktop,
            Some("kubernetes"),
            ExtAction::Apply,
            "{}",
            r#"{"deploymentName":"x","projectDir":"/tmp"}"#,
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::BackendExecutionFailed {
                backend: BuiltinBackendId::Desktop,
                ..
            }
        ));
    }

    #[test]
    fn single_vm_invalid_config_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::SingleVm,
            Some("single-vm"),
            ExtAction::Apply,
            "{}",
            "not json",
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::BackendExecutionFailed {
                backend: BuiltinBackendId::SingleVm,
                ..
            }
        ));
    }

    #[test]
    fn aws_invalid_config_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::Aws,
            None,
            ExtAction::Apply,
            "{}",
            "not json",
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::BackendExecutionFailed {
                backend: BuiltinBackendId::Aws,
                ..
            }
        ));
    }

    #[test]
    fn aws_destroy_invalid_config_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::Aws,
            None,
            ExtAction::Destroy,
            "{}",
            "not json",
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::BackendExecutionFailed {
                backend: BuiltinBackendId::Aws,
                ..
            }
        ));
    }

    #[test]
    fn azure_invalid_config_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::Azure,
            None,
            ExtAction::Apply,
            "{}",
            "not json",
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::BackendExecutionFailed {
                backend: BuiltinBackendId::Azure,
                ..
            }
        ));
    }

    #[test]
    fn azure_destroy_invalid_config_surfaces_as_backend_execution_failed() {
        let err = run(
            BuiltinBackendId::Azure,
            None,
            ExtAction::Destroy,
            "{}",
            "not json",
            None,
        )
        .unwrap_err();
        assert!(matches!(
            err,
            ExtensionError::BackendExecutionFailed {
                backend: BuiltinBackendId::Azure,
                ..
            }
        ));
    }

    #[test]
    fn ext_action_copy_semantics() {
        let a = ExtAction::Apply;
        let b = a;
        assert_eq!(a, b);
    }
}
