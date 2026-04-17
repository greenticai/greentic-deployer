use std::str::FromStr;

use crate::ext::describe::Execution;
use crate::ext::errors::{ExtensionError, ExtensionResult};
use crate::extension::BuiltinBackendId;

/// Resolved built-in dispatch parameters. IO-free. Actual execution is
/// performed by the caller via `cli_builtin_dispatch`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BridgeResolved {
    pub backend: BuiltinBackendId,
    pub handler: Option<String>,
}

/// Resolve `Execution::Builtin { backend, handler }` into a validated
/// `(BuiltinBackendId, handler)` pair. Returns an error if the backend string
/// is unknown or the handler is not permitted by the backend.
pub fn resolve(execution: &Execution, target_id: &str) -> ExtensionResult<BridgeResolved> {
    match execution {
        Execution::Builtin { backend, handler } => {
            let id = BuiltinBackendId::from_str(backend).map_err(|_| {
                ExtensionError::UnknownBuiltinBackend {
                    backend: backend.clone(),
                    target_id: target_id.into(),
                }
            })?;
            if !id.handler_matches(handler.as_deref()) {
                return Err(ExtensionError::UnsupportedHandler {
                    backend: backend.clone(),
                    handler: handler.clone(),
                });
            }
            Ok(BridgeResolved { backend: id, handler: handler.clone() })
        }
        Execution::Wasm => Err(ExtensionError::ModeBNotImplemented),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_builtin_known_backend_no_handler() {
        let exec = Execution::Builtin { backend: "terraform".into(), handler: None };
        let r = resolve(&exec, "some-tf-target").unwrap();
        assert_eq!(r.backend, BuiltinBackendId::Terraform);
        assert!(r.handler.is_none());
    }

    #[test]
    fn resolve_unknown_backend_errors_with_target_id() {
        let exec = Execution::Builtin { backend: "mystery".into(), handler: None };
        let err = resolve(&exec, "t").unwrap_err();
        match err {
            ExtensionError::UnknownBuiltinBackend { backend, target_id } => {
                assert_eq!(backend, "mystery");
                assert_eq!(target_id, "t");
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn resolve_unsupported_handler_for_existing_backend_errors() {
        let exec = Execution::Builtin {
            backend: "aws".into(),
            handler: Some("eks".into()),
        };
        let err = resolve(&exec, "t").unwrap_err();
        match err {
            ExtensionError::UnsupportedHandler { backend, handler } => {
                assert_eq!(backend, "aws");
                assert_eq!(handler.as_deref(), Some("eks"));
            }
            other => panic!("wrong error: {other:?}"),
        }
    }

    #[test]
    fn resolve_wasm_returns_mode_b_not_implemented() {
        let exec = Execution::Wasm;
        let err = resolve(&exec, "t").unwrap_err();
        assert!(matches!(err, ExtensionError::ModeBNotImplemented));
    }
}
