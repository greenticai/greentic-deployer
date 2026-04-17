//! Shared diagnostic types for extension validation results.
//!
//! Placed here (rather than in `wasm.rs` or `errors.rs`) so that both modules
//! can depend on this one without creating a circular import cycle.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Diagnostic {
    pub severity: DiagnosticSeverity,
    pub code: String,
    pub message: String,
    pub path: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiagnosticSeverity {
    Error,
    Warning,
    Info,
}

impl<'de> serde::Deserialize<'de> for Diagnostic {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        #[derive(serde::Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct Raw {
            severity: String,
            code: String,
            message: String,
            #[serde(default)]
            path: Option<String>,
        }
        let r = Raw::deserialize(d)?;
        Ok(Diagnostic {
            severity: match r.severity.as_str() {
                "error" => DiagnosticSeverity::Error,
                "warning" => DiagnosticSeverity::Warning,
                _ => DiagnosticSeverity::Info,
            },
            code: r.code,
            message: r.message,
            path: r.path,
        })
    }
}
