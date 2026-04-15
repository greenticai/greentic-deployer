use std::collections::HashMap;

use greentic_config_types::{TelemetryConfig as ResolvedTelemetryConfig, TelemetryExporterKind};
use greentic_telemetry::{
    TelemetryConfig,
    export::{ExportConfig, ExportMode, Sampling},
    init_telemetry_from_config,
};

use crate::config::DeployerConfig;
use crate::error::{DeployerError, Result};

pub fn init(config: &DeployerConfig) -> Result<()> {
    let telemetry_cfg = config.telemetry_config();
    if !telemetry_cfg.enabled || matches!(telemetry_cfg.exporter, TelemetryExporterKind::None) {
        return Ok(());
    }

    let export = export_from_config(telemetry_cfg);
    let cfg = TelemetryConfig {
        service_name: format!("greentic-deployer-{}", config.provider.as_str()),
    };

    init_telemetry_from_config(cfg, export).map_err(|err| DeployerError::Telemetry(err.to_string()))
}

fn export_from_config(cfg: &ResolvedTelemetryConfig) -> ExportConfig {
    let sampling = Sampling::TraceIdRatio(cfg.sampling as f64);

    let mut export = ExportConfig::json_default();
    export.sampling = sampling;

    match cfg.exporter {
        TelemetryExporterKind::Stdout => export,
        TelemetryExporterKind::Otlp => {
            export.mode = ExportMode::OtlpGrpc;
            export.endpoint = cfg
                .endpoint
                .clone()
                .or_else(|| std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT").ok())
                .or_else(|| Some("https://otel.greentic.ai".to_string()));
            export.headers = HashMap::new();
            export.compression = None;
            export
        }
        TelemetryExporterKind::None => ExportConfig::json_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base_config(exporter: TelemetryExporterKind) -> ResolvedTelemetryConfig {
        ResolvedTelemetryConfig {
            enabled: true,
            exporter,
            endpoint: Some("https://otel.test".to_string()),
            sampling: 0.5,
        }
    }

    #[test]
    fn stdout_uses_json_export() {
        let export = export_from_config(&base_config(TelemetryExporterKind::Stdout));
        assert!(matches!(export.mode, ExportMode::JsonStdout));
        assert!(
            matches!(export.sampling, Sampling::TraceIdRatio(v) if (v - 0.5).abs() < f64::EPSILON)
        );
    }

    #[test]
    fn otlp_prefers_config_endpoint() {
        let export = export_from_config(&base_config(TelemetryExporterKind::Otlp));
        assert!(matches!(export.mode, ExportMode::OtlpGrpc));
        assert_eq!(export.endpoint.as_deref(), Some("https://otel.test"));
    }
}
