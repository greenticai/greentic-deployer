//! cpu / memory sizing: snap a request to a valid Container Apps consumption pair.
//!
//! The pair table is `NEEDS_LIVE` (decision record); it is isolated here.

/// Valid consumption pairs: (cpu, memory MiB), memory = 2 x cpu GiB.
const PAIRS: &[(f64, u32)] = &[
    (0.25, 512),
    (0.5, 1024),
    (0.75, 1536),
    (1.0, 2048),
    (1.25, 2560),
    (1.5, 3072),
    (1.75, 3584),
    (2.0, 4096),
    (2.25, 4608),
    (2.5, 5120),
    (2.75, 5632),
    (3.0, 6144),
    (3.25, 6656),
    (3.5, 7168),
    (3.75, 7680),
    (4.0, 8192),
];

/// The snapped container resources.
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Resources {
    pub cpu: f64,
    /// ARM string, e.g. `1Gi`.
    pub memory: String,
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub(crate) enum SizingError {
    #[error("`{0}` is not a valid cpu (a positive number of cores)")]
    BadCpu(String),
    #[error("`{0}` is not a valid memory size (use e.g. `1Gi` or `512Mi`)")]
    BadMemory(String),
    #[error(
        "no Container Apps consumption size fits cpu {cpu:?} / memory {memory:?} (max 4 cpu, 8Gi)"
    )]
    TooLarge {
        cpu: Option<String>,
        memory: Option<String>,
    },
}

fn parse_cpu(raw: &str) -> Result<f64, SizingError> {
    match raw.trim().parse::<f64>() {
        Ok(v) if v.is_finite() && v > 0.0 => Ok(v),
        _ => Err(SizingError::BadCpu(raw.to_string())),
    }
}

/// Memory in MiB from `<n>Mi` / `<n>Gi` (decimal Gi allowed).
pub(crate) fn parse_memory_mib(raw: &str) -> Result<u32, SizingError> {
    let bad = || SizingError::BadMemory(raw.to_string());
    let t = raw.trim();
    let (num, mult) = if let Some(n) = t.strip_suffix("Gi") {
        (n, 1024.0)
    } else if let Some(n) = t.strip_suffix("Mi") {
        (n, 1.0)
    } else {
        return Err(bad());
    };
    let v: f64 = num.parse().map_err(|_| bad())?;
    if !v.is_finite() || v <= 0.0 || v * mult > f64::from(u32::MAX) {
        return Err(bad());
    }
    Ok((v * mult).ceil() as u32)
}

fn memory_string(mib: u32) -> String {
    if mib.is_multiple_of(1024) {
        format!("{}Gi", mib / 1024)
    } else {
        format!("{:.1}Gi", f64::from(mib) / 1024.0)
    }
}

/// Smallest valid pair covering both requests. With neither, the smallest
/// pair that fits the runtime (0.5 cpu / 1Gi).
pub(crate) fn snap(cpu: Option<&str>, memory: Option<&str>) -> Result<Resources, SizingError> {
    let want_cpu = cpu.map(parse_cpu).transpose()?;
    let want_mem = memory.map(parse_memory_mib).transpose()?;
    let (want_cpu, want_mem) = match (want_cpu, want_mem) {
        (None, None) => (0.5, 1024),
        (c, m) => (c.unwrap_or(0.25), m.unwrap_or(512)),
    };
    PAIRS
        .iter()
        .find(|(c, m)| *c >= want_cpu && *m >= want_mem)
        .map(|(c, m)| Resources {
            cpu: *c,
            memory: memory_string(*m),
        })
        .ok_or(SizingError::TooLarge {
            cpu: cpu.map(str::to_string),
            memory: memory.map(str::to_string),
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_is_half_a_core_and_1gi() {
        assert_eq!(snap(None, None).unwrap().memory, "1Gi");
        assert_eq!(snap(None, None).unwrap().cpu, 0.5);
    }

    #[test]
    fn memory_drives_the_pair() {
        let r = snap(None, Some("832Mi")).unwrap();
        assert_eq!((r.cpu, r.memory.as_str()), (0.5, "1Gi"));
        let r = snap(Some("1"), Some("512Mi")).unwrap();
        assert_eq!((r.cpu, r.memory.as_str()), (1.0, "2Gi"));
        assert_eq!(snap(None, Some("2.5Gi")).unwrap().memory, "2.5Gi");
    }

    #[test]
    fn bad_and_oversized_requests_are_refused() {
        assert!(matches!(snap(Some("0"), None), Err(SizingError::BadCpu(_))));
        assert!(matches!(
            snap(None, Some("1G")),
            Err(SizingError::BadMemory(_))
        ));
        assert!(matches!(
            snap(None, Some("9Gi")),
            Err(SizingError::TooLarge { .. })
        ));
        assert!(matches!(
            snap(Some("5"), None),
            Err(SizingError::TooLarge { .. })
        ));
    }
}
