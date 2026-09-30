//! Adapter capability flags (P5-R3): feature exposure follows capability.
//!
//! Every deployer declares what it can actually do. A plan that needs a
//! capability the bound adapter lacks is refused with the capability's name
//! ([`AdapterCapabilities::require`]) instead of running a verb that would
//! silently do less than asked. The default is [`AdapterCapabilities::NONE`]:
//! an adapter that has not been assessed claims nothing.

use serde::Serialize;
use thiserror::Error;

/// One capability an adapter may or may not have.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    /// `drain_revision` waits the drain window and CONFIRMS the revision
    /// serves nothing, and the archive gate can check it.
    Drain,
    /// Weighted traffic splits across revisions are enforced live.
    TrafficSplit,
    /// The adapter provisions the public ingress / address itself.
    IngressManaged,
    /// The runtime can pull bundles/images from a registry needing auth.
    PrivateRegistryAuth,
    /// More than one instance of a revision may serve at once without
    /// corrupting session state.
    MultiInstanceSafe,
    /// The adapter can tear its provider resources down (archive / sweep).
    Remove,
    /// Each revision runs the runtime image its own manifest pinned
    /// (unified update L2), not just the environment-wide answer.
    RuntimePin,
}

impl Capability {
    /// Every capability, in report order.
    pub const ALL: [Capability; 7] = [
        Capability::Drain,
        Capability::TrafficSplit,
        Capability::IngressManaged,
        Capability::PrivateRegistryAuth,
        Capability::MultiInstanceSafe,
        Capability::Remove,
        Capability::RuntimePin,
    ];

    /// Wire name (matches the serde spelling).
    pub fn as_str(self) -> &'static str {
        match self {
            Capability::Drain => "drain",
            Capability::TrafficSplit => "traffic_split",
            Capability::IngressManaged => "ingress_managed",
            Capability::PrivateRegistryAuth => "private_registry_auth",
            Capability::MultiInstanceSafe => "multi_instance_safe",
            Capability::Remove => "remove",
            Capability::RuntimePin => "runtime_pin",
        }
    }
}

impl std::fmt::Display for Capability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A refused plan: the bound adapter lacks a capability the plan needs.
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[error("deployer `{adapter}` lacks capability `{capability}`")]
pub struct CapabilityMissing {
    pub adapter: String,
    pub capability: Capability,
}

/// What one adapter can do. Field names are the P5-R3 wire names.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct AdapterCapabilities {
    pub drain: bool,
    pub traffic_split: bool,
    pub ingress_managed: bool,
    pub private_registry_auth: bool,
    pub multi_instance_safe: bool,
    pub remove: bool,
    pub runtime_pin: bool,
}

impl AdapterCapabilities {
    /// Claims nothing — the default for an unassessed adapter.
    pub const NONE: Self = Self {
        drain: false,
        traffic_split: false,
        ingress_managed: false,
        private_registry_auth: false,
        multi_instance_safe: false,
        remove: false,
        runtime_pin: false,
    };

    /// Whether `capability` is present.
    pub fn has(&self, capability: Capability) -> bool {
        match capability {
            Capability::Drain => self.drain,
            Capability::TrafficSplit => self.traffic_split,
            Capability::IngressManaged => self.ingress_managed,
            Capability::PrivateRegistryAuth => self.private_registry_auth,
            Capability::MultiInstanceSafe => self.multi_instance_safe,
            Capability::Remove => self.remove,
            Capability::RuntimePin => self.runtime_pin,
        }
    }

    /// The capabilities in `required` this adapter lacks, in input order.
    pub fn missing(&self, required: &[Capability]) -> Vec<Capability> {
        required.iter().copied().filter(|c| !self.has(*c)).collect()
    }

    /// Refuse a plan needing `capability` when the adapter lacks it.
    pub fn require(&self, adapter: &str, capability: Capability) -> Result<(), CapabilityMissing> {
        if self.has(capability) {
            Ok(())
        } else {
            Err(CapabilityMissing {
                adapter: adapter.to_string(),
                capability,
            })
        }
    }
}

/// Capabilities plus the adapter's own caveats, for report output.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct CapabilityReport {
    pub kind: String,
    pub capabilities: AdapterCapabilities,
    /// Capabilities this adapter lacks, by wire name.
    pub missing: Vec<Capability>,
    /// Why a flag has the value it has, where that is not obvious.
    pub notes: Vec<&'static str>,
}

impl CapabilityReport {
    pub fn new(kind: &str, capabilities: AdapterCapabilities, notes: &[&'static str]) -> Self {
        Self {
            kind: kind.to_string(),
            capabilities,
            missing: capabilities.missing(&Capability::ALL),
            notes: notes.to_vec(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn none_lacks_everything() {
        assert_eq!(
            AdapterCapabilities::NONE.missing(&Capability::ALL),
            Capability::ALL.to_vec()
        );
        assert_eq!(AdapterCapabilities::default(), AdapterCapabilities::NONE);
    }

    #[test]
    fn require_refuses_with_the_capability_name() {
        let caps = AdapterCapabilities {
            drain: true,
            ..AdapterCapabilities::NONE
        };
        caps.require("k", Capability::Drain).unwrap();
        let err = caps
            .require("greentic.deployer.x", Capability::MultiInstanceSafe)
            .unwrap_err();
        assert_eq!(err.capability, Capability::MultiInstanceSafe);
        assert!(err.to_string().contains("multi_instance_safe"), "{err}");
    }

    #[test]
    fn report_serializes_wire_names_and_missing() {
        let caps = AdapterCapabilities {
            drain: true,
            remove: true,
            ..AdapterCapabilities::NONE
        };
        let v = serde_json::to_value(CapabilityReport::new("k", caps, &["n"])).unwrap();
        assert_eq!(v["capabilities"]["drain"], true);
        assert_eq!(v["capabilities"]["multi_instance_safe"], false);
        assert_eq!(
            v["missing"],
            serde_json::json!([
                "traffic_split",
                "ingress_managed",
                "private_registry_auth",
                "multi_instance_safe",
                "runtime_pin"
            ])
        );
        for c in Capability::ALL {
            assert_eq!(serde_json::to_value(c).unwrap(), c.as_str());
        }
    }
}
