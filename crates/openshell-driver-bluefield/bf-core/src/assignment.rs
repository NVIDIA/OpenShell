//! The VF assignment the control-plane leader hands to a compute node.
//!
//! The leader allocates a VF, programs OVS via the DPU controller, then stamps
//! the resulting assignment into the sandbox's `template.labels`. The
//! compute-node role reads it back and binds exactly that VF. Carrying the
//! assignment as labels keeps it on the existing `ComputeDriver` contract with
//! no new proto, and makes it policy-stamped (a guest cannot forge it).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

/// Label key prefix for all BlueField assignment fields.
pub const LABEL_PREFIX: &str = "openshell.io/bluefield.";

pub const LABEL_HOST_BDF: &str = "openshell.io/bluefield.host-bdf";
pub const LABEL_LEASE_GENERATION: &str = "openshell.io/bluefield.lease-generation";
pub const LABEL_GUEST_MAC: &str = "openshell.io/bluefield.guest-mac";
pub const LABEL_ATTACHMENT_ID: &str = "openshell.io/bluefield.attachment-id";
pub const LABEL_PF: &str = "openshell.io/bluefield.pf";
pub const LABEL_VF_INDEX: &str = "openshell.io/bluefield.vf-index";

/// A leader-decided VF assignment for one sandbox.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BluefieldAssignment {
    /// Host PCI BDF of the VF the compute node must bind.
    pub host_bdf: String,
    /// Controller lease generation. Carried for correlation/fencing; the
    /// compute node never detaches, so it does not act on this directly.
    pub lease_generation: u64,
    /// Guest-visible VF MAC (the leader derives this deterministically).
    pub guest_mac: String,
    /// Controller attachment id, for logging/correlation.
    pub attachment_id: String,
    /// Optional cross-host coordinate; not required to bind.
    pub pf: Option<String>,
    pub vf_index: Option<u32>,
}

impl BluefieldAssignment {
    /// True when the labels carry a (claimed) BlueField assignment. Used by the
    /// compute node to fail closed when an unassigned sandbox arrives.
    #[must_use]
    pub fn is_present(labels: &HashMap<String, String>) -> bool {
        labels.contains_key(LABEL_HOST_BDF)
    }

    /// Render the assignment as label key/value pairs.
    #[must_use]
    pub fn to_labels(&self) -> Vec<(String, String)> {
        let mut out = vec![
            (LABEL_HOST_BDF.to_string(), self.host_bdf.clone()),
            (
                LABEL_LEASE_GENERATION.to_string(),
                self.lease_generation.to_string(),
            ),
            (LABEL_GUEST_MAC.to_string(), self.guest_mac.clone()),
            (LABEL_ATTACHMENT_ID.to_string(), self.attachment_id.clone()),
        ];
        if let Some(pf) = &self.pf {
            out.push((LABEL_PF.to_string(), pf.clone()));
        }
        if let Some(vf_index) = self.vf_index {
            out.push((LABEL_VF_INDEX.to_string(), vf_index.to_string()));
        }
        out
    }

    /// Stamp the assignment into a labels map (overwriting any prior values).
    pub fn apply(&self, labels: &mut HashMap<String, String>) {
        for (key, value) in self.to_labels() {
            labels.insert(key, value);
        }
    }

    /// Parse an assignment from a labels map. Returns `Err` when a required
    /// key is missing or malformed (the compute node treats this as fail-closed).
    pub fn from_labels(labels: &HashMap<String, String>) -> Result<Self, String> {
        let required = |key: &str| -> Result<String, String> {
            labels
                .get(key)
                .map(|v| v.trim().to_string())
                .filter(|v| !v.is_empty())
                .ok_or_else(|| format!("missing required BlueField assignment label {key}"))
        };

        let host_bdf = required(LABEL_HOST_BDF)?;
        let guest_mac = required(LABEL_GUEST_MAC)?;
        let attachment_id = required(LABEL_ATTACHMENT_ID)?;
        let lease_generation = required(LABEL_LEASE_GENERATION)?
            .parse::<u64>()
            .map_err(|err| format!("invalid {LABEL_LEASE_GENERATION}: {err}"))?;

        let pf = labels
            .get(LABEL_PF)
            .map(|v| v.trim().to_string())
            .filter(|v| !v.is_empty());
        let vf_index = match labels.get(LABEL_VF_INDEX).map(|v| v.trim()) {
            Some(v) if !v.is_empty() => Some(
                v.parse::<u32>()
                    .map_err(|err| format!("invalid {LABEL_VF_INDEX}: {err}"))?,
            ),
            _ => None,
        };

        Ok(Self {
            host_bdf,
            lease_generation,
            guest_mac,
            attachment_id,
            pf,
            vf_index,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> BluefieldAssignment {
        BluefieldAssignment {
            host_bdf: "0000:03:00.2".to_string(),
            lease_generation: 42,
            guest_mac: "02:00:00:00:00:01".to_string(),
            attachment_id: "bf-sb-1".to_string(),
            pf: Some("0".to_string()),
            vf_index: Some(3),
        }
    }

    #[test]
    fn round_trips_through_labels() {
        let assignment = sample();
        let mut labels = HashMap::new();
        assignment.apply(&mut labels);
        assert!(BluefieldAssignment::is_present(&labels));
        assert_eq!(
            BluefieldAssignment::from_labels(&labels).unwrap(),
            assignment
        );
    }

    #[test]
    fn round_trips_without_optional_coordinate() {
        let assignment = BluefieldAssignment {
            pf: None,
            vf_index: None,
            ..sample()
        };
        let mut labels = HashMap::new();
        assignment.apply(&mut labels);
        assert_eq!(
            BluefieldAssignment::from_labels(&labels).unwrap(),
            assignment
        );
    }

    #[test]
    fn missing_required_label_is_rejected() {
        let mut labels = HashMap::new();
        sample().apply(&mut labels);
        labels.remove(LABEL_HOST_BDF);
        assert!(!BluefieldAssignment::is_present(&labels));
        let err = BluefieldAssignment::from_labels(&labels).unwrap_err();
        assert!(err.contains(LABEL_HOST_BDF));
    }

    #[test]
    fn malformed_lease_generation_is_rejected() {
        let mut labels = HashMap::new();
        sample().apply(&mut labels);
        labels.insert(
            LABEL_LEASE_GENERATION.to_string(),
            "not-a-number".to_string(),
        );
        let err = BluefieldAssignment::from_labels(&labels).unwrap_err();
        assert!(err.contains(LABEL_LEASE_GENERATION));
    }
}
