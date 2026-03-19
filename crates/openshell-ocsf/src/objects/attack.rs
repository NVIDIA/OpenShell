// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `attack`, `technique`, and `tactic` objects.

use serde::{Deserialize, Serialize};

/// OCSF Attack object — MITRE ATT&CK mapping.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Attack {
    /// The attack technique.
    pub technique: Technique,

    /// The attack tactic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tactic: Option<Tactic>,
}

/// OCSF Technique object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Technique {
    /// Technique ID (e.g., "T1550").
    pub uid: String,

    /// Technique name.
    pub name: String,
}

/// OCSF Tactic object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tactic {
    /// Tactic ID (e.g., "TA0008").
    pub uid: String,

    /// Tactic name.
    pub name: String,
}

impl Attack {
    /// Create a MITRE ATT&CK mapping with technique and tactic.
    #[must_use]
    pub fn mitre(
        technique_uid: &str,
        technique_name: &str,
        tactic_uid: &str,
        tactic_name: &str,
    ) -> Self {
        Self {
            technique: Technique {
                uid: technique_uid.to_string(),
                name: technique_name.to_string(),
            },
            tactic: Some(Tactic {
                uid: tactic_uid.to_string(),
                name: tactic_name.to_string(),
            }),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_attack_mitre() {
        let attack = Attack::mitre(
            "T1550",
            "Use Alternate Authentication Material",
            "TA0008",
            "Lateral Movement",
        );
        let json = serde_json::to_value(&attack).unwrap();
        assert_eq!(json["technique"]["uid"], "T1550");
        assert_eq!(
            json["technique"]["name"],
            "Use Alternate Authentication Material"
        );
        assert_eq!(json["tactic"]["uid"], "TA0008");
        assert_eq!(json["tactic"]["name"], "Lateral Movement");
    }
}
