// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! OCSF `connection_info` object.

use serde::{Deserialize, Serialize};

use crate::enums::ConnectionDirectionId;

/// OCSF Connection Info object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectionInfo {
    /// Protocol name (e.g., "tcp", "udp").
    ///
    /// Kept as `String` because the OCSF spec defines this as free-form
    /// `string_t`, and sandbox integration passes runtime-dynamic values.
    pub protocol_name: String,

    /// Connection direction id. Required by the OCSF schema.
    pub direction_id: ConnectionDirectionId,

    /// Sibling label for `direction_id`.
    pub direction: String,
}

impl ConnectionInfo {
    /// Create connection info with the given protocol and an unknown direction.
    #[must_use]
    pub fn new(protocol: &str) -> Self {
        let direction_id = ConnectionDirectionId::Unknown;
        Self {
            protocol_name: protocol.to_string(),
            direction_id,
            direction: direction_id.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_info() {
        let info = ConnectionInfo::new("tcp");
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["protocol_name"], "tcp");
        // Required by the OCSF schema; the direction is not known at these call sites.
        assert_eq!(json["direction_id"], 0);
        assert_eq!(json["direction"], "Unknown");
    }
}
