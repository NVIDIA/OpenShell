// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Canonical DNS-name handling for policy lookup and correlation keys.

use hickory_proto::rr::Name;
use std::fmt;

/// A lower-case absolute DNS name without its presentation trailing dot.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) struct NormalizedName(String);

impl NormalizedName {
    pub(crate) fn parse(raw: &str) -> Result<Self, NameError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() || trimmed.parse::<std::net::IpAddr>().is_ok() {
            return Err(NameError);
        }

        let absolute = if trimmed.ends_with('.') {
            trimmed.to_string()
        } else {
            format!("{trimmed}.")
        };
        let parsed = Name::from_ascii(&absolute).map_err(|_| NameError)?;
        if parsed.is_root() {
            return Err(NameError);
        }

        // DNS names are case-insensitive. Canonicalizing to lowercase also
        // prevents DNS 0x20 case variation from becoming an unobserved data
        // channel in policy matching and synthetic-allocation identities.
        let normalized = parsed.to_ascii().trim_end_matches('.').to_ascii_lowercase();
        if normalized.is_empty() {
            return Err(NameError);
        }
        Ok(Self(normalized))
    }

    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }

    pub(crate) fn as_absolute_name(&self) -> Name {
        Name::from_ascii(format!("{}.", self.0)).expect("normalized DNS name must remain valid")
    }
}

impl fmt::Display for NormalizedName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct NameError;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_case_and_trailing_dot() {
        let lower = NormalizedName::parse("Db.Example.COM.").unwrap();
        assert_eq!(lower.as_str(), "db.example.com");
        assert_eq!(NormalizedName::parse("db.example.com").unwrap(), lower);
    }

    #[test]
    fn rejects_empty_root_ip_literals_and_invalid_labels() {
        for raw in ["", ".", "192.0.2.10", "2001:db8::1", "bad name.example"] {
            assert!(NormalizedName::parse(raw).is_err(), "accepted {raw:?}");
        }
    }
}
