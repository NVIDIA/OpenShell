// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Extension mechanism that owns a service registration.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[non_exhaustive]
pub enum ExtensionKind {
    Middleware,
    Interceptor,
}

impl ExtensionKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Middleware => "middleware",
            Self::Interceptor => "interceptor",
        }
    }
}

impl fmt::Display for ExtensionKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

/// A gateway-owned registration name for a middleware or interceptor service.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExtensionIdentity(String);

/// The exact JWT audience expected by an extension service.
///
/// Audiences are intentionally opaque. Callers must resolve them from trusted
/// gateway configuration rather than constructing them from untrusted input.
#[derive(Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct ExtensionAudience(String);

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("extension {kind} must not be empty")]
    Empty { kind: &'static str },
    #[error("extension {kind} must not have leading or trailing whitespace")]
    SurroundingWhitespace { kind: &'static str },
    #[error("extension {kind} must not contain control characters")]
    ControlCharacter { kind: &'static str },
}

macro_rules! opaque_value {
    ($ty:ident, $kind:literal) => {
        impl $ty {
            pub fn new(value: impl Into<String>) -> Result<Self, IdentityError> {
                let value = value.into();
                validate(&value, $kind)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }

            pub fn into_inner(self) -> String {
                self.0
            }
        }

        impl fmt::Debug for $ty {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter
                    .debug_tuple(stringify!($ty))
                    .field(&self.0)
                    .finish()
            }
        }

        impl fmt::Display for $ty {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl AsRef<str> for $ty {
            fn as_ref(&self) -> &str {
                self.as_str()
            }
        }

        impl FromStr for $ty {
            type Err = IdentityError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }
    };
}

opaque_value!(ExtensionIdentity, "identity");
opaque_value!(ExtensionAudience, "audience");

impl ExtensionAudience {
    /// Build the deterministic fallback audience for a validated registration.
    ///
    /// Explicit operator-configured audiences remain opaque and take precedence.
    /// This helper gives both extension mechanisms the same fallback namespace.
    pub fn for_registration(
        kind: ExtensionKind,
        registration_name: &str,
    ) -> Result<Self, IdentityError> {
        let identity = ExtensionIdentity::new(registration_name)?;
        Ok(Self(format!("urn:openshell:extension:{kind}:{identity}")))
    }
}

fn validate(value: &str, kind: &'static str) -> Result<(), IdentityError> {
    if value.is_empty() {
        return Err(IdentityError::Empty { kind });
    }
    if value.trim() != value {
        return Err(IdentityError::SurroundingWhitespace { kind });
    }
    if value.chars().any(char::is_control) {
        return Err(IdentityError::ControlCharacter { kind });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_and_audience_are_opaque_exact_values() {
        let identity = ExtensionIdentity::new("content-filter").unwrap();
        let audience = ExtensionAudience::new("https://filters.example/openshell").unwrap();
        assert_eq!(identity.as_str(), "content-filter");
        assert_eq!(audience.as_str(), "https://filters.example/openshell");
    }

    #[test]
    fn values_reject_ambiguous_whitespace_and_controls() {
        assert_eq!(
            ExtensionIdentity::new(" content-filter").unwrap_err(),
            IdentityError::SurroundingWhitespace { kind: "identity" }
        );
        assert_eq!(
            ExtensionAudience::new("audience\n").unwrap_err(),
            IdentityError::SurroundingWhitespace { kind: "audience" }
        );
        assert_eq!(
            ExtensionAudience::new("").unwrap_err(),
            IdentityError::Empty { kind: "audience" }
        );
    }

    #[test]
    fn fallback_audience_is_kind_scoped_and_validates_registration() {
        assert_eq!(
            ExtensionAudience::for_registration(ExtensionKind::Middleware, "content-filter")
                .unwrap()
                .as_str(),
            "urn:openshell:extension:middleware:content-filter"
        );
        assert_eq!(
            ExtensionAudience::for_registration(ExtensionKind::Interceptor, "content-filter")
                .unwrap()
                .as_str(),
            "urn:openshell:extension:interceptor:content-filter"
        );
        assert!(matches!(
            ExtensionAudience::for_registration(ExtensionKind::Middleware, " bad-name"),
            Err(IdentityError::SurroundingWhitespace { kind: "identity" })
        ));
    }
}
