// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Trust-on-first-use executable pins kept by the sandbox runtime itself.
//!
//! A supervisor pins the digest of every executable in an identity chain the
//! first time a mediated TCP open offers it, before it evaluates policy, and
//! denies a later open whose executable at that path has another digest. Those
//! pins live in the supervisor process, so a replacement supervisor that takes
//! over a running generation would start without them and pin a binary the
//! workload replaced in the meantime.
//!
//! The runtime therefore records the first digest it ever offered for each
//! path, from its own measurements, for the lifetime of the generation, and
//! refuses to offer an identity that contradicts one: such an open reaches
//! every supervisor, old or new, as an identity failure, which it denies. The
//! pins are never relayed by a supervisor. The bound matches the supervisor's
//! identity cache, so a full journal refuses new paths as a full cache does.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Mutex;

use openshell_isolation_interface::contract::{BinaryIdentity, ResolveError, Sha256Digest};

/// Most pinned paths, matching the supervisor's binary identity cache.
pub const MAX_BINARY_IDENTITY_PINS: usize = 4096;

/// First digest offered for each executable path in this generation.
#[derive(Debug, Default)]
pub struct BinaryIdentityPins {
    pins: Mutex<HashMap<PathBuf, Sha256Digest>>,
}

impl BinaryIdentityPins {
    /// Check an identity about to be offered for a TCP open against the
    /// pins, recording the paths it introduces.
    ///
    /// An identity a supervisor could not pin (an unresolved one, a relative
    /// path, a missing digest, or conflicting evidence) passes unchanged: the
    /// supervisor rejects it itself. An executable whose digest differs from
    /// its pin, or a new path once the journal is full, turns the identity
    /// into a resolution failure.
    pub fn admit(
        &self,
        identity: Result<BinaryIdentity, ResolveError>,
    ) -> Result<BinaryIdentity, ResolveError> {
        let Ok(identity) = identity else {
            return identity;
        };
        let mut offered = HashMap::new();
        for executable in std::iter::once(&identity.executable).chain(&identity.ancestors) {
            let Some(digest) = executable.digest else {
                return Ok(identity);
            };
            if !executable.path.is_absolute() {
                return Ok(identity);
            }
            if offered
                .insert(executable.path.clone(), digest)
                .is_some_and(|existing| existing != digest)
            {
                return Ok(identity);
            }
        }
        let mut pins = self
            .pins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        for (path, digest) in &offered {
            if pins.get(path).is_some_and(|pinned| pinned != digest) {
                return Err(ResolveError::Failed(format!(
                    "binary integrity violation: {} executable changed",
                    path.display()
                )));
            }
        }
        let new_paths = offered
            .keys()
            .filter(|path| !pins.contains_key(*path))
            .count();
        if new_paths > MAX_BINARY_IDENTITY_PINS.saturating_sub(pins.len()) {
            return Err(ResolveError::Failed(format!(
                "binary identity pins exhausted (maximum {MAX_BINARY_IDENTITY_PINS} pinned paths)"
            )));
        }
        for (path, digest) in offered {
            pins.entry(path).or_insert(digest);
        }
        Ok(identity)
    }

    /// Number of pinned paths.
    #[must_use]
    pub fn len(&self) -> usize {
        self.pins
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .len()
    }

    /// Whether nothing is pinned yet.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

#[cfg(test)]
mod tests {
    use openshell_isolation_interface::contract::ExecutableIdentity;

    use super::*;

    fn executable(path: &str, digest: char) -> ExecutableIdentity {
        ExecutableIdentity {
            path: PathBuf::from(path),
            digest: Some(digest.to_string().repeat(64).parse().expect("digest")),
        }
    }

    /// A resolved identity, as offered for a TCP open.
    fn identity(leaf: ExecutableIdentity, ancestors: Vec<ExecutableIdentity>) -> BinaryIdentity {
        BinaryIdentity {
            executable: leaf,
            ancestors,
            cmdline_paths: Vec::new(),
        }
    }

    #[test]
    fn first_offered_digests_are_pinned_and_contradictions_refused() {
        let pins = BinaryIdentityPins::default();
        let curl = || executable("/usr/bin/curl", 'a');
        let shell = || executable("/bin/sh", 'b');
        assert!(pins.admit(Ok(identity(curl(), vec![shell()]))).is_ok());
        assert_eq!(pins.len(), 2);
        assert!(pins.admit(Ok(identity(curl(), vec![]))).is_ok());
        // A replaced leaf or ancestor is refused, and pins never move.
        for replaced in [
            identity(executable("/usr/bin/curl", 'c'), vec![shell()]),
            identity(curl(), vec![executable("/bin/sh", 'd')]),
        ] {
            assert!(matches!(
                pins.admit(Ok(replaced)),
                Err(ResolveError::Failed(_))
            ));
        }
        assert!(pins.admit(Ok(identity(curl(), vec![shell()]))).is_ok());
        assert_eq!(pins.len(), 2);
    }

    #[test]
    fn identities_a_supervisor_rejects_itself_pass_unpinned() {
        let pins = BinaryIdentityPins::default();
        assert!(matches!(
            pins.admit(Err(ResolveError::NotFound)),
            Err(ResolveError::NotFound)
        ));
        let missing_digest = ExecutableIdentity {
            path: PathBuf::from("/usr/bin/curl"),
            digest: None,
        };
        let conflicting = vec![executable("/bin/sh", 'b'), executable("/bin/sh", 'c')];
        for unpinnable in [
            identity(missing_digest, vec![]),
            identity(executable("relative/tool", 'a'), vec![]),
            identity(executable("/usr/bin/env", 'a'), conflicting),
        ] {
            assert!(pins.admit(Ok(unpinnable)).is_ok());
        }
        assert!(pins.is_empty());
    }

    #[test]
    fn a_full_journal_refuses_new_paths_but_keeps_known_ones() {
        let pins = BinaryIdentityPins::default();
        for index in 0..MAX_BINARY_IDENTITY_PINS {
            let tool = identity(executable(&format!("/bin/tool-{index}"), 'a'), vec![]);
            assert!(pins.admit(Ok(tool)).is_ok());
        }
        assert!(matches!(
            pins.admit(Ok(identity(executable("/bin/one-more", 'a'), vec![]))),
            Err(ResolveError::Failed(_))
        ));
        assert!(
            pins.admit(Ok(identity(executable("/bin/tool-7", 'a'), vec![])))
                .is_ok()
        );
    }
}
