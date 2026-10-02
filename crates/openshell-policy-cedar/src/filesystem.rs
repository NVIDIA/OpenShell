// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Filesystem path grants and their offline verification.
//!
//! Landlock rulesets, built once at sandbox startup, are the sole runtime
//! enforcer of filesystem access; there is no request-time decision for
//! Cedar to make. [`FilesystemPolicyInput`] is the flat grant list Landlock
//! consumes. For a Cedar-authored policy it comes from
//! [`CedarNetworkEngine::filesystem_grants`](crate::CedarNetworkEngine::filesystem_grants).
//!
//! [`compile_filesystem_entities`] and [`verify_filesystem_policy`] check a
//! grant list for conflicting or redundant entries. They are advisory only:
//! nothing in `openshell-sandbox` consults them.

use std::collections::HashSet;
use std::path::Path;

use cedar_policy::{Entities, Entity, Schema};
use openshell_policy_cedar_schema::entity_types;

use crate::{CedarEngineError, entity_uid};

/// The `read_only`/`read_write` path lists from an authored
/// `FilesystemPolicy`, before Landlock-specific normalization.
#[derive(Debug, Clone, Default)]
pub struct FilesystemPolicyInput {
    /// Paths granted read-only access.
    pub read_only: Vec<String>,
    /// Paths granted read-write access.
    pub read_write: Vec<String>,
}

/// Which grant list a path came from, for [`FilesystemFinding`] messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilesystemAccess {
    /// The path is listed under `read_only`.
    ReadOnly,
    /// The path is listed under `read_write`.
    ReadWrite,
}

/// An issue found in a [`FilesystemPolicyInput`]. Advisory: these describe
/// authoring mistakes worth a human's attention, not enforcement failures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesystemFinding {
    /// `path` (or a filesystem ancestor/descendant of it) is granted both
    /// read-only and read-write access.
    ConflictingGrant {
        /// The more specific of the two conflicting paths.
        path: String,
        /// The `read_only` entry involved in the conflict.
        read_only_entry: String,
        /// The `read_write` entry involved in the conflict.
        read_write_entry: String,
    },
    /// `path` is already covered by `covered_by`, a broader grant present in
    /// the same access list.
    RedundantEntry {
        /// The redundant (narrower) path.
        path: String,
        /// The broader path in the same list that already covers it.
        covered_by: String,
        /// Which access list both paths belong to.
        access: FilesystemAccess,
    },
}

/// Compiles a [`FilesystemPolicyInput`] into Cedar `FilesystemPath`
/// entities, encoding filesystem ancestry as the schema's `in` hierarchy
/// (`entity FilesystemPath in [FilesystemPath] {}`).
///
/// This is the "compile to Cedar" step referenced by the RFC: it produces a
/// real Cedar `Entities` value suitable for future `symcc`-style analysis,
/// even though the verification checks in this module compute their
/// findings directly rather than by querying Cedar.
///
/// # Errors
///
/// Returns [`CedarEngineError`] if a path cannot be represented as a Cedar
/// entity id, or if the resulting entities fail schema conformance.
pub fn compile_filesystem_entities(
    input: &FilesystemPolicyInput,
) -> Result<Entities, CedarEngineError> {
    let mut paths: Vec<&str> = input
        .read_only
        .iter()
        .chain(input.read_write.iter())
        .map(String::as_str)
        .collect();
    paths.sort_unstable();
    paths.dedup();

    let mut entities = Vec::with_capacity(paths.len());
    for &path in &paths {
        let uid = entity_uid(entity_types::FILESYSTEM_PATH, path)?;
        let mut parents = HashSet::new();
        for &other in &paths {
            if other != path && is_strict_ancestor(other, path) {
                parents.insert(entity_uid(entity_types::FILESYSTEM_PATH, other)?);
            }
        }
        entities.push(Entity::new_no_attrs(uid, parents));
    }

    let (schema, _warnings) =
        Schema::from_cedarschema_str(openshell_policy_cedar_schema::SANDBOX_SCHEMA_SRC)
            .map_err(|e| CedarEngineError::SchemaParse(Box::new(e)))?;
    Entities::from_entities(entities, Some(&schema))
        .map_err(|e| CedarEngineError::EntitiesBuild(Box::new(e)))
}

/// Checks a [`FilesystemPolicyInput`] for conflicting or redundant grants.
///
/// Returns an empty `Vec` when the policy is clean. Order is not
/// significant; callers that need determinism should sort the result.
#[must_use]
pub fn verify_filesystem_policy(input: &FilesystemPolicyInput) -> Vec<FilesystemFinding> {
    let mut findings = Vec::new();

    for read_only_entry in &input.read_only {
        for read_write_entry in &input.read_write {
            if paths_relate(read_only_entry, read_write_entry) {
                let path = if is_strict_ancestor(read_only_entry, read_write_entry) {
                    read_write_entry.clone()
                } else {
                    read_only_entry.clone()
                };
                findings.push(FilesystemFinding::ConflictingGrant {
                    path,
                    read_only_entry: read_only_entry.clone(),
                    read_write_entry: read_write_entry.clone(),
                });
            }
        }
    }

    findings.extend(find_redundant_entries(
        &input.read_only,
        FilesystemAccess::ReadOnly,
    ));
    findings.extend(find_redundant_entries(
        &input.read_write,
        FilesystemAccess::ReadWrite,
    ));

    findings
}

/// Finds paths in `paths` that are already covered by a broader path
/// elsewhere in the same list.
fn find_redundant_entries(paths: &[String], access: FilesystemAccess) -> Vec<FilesystemFinding> {
    let mut findings = Vec::new();
    for path in paths {
        if let Some(covered_by) = paths
            .iter()
            .find(|&other| other != path && is_strict_ancestor(other, path))
        {
            findings.push(FilesystemFinding::RedundantEntry {
                path: path.clone(),
                covered_by: covered_by.clone(),
                access,
            });
        }
    }
    findings
}

/// True if `a` and `b` name the same path, or one is a filesystem ancestor
/// of the other.
fn paths_relate(a: &str, b: &str) -> bool {
    a == b || is_strict_ancestor(a, b) || is_strict_ancestor(b, a)
}

/// True if `candidate` is a strict filesystem ancestor of `path` (component-
/// aware, so `/usr` is an ancestor of `/usr/bin` but not of `/usrbin`).
fn is_strict_ancestor(candidate: &str, path: &str) -> bool {
    candidate != path && Path::new(path).starts_with(Path::new(candidate))
}
