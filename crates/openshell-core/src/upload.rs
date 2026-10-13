// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Internal streaming-upload protocol shared by the CLI and SSH supervisor.
//!
//! SSH receive credit is replenished before application consumption, so this
//! subsystem returns its own credit and relies on SSH for everything else. The
//! client sends one JSON plan line, the raw archive, then EOF. The supervisor's
//! stdout carries only big-endian `u64` totals of archive bytes written to
//! extraction stdin; the first total, zero, means extraction started.
//! Extraction output arrives on stderr and the SSH exit status is the result.

use serde::{Deserialize, Serialize};

use crate::forward::shell_escape;

pub const SUBSYSTEM: &str = "openshell-upload-v1";
/// Archive bytes a client may send beyond the last acknowledged total. This
/// must stay below the supervisor's pending-stdin budget.
pub const WINDOW_BYTES: u64 = 1024 * 1024;
/// Archive bytes between progress reports; success also reports the final total.
///
/// Clients must write archive chunks of at most
/// `WINDOW_BYTES - ACK_INTERVAL_BYTES`, so a drained extractor always returns
/// enough credit for the next chunk.
pub const ACK_INTERVAL_BYTES: u64 = 256 * 1024;
pub const MAX_PLAN_BYTES: usize = 16 * 1024;
pub const DESTINATION_CHANGED_EXIT_CODE: i32 = 73;

#[derive(Debug, thiserror::Error)]
pub enum PlanError {
    #[error("invalid upload plan: {0}")]
    Invalid(&'static str),
    #[error("invalid upload plan: {0}")]
    Json(#[from] serde_json::Error),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DestinationKind {
    Directory,
    File,
    Missing,
}

impl DestinationKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Directory => "directory",
            Self::File => "file",
            Self::Missing => "missing",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExpectedDestination {
    pub path: String,
    pub kind: DestinationKind,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UploadPlan {
    pub destination_directory: String,
    pub expected_destination: Option<ExpectedDestination>,
}

impl UploadPlan {
    pub fn validate(&self) -> Result<(), PlanError> {
        validate_path(&self.destination_directory)?;
        if let Some(expected) = &self.expected_destination {
            validate_path(&expected.path)?;
        }
        Ok(())
    }

    /// Encode the newline-terminated plan that precedes the archive. JSON
    /// escapes newlines inside strings, so the first newline ends the plan.
    pub fn encode(&self) -> Result<Vec<u8>, PlanError> {
        self.validate()?;
        let mut line = serde_json::to_vec(self)?;
        if line.len() > MAX_PLAN_BYTES {
            return Err(PlanError::Invalid("plan exceeds limit"));
        }
        line.push(b'\n');
        Ok(line)
    }
}

fn validate_path(path: &str) -> Result<(), PlanError> {
    if path.is_empty() || path.contains('\0') {
        return Err(PlanError::Invalid("invalid destination path"));
    }
    Ok(())
}

/// Accumulates the plan line across SSH packets without exceeding the limit.
#[derive(Default)]
pub struct PlanReader(Vec<u8>);

impl PlanReader {
    /// Consume plan bytes from `input`, leaving any archive bytes after the
    /// newline in place. Returns the plan once its line is complete.
    pub fn read(&mut self, input: &mut &[u8]) -> Result<Option<UploadPlan>, PlanError> {
        let end = input.iter().position(|byte| *byte == b'\n');
        let line = &input[..end.unwrap_or(input.len())];
        if self.0.len() + line.len() > MAX_PLAN_BYTES {
            return Err(PlanError::Invalid("plan exceeds limit"));
        }
        self.0.extend_from_slice(line);
        let Some(end) = end else {
            *input = &[];
            return Ok(None);
        };
        *input = &input[end + 1..];
        let plan: UploadPlan = serde_json::from_slice(&self.0)?;
        plan.validate()?;
        Ok(Some(plan))
    }
}

// This is the existing CLI destination probe, now shared with the receiving
// supervisor. Check existing parents before treating failed existence as absence.
const DESTINATION_KIND_SH: &str = r#"upload_destination_kind() {
    upload_path=$1
    upload_parent=$2
    while :; do
        if [ -d "$upload_parent" ]; then
            if [ ! -x "$upload_parent" ]; then
                printf 'cannot inspect upload destination parent: %s\n' "$upload_parent" >&2
                return 1
            fi
        elif [ -e "$upload_parent" ] || [ -L "$upload_parent" ]; then
            printf 'upload destination parent is not a directory: %s\n' "$upload_parent" >&2
            return 1
        fi
        case "$upload_parent" in
            /|.) break ;;
            */*) upload_parent=${upload_parent%/*}; [ -n "$upload_parent" ] || upload_parent=/ ;;
            *) upload_parent=. ;;
        esac
    done
    if [ -d "$upload_path" ]; then
        printf directory
    elif [ -e "$upload_path" ] || [ -L "$upload_path" ]; then
        printf file
    else
        printf missing
    fi
}"#;

fn destination_invocation(path: &str) -> String {
    let parent = match path.rfind('/') {
        Some(0) => "/",
        Some(position) => &path[..position],
        None => ".",
    };
    format!(
        "upload_destination_kind {} {}",
        shell_escape(path),
        shell_escape(parent)
    )
}

#[must_use]
pub fn build_destination_probe(path: &str) -> String {
    format!("{DESTINATION_KIND_SH}\n{}", destination_invocation(path))
}

pub fn build_extract_command(plan: &UploadPlan) -> Result<String, PlanError> {
    plan.validate()?;
    let dest = shell_escape(&plan.destination_directory);
    let extract = format!("mkdir -p -- {dest} && cat | tar xf - -C {dest}");
    let Some(expected) = &plan.expected_destination else {
        return Ok(extract);
    };
    Ok(format!(
        "{DESTINATION_KIND_SH}\n\
         upload_kind=$({probe}) || exit 1\n\
         if [ \"$upload_kind\" != {kind} ]; then\n\
             printf 'upload destination changed type before extraction: %s\\n' {path} >&2\n\
             exit {status}\n\
         fi\n\
         {extract}",
        probe = destination_invocation(&expected.path),
        kind = expected.kind.as_str(),
        path = shell_escape(&expected.path),
        status = DESTINATION_CHANGED_EXIT_CODE,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn plan() -> UploadPlan {
        UploadPlan {
            destination_directory: "/tmp/with 'quotes'\nand newline".into(),
            expected_destination: Some(ExpectedDestination {
                path: "/tmp/file".into(),
                kind: DestinationKind::Missing,
            }),
        }
    }

    #[test]
    fn fragmented_plan_line_leaves_archive_bytes() {
        let mut stream = plan().encode().unwrap();
        stream.extend_from_slice(b"archive\nbytes");
        for size in [1, 7, stream.len()] {
            let mut reader = PlanReader::default();
            let mut decoded = None;
            let mut rest = Vec::new();
            for chunk in stream.chunks(size) {
                let mut input = chunk;
                if decoded.is_none() {
                    decoded = reader.read(&mut input).unwrap();
                }
                rest.extend_from_slice(input);
            }
            assert_eq!(decoded, Some(plan()));
            assert_eq!(rest, b"archive\nbytes");
        }
    }

    #[test]
    fn plan_rejects_unknown_fields_nul_paths_and_unbounded_lines() {
        let mut input =
            &br#"{"destination_directory":"/tmp","expected_destination":null,"command":"id"}
"#[..];
        assert!(PlanReader::default().read(&mut input).is_err());
        let nul = UploadPlan {
            destination_directory: "/tmp\0bad".into(),
            expected_destination: None,
        };
        assert!(nul.encode().is_err());
        let long = UploadPlan {
            destination_directory: "/".repeat(MAX_PLAN_BYTES),
            expected_destination: None,
        };
        assert!(long.encode().is_err());
        let unterminated = vec![b'{'; MAX_PLAN_BYTES + 1];
        let mut reader = PlanReader::default();
        let (first, second) = unterminated.split_at(MAX_PLAN_BYTES);
        assert!(reader.read(&mut &first[..]).unwrap().is_none());
        assert!(reader.read(&mut &second[..]).is_err());
    }
}
