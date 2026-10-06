// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Pure assertions for a single scoped mechanistic policy draft.

pub(super) struct ExpectedDraft<'a> {
    pub(super) rule: &'a str,
    pub(super) endpoint: &'a str,
    pub(super) binary: &'a str,
}

pub(super) fn assert_mechanistic_draft(
    output: &str,
    expected: &ExpectedDraft<'_>,
) -> Result<(), String> {
    let fields = output.lines().map(str::trim).collect::<Vec<_>>();
    let field = |name: &str| {
        fields
            .iter()
            .find_map(|line| line.strip_prefix(name).map(str::trim))
    };
    let endpoints = format!("{} [L4]", expected.endpoint);
    if fields
        .iter()
        .filter(|line| line.starts_with("Chunk:"))
        .count()
        != 1
        || !matches!(field("Status:"), Some("pending" | "approved"))
        || field("Rule:") != Some(expected.rule)
        || field("Binary:") != Some(expected.binary)
        || field("Binaries:") != Some(expected.binary)
        || field("Endpoints:") != Some(endpoints.as_str())
        || !field("Rationale:").is_some_and(|value| value.contains(expected.endpoint))
    {
        return Err(format!(
            "expected one pending or approved L4 mechanistic draft scoped to {} and {}",
            expected.binary, expected.endpoint
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ExpectedDraft, assert_mechanistic_draft};

    const EXPECTED: ExpectedDraft<'static> = ExpectedDraft {
        rule: "allow_pypi_org_80",
        endpoint: "pypi.org:80",
        binary: "/usr/bin/bash",
    };

    fn draft(binary: &str) -> String {
        format!(
            "Chunk: id\nStatus: pending\nRule: allow_pypi_org_80\nBinary: {binary}\nRationale: Allow {binary} to connect to pypi.org:80 (HTTP).\nEndpoints: pypi.org:80 [L4]\nBinaries: {binary}\n"
        )
    }

    #[test]
    fn draft_assertion_accepts_a_hostname_scoped_draft() {
        assert!(assert_mechanistic_draft(&draft("/usr/bin/bash"), &EXPECTED).is_ok());
    }

    #[test]
    fn draft_assertion_rejects_unrelated_binary() {
        assert!(assert_mechanistic_draft(&draft("/usr/bin/sh"), &EXPECTED).is_err());
    }

    #[test]
    fn draft_assertion_rejects_fields_spread_across_drafts() {
        let drafts = format!(
            "{}Chunk: other\nStatus: pending\nRule: allow_1_1_1_1_443\n",
            draft("/usr/bin/bash")
        );
        assert!(assert_mechanistic_draft(&drafts, &EXPECTED).is_err());
    }
}
