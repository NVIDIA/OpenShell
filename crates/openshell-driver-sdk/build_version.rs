// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

type StableVersion = (u32, u32, u32);
type PrereleaseVersion = (u32, u32, u32, u32);

fn parse_stable_tag(tag: &str) -> Option<StableVersion> {
    let tag = tag.strip_prefix('v').unwrap_or(tag);
    let mut parts = tag.split('.');
    let version = (
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
        parts.next()?.parse().ok()?,
    );
    parts.next().is_none().then_some(version)
}

fn parse_prerelease_tag(tag: &str) -> Option<PrereleaseVersion> {
    let tag = tag.strip_prefix('v').unwrap_or(tag);
    let (base, sequence) = tag.rsplit_once("-pre.")?;
    let (major, minor, patch) = parse_stable_tag(base)?;
    let sequence = sequence.parse().ok()?;
    (sequence > 0).then_some((major, minor, patch, sequence))
}

pub fn exact_release_version<'a>(tags: impl Iterator<Item = &'a str>) -> Option<String> {
    let tags = tags.collect::<Vec<_>>();

    if let Some(((major, minor, patch), _)) = tags
        .iter()
        .filter_map(|tag| parse_stable_tag(tag).map(|version| (version, tag)))
        .max_by_key(|(version, _)| *version)
    {
        return Some(format!("{major}.{minor}.{patch}"));
    }

    tags.iter()
        .filter_map(|tag| parse_prerelease_tag(tag))
        .max()
        .map(|(major, minor, patch, sequence)| format!("{major}.{minor}.{patch}-pre.{sequence}"))
}

pub fn latest_stable_tag<'a>(tags: impl Iterator<Item = &'a str>) -> Option<String> {
    tags.filter_map(|tag| parse_stable_tag(tag).map(|version| (version, tag)))
        .max_by_key(|(version, _)| *version)
        .map(|(_, tag)| tag.to_string())
}

pub fn next_dev_version(tag: Option<&str>, distance: u32, sha: &str) -> Option<String> {
    let (major, minor, patch) = tag.map_or(Some((0, 0, 0)), parse_stable_tag)?;
    Some(format!(
        "{major}.{minor}.{}-dev.{distance}+g{sha}",
        patch + 1
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_stable_release_wins_over_prerelease() {
        let tags = ["v0.1.0-pre.2", "v0.1.0", "vm-dev"];
        assert_eq!(
            exact_release_version(tags.into_iter()).as_deref(),
            Some("0.1.0")
        );
    }

    #[test]
    fn exact_prerelease_uses_highest_sequence() {
        let tags = ["v0.1.0-pre.1", "v0.1.0-pre.2"];
        assert_eq!(
            exact_release_version(tags.into_iter()).as_deref(),
            Some("0.1.0-pre.2")
        );
    }

    #[test]
    fn latest_stable_ignores_prerelease_and_non_release_tags() {
        let tags = ["v0.0.116", "v0.1.0-pre.1", "vm-dev", "v0.0.99"];
        assert_eq!(
            latest_stable_tag(tags.into_iter()).as_deref(),
            Some("v0.0.116")
        );
    }

    #[test]
    fn next_dev_version_bumps_latest_stable_patch() {
        assert_eq!(
            next_dev_version(Some("v0.0.116"), 32, "5b925dd8a").as_deref(),
            Some("0.0.117-dev.32+g5b925dd8a")
        );
    }

    #[test]
    fn next_dev_version_without_a_release_starts_at_first_patch() {
        assert_eq!(
            next_dev_version(None, 7, "abcdef123").as_deref(),
            Some("0.0.1-dev.7+gabcdef123")
        );
    }
}
