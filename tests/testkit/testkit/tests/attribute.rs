// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! What `#[testkit::test]` expands to, checked by compiling tests with it in
//! an ordinary libtest target. The tests need a gateway, so they are ignored;
//! the check compares the registry with what libtest lists.

use std::collections::BTreeSet;
use std::process::Command;

/// Ignored with a reason.
#[testkit::test]
#[ignore = "needs a gateway"]
async fn ignored_with_reason(_cx: &mut testkit::Context) -> testkit::Result {
    Ok(())
}

/// Lint attributes reach the body: `cx` is unused.
#[testkit::test]
#[ignore]
#[allow(unused_variables)]
async fn lint_allowed(cx: &mut testkit::Context) -> testkit::Result {
    Ok(())
}

/// Compiled out, so neither a test nor registered.
#[testkit::test]
#[cfg(any())]
async fn compiled_out(_cx: &mut testkit::Context) -> testkit::Result {
    Ok(())
}

mod nested {
    /// Named with its module.
    #[testkit::test]
    #[ignore]
    async fn in_a_module(_cx: &mut testkit::Context) -> testkit::Result {
        Ok(())
    }
}

/// The names libtest lists for this binary, with `extra` arguments.
fn libtest_list(extra: &[&str]) -> BTreeSet<String> {
    let output = Command::new(std::env::current_exe().expect("current exe"))
        .args(["--list", "--format", "terse"])
        .args(extra)
        .output()
        .expect("list the tests");
    assert!(output.status.success(), "{output:?}");
    String::from_utf8(output.stdout)
        .expect("utf-8")
        .lines()
        .filter_map(|line| line.strip_suffix(": test"))
        .filter(|name| *name != "registry_matches_libtest")
        .map(str::to_string)
        .collect()
}

#[test]
fn registry_matches_libtest() {
    let registered: Vec<_> = testkit::__private::TESTS
        .iter()
        .map(|test| {
            (
                test.name(),
                test.module_path,
                test.family,
                test.ignored,
                test.ignore_reason,
                test.info.description,
            )
        })
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    assert_eq!(
        registered,
        [
            (
                "ignored_with_reason".to_string(),
                "attribute",
                None,
                true,
                Some("needs a gateway"),
                "Ignored with a reason."
            ),
            (
                "lint_allowed".to_string(),
                "attribute",
                None,
                true,
                None,
                "Lint attributes reach the body: `cx` is unused."
            ),
            (
                "nested::in_a_module".to_string(),
                "attribute::nested",
                None,
                true,
                None,
                "Named with its module."
            ),
        ]
    );

    // libtest runs and ignores the same tests, under the same names.
    let names = |ignored_only: bool| -> BTreeSet<String> {
        testkit::__private::TESTS
            .iter()
            .filter(|test| test.ignored || !ignored_only)
            .map(testkit::Test::name)
            .collect()
    };
    assert_eq!(libtest_list(&[]), names(false));
    assert_eq!(libtest_list(&["--ignored"]), names(true));
}
