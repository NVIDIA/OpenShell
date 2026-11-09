// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Sandbox labels suite: labels are stored and select sandboxes in list.

use std::collections::{BTreeSet, HashMap};

use testkit::Context;
use testkit::sdk::ListOptions;

/// Labels given at create are returned by get, and list filters by one label
/// or by several (all must match). Label values are unique to the run, so
/// other tests' sandboxes can't match.
#[testkit::test]
async fn labels_are_stored_and_filter_list(cx: &mut Context) -> testkit::Result {
    let run = cx.run_id().to_string();
    let dev = format!("dev-{run}");
    let staging = format!("staging-{run}");
    let backend = format!("backend-{run}");
    let data = format!("data-{run}");
    let cases = [
        ("ldb", dev.as_str(), backend.as_str()),
        ("lsb", staging.as_str(), backend.as_str()),
        ("ldd", dev.as_str(), data.as_str()),
    ];

    let mut names = Vec::new();
    for (suffix, env, team) in cases {
        let labels = HashMap::from([
            ("env".to_string(), env.to_string()),
            ("team".to_string(), team.to_string()),
        ]);
        let sandbox = cx
            .sandbox(suffix)
            .spec(|spec| spec.labels = labels.clone())
            .create()
            .await?;
        let got = sandbox.get().await?;
        testkit::ensure!(
            labels
                .iter()
                .all(|(key, value)| got.labels.get(key) == Some(value)),
            "sandbox {} has labels {:?}; expected {labels:?}",
            sandbox.name(),
            got.labels
        );
        names.push(sandbox.name().to_string());
    }
    let [dev_backend, staging_backend, dev_data] = names.as_slice() else {
        unreachable!("one name per case");
    };

    let checks = [
        (format!("env={dev}"), vec![dev_backend, dev_data]),
        (
            format!("team={backend}"),
            vec![dev_backend, staging_backend],
        ),
        (format!("env={dev},team={backend}"), vec![dev_backend]),
        (format!("team=qa-{run}"), vec![]),
    ];
    for (selector, expected) in checks {
        let listed: BTreeSet<String> = cx
            .client()
            .list_all_sandboxes(ListOptions {
                label_selector: Some(selector.clone()),
                ..ListOptions::default()
            })
            .await?
            .into_iter()
            .map(|sandbox| sandbox.name)
            .collect();
        let expected: BTreeSet<String> = expected.into_iter().cloned().collect();
        testkit::ensure!(
            listed == expected,
            "list with selector {selector:?} returned {listed:?}; expected {expected:?}"
        );
    }

    let all: BTreeSet<String> = cx
        .client()
        .list_all_sandboxes(ListOptions::default())
        .await?
        .into_iter()
        .map(|sandbox| sandbox.name)
        .collect();
    let missing: Vec<&String> = names.iter().filter(|name| !all.contains(*name)).collect();
    testkit::ensure!(
        missing.is_empty(),
        "list without a selector is missing {missing:?}"
    );
    Ok(())
}
