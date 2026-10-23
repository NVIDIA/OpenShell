// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Variables an environment publishes for its tests.
//!
//! An environment that runs something besides `OpenShell`, such as Keycloak,
//! says how tests reach it in `/etc/openshell-test/env.d/*.env`: one
//! `OPENSHELL_TEST_*=value` per line. The tmachine environment's setup
//! writes the file; the runner passes its variables to the tests, and suite
//! fixtures read them. Tests don't depend on tmachine: anyone running a suite
//! against their own deployment sets the same variables.

use anyhow::{Context, Result, bail, ensure};
use tmachine::Session;

/// Where environments publish the variables tests read.
pub const ENV_DIR: &str = "/etc/openshell-test/env.d";
/// The prefix every published variable must have, so an environment can't
/// override how tests find the gateway or the CLI.
pub const ENV_PREFIX: &str = "OPENSHELL_TEST_";

/// Read the variables the booted environment publishes, as `KEY=VALUE`
/// strings. An environment that publishes none has no `ENV_DIR`.
pub async fn read(session: &Session) -> Result<Vec<String>> {
    let script = format!(
        "for f in {ENV_DIR}/*.env; do [ -e \"$f\" ] || continue; printf '\\0%s\\n' \"$f\"; cat \"$f\"; done"
    );
    let output = session.exec(&["sh", "-c", &script]).await?;
    ensure!(
        output.status.success(),
        "read {ENV_DIR}: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    let contents =
        String::from_utf8(output.stdout).with_context(|| format!("{ENV_DIR} is not UTF-8"))?;
    parse_files(&contents)
}

/// Parse the files `read` prints: each is a NUL, its path and a newline,
/// then its contents.
fn parse_files(output: &str) -> Result<Vec<String>> {
    let mut vars = Vec::new();
    for file in output.split('\0').filter(|file| !file.is_empty()) {
        let (path, body) = file.split_once('\n').unwrap_or((file, ""));
        vars.extend(parse_env(path, body)?);
    }
    Ok(vars)
}

/// Parse a published env file: `KEY=VALUE` lines, blank lines and `#`
/// comments. Values are taken literally; there is no quoting. Errors name
/// the key, never the value, since values can be credentials.
pub fn parse_env(path: &str, contents: &str) -> Result<Vec<String>> {
    let mut vars = Vec::new();
    for (number, line) in contents.lines().enumerate() {
        let line = line.trim_end();
        if line.trim().is_empty() || line.trim_start().starts_with('#') {
            continue;
        }
        let Some((key, _value)) = line.split_once('=') else {
            bail!("{path}:{}: expected KEY=VALUE", number + 1);
        };
        ensure!(
            key.starts_with(ENV_PREFIX)
                && key.len() > ENV_PREFIX.len()
                && key
                    .bytes()
                    .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit() || b == b'_'),
            "{path}:{}: {key:?} is not an {ENV_PREFIX}* variable name",
            number + 1
        );
        vars.push(line.to_string());
    }
    Ok(vars)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_published_variables() {
        let vars = parse_env(
            "keycloak.env",
            "# Published by keycloak.yaml\n\nOPENSHELL_TEST_KEYCLOAK_ISSUER=http://127.0.0.1:8180/realms/openshell\nOPENSHELL_TEST_KEYCLOAK_PASSWORD=a=b\n",
        )
        .unwrap();
        assert_eq!(
            vars,
            [
                "OPENSHELL_TEST_KEYCLOAK_ISSUER=http://127.0.0.1:8180/realms/openshell",
                "OPENSHELL_TEST_KEYCLOAK_PASSWORD=a=b",
            ]
        );
    }

    #[test]
    fn reads_every_published_file() {
        assert_eq!(parse_files("").unwrap(), Vec::<String>::new());
        let vars = parse_files(
            "\0/etc/openshell-test/env.d/a.env\nOPENSHELL_TEST_A=1\n\0/etc/openshell-test/env.d/b.env\nOPENSHELL_TEST_B=2",
        )
        .unwrap();
        assert_eq!(vars, ["OPENSHELL_TEST_A=1", "OPENSHELL_TEST_B=2"]);

        let err = parse_files("\0/etc/openshell-test/env.d/b.env\nPATH=/x\n").unwrap_err();
        assert!(err.to_string().contains("b.env:1"), "{err}");
    }

    #[test]
    fn refuses_variables_outside_the_prefix() {
        let err = parse_env("x.env", "OPENSHELL_GATEWAY=other\n").unwrap_err();
        assert!(err.to_string().contains("OPENSHELL_GATEWAY"), "{err}");
    }

    #[test]
    fn errors_do_not_echo_values() {
        let err = parse_env("x.env", "openshell_test_secret=hunter2\n").unwrap_err();
        assert!(!err.to_string().contains("hunter2"), "{err}");
        let err = parse_env("x.env", "hunter2\n").unwrap_err();
        assert!(!err.to_string().contains("hunter2"), "{err}");
    }
}
