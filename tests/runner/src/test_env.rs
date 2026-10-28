// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Variables an environment publishes for its tests.
//!
//! An environment that runs something besides `OpenShell`, such as Keycloak,
//! says how tests reach it in `/etc/openshell-test/env.d/*.env`: one
//! `OPENSHELL_TEST_*=value` per line. The tmachine environment's setup
//! writes the file and suite fixtures read the variables. Tests don't depend
//! on tmachine: anyone running a suite against their own deployment sets the
//! same variables.
//!
//! The values can be credentials, so they stay in the guest. The runner
//! [`check`]s the files but never puts a value in a command it runs over
//! SSH; the test command exports the files itself with [`export_script`].

use anyhow::{Context, Result, bail, ensure};
use tmachine::Session;

/// Where environments publish the variables tests read.
pub const ENV_DIR: &str = "/etc/openshell-test/env.d";
/// The prefix every published variable must have, so an environment can't
/// override how tests find the gateway or the CLI.
pub const ENV_PREFIX: &str = "OPENSHELL_TEST_";

/// Check the variables the booted environment publishes, so a malformed file
/// fails the run up front rather than in the test command. An environment
/// that publishes none has no `ENV_DIR`.
pub async fn check(session: &Session) -> Result<()> {
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
    parse_files(&contents)?;
    Ok(())
}

/// A shell fragment that exports every variable published in `dir`, the way
/// [`parse_env`] reads it: each line literally, skipping blank lines and `#`
/// comments. It exits non-zero if a file can't be read or a line can't be
/// exported.
pub fn export_script(dir: &str) -> String {
    format!(
        r#"for f in {dir}/*.env; do [ -e "$f" ] || continue; while IFS= read -r line || [ -n "$line" ]; do case $line in ''|'#'*) ;; *) export "$line" || exit 1;; esac; done <"$f" || exit 1; done"#
    )
}

/// Parse the files `check` prints: each is a NUL, its path and a newline,
/// then its contents. Returns the variable names.
fn parse_files(output: &str) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for file in output.split('\0').filter(|file| !file.is_empty()) {
        let (path, body) = file.split_once('\n').unwrap_or((file, ""));
        names.extend(parse_env(path, body)?);
    }
    Ok(names)
}

/// Parse a published env file: `KEY=VALUE` lines, empty lines and lines
/// starting with `#`. Lines are taken literally, as [`export_script`] exports
/// them: no quoting and no trimming. Returns the variable names. Errors name
/// the key, never the value, since values can be credentials.
pub fn parse_env(path: &str, contents: &str) -> Result<Vec<String>> {
    let mut names = Vec::new();
    for (number, line) in contents.split('\n').enumerate() {
        if line.is_empty() || line.starts_with('#') {
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
        names.push(key.to_string());
    }
    Ok(names)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_published_variables() {
        let names = parse_env(
            "keycloak.env",
            "# Published by keycloak.yaml\n\nOPENSHELL_TEST_KEYCLOAK_ISSUER=http://127.0.0.1:8180/realms/openshell\nOPENSHELL_TEST_KEYCLOAK_PASSWORD=a=b\n",
        )
        .unwrap();
        assert_eq!(
            names,
            [
                "OPENSHELL_TEST_KEYCLOAK_ISSUER",
                "OPENSHELL_TEST_KEYCLOAK_PASSWORD",
            ]
        );
    }

    #[test]
    fn reads_every_published_file() {
        assert_eq!(parse_files("").unwrap(), Vec::<String>::new());
        let names = parse_files(
            "\0/etc/openshell-test/env.d/a.env\nOPENSHELL_TEST_A=1\n\0/etc/openshell-test/env.d/b.env\nOPENSHELL_TEST_B=2",
        )
        .unwrap();
        assert_eq!(names, ["OPENSHELL_TEST_A", "OPENSHELL_TEST_B"]);

        let err = parse_files("\0/etc/openshell-test/env.d/b.env\nPATH=/x\n").unwrap_err();
        assert!(err.to_string().contains("b.env:1"), "{err}");
    }

    #[test]
    fn refuses_variables_outside_the_prefix() {
        let err = parse_env("x.env", "OPENSHELL_GATEWAY=other\n").unwrap_err();
        assert!(err.to_string().contains("OPENSHELL_GATEWAY"), "{err}");
    }

    #[test]
    fn takes_lines_literally() {
        // The export script doesn't trim either, so neither may be accepted.
        assert!(parse_env("x.env", "  # indented comment\n").is_err());
        assert!(parse_env("x.env", " OPENSHELL_TEST_A=1\n").is_err());
    }

    #[test]
    fn errors_do_not_echo_values() {
        let err = parse_env("x.env", "openshell_test_secret=hunter2\n").unwrap_err();
        assert!(!err.to_string().contains("hunter2"), "{err}");
        let err = parse_env("x.env", "hunter2\n").unwrap_err();
        assert!(!err.to_string().contains("hunter2"), "{err}");
    }

    /// Run the export script with the local `sh` and return the variables it
    /// exported with the given prefix.
    fn exported(dir: &std::path::Path) -> Vec<String> {
        let script = format!("{}; env", export_script(dir.to_str().unwrap()));
        let output = std::process::Command::new("sh")
            .args(["-c", &script])
            .env_clear()
            .output()
            .unwrap();
        assert!(output.status.success(), "{output:?}");
        let mut vars: Vec<String> = String::from_utf8(output.stdout)
            .unwrap()
            .lines()
            .filter(|line| line.starts_with(ENV_PREFIX))
            .map(str::to_string)
            .collect();
        vars.sort();
        vars
    }

    #[test]
    fn export_script_exports_what_the_parser_accepts() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(exported(dir.path()), Vec::<String>::new());

        let a = "# Published by keycloak.yaml\n\nOPENSHELL_TEST_SPACES=a b  c\nOPENSHELL_TEST_SHELL=$HOME`id`$(id)\\n'\"\nOPENSHELL_TEST_EQUALS=a=b=\n";
        // The last line has no newline and must still be exported.
        let b = "OPENSHELL_TEST_LAST=1";
        std::fs::write(dir.path().join("a.env"), a).unwrap();
        std::fs::write(dir.path().join("b.env"), b).unwrap();
        std::fs::write(dir.path().join("ignored.txt"), "OPENSHELL_TEST_X=1\n").unwrap();
        parse_env("a.env", a).unwrap();
        parse_env("b.env", b).unwrap();

        assert_eq!(
            exported(dir.path()),
            [
                "OPENSHELL_TEST_EQUALS=a=b=",
                "OPENSHELL_TEST_LAST=1",
                "OPENSHELL_TEST_SHELL=$HOME`id`$(id)\\n'\"",
                "OPENSHELL_TEST_SPACES=a b  c",
            ]
        );
    }
}
