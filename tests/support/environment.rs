// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Run environment-dependent assertions in a fresh copy of the test process.
//! The test is re-entered to rebuild its fixtures; only the selected case runs.
//! Use `fixture_dir` to share captured directory paths across re-entry, or
//! read paths from the child's environment when the parent supplied them.

use std::cell::Cell;
use std::ffi::OsStr;
use std::future::Future;
use std::pin::Pin;
use std::process::Command;

const CHILD_CASE: &str = "OPENSHELL_TEST_ENVIRONMENT_CASE";
const COMPLETED: &str = "OPENSHELL_TEST_ENVIRONMENT_COMPLETED";

thread_local! {
    static NEXT_CASE: Cell<usize> = const { Cell::new(0) };
    static FIXTURE_DIRS: std::cell::RefCell<Vec<std::path::PathBuf>> = const { std::cell::RefCell::new(Vec::new()) };
    static NEXT_DIR: Cell<usize> = const { Cell::new(0) };
}

#[derive(Default)]
pub struct Environment {
    variables: Vec<(String, Option<std::ffi::OsString>)>,
}

#[allow(dead_code)]
impl Environment {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn set(mut self, key: impl Into<String>, value: impl AsRef<OsStr>) -> Self {
        self.variables
            .push((key.into(), Some(value.as_ref().to_owned())));
        self
    }

    pub fn remove(mut self, key: impl Into<String>) -> Self {
        self.variables.push((key.into(), None));
        self
    }

    fn selected(&self) -> bool {
        let test = std::thread::current()
            .name()
            .expect("named test thread")
            .to_owned();
        let index = NEXT_CASE.with(|next| {
            let index = next.get();
            next.set(index + 1);
            index
        });
        let case = format!("{test}:{index}");
        if let Some(selected) = std::env::var_os(CHILD_CASE) {
            return selected == OsStr::new(&case);
        }

        let mut command = Command::new(std::env::current_exe().expect("test executable"));
        command.args([
            "--exact",
            &test,
            "--nocapture",
            "--test-threads=1",
            "--include-ignored",
        ]);
        command.env(CHILD_CASE, &case);
        FIXTURE_DIRS.with(|dirs| {
            for (index, path) in dirs.borrow().iter().enumerate() {
                command.env(format!("OPENSHELL_TEST_FIXTURE_DIR_{index}"), path);
            }
        });
        for (key, value) in &self.variables {
            match value {
                Some(value) => {
                    command.env(key, value);
                }
                None => {
                    command.env_remove(key);
                }
            }
        }
        let output = command.output().expect("spawn environment-isolated test");
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            output.status.success(),
            "isolated test {case} failed: {}\n{stdout}\n{stderr}",
            output.status
        );
        // A misspelled filter or an early return must not silently pass.
        assert!(
            stderr
                .lines()
                .any(|line| line == format!("{COMPLETED}:{case}")),
            "isolated test {case} did not run its assertions:\n{stdout}\n{stderr}"
        );
        false
    }

    fn completed() {
        eprintln!(
            "{COMPLETED}:{}",
            std::env::var(CHILD_CASE).expect("selected child case")
        );
    }

    pub fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        pairs
            .iter()
            .fold(Self::new(), |env, (key, value)| env.set(*key, value))
    }

    pub fn run_async(
        self,
        assertions: impl Future<Output = ()>,
    ) -> Pin<Box<impl Future<Output = ()>>> {
        let selected = self.selected();
        // Integration-test futures can contain large gateway request state.
        // Keep the enclosing test future small by storing the case on the heap.
        Box::pin(async move {
            if selected {
                assertions.await;
                Self::completed();
            }
        })
    }

    pub fn run(self, assertions: impl FnOnce()) {
        if self.selected() {
            assertions();
            Self::completed();
        }
    }
}

/// Temporary fixture directory kept alive by the parent while a child re-enters
/// the test. Reusing its path keeps captured fixture paths and child environment
/// values consistent. Directories first created inside the assertions are local.
#[allow(dead_code)]
pub struct FixtureDir {
    path: std::path::PathBuf,
    _owner: Option<tempfile::TempDir>,
}

#[allow(dead_code)]
impl FixtureDir {
    pub fn path(&self) -> &std::path::Path {
        &self.path
    }
}

#[allow(dead_code)]
pub fn fixture_dir() -> std::io::Result<FixtureDir> {
    let index = NEXT_DIR.with(|next| {
        let index = next.get();
        next.set(index + 1);
        index
    });
    if std::env::var_os(CHILD_CASE).is_some()
        && let Some(path) = std::env::var_os(format!("OPENSHELL_TEST_FIXTURE_DIR_{index}"))
    {
        return Ok(FixtureDir {
            path: path.into(),
            _owner: None,
        });
    }
    let owner = tempfile::tempdir()?;
    let path = owner.path().to_owned();
    FIXTURE_DIRS.with(|dirs| dirs.borrow_mut().push(path.clone()));
    Ok(FixtureDir {
        path,
        _owner: Some(owner),
    })
}
