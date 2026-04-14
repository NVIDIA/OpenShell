#![allow(clippy::type_complexity, clippy::uninlined_format_args)]

mod bin;
#[path = "../src/bin/run-emitter-test-suite.rs"]
#[allow(dead_code)]
mod run_emitter_test_suite;

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

// Add this wrapper function
unsafe fn unsafe_main_wrapper(
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
) -> Result<(), bin::MyError> {
    run_emitter_test_suite::unsafe_main(stdin, stdout)
        .map_err(|e| bin::MyError::Other(e.to_string()))
}

fn test(id: &str) {
    let dir = Path::new("tests")
        .join("data")
        .join("yaml-test-suite")
        .join(id);

    let output = bin::run(
        env!("CARGO_BIN_EXE_run-emitter-test-suite"),
        unsafe_main_wrapper,
        &dir.join("test.event"),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprint!("{}", stderr);

    let out = if dir.join("out.yaml").exists() {
        dir.join("out.yaml")
    } else {
        dir.join("in.yaml")
    };
    let expected = fs::read_to_string(out).unwrap();
    pretty_assertions::assert_str_eq!(expected, stdout);
    assert!(output.success);
}

libyml_test_suite::test_emitter!();
