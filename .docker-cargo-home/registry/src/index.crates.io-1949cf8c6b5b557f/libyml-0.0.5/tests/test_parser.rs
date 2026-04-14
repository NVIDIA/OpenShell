//! This module contains tests for the YAML parser functionality.
//! It includes both general parsing tests and specific test cases for various YAML features.

#![allow(clippy::type_complexity, clippy::uninlined_format_args)]

use std::fs;
use std::io::{Read, Write};
use std::path::Path;

mod bin;
#[path = "../src/bin/run-parser-test-suite.rs"]
#[allow(dead_code)]
mod run_parser_test_suite;

/// Wrapper function to bridge the error types between the test suite and the parser.
///
/// # Safety
///
/// This function is unsafe because it calls an unsafe function `unsafe_main`.
/// The caller must ensure that the provided `stdin` and `stdout` are valid for the lifetime of the call.
///
/// # Arguments
///
/// * `stdin` - A mutable reference to a type that implements `Read`
/// * `stdout` - A mutable reference to a type that implements `Write`
///
/// # Returns
///
/// Returns `Ok(())` if parsing succeeds, or `Err(bin::MyError)` if an error occurs.
unsafe fn unsafe_main_wrapper(
    stdin: &mut dyn Read,
    stdout: &mut dyn Write,
) -> Result<(), bin::MyError> {
    run_parser_test_suite::unsafe_main(stdin, stdout)
        .map_err(|e| bin::MyError::Other(e.to_string()))
}

/// Test function for running parser tests from the YAML Test Suite
///
/// # Arguments
///
/// * `id` - A string slice that holds the identifier for the test case
///
/// # Panics
///
/// This function will panic if the parser output doesn't match the expected output or if the parser fails unexpectedly.
fn test(id: &str) {
    let dir = Path::new("tests")
        .join("data")
        .join("yaml-test-suite")
        .join(id);

    let output = bin::run(
        env!("CARGO_BIN_EXE_run-parser-test-suite"),
        unsafe_main_wrapper,
        &dir.join("in.yaml"),
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    eprint!("{}", stderr);

    let expected = fs::read_to_string(dir.join("test.event")).unwrap();
    pretty_assertions::assert_str_eq!(expected, stdout);
    assert!(output.success);
}

/// Test parsing of an empty YAML file
#[test]
fn test_empty_file() {
    let temp_file = Path::new("tests").join("empty.yaml");
    fs::write(&temp_file, "").unwrap();

    let output = bin::run(
        env!("CARGO_BIN_EXE_run-parser-test-suite"),
        unsafe_main_wrapper,
        &temp_file,
    );

    assert!(output.success, "Parser should succeed for empty file");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("+STR") && stdout.contains("-STR"),
        "Empty file should still have stream start/end"
    );

    fs::remove_file(temp_file).unwrap();
}

/// Test parsing of a simple scalar YAML
#[test]
fn test_scalar_parsing() {
    let yaml = "scalar: value";
    let temp_file = Path::new("tests").join("temp_scalar.yaml");
    fs::write(&temp_file, yaml).unwrap();

    let output = bin::run(
        env!("CARGO_BIN_EXE_run-parser-test-suite"),
        unsafe_main_wrapper,
        &temp_file,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    println!("Actual output:\n{}", stdout);

    assert!(output.success, "Parser did not exit successfully");

    assert!(stdout.contains("+STR"), "Output doesn't contain '+STR'");
    assert!(stdout.contains("+DOC"), "Output doesn't contain '+DOC'");
    assert!(stdout.contains("+MAP"), "Output doesn't contain '+MAP'");
    assert!(
        stdout.contains("=VAL :scalar"),
        "Output doesn't contain '=VAL :scalar'"
    );
    assert!(
        stdout.contains("=VAL :value"),
        "Output doesn't contain '=VAL :value'"
    );
    assert!(stdout.contains("-MAP"), "Output doesn't contain '-MAP'");
    assert!(stdout.contains("-DOC"), "Output doesn't contain '-DOC'");
    assert!(stdout.contains("-STR"), "Output doesn't contain '-STR'");

    fs::remove_file(temp_file).unwrap();
}

/// Test parsing of a YAML sequence
#[test]
fn test_sequence_parsing() {
    let yaml = "- item1\n- item2\n- item3";
    let temp_file = Path::new("tests").join("temp_sequence.yaml");
    fs::write(&temp_file, yaml).unwrap();

    let output = bin::run(
        env!("CARGO_BIN_EXE_run-parser-test-suite"),
        unsafe_main_wrapper,
        &temp_file,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    println!("Actual output:\n{}", stdout);

    assert!(output.success, "Parser did not exit successfully");

    assert!(stdout.contains("+STR"), "Output doesn't contain '+STR'");
    assert!(stdout.contains("+DOC"), "Output doesn't contain '+DOC'");
    assert!(stdout.contains("+SEQ"), "Output doesn't contain '+SEQ'");
    assert!(
        stdout.contains("=VAL :item1"),
        "Output doesn't contain '=VAL :item1'"
    );
    assert!(
        stdout.contains("=VAL :item2"),
        "Output doesn't contain '=VAL :item2'"
    );
    assert!(
        stdout.contains("=VAL :item3"),
        "Output doesn't contain '=VAL :item3'"
    );
    assert!(stdout.contains("-SEQ"), "Output doesn't contain '-SEQ'");
    assert!(stdout.contains("-DOC"), "Output doesn't contain '-DOC'");
    assert!(stdout.contains("-STR"), "Output doesn't contain '-STR'");

    fs::remove_file(temp_file).unwrap();
}

/// Test parsing of a YAML mapping
#[test]
fn test_mapping_parsing() {
    let yaml = "key1: value1\nkey2: value2";
    let temp_file = Path::new("tests").join("temp_mapping.yaml");
    fs::write(&temp_file, yaml).unwrap();

    let output = bin::run(
        env!("CARGO_BIN_EXE_run-parser-test-suite"),
        unsafe_main_wrapper,
        &temp_file,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    println!("Actual output:\n{}", stdout);

    assert!(output.success, "Parser did not exit successfully");

    assert!(stdout.contains("+STR"), "Output doesn't contain '+STR'");
    assert!(stdout.contains("+DOC"), "Output doesn't contain '+DOC'");
    assert!(stdout.contains("+MAP"), "Output doesn't contain '+MAP'");
    assert!(
        stdout.contains("=VAL :key1"),
        "Output doesn't contain '=VAL :key1'"
    );
    assert!(
        stdout.contains("=VAL :value1"),
        "Output doesn't contain '=VAL :value1'"
    );
    assert!(
        stdout.contains("=VAL :key2"),
        "Output doesn't contain '=VAL :key2'"
    );
    assert!(
        stdout.contains("=VAL :value2"),
        "Output doesn't contain '=VAL :value2'"
    );
    assert!(stdout.contains("-MAP"), "Output doesn't contain '-MAP'");
    assert!(stdout.contains("-DOC"), "Output doesn't contain '-DOC'");
    assert!(stdout.contains("-STR"), "Output doesn't contain '-STR'");

    fs::remove_file(temp_file).unwrap();
}

/// Test parsing of nested YAML structures
#[test]
fn test_nested_structures() {
    let yaml = "
    outer:
      inner:
        - item1
        - item2:
            subkey: subvalue
    ";
    let temp_file = Path::new("tests").join("nested.yaml");
    fs::write(&temp_file, yaml).unwrap();

    let output = bin::run(
        env!("CARGO_BIN_EXE_run-parser-test-suite"),
        unsafe_main_wrapper,
        &temp_file,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.success, "Parser did not exit successfully");
    assert!(stdout.contains("+MAP"), "Output doesn't contain '+MAP'");
    assert!(stdout.contains("+SEQ"), "Output doesn't contain '+SEQ'");
    assert!(
        stdout.contains("=VAL :outer"),
        "Output doesn't contain '=VAL :outer'"
    );
    assert!(
        stdout.contains("=VAL :inner"),
        "Output doesn't contain '=VAL :inner'"
    );
    assert!(
        stdout.contains("=VAL :item1"),
        "Output doesn't contain '=VAL :item1'"
    );
    assert!(
        stdout.contains("=VAL :item2"),
        "Output doesn't contain '=VAL :item2'"
    );
    assert!(
        stdout.contains("=VAL :subkey"),
        "Output doesn't contain '=VAL :subkey'"
    );
    assert!(
        stdout.contains("=VAL :subvalue"),
        "Output doesn't contain '=VAL :subvalue'"
    );

    fs::remove_file(temp_file).unwrap();
}

/// Test parsing of YAML with anchors and aliases
#[test]
fn test_anchors_and_aliases() {
    let yaml = "
    anchor: &anchor_value
        key: value
    alias: *anchor_value
    ";
    let temp_file = Path::new("tests").join("anchors.yaml");
    fs::write(&temp_file, yaml).unwrap();

    let output = bin::run(
        env!("CARGO_BIN_EXE_run-parser-test-suite"),
        unsafe_main_wrapper,
        &temp_file,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.success, "Parser did not exit successfully");
    assert!(
        stdout.contains("&anchor_value"),
        "Output doesn't contain '&anchor_value'"
    );
    assert!(
        stdout.contains("*anchor_value"),
        "Output doesn't contain '*anchor_value'"
    );

    fs::remove_file(temp_file).unwrap();
}

/// Test parsing of YAML with multiline strings
#[test]
fn test_multiline_strings() {
    let yaml = r#"
    literal: |
      This is a
      multiline string
    folded: >
      This is another
      multiline string
    "#;
    let temp_file = Path::new("tests").join("multiline.yaml");
    fs::write(&temp_file, yaml).unwrap();

    let output = bin::run(
        env!("CARGO_BIN_EXE_run-parser-test-suite"),
        unsafe_main_wrapper,
        &temp_file,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.success, "Parser did not exit successfully");
    assert!(
        stdout.contains("=VAL |"),
        "Output doesn't contain literal multiline indicator"
    );
    assert!(
        stdout.contains("=VAL >"),
        "Output doesn't contain folded multiline indicator"
    );

    fs::remove_file(temp_file).unwrap();
}

/// Test parsing of YAML in flow style
#[test]
fn test_flow_style() {
    let yaml = "{key1: value1, key2: [item1, item2]}";
    let temp_file = Path::new("tests").join("flow_style.yaml");
    fs::write(&temp_file, yaml).unwrap();

    let output = bin::run(
        env!("CARGO_BIN_EXE_run-parser-test-suite"),
        unsafe_main_wrapper,
        &temp_file,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    assert!(output.success, "Parser did not exit successfully");
    assert!(stdout.contains("+MAP"), "Output doesn't contain '+MAP'");
    assert!(stdout.contains("+SEQ"), "Output doesn't contain '+SEQ'");
    assert!(
        stdout.contains("=VAL :key1"),
        "Output doesn't contain '=VAL :key1'"
    );
    assert!(
        stdout.contains("=VAL :value1"),
        "Output doesn't contain '=VAL :value1'"
    );
    assert!(
        stdout.contains("=VAL :key2"),
        "Output doesn't contain '=VAL :key2'"
    );
    assert!(
        stdout.contains("=VAL :item1"),
        "Output doesn't contain '=VAL :item1'"
    );
    assert!(
        stdout.contains("=VAL :item2"),
        "Output doesn't contain '=VAL :item2'"
    );

    fs::remove_file(temp_file).unwrap();
}

/// Test parsing of YAML with Unicode characters
#[test]
fn test_unicode() {
    let yaml = "unicode: 你好世界";
    let temp_file = Path::new("tests").join("unicode.yaml");
    fs::write(&temp_file, yaml).unwrap();

    let output = bin::run(
        env!("CARGO_BIN_EXE_run-parser-test-suite"),
        unsafe_main_wrapper,
        &temp_file,
    );

    assert!(
        output.success,
        "Parser should succeed for Unicode content"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("你好世界"),
        "Unicode characters should be preserved"
    );

    fs::remove_file(temp_file).unwrap();
}

/// Test parsing of YAML with comments
#[test]
fn test_comments() {
    let yaml = "key: value # This is a comment\n# This is another comment\nother: value";
    let temp_file = Path::new("tests").join("comments.yaml");
    fs::write(&temp_file, yaml).unwrap();

    let output = bin::run(
        env!("CARGO_BIN_EXE_run-parser-test-suite"),
        unsafe_main_wrapper,
        &temp_file,
    );

    assert!(
        output.success,
        "Parser should succeed for YAML with comments"
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stdout.contains("# This is a comment"),
        "Comments should be ignored in the output"
    );

    fs::remove_file(temp_file).unwrap();
}

/// Test parsing of YAML with directives
#[test]
fn test_yaml_directive() {
    let yaml = "%YAML 1.2\n---\nkey: value";
    let temp_file = Path::new("tests").join("directive.yaml");
    fs::write(&temp_file, yaml).unwrap();

    let output = bin::run(
        env!("CARGO_BIN_EXE_run-parser-test-suite"),
        unsafe_main_wrapper,
        &temp_file,
    );

    let stdout = String::from_utf8_lossy(&output.stdout);

    println!("Actual output:\n{}", stdout);

    assert!(
        output.success,
        "Parser should succeed for YAML with directives"
    );
    assert!(stdout.contains("+STR"), "Output doesn't contain '+STR'");
    assert!(stdout.contains("+DOC"), "Output doesn't contain '+DOC'");
    assert!(stdout.contains("+MAP"), "Output doesn't contain '+MAP'");
    assert!(
        stdout.contains("=VAL :key"),
        "Output doesn't contain '=VAL :key'"
    );
    assert!(
        stdout.contains("=VAL :value"),
        "Output doesn't contain '=VAL :value'"
    );
    assert!(stdout.contains("-MAP"), "Output doesn't contain '-MAP'");
    assert!(stdout.contains("-DOC"), "Output doesn't contain '-DOC'");
    assert!(stdout.contains("-STR"), "Output doesn't contain '-STR'");

    fs::remove_file(temp_file).unwrap();
}

/// Test parsing of invalid YAML
#[test]
fn test_invalid_yaml() {
    let yaml = "key: : value";
    let temp_file = Path::new("tests").join("invalid.yaml");
    fs::write(&temp_file, yaml).unwrap();

    let output = bin::run(
        env!("CARGO_BIN_EXE_run-parser-test-suite"),
        unsafe_main_wrapper,
        &temp_file,
    );

    assert!(!output.success, "Parser should fail for invalid YAML");

    fs::remove_file(temp_file).unwrap();
}

// Run the test suite for parser
libyml_test_suite::test_parser!();
