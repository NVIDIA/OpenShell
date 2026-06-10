// Copyright (C) 2025 NVIDIA Corporation
// SPDX-License-Identifier: Apache-2.0

//! Generic output formatting helpers for CLI commands.
//!
//! This module provides helper functions to eliminate duplication across CLI commands
//! that support `--output` flags (json, yaml, table).
//!
//! # Early-return Pattern
//!
//! All helper functions return `Result<bool>`:
//! - `Ok(true)` — Format was handled (json/yaml), caller should return immediately
//! - `Ok(false)` — Format is "table", caller should continue to table rendering
//! - `Err(e)` — Unsupported format or serialization error
//!
//! # Example
//!
//! ```ignore
//! use crate::output::print_output_collection;
//!
//! pub fn sandbox_list(output: &str) -> Result<()> {
//!     let sandboxes = fetch_sandboxes()?;
//!
//!     if print_output_collection(output, &sandboxes, sandbox_to_json)? {
//!         return Ok(());
//!     }
//!
//!     // Fall through to table rendering
//!     render_sandbox_table(&sandboxes);
//!     Ok(())
//! }
//! ```

use miette::{IntoDiagnostic, Result};
use std::io::Write;

/// Print collection output in specified format (json/yaml/table).
///
/// # Returns
/// - `Ok(true)` if format was handled (json/yaml), caller should return
/// - `Ok(false)` if format is "table", caller should continue to table rendering
/// - `Err` for unsupported formats or serialization errors
///
/// # Behavior
/// - JSON: uses `println!()` (includes trailing newline)
/// - YAML: uses `print!()` (no trailing newline, `serde_yml` includes one)
///
/// # Example
/// ```ignore
/// if print_output_collection(output, &sandboxes, sandbox_to_json)? {
///     return Ok(());
/// }
/// ```
pub fn print_output_collection<T, F>(
    format: impl AsRef<str>,
    items: &[T],
    to_json: F,
) -> Result<bool>
where
    F: Fn(&T) -> serde_json::Value,
{
    match format.as_ref() {
        "json" => {
            let values: Vec<_> = items.iter().map(to_json).collect();
            println!(
                "{}",
                serde_json::to_string_pretty(&values).into_diagnostic()?
            );
            Ok(true)
        }
        "yaml" => {
            let values: Vec<_> = items.iter().map(to_json).collect();
            print!("{}", serde_yml::to_string(&values).into_diagnostic()?);
            Ok(true)
        }
        "table" => Ok(false),
        _ => Err(miette::miette!(
            "unsupported output format: {}",
            format.as_ref()
        )),
    }
}

/// Print single item output in specified format (json/yaml/table).
///
/// # Returns
/// - `Ok(true)` if format was handled (json/yaml), caller should return
/// - `Ok(false)` if format is "table", caller should continue to table rendering
/// - `Err` for unsupported formats or serialization errors
///
/// # Example
/// ```ignore
/// if print_output_single(output, &sandbox, sandbox_to_json)? {
///     return Ok(());
/// }
/// ```
pub fn print_output_single<T, F>(format: impl AsRef<str>, item: &T, to_json: F) -> Result<bool>
where
    F: Fn(&T) -> serde_json::Value,
{
    match format.as_ref() {
        "json" => {
            let value = to_json(item);
            println!(
                "{}",
                serde_json::to_string_pretty(&value).into_diagnostic()?
            );
            Ok(true)
        }
        "yaml" => {
            let value = to_json(item);
            print!("{}", serde_yml::to_string(&value).into_diagnostic()?);
            Ok(true)
        }
        "table" => Ok(false),
        _ => Err(miette::miette!(
            "unsupported output format: {}",
            format.as_ref()
        )),
    }
}

/// Print pre-formatted output in specified format (json/yaml/table).
///
/// Use this when converter functions return `Result<String>` instead of `serde_json::Value`.
///
/// # Returns
/// - `Ok(true)` if format was handled (json/yaml), caller should return
/// - `Ok(false)` if format is "table", caller should continue to table rendering
/// - `Err` for unsupported formats or conversion errors
///
/// # Example
/// ```ignore
/// if print_output_direct(
///     output,
///     || profiles_to_json(&profiles).into_diagnostic(),
///     || profiles_to_yaml(&profiles).into_diagnostic(),
/// )? {
///     return Ok(());
/// }
/// ```
pub fn print_output_direct<J, Y>(format: impl AsRef<str>, json_fn: J, yaml_fn: Y) -> Result<bool>
where
    J: FnOnce() -> Result<String>,
    Y: FnOnce() -> Result<String>,
{
    match format.as_ref() {
        "json" => {
            let json = json_fn()?;
            println!("{json}");
            Ok(true)
        }
        "yaml" => {
            let yaml = yaml_fn()?;
            print!("{yaml}");
            Ok(true)
        }
        "table" => Ok(false),
        _ => Err(miette::miette!(
            "unsupported output format: {}",
            format.as_ref()
        )),
    }
}

/// Print collection output to a custom writer in specified format (json/yaml/table).
///
/// Writer variant for commands that need custom output destinations.
///
/// # Returns
/// - `Ok(true)` if format was handled (json/yaml), caller should return
/// - `Ok(false)` if format is "table", caller should continue to table rendering
/// - `Err` for unsupported formats, serialization errors, or write errors
pub fn print_output_collection_to_writer<W, T, F>(
    format: impl AsRef<str>,
    writer: &mut W,
    items: &[T],
    to_json: F,
) -> Result<bool>
where
    W: Write,
    F: Fn(&T) -> serde_json::Value,
{
    match format.as_ref() {
        "json" => {
            let values: Vec<_> = items.iter().map(to_json).collect();
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&values).into_diagnostic()?
            )
            .into_diagnostic()?;
            Ok(true)
        }
        "yaml" => {
            let values: Vec<_> = items.iter().map(to_json).collect();
            write!(
                writer,
                "{}",
                serde_yml::to_string(&values).into_diagnostic()?
            )
            .into_diagnostic()?;
            Ok(true)
        }
        "table" => Ok(false),
        _ => Err(miette::miette!(
            "unsupported output format: {}",
            format.as_ref()
        )),
    }
}

/// Print single item output to a custom writer in specified format (json/yaml/table).
///
/// Writer variant for commands that need custom output destinations.
///
/// # Returns
/// - `Ok(true)` if format was handled (json/yaml), caller should return
/// - `Ok(false)` if format is "table", caller should continue to table rendering
/// - `Err` for unsupported formats, serialization errors, or write errors
pub fn print_output_single_to_writer<W, T, F>(
    format: impl AsRef<str>,
    writer: &mut W,
    item: &T,
    to_json: F,
) -> Result<bool>
where
    W: Write,
    F: Fn(&T) -> serde_json::Value,
{
    match format.as_ref() {
        "json" => {
            let value = to_json(item);
            writeln!(
                writer,
                "{}",
                serde_json::to_string_pretty(&value).into_diagnostic()?
            )
            .into_diagnostic()?;
            Ok(true)
        }
        "yaml" => {
            let value = to_json(item);
            write!(
                writer,
                "{}",
                serde_yml::to_string(&value).into_diagnostic()?
            )
            .into_diagnostic()?;
            Ok(true)
        }
        "table" => Ok(false),
        _ => Err(miette::miette!(
            "unsupported output format: {}",
            format.as_ref()
        )),
    }
}

/// Print pre-formatted output to a custom writer in specified format (json/yaml/table).
///
/// Writer variant for commands that need custom output destinations and use
/// pre-formatted converters returning `Result<String>`.
///
/// # Returns
/// - `Ok(true)` if format was handled (json/yaml), caller should return
/// - `Ok(false)` if format is "table", caller should continue to table rendering
/// - `Err` for unsupported formats, conversion errors, or write errors
pub fn print_output_direct_to_writer<W, J, Y>(
    format: impl AsRef<str>,
    writer: &mut W,
    json_fn: J,
    yaml_fn: Y,
) -> Result<bool>
where
    W: Write,
    J: FnOnce() -> Result<String>,
    Y: FnOnce() -> Result<String>,
{
    match format.as_ref() {
        "json" => {
            let json = json_fn()?;
            writeln!(writer, "{json}").into_diagnostic()?;
            Ok(true)
        }
        "yaml" => {
            let yaml = yaml_fn()?;
            write!(writer, "{yaml}").into_diagnostic()?;
            Ok(true)
        }
        "table" => Ok(false),
        _ => Err(miette::miette!(
            "unsupported output format: {}",
            format.as_ref()
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone)]
    struct TestItem {
        id: u32,
        name: String,
    }

    fn test_item_to_json(item: &TestItem) -> serde_json::Value {
        serde_json::json!({
            "id": item.id,
            "name": item.name,
        })
    }

    #[test]
    fn test_print_output_collection_json() {
        let items = vec![
            TestItem {
                id: 1,
                name: "first".to_string(),
            },
            TestItem {
                id: 2,
                name: "second".to_string(),
            },
        ];

        // Note: This test doesn't capture stdout, but verifies the function returns Ok(true)
        let result = print_output_collection("json", &items, test_item_to_json);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_print_output_collection_yaml() {
        let items = vec![TestItem {
            id: 1,
            name: "test".to_string(),
        }];

        let result = print_output_collection("yaml", &items, test_item_to_json);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_print_output_collection_table() {
        let items = vec![TestItem {
            id: 1,
            name: "test".to_string(),
        }];

        let result = print_output_collection("table", &items, test_item_to_json);
        assert!(result.is_ok());
        assert!(!result.unwrap()); // Should return false for table
    }

    #[test]
    fn test_print_output_collection_unsupported() {
        let items = vec![TestItem {
            id: 1,
            name: "test".to_string(),
        }];

        let result = print_output_collection("csv", &items, test_item_to_json);
        assert!(result.is_err());
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("unsupported output format")
        );
    }

    #[test]
    fn test_print_output_collection_empty() {
        let items: Vec<TestItem> = vec![];

        let result = print_output_collection("json", &items, test_item_to_json);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_print_output_single_json() {
        let item = TestItem {
            id: 42,
            name: "single".to_string(),
        };

        let result = print_output_single("json", &item, test_item_to_json);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_print_output_single_yaml() {
        let item = TestItem {
            id: 42,
            name: "single".to_string(),
        };

        let result = print_output_single("yaml", &item, test_item_to_json);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_print_output_direct_json() {
        let json_fn = || Ok(r#"{"test": true}"#.to_string());
        let yaml_fn = || Ok("test: true".to_string());

        let result = print_output_direct("json", json_fn, yaml_fn);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_print_output_direct_yaml() {
        let json_fn = || Ok(r#"{"test": true}"#.to_string());
        let yaml_fn = || Ok("test: true".to_string());

        let result = print_output_direct("yaml", json_fn, yaml_fn);
        assert!(result.is_ok());
        assert!(result.unwrap());
    }

    #[test]
    fn test_print_output_direct_error_propagation() {
        let json_fn = || Err(miette::miette!("json conversion failed"));
        let yaml_fn = || Ok("test: true".to_string());

        let result = print_output_direct("json", json_fn, yaml_fn);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("json conversion"));
    }

    #[test]
    fn test_print_output_collection_to_writer_json() {
        let items = vec![TestItem {
            id: 1,
            name: "test".to_string(),
        }];
        let mut buffer = Vec::new();

        let result =
            print_output_collection_to_writer("json", &mut buffer, &items, test_item_to_json);
        assert!(result.is_ok());
        assert!(result.unwrap());

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("\"id\": 1"));
        assert!(output.contains("\"name\": \"test\""));
    }

    #[test]
    fn test_print_output_collection_to_writer_yaml() {
        let items = vec![TestItem {
            id: 1,
            name: "test".to_string(),
        }];
        let mut buffer = Vec::new();

        let result =
            print_output_collection_to_writer("yaml", &mut buffer, &items, test_item_to_json);
        assert!(result.is_ok());
        assert!(result.unwrap());

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("id: 1"));
        assert!(output.contains("name: test"));
    }

    #[test]
    fn test_print_output_single_to_writer_json() {
        let item = TestItem {
            id: 42,
            name: "single".to_string(),
        };
        let mut buffer = Vec::new();

        let result = print_output_single_to_writer("json", &mut buffer, &item, test_item_to_json);
        assert!(result.is_ok());
        assert!(result.unwrap());

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains("\"id\": 42"));
        assert!(output.contains("\"name\": \"single\""));
    }

    #[test]
    fn test_print_output_direct_to_writer_json() {
        let mut buffer = Vec::new();
        let json_fn = || Ok(r#"{"test": true}"#.to_string());
        let yaml_fn = || Ok("test: true".to_string());

        let result = print_output_direct_to_writer("json", &mut buffer, json_fn, yaml_fn);
        assert!(result.is_ok());
        assert!(result.unwrap());

        let output = String::from_utf8(buffer).unwrap();
        assert!(output.contains(r#"{"test": true}"#));
    }
}
