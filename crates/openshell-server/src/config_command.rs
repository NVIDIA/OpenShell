// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI handlers for inspecting and updating the gateway TOML configuration.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::str::FromStr;

use clap::{Args, Subcommand};
use miette::{IntoDiagnostic, Result, WrapErr};
use tempfile::NamedTempFile;
use toml_edit::{DocumentMut, Item, Table, value};

use crate::{config_file, defaults};

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    command: ConfigCommand,
}

#[derive(Debug, Subcommand)]
enum ConfigCommand {
    /// Detect the compute driver available in the current environment.
    DetectDriver,
    /// Update fields in the gateway TOML configuration.
    Set(SetArgs),
}

#[derive(Debug, Args)]
struct SetArgs {
    /// Dotted TOML key and value to set. May be repeated.
    #[arg(required = true, value_name = "KEY=VALUE")]
    assignments: Vec<Assignment>,
}

#[derive(Clone, Debug)]
struct Assignment {
    key: Vec<String>,
    value: Item,
}

impl FromStr for Assignment {
    type Err = String;

    fn from_str(input: &str) -> std::result::Result<Self, Self::Err> {
        let (raw_key, raw_value) = input.split_once('=').ok_or_else(|| {
            format!("invalid assignment '{input}': expected a dotted KEY=VALUE argument")
        })?;

        let key = raw_key
            .split('.')
            .map(|component| {
                if component.is_empty()
                    || !component
                        .chars()
                        .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-'))
                {
                    return Err(format!(
                        "invalid config key '{raw_key}': use dot-separated TOML bare keys"
                    ));
                }
                Ok(component.to_string())
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;

        Ok(Self {
            key,
            value: parse_assignment_value(raw_value.trim()),
        })
    }
}

pub fn run(args: ConfigArgs, explicit_path: Option<PathBuf>) -> Result<()> {
    match args.command {
        ConfigCommand::DetectDriver => {
            println!(
                "{}",
                detected_driver_name(openshell_core::config::detect_driver())
            );
        }
        ConfigCommand::Set(settings) => {
            let path = explicit_path.map_or_else(defaults::default_gateway_config_path, Ok)?;
            set(&path, &settings)?;
            println!("updated gateway configuration: {}", path.display());
            println!("Restart the gateway service for changes to take effect.");
        }
    }
    Ok(())
}

fn detected_driver_name(driver: Option<openshell_core::ComputeDriverKind>) -> &'static str {
    driver.map_or("none", openshell_core::ComputeDriverKind::as_str)
}

fn set(path: &Path, settings: &SetArgs) -> Result<()> {
    let original = match fs::read_to_string(path) {
        Ok(contents) => contents,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(err) => {
            return Err(err)
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to read gateway config '{}'", path.display()));
        }
    };

    let mut document = if original.trim().is_empty() {
        DocumentMut::new()
    } else {
        original
            .parse::<DocumentMut>()
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to parse gateway config '{}'", path.display()))?
    };

    let openshell = ensure_table(document.as_table_mut(), "openshell")?;
    if !openshell.contains_key("version") {
        openshell.insert("version", value(i64::from(config_file::SCHEMA_VERSION)));
    }

    for assignment in &settings.assignments {
        apply_assignment(&mut document, assignment)?;
    }

    let rendered = document.to_string();
    config_file::parse(&rendered, path).map_err(|err| miette::miette!("{err}"))?;
    write_atomically(path, rendered.as_bytes())
}

fn parse_assignment_value(raw: &str) -> Item {
    let source = format!("value = {raw}");
    source
        .parse::<DocumentMut>()
        .ok()
        .and_then(|mut document| document.as_table_mut().remove("value"))
        .unwrap_or_else(|| value(raw))
}

fn apply_assignment(document: &mut DocumentMut, assignment: &Assignment) -> Result<()> {
    let (key, parents) = assignment
        .key
        .split_last()
        .ok_or_else(|| miette::miette!("config assignment key must not be empty"))?;
    let mut table = document.as_table_mut();
    for parent in parents {
        table = ensure_table(table, parent)?;
    }
    table.insert(key, assignment.value.clone());
    Ok(())
}

fn ensure_table<'a>(parent: &'a mut Table, key: &str) -> Result<&'a mut Table> {
    if !parent.contains_key(key) {
        parent.insert(key, Item::Table(Table::new()));
    }
    parent
        .get_mut(key)
        .and_then(Item::as_table_mut)
        .ok_or_else(|| miette::miette!("gateway config key '{key}' must be a TOML table"))
}

fn write_atomically(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or_else(|| {
        miette::miette!(
            "gateway config path '{}' has no parent directory",
            path.display()
        )
    })?;
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    fs::create_dir_all(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create config directory '{}'", parent.display()))?;

    let permissions = fs::metadata(path)
        .ok()
        .map(|metadata| metadata.permissions());
    let mut temp = NamedTempFile::new_in(parent)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to create temporary file in '{}'", parent.display()))?;
    temp.write_all(contents)
        .into_diagnostic()
        .wrap_err("failed to write gateway configuration")?;
    temp.as_file()
        .sync_all()
        .into_diagnostic()
        .wrap_err("failed to sync gateway configuration")?;
    if let Some(permissions) = permissions {
        temp.as_file()
            .set_permissions(permissions)
            .into_diagnostic()
            .wrap_err("failed to preserve gateway config permissions")?;
    }
    temp.persist(path)
        .map_err(|err| err.error)
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to replace gateway config '{}'", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(assignments: &[&str]) -> SetArgs {
        SetArgs {
            assignments: assignments
                .iter()
                .map(|assignment| assignment.parse().unwrap())
                .collect(),
        }
    }

    #[test]
    fn detect_driver_output_is_machine_readable() {
        assert_eq!(
            detected_driver_name(Some(openshell_core::ComputeDriverKind::Podman)),
            "podman"
        );
        assert_eq!(
            detected_driver_name(Some(openshell_core::ComputeDriverKind::Docker)),
            "docker"
        );
        assert_eq!(detected_driver_name(None), "none");
    }

    #[test]
    fn set_creates_config_with_driver_and_bind_address() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("openshell/gateway.toml");

        set(
            &path,
            &settings(&[
                "openshell.gateway.compute_drivers=[\"podman\"]",
                "openshell.gateway.bind_address=0.0.0.0:17670",
            ]),
        )
        .unwrap();

        let loaded = config_file::load(&path).unwrap();
        assert_eq!(loaded.openshell.version, Some(config_file::SCHEMA_VERSION));
        assert_eq!(
            loaded.openshell.gateway.compute_drivers,
            Some(vec!["podman".to_string()])
        );
        assert_eq!(
            loaded.openshell.gateway.bind_address,
            Some("0.0.0.0:17670".parse().unwrap())
        );
    }

    #[test]
    fn set_preserves_comments_and_unrelated_settings() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gateway.toml");
        fs::write(
            &path,
            "# keep this comment\n[openshell]\nversion = 1\n\n[openshell.gateway]\nlog_level = \"debug\"\ncompute_drivers = [\"docker\"]\n",
        )
        .unwrap();

        set(
            &path,
            &settings(&["openshell.gateway.compute_drivers=[\"podman\"]"]),
        )
        .unwrap();

        let updated = fs::read_to_string(&path).unwrap();
        assert!(updated.contains("# keep this comment"));
        assert!(updated.contains("log_level = \"debug\""));
        let loaded = config_file::load(&path).unwrap();
        assert_eq!(
            loaded.openshell.gateway.compute_drivers,
            Some(vec!["podman".to_string()])
        );
    }

    #[test]
    fn empty_driver_array_enables_auto_detection_without_changing_bind_address() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gateway.toml");
        fs::write(
            &path,
            "[openshell]\nversion = 1\n\n[openshell.gateway]\nbind_address = \"0.0.0.0:17670\"\ncompute_drivers = [\"podman\"]\n",
        )
        .unwrap();

        set(&path, &settings(&["openshell.gateway.compute_drivers=[]"])).unwrap();

        let loaded = config_file::load(&path).unwrap();
        assert_eq!(loaded.openshell.gateway.compute_drivers, Some(Vec::new()));
        assert_eq!(
            loaded.openshell.gateway.bind_address,
            Some("0.0.0.0:17670".parse().unwrap())
        );
    }

    #[test]
    fn invalid_existing_config_is_not_replaced() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gateway.toml");
        let original = "[openshell\ninvalid";
        fs::write(&path, original).unwrap();

        let error = set(
            &path,
            &settings(&["openshell.gateway.compute_drivers=[\"docker\"]"]),
        )
        .unwrap_err();

        assert!(error.to_string().contains("failed to parse gateway config"));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn schema_validation_failure_is_not_written() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gateway.toml");
        let original = "[openshell]\nversion = 999\n";
        fs::write(&path, original).unwrap();

        let error = set(
            &path,
            &settings(&["openshell.gateway.compute_drivers=[\"docker\"]"]),
        )
        .unwrap_err();

        assert!(
            error
                .to_string()
                .contains("unsupported gateway config version")
        );
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn unknown_key_is_not_written() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gateway.toml");
        let original = "[openshell]\nversion = 1\n";
        fs::write(&path, original).unwrap();

        let error = set(
            &path,
            &settings(&["openshell.gateway.unknown_setting=value"]),
        )
        .unwrap_err();

        assert!(error.to_string().contains("unknown field"));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }

    #[test]
    fn assignment_values_support_toml_types_and_unquoted_strings() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gateway.toml");

        set(
            &path,
            &settings(&[
                "openshell.gateway.log_level=debug",
                "openshell.gateway.grpc_rate_limit_requests=42",
                "openshell.gateway.enable_loopback_service_http=false",
                "openshell.gateway.server_sans=[\"gateway.example.com\", \"*.example.com\"]",
                "openshell.drivers.vm.vcpus=4",
            ]),
        )
        .unwrap();

        let loaded = config_file::load(&path).unwrap();
        let gateway = loaded.openshell.gateway;
        assert_eq!(gateway.log_level.as_deref(), Some("debug"));
        assert_eq!(gateway.grpc_rate_limit_requests, Some(42));
        assert_eq!(gateway.enable_loopback_service_http, Some(false));
        assert_eq!(
            gateway.server_sans,
            Some(vec![
                "gateway.example.com".to_string(),
                "*.example.com".to_string()
            ])
        );
        assert_eq!(
            loaded.openshell.drivers["vm"]
                .get("vcpus")
                .and_then(toml::Value::as_integer),
            Some(4)
        );
    }

    #[test]
    fn later_assignment_to_the_same_key_wins() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gateway.toml");

        set(
            &path,
            &settings(&[
                "openshell.gateway.log_level=info",
                "openshell.gateway.log_level=debug",
            ]),
        )
        .unwrap();

        let loaded = config_file::load(&path).unwrap();
        assert_eq!(loaded.openshell.gateway.log_level.as_deref(), Some("debug"));
    }

    #[test]
    fn assignment_requires_key_value_syntax_and_bare_dotted_keys() {
        let missing_value = "openshell.gateway.log_level"
            .parse::<Assignment>()
            .unwrap_err();
        assert!(missing_value.contains("KEY=VALUE"));

        let invalid_key = "openshell.gateway.bad key=value"
            .parse::<Assignment>()
            .unwrap_err();
        assert!(invalid_key.contains("dot-separated TOML bare keys"));
    }

    #[test]
    fn repeated_assignments_are_atomic_when_validation_fails() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gateway.toml");
        let original = "[openshell]\nversion = 1\n\n[openshell.gateway]\nlog_level = \"info\"\n";
        fs::write(&path, original).unwrap();

        let error = set(
            &path,
            &settings(&[
                "openshell.gateway.log_level=debug",
                "openshell.gateway.unknown_setting=value",
            ]),
        )
        .unwrap_err();

        assert!(error.to_string().contains("unknown field"));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }
}
