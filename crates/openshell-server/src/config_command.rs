// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI handlers for updating the gateway TOML configuration.

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
    /// Update the selected gateway TOML file.
    ///
    /// The command validates the result and atomically replaces the file.
    Set(SetArgs),
}

#[derive(Debug, Args)]
struct SetArgs {
    /// TOML dotted key and value to set. May be repeated.
    /// String values must be quoted according to TOML syntax.
    /// Array elements cannot be addressed individually; assign the complete array instead.
    #[arg(required = true, value_name = "KEY=VALUE")]
    assignments: Vec<Assignment>,
}

#[derive(Clone, Debug)]
struct Assignment {
    path: Vec<String>,
    value: Item,
}

impl FromStr for Assignment {
    type Err = String;

    fn from_str(input: &str) -> std::result::Result<Self, Self::Err> {
        let document = input.parse::<DocumentMut>().map_err(|err| {
            format!("invalid assignment: expected one TOML KEY=VALUE assignment: {err}")
        })?;
        let values = document.as_table().get_values();
        let [(keys, value)] = values.as_slice() else {
            return Err(
                "invalid assignment: expected exactly one TOML KEY=VALUE assignment".to_string(),
            );
        };
        if !has_only_dotted_parents(document.as_table(), keys) {
            return Err(
                "invalid assignment: expected a TOML dotted key, not a table header".to_string(),
            );
        }
        let mut value = (*value).clone();
        value.decor_mut().clear();

        Ok(Self {
            path: keys.iter().map(|key| key.get().to_string()).collect(),
            value: Item::Value(value),
        })
    }
}

fn has_only_dotted_parents(table: &Table, keys: &[&toml_edit::Key]) -> bool {
    let mut current = table;
    for key in keys.iter().take(keys.len().saturating_sub(1)) {
        let Some(Item::Table(next)) = current.get(key.get()) else {
            return false;
        };
        if !next.is_dotted() {
            return false;
        }
        current = next;
    }
    true
}

pub fn run(args: ConfigArgs, explicit_path: Option<PathBuf>) -> Result<()> {
    match args.command {
        ConfigCommand::Set(settings) => {
            let path = explicit_path.map_or_else(defaults::default_gateway_config_path, Ok)?;
            update_file(&path, &settings)?;
            println!("updated gateway configuration: {}", path.display());
            println!("Restart the gateway service for changes to take effect.");
        }
    }
    Ok(())
}

fn update_file(path: &Path, settings: &SetArgs) -> Result<()> {
    let write_path = resolve_write_path(path)?;
    let original = read_config(&write_path)
        .wrap_err_with(|| format!("failed to read gateway config '{}'", path.display()))?;
    let document = update_document(&original, settings)
        .wrap_err_with(|| format!("failed to update gateway config '{}'", path.display()))?;
    let rendered = document.to_string();
    config_file::parse(&rendered, path).map_err(|err| miette::miette!("{err}"))?;
    write_atomically(&write_path, rendered.as_bytes())
}

fn read_config(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(contents) => Ok(contents),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(String::new()),
        Err(err) => Err(err).into_diagnostic(),
    }
}

fn update_document(original: &str, settings: &SetArgs) -> Result<DocumentMut> {
    let mut document = if original.trim().is_empty() {
        DocumentMut::new()
    } else {
        original
            .parse::<DocumentMut>()
            .into_diagnostic()
            .wrap_err("failed to parse gateway configuration")?
    };

    let openshell = ensure_table(document.as_table_mut(), "openshell")?;
    if !openshell.contains_key("version") {
        openshell.insert("version", value(i64::from(config_file::SCHEMA_VERSION)));
    }

    for assignment in &settings.assignments {
        apply_assignment(&mut document, assignment)?;
    }

    Ok(document)
}

fn resolve_write_path(path: &Path) -> Result<PathBuf> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() => {
            fs::canonicalize(path).into_diagnostic().wrap_err_with(|| {
                format!(
                    "failed to resolve gateway config symlink '{}'",
                    path.display()
                )
            })
        }
        Ok(_) => Ok(path.to_path_buf()),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(path.to_path_buf()),
        Err(err) => Err(err)
            .into_diagnostic()
            .wrap_err_with(|| format!("failed to inspect gateway config '{}'", path.display())),
    }
}

fn apply_assignment(document: &mut DocumentMut, assignment: &Assignment) -> Result<()> {
    let (key, parents) = assignment
        .path
        .split_last()
        .ok_or_else(|| miette::miette!("config assignment key must not be empty"))?;
    let mut table = document.as_table_mut();
    for parent in parents {
        table = ensure_table(table, parent)?;
    }
    let existing_decor = table
        .get(key)
        .and_then(Item::as_value)
        .map(|existing| existing.decor().clone());
    let mut replacement = assignment.value.clone();
    if let (Some(decor), Some(value)) = (existing_decor, replacement.as_value_mut()) {
        *value.decor_mut() = decor;
    }
    table.insert(key, replacement);
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
    fn set_creates_config_with_typed_values() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("openshell/gateway.toml");

        update_file(
            &path,
            &settings(&[
                "openshell.gateway.compute_drivers=[\"podman\"]",
                "openshell.gateway.bind_address=\"0.0.0.0:17670\"",
                "openshell.gateway.log_level=\"debug\"",
                "openshell.gateway.grpc_rate_limit_requests=42",
                "openshell.gateway.enable_loopback_service_http=false",
                "openshell.drivers.vm.vcpus=4",
                "openshell.drivers.\"containerd.io\".socket_path=\"/run/containerd.sock\"",
            ]),
        )
        .unwrap();

        let loaded = config_file::load(&path).unwrap();
        assert_eq!(loaded.openshell.version, Some(config_file::SCHEMA_VERSION));
        assert_eq!(
            loaded.openshell.gateway.compute_drivers,
            Some(vec!["podman".to_string()])
        );
        assert_eq!(loaded.openshell.gateway.log_level.as_deref(), Some("debug"));
        assert_eq!(loaded.openshell.gateway.grpc_rate_limit_requests, Some(42));
        assert_eq!(
            loaded.openshell.gateway.enable_loopback_service_http,
            Some(false)
        );
        assert_eq!(
            loaded.openshell.drivers["vm"]
                .get("vcpus")
                .and_then(toml::Value::as_integer),
            Some(4)
        );
        assert_eq!(
            loaded.openshell.drivers["containerd.io"]
                .get("socket_path")
                .and_then(toml::Value::as_str),
            Some("/run/containerd.sock")
        );
    }

    #[test]
    fn update_document_preserves_comments_and_unrelated_settings() {
        let original = "# keep this comment\n[openshell]\nversion = 1\n\n[openshell.gateway]\nlog_level = \"info\" # keep this inline comment\ncompute_drivers = [\"docker\"]\n";
        let updated = update_document(
            original,
            &settings(&[
                "openshell.gateway.log_level=\"debug\"",
                "openshell.gateway.compute_drivers=[\"podman\"]",
            ]),
        )
        .unwrap()
        .to_string();

        assert!(updated.contains("# keep this comment"));
        assert!(updated.contains("log_level = \"debug\" # keep this inline comment"));
    }

    #[cfg(unix)]
    #[test]
    fn set_updates_a_symlink_target_without_replacing_the_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("managed-gateway.toml");
        let path = temp.path().join("gateway.toml");
        fs::write(
            &target,
            "[openshell]\nversion = 1\n\n[openshell.gateway]\nlog_level = \"info\"\n",
        )
        .unwrap();
        symlink("managed-gateway.toml", &path).unwrap();

        update_file(&path, &settings(&["openshell.gateway.log_level=\"debug\""])).unwrap();

        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        let loaded = config_file::load(&target).unwrap();
        assert_eq!(loaded.openshell.gateway.log_level.as_deref(), Some("debug"));
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            fs::read_to_string(&target).unwrap()
        );
    }

    #[cfg(unix)]
    #[test]
    fn set_rejects_a_dangling_config_symlink() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("missing-gateway.toml");
        let path = temp.path().join("gateway.toml");
        symlink("missing-gateway.toml", &path).unwrap();

        let error =
            update_file(&path, &settings(&["openshell.gateway.log_level=\"debug\""])).unwrap_err();

        assert!(
            format!("{error:?}").contains("failed to resolve gateway config symlink"),
            "unexpected error: {error:?}"
        );
        assert!(
            fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert!(!target.exists());
    }

    #[test]
    fn update_document_applies_assignments_in_order() {
        let updated = update_document(
            "",
            &settings(&[
                "openshell.gateway.log_level=\"info\"",
                "openshell.gateway.log_level=\"debug\"",
            ]),
        )
        .unwrap()
        .to_string();

        let loaded = config_file::parse(&updated, Path::new("gateway.toml")).unwrap();
        assert_eq!(loaded.openshell.gateway.log_level.as_deref(), Some("debug"));
    }

    #[test]
    fn assignment_requires_exactly_one_toml_key_value() {
        let missing_value = "openshell.gateway.log_level"
            .parse::<Assignment>()
            .unwrap_err();
        assert!(missing_value.contains("KEY=VALUE"));

        let unquoted_string = "openshell.gateway.log_level=debug"
            .parse::<Assignment>()
            .unwrap_err();
        assert!(unquoted_string.contains("TOML KEY=VALUE"));

        let multiple = "openshell.gateway.log_level=\"debug\"\nopenshell.gateway.disable_tls=true"
            .parse::<Assignment>()
            .unwrap_err();
        assert!(multiple.contains("exactly one"));

        let table_header = "[openshell.gateway]\nlog_level=\"debug\""
            .parse::<Assignment>()
            .unwrap_err();
        assert!(table_header.contains("exactly one"));
    }

    #[test]
    fn assignment_uses_toml_key_and_value_syntax() {
        let assignment =
            "openshell.drivers.\"containerd.io\".socket_path = \"/run/containerd.sock\""
                .parse::<Assignment>()
                .unwrap();

        assert_eq!(
            assignment.path,
            ["openshell", "drivers", "containerd.io", "socket_path"]
        );
        assert_eq!(assignment.value.as_str(), Some("/run/containerd.sock"));
    }

    #[test]
    fn assignment_accepts_multiline_toml_strings() {
        let basic = "openshell.gateway.log_level=\"\"\"debug\ntrace\"\"\""
            .parse::<Assignment>()
            .unwrap();
        assert_eq!(basic.value.as_str(), Some("debug\ntrace"));

        let literal = "openshell.gateway.log_level='''debug\\n\ntrace'''"
            .parse::<Assignment>()
            .unwrap();
        assert_eq!(literal.value.as_str(), Some("debug\\n\ntrace"));
    }

    #[test]
    fn validation_failure_does_not_replace_the_config() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("gateway.toml");
        let original = "[openshell]\nversion = 1\n\n[openshell.gateway]\nlog_level = \"info\"\n";
        fs::write(&path, original).unwrap();

        let error = update_file(
            &path,
            &settings(&[
                "openshell.gateway.log_level=\"debug\"",
                "openshell.gateway.unknown_setting=\"value\"",
            ]),
        )
        .unwrap_err();

        assert!(error.to_string().contains("unknown field"));
        assert_eq!(fs::read_to_string(&path).unwrap(), original);
    }
}
