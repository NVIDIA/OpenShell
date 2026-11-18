// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Layered gateway configuration: a base file plus `*.toml` drop-in configs
//! merged over it, validated once, with errors attributed to the file that
//! caused them.

use std::path::{Path, PathBuf};

use super::{
    ConfigFile, ConfigFileError, ConfigPreflightError, SCHEMA_VERSION, parse_error_detail,
    preflight_error, read_config_contents, validate_loaded, without_quoted_strings,
};

/// Result of loading a base file plus drop-in configs.
#[derive(Debug)]
pub struct LayeredConfig {
    pub file: ConfigFile,
    /// Files that contributed to `file`, in merge order (base first).
    pub sources: Vec<PathBuf>,
}

/// List the `*.toml` drop-in configs in `dir`, sorted by file name.
///
/// Hidden files and entries without a `.toml` extension are ignored so editor
/// backups and package-manager leftovers never take effect.
pub fn drop_in_paths(dir: &Path) -> Result<Vec<PathBuf>, ConfigFileError> {
    let io_error = |source| ConfigFileError::Io {
        path: dir.to_path_buf(),
        source,
    };
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(dir).map_err(io_error)? {
        let entry = entry.map_err(io_error)?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') || Path::new(name.as_ref()).extension() != Some("toml".as_ref()) {
            continue;
        }
        paths.push(entry.path());
    }
    paths.sort_by(|a, b| a.file_name().cmp(&b.file_name()));
    Ok(paths)
}

/// Overlay `overlay` onto `base`: tables merge key by key; every other value,
/// arrays included, replaces the existing one.
pub(super) fn merge_tables(base: &mut toml::Table, overlay: toml::Table) {
    for (key, value) in overlay {
        match (base.get_mut(&key), value) {
            (Some(toml::Value::Table(existing)), toml::Value::Table(incoming)) => {
                merge_tables(existing, incoming);
            }
            (_, value) => {
                base.insert(key, value);
            }
        }
    }
}

fn parse_table(path: &Path, contents: &str) -> Result<toml::Table, ConfigFileError> {
    contents
        .parse::<toml::Table>()
        .map_err(|error| ConfigFileError::Parse {
            path: path.to_path_buf(),
            detail: parse_error_detail(contents, &error),
        })
}

/// A failed layer load with what preflight needs to report it.
struct LayerFailure {
    error: ConfigFileError,
    /// The file that caused the failure, or the base or directory when the
    /// failure belongs to the merged result.
    path: PathBuf,
    /// The version the failing file or merged result declares.
    version: String,
}

/// The `[openshell]` table's `version` value. The outer error is `true` when
/// `openshell` exists but is not a table.
fn declared_version(table: &toml::Table) -> Result<Option<&toml::Value>, ()> {
    match table.get("openshell") {
        None => Ok(None),
        Some(toml::Value::Table(openshell)) => Ok(openshell.get("version")),
        Some(_) => Err(()),
    }
}

/// Version declared by `table`, in the form preflight reports it.
fn table_version(table: &toml::Table) -> String {
    match declared_version(table) {
        Ok(None) => "missing".to_string(),
        Ok(Some(version)) => version
            .as_integer()
            .map_or_else(|| "unavailable".to_string(), |v| v.to_string()),
        Err(()) => "unavailable".to_string(),
    }
}

/// Check the declared version before deserializing so a legacy schema
/// reports its version instead of tripping over fields it no longer has.
fn check_version(table: &toml::Table) -> Result<(), ConfigFileError> {
    match declared_version(table) {
        Ok(None) => Err(ConfigFileError::MissingVersion),
        Ok(Some(toml::Value::Integer(version))) => match u32::try_from(*version) {
            Ok(SCHEMA_VERSION) => Ok(()),
            Ok(version) => Err(ConfigFileError::UnsupportedVersion { version }),
            // A negative or oversized integer names no schema version.
            Err(_) => Err(ConfigFileError::InvalidVersion),
        },
        // A string or table here could be overwritten by a later file that
        // declares the integer, so each file must declare it itself.
        Ok(Some(_)) | Err(()) => Err(ConfigFileError::InvalidVersion),
    }
}

/// One file of a layered configuration.
struct Layer {
    path: PathBuf,
    contents: String,
    table: toml::Table,
}

/// Read a drop-in config. A symlink is accepted only when it resolves to a
/// regular file inside `dir`, as in a Kubernetes `ConfigMap` mount, so a link
/// can never pull in a file from elsewhere. The resolved path is opened
/// without following further links.
fn read_drop_in_contents(path: &Path, dir: &Path) -> Result<String, ConfigFileError> {
    let is_link = std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink());
    if !is_link {
        return read_config_contents(path);
    }
    let io_error = |path: &Path| {
        let path = path.to_path_buf();
        move |source| ConfigFileError::Io { path, source }
    };
    let target = std::fs::canonicalize(path).map_err(io_error(path))?;
    let root = std::fs::canonicalize(dir).map_err(io_error(dir))?;
    if !target.starts_with(&root) {
        return Err(ConfigFileError::NonRegular {
            path: path.to_path_buf(),
            kind: "symlink to a file outside the config directory",
        });
    }
    read_config_contents(&target)
}

/// Read one file and check that it parses and declares [`SCHEMA_VERSION`].
/// Everything else is checked on the merged result, because a drop-in may set
/// only some keys of a table whose required keys live in another file.
fn load_layer(path: &Path, drop_in_dir: Option<&Path>) -> Result<Layer, LayerFailure> {
    let fail = |error: ConfigFileError, version: String| LayerFailure {
        error,
        path: path.to_path_buf(),
        version,
    };
    let contents = drop_in_dir
        .map_or_else(
            || read_config_contents(path),
            |dir| read_drop_in_contents(path, dir),
        )
        .map_err(|e| fail(e, "unavailable".into()))?;
    let table = parse_table(path, &contents).map_err(|e| fail(e, "unavailable".into()))?;
    let version = table_version(&table);
    check_version(&table).map_err(|e| fail(e.in_file(path), version))?;
    Ok(Layer {
        path: path.to_path_buf(),
        contents,
        table,
    })
}

/// Load `base` (when present) and the drop-in configs in `dir` (when present),
/// then merge them in order.
///
/// Every file must parse and declare [`SCHEMA_VERSION`]. The merged result is
/// then validated once, and an error is attributed to the file that holds the
/// offending key. Errors that no single key explains, such as a required key
/// missing from the merged table, name the merged configuration and its files.
#[cfg_attr(target_os = "windows", allow(clippy::result_large_err))]
pub fn load_layered(
    base: Option<&Path>,
    dir: Option<&Path>,
) -> Result<LayeredConfig, ConfigFileError> {
    load_layered_inner(base, dir).map_err(|failure| failure.error)
}

fn load_layered_inner(
    base: Option<&Path>,
    dir: Option<&Path>,
) -> Result<LayeredConfig, LayerFailure> {
    let origin = base.or(dir).map(Path::to_path_buf).unwrap_or_default();
    let mut layers = Vec::new();
    if let Some(base) = base {
        layers.push(load_layer(base, None)?);
    }
    if let Some(dir) = dir {
        let listed = drop_in_paths(dir).map_err(|error| LayerFailure {
            error,
            path: dir.to_path_buf(),
            version: "unavailable".to_string(),
        })?;
        for path in listed {
            layers.push(load_layer(&path, Some(dir))?);
        }
    }

    let mut merged = toml::Table::new();
    for layer in &layers {
        merge_tables(&mut merged, layer.table.clone());
    }
    let version = table_version(&merged);
    let file = finish_layered(&layers, merged).map_err(|error| LayerFailure {
        path: error.file().map_or(origin, Path::to_path_buf),
        error,
        version,
    })?;
    Ok(LayeredConfig {
        file,
        sources: layers.into_iter().map(|layer| layer.path).collect(),
    })
}

/// Whether `table` sets the key at `path`, however deeply nested.
fn has_path(table: &toml::Table, path: &[String]) -> bool {
    match path {
        [] => false,
        [key] => table.contains_key(key),
        [key, rest @ ..] => table
            .get(key)
            .and_then(toml::Value::as_table)
            .is_some_and(|inner| has_path(inner, rest)),
    }
}

/// The value at `path` in `table`.
fn value_at<'a>(table: &'a toml::Table, path: &[String]) -> Option<&'a toml::Value> {
    let (first, rest) = path.split_first()?;
    let value = table.get(first)?;
    if rest.is_empty() {
        Some(value)
    } else {
        value_at(value.as_table()?, rest)
    }
}

/// The file that sets the key at `path`: the last one, whose value wins, or
/// the first one for a key that is wrong wherever it appears.
fn locate<'a>(layers: &'a [Layer], path: &[String], first: bool) -> Option<&'a Path> {
    let mut owners = layers.iter().filter(|layer| has_path(&layer.table, path));
    let owner = if first {
        owners.next()
    } else {
        owners.next_back()
    };
    owner.map(|layer| layer.path.as_path())
}

fn describe_layers(layers: &[Layer]) -> String {
    layers
        .iter()
        .map(|layer| layer.path.display().to_string())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Report a deserialization error against the file that holds the key.
fn attribute_parse(
    layers: &[Layer],
    merged: &toml::Table,
    error: &serde_path_to_error::Error<toml::de::Error>,
) -> ConfigFileError {
    // With one file nothing was merged, so reread it with spans and report the
    // line and column of the problem.
    if let [layer] = layers
        && let Err(spanned) = toml::from_str::<ConfigFile>(&layer.contents)
    {
        return ConfigFileError::Parse {
            path: layer.path.clone(),
            detail: parse_error_detail(&layer.contents, &spanned),
        };
    }
    let message = error.inner().message().trim_end();
    let mut detail = without_quoted_strings(message);
    // The merged table has no spans, so give the key path instead. It holds
    // key names, never values.
    if error.path().iter().next().is_some() {
        detail = format!("`{}`: {detail}", error.path());
    }
    let mut path: Vec<String> = error
        .path()
        .iter()
        .map_while(|segment| match segment {
            serde_path_to_error::Segment::Map { key } => Some(key.clone()),
            _ => None,
        })
        .collect();
    let unknown = message
        .strip_prefix("unknown field `")
        .and_then(|rest| rest.split('`').next());
    if let Some(name) = unknown
        && path.last().map(String::as_str) != Some(name)
    {
        path.push(name.to_string());
    }
    // A missing key is a property of the merged table, not of one file. So is
    // an error about a whole table that several files contribute to, such as a
    // rule over two of its keys.
    let spans_files = unknown.is_none()
        && value_at(merged, &path).is_some_and(toml::Value::is_table)
        && layers
            .iter()
            .filter(|layer| has_path(&layer.table, &path))
            .count()
            > 1;
    let owner = if message.starts_with("missing field") || spans_files {
        None
    } else {
        locate(layers, &path, unknown.is_some())
    };
    match owner {
        Some(path) => ConfigFileError::Parse {
            path: path.to_path_buf(),
            detail,
        },
        None => ConfigFileError::MergedParse {
            files: describe_layers(layers),
            detail,
        },
    }
}

/// Report a validation error against the file that sets the offending key.
fn attribute_semantic(layers: &[Layer], error: ConfigFileError) -> ConfigFileError {
    let to_path = |segments: &[&str]| segments.iter().map(ToString::to_string).collect::<Vec<_>>();
    let path = match &error {
        ConfigFileError::SecretInFile { field, .. } => {
            Some(to_path(&["openshell", "gateway", field]))
        }
        ConfigFileError::InvalidValue { field, .. } => {
            Some(field.split('.').map(str::to_string).collect())
        }
        ConfigFileError::InvalidDriverTable { name } => {
            Some(to_path(&["openshell", "drivers", name]))
        }
        ConfigFileError::InvalidIsolationBackend { name, .. } => Some(to_path(&[
            "openshell",
            "drivers",
            name,
            "isolation_backend",
        ])),
        _ => None,
    };
    match path.and_then(|path| locate(layers, &path, false).map(Path::to_path_buf)) {
        Some(owner) => error.in_file(&owner),
        None => error,
    }
}

/// Deserialize and validate the merged table.
fn finish_layered(layers: &[Layer], merged: toml::Table) -> Result<ConfigFile, ConfigFileError> {
    check_version(&merged)?;
    let file: ConfigFile = serde_path_to_error::deserialize(toml::Value::Table(merged.clone()))
        .map_err(|error| attribute_parse(layers, &merged, &error))?;
    validate_loaded(file).map_err(|error| attribute_semantic(layers, error))
}

/// Layered counterpart of [`preflight`].
///
/// Validates the base and drop-in configs without starting the gateway. The
/// failure names the offending file, or the base or directory when the error
/// belongs to the merged result.
#[cfg_attr(target_os = "windows", allow(clippy::result_large_err))]
pub fn preflight_layered(
    base: Option<&Path>,
    dir: Option<&Path>,
) -> Result<LayeredConfig, ConfigPreflightError> {
    load_layered_inner(base, dir)
        .map_err(|failure| preflight_error(&failure.path, failure.version, failure.error))
}
