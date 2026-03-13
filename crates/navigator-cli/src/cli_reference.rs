// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Auto-generate a Markdown CLI reference from a clap [`Command`] tree.
//!
//! Usage from the CLI: `openshell docs cli-reference`

use clap::{Arg, Command};
use std::fmt::Write;

/// Generate a complete CLI reference document from a clap [`Command`] tree.
pub fn generate(cmd: &Command) -> String {
    let mut out = String::with_capacity(16_384);

    writeln!(
        out,
        "# OpenShell CLI Reference\n\
         \n\
         <!-- Auto-generated from CLI source definitions. Do not edit manually. -->\n\
         <!-- Regenerate: openshell docs cli-reference -->"
    )
    .unwrap();

    write_env_vars(cmd, &mut out);
    write_command_tree(cmd, &mut out);
    write_all_commands(cmd, &mut out, cmd.get_name());

    out
}

// ---------------------------------------------------------------------------
// Environment variables
// ---------------------------------------------------------------------------

fn write_env_vars(cmd: &Command, out: &mut String) {
    let vars: Vec<_> = cmd
        .get_arguments()
        .filter(|a| a.get_env().is_some() && !a.is_hide_set())
        .collect();

    if vars.is_empty() {
        return;
    }

    writeln!(out, "\n## Environment Variables\n").unwrap();
    writeln!(out, "| Variable | Description |").unwrap();
    writeln!(out, "|----------|-------------|").unwrap();

    for arg in vars {
        let env = arg.get_env().unwrap().to_string_lossy();
        let help = arg_help(arg);
        writeln!(out, "| `{env}` | {help} |").unwrap();
    }
}

// ---------------------------------------------------------------------------
// Command tree
// ---------------------------------------------------------------------------

fn write_command_tree(root: &Command, out: &mut String) {
    writeln!(out, "\n## Command Tree\n").unwrap();
    writeln!(out, "```text").unwrap();
    writeln!(out, "{}", root.get_name()).unwrap();

    let visible: Vec<_> = root
        .get_subcommands()
        .filter(|c| !c.is_hide_set())
        .collect();

    for (i, sub) in visible.iter().enumerate() {
        let is_last = i == visible.len() - 1;
        write_tree_node(sub, out, "", is_last);
    }

    writeln!(out, "```").unwrap();
}

fn write_tree_node(cmd: &Command, out: &mut String, prefix: &str, is_last: bool) {
    let connector = if is_last { "└── " } else { "├── " };
    let child_prefix = if is_last {
        format!("{prefix}    ")
    } else {
        format!("{prefix}│   ")
    };

    let positionals = positional_synopsis(cmd);
    let name = cmd.get_name();

    writeln!(out, "{prefix}{connector}{name}{positionals}").unwrap();

    let children: Vec<_> = cmd.get_subcommands().filter(|c| !c.is_hide_set()).collect();

    for (i, child) in children.iter().enumerate() {
        write_tree_node(child, out, &child_prefix, i == children.len() - 1);
    }
}

/// Build a compact positional-args synopsis like ` <name> [dest]` or ` [-- CMD...]`.
fn positional_synopsis(cmd: &Command) -> String {
    let mut parts = String::new();

    for arg in cmd.get_arguments() {
        if arg.is_hide_set() || !arg.is_positional() {
            continue;
        }
        let id = arg.get_id().as_str();
        if id == "help" || id == "version" {
            continue;
        }

        let value = arg
            .get_value_names()
            .and_then(|v| v.first().map(|s| s.as_str()))
            .unwrap_or(id);

        if arg.is_last_set() {
            write!(parts, " [-- {value}...]").unwrap();
        } else if arg.is_required_set() {
            write!(parts, " <{value}>").unwrap();
        } else {
            write!(parts, " [{value}]").unwrap();
        }
    }

    parts
}

// ---------------------------------------------------------------------------
// Detailed command sections
// ---------------------------------------------------------------------------

fn write_all_commands(root: &Command, out: &mut String, root_name: &str) {
    let mut groups: Vec<&Command> = Vec::new();
    let mut leaves: Vec<&Command> = Vec::new();

    for sub in root.get_subcommands() {
        if sub.is_hide_set() {
            continue;
        }
        let has_children = sub.get_subcommands().any(|c| !c.is_hide_set());
        if has_children {
            groups.push(sub);
        } else {
            leaves.push(sub);
        }
    }

    for group in &groups {
        let title = titlecase(group.get_name());
        writeln!(out, "\n---\n").unwrap();
        writeln!(out, "## {title} Commands\n").unwrap();

        if let Some(about) = group.get_about() {
            writeln!(out, "{}\n", ensure_period(&about.to_string())).unwrap();
        }

        if let Some(aliases) = visible_aliases_str(group) {
            writeln!(out, "**Alias:** `{aliases}`\n").unwrap();
        }

        let children: Vec<_> = group
            .get_subcommands()
            .filter(|c| !c.is_hide_set())
            .collect();

        for child in &children {
            write_leaf_command(child, out, &format!("{root_name} {}", group.get_name()));
        }
    }

    if !leaves.is_empty() {
        writeln!(out, "\n---\n").unwrap();
        writeln!(out, "## Additional Commands\n").unwrap();

        for leaf in &leaves {
            write_leaf_command(leaf, out, root_name);
        }
    }
}

fn write_leaf_command(cmd: &Command, out: &mut String, parent_path: &str) {
    let positionals = positional_synopsis(cmd);
    let full_cmd = format!("{parent_path} {}{positionals}", cmd.get_name());

    writeln!(out, "\n### `{full_cmd}`\n").unwrap();

    if let Some(about) = cmd.get_long_about().or_else(|| cmd.get_about()) {
        let text = ensure_period(&strip_ansi(&about.to_string()));
        writeln!(out, "{text}\n").unwrap();
    }

    if let Some(aliases) = visible_aliases_str(cmd) {
        writeln!(out, "**Alias:** `{aliases}`\n").unwrap();
    }

    let flags: Vec<_> = cmd
        .get_arguments()
        .filter(|a| !a.is_hide_set() && !a.is_global_set())
        .filter(|a| {
            let id = a.get_id().as_str();
            id != "help" && id != "version"
        })
        .collect();

    if flags.is_empty() {
        return;
    }

    let has_defaults = flags.iter().any(|a| !a.get_default_values().is_empty());

    if has_defaults {
        writeln!(out, "| Flag | Default | Description |").unwrap();
        writeln!(out, "|------|---------|-------------|").unwrap();
    } else {
        writeln!(out, "| Flag | Description |").unwrap();
        writeln!(out, "|------|-------------|").unwrap();
    }

    for arg in &flags {
        let flag_col = format_flag_name(arg);
        let help = arg_help(arg);

        let env_suffix = match arg.get_env() {
            Some(env) => format!(" Env: `{}`.", env.to_string_lossy()),
            None => String::new(),
        };

        if has_defaults {
            let default = format_default(arg);
            writeln!(out, "| {flag_col} | {default} | {help}{env_suffix} |").unwrap();
        } else {
            writeln!(out, "| {flag_col} | {help}{env_suffix} |").unwrap();
        }
    }
}

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------

fn format_flag_name(arg: &Arg) -> String {
    let value_name = arg
        .get_value_names()
        .and_then(|v| v.first().map(|s| s.as_str()));

    if arg.is_positional() {
        let name = value_name.unwrap_or(arg.get_id().as_str());
        if arg.is_last_set() {
            return format!("`[-- {name}...]`");
        }
        if arg.is_required_set() {
            return format!("`<{name}>`");
        }
        return format!("`[{name}]`");
    }

    let mut parts = Vec::new();
    if let Some(short) = arg.get_short() {
        parts.push(format!("-{short}"));
    }
    if let Some(long) = arg.get_long() {
        parts.push(format!("--{long}"));
    }

    let name = parts.join("`, `");

    match value_name {
        Some(v) if !is_bool_flag(arg) => format!("`{name} <{v}>`"),
        _ => format!("`{name}`"),
    }
}

fn format_default(arg: &Arg) -> String {
    let vals = arg.get_default_values();
    if vals.is_empty() {
        return String::new();
    }
    let joined: String = vals
        .iter()
        .map(|v| v.to_string_lossy().to_string())
        .collect::<Vec<_>>()
        .join(", ");
    if joined.is_empty() {
        return String::new();
    }
    format!("`{joined}`")
}

fn arg_help(arg: &Arg) -> String {
    arg.get_help()
        .map(|h| ensure_period(&strip_ansi(&h.to_string())))
        .unwrap_or_default()
}

fn visible_aliases_str(cmd: &Command) -> Option<String> {
    let aliases: Vec<_> = cmd.get_visible_aliases().collect();
    if aliases.is_empty() {
        return None;
    }
    Some(aliases.join("`, `"))
}

fn is_bool_flag(arg: &Arg) -> bool {
    arg.get_num_args().is_some_and(|r| r.max_values() == 0)
        || matches!(
            arg.get_action(),
            clap::ArgAction::SetTrue | clap::ArgAction::SetFalse
        )
}

fn titlecase(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_uppercase().collect::<String>() + chars.as_str(),
    }
}

/// Clap's derive macro strips trailing periods from single-line doc comments.
/// This restores them so generated documentation has consistent punctuation.
fn ensure_period(s: &str) -> String {
    let trimmed = s.trim_end();
    if trimmed.is_empty() {
        return String::new();
    }
    if trimmed.ends_with('.') || trimmed.ends_with('!') || trimmed.ends_with('?') {
        trimmed.to_string()
    } else {
        format!("{trimmed}.")
    }
}

fn strip_ansi(s: &str) -> String {
    let mut result = String::with_capacity(s.len());
    let mut in_escape = false;
    for c in s.chars() {
        if c == '\x1b' {
            in_escape = true;
            continue;
        }
        if in_escape {
            if c.is_ascii_alphabetic() {
                in_escape = false;
            }
            continue;
        }
        result.push(c);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::{CommandFactory, Parser};

    #[derive(Parser, Debug)]
    #[command(name = "test-cli")]
    struct TestCli {
        #[command(subcommand)]
        command: Option<TestCommands>,
    }

    #[derive(clap::Subcommand, Debug)]
    enum TestCommands {
        /// Do something.
        Hello {
            /// Your name.
            #[arg(long)]
            name: String,

            /// Greeting count.
            #[arg(short, default_value_t = 1)]
            n: u32,
        },
    }

    #[test]
    fn generates_markdown_with_command_tree() {
        let cmd = TestCli::command();
        let md = generate(&cmd);

        assert!(md.contains("# OpenShell CLI Reference"), "has title");
        assert!(md.contains("## Command Tree"), "has tree section");
        assert!(md.contains("hello"), "has hello command in tree");
        assert!(md.contains("`--name <NAME>`"), "has flag");
    }

    #[test]
    fn strip_ansi_removes_escape_codes() {
        assert_eq!(strip_ansi("\x1b[1mBOLD\x1b[0m"), "BOLD");
        assert_eq!(strip_ansi("no codes"), "no codes");
    }
}
