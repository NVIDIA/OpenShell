// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `OpenShell` CLI - command-line interface for `OpenShell`.

use clap::{CommandFactory, Parser, Subcommand, ValueEnum, ValueHint};
use clap_complete::engine::ArgValueCompleter;
use clap_complete::env::CompleteEnv;
use miette::Result;
use owo_colors::OwoColorize;
use std::io::Write;

use openshell_bootstrap::{
    edge_token::load_edge_token, get_gateway_metadata, list_gateways, load_active_gateway,
    load_gateway_metadata, load_last_sandbox, save_last_sandbox,
};
use openshell_cli::completers;
use openshell_cli::run;
use openshell_cli::tls::TlsOptions;

/// Resolved gateway context: name + gateway endpoint.
struct GatewayContext {
    /// The gateway name (used for TLS cert directory, metadata lookup, etc.).
    name: String,
    /// The gateway endpoint URL (e.g., `https://127.0.0.1` or `https://10.0.0.5`).
    endpoint: String,
}

/// Resolve the gateway name to a [`GatewayContext`] with the gateway endpoint.
///
/// Resolution priority:
/// 1. `--gateway-endpoint` flag (direct URL, preserving metadata when available)
/// 2. `--gateway` flag (explicit name)
/// 3. `OPENSHELL_GATEWAY` environment variable
/// 4. Active gateway from `~/.config/openshell/active_gateway`
///
/// When `--gateway-endpoint` is provided, it is used directly as the endpoint.
/// If stored metadata can still identify the gateway, the stored gateway name
/// is preserved so auth and TLS materials continue to resolve correctly.
fn normalize_gateway_endpoint(endpoint: &str) -> &str {
    endpoint.trim_end_matches('/')
}

fn find_gateway_by_endpoint(endpoint: &str) -> Option<String> {
    let endpoint = normalize_gateway_endpoint(endpoint);

    if let Some(active_name) = load_active_gateway()
        && let Ok(metadata) = load_gateway_metadata(&active_name)
        && normalize_gateway_endpoint(&metadata.gateway_endpoint) == endpoint
    {
        return Some(metadata.name);
    }

    list_gateways().ok()?.into_iter().find_map(|metadata| {
        (normalize_gateway_endpoint(&metadata.gateway_endpoint) == endpoint)
            .then_some(metadata.name)
    })
}

fn resolve_gateway(
    gateway_flag: &Option<String>,
    gateway_endpoint: &Option<String>,
) -> Result<GatewayContext> {
    if let Some(endpoint) = gateway_endpoint {
        let name = gateway_flag
            .clone()
            .filter(|name| get_gateway_metadata(name).is_some())
            .or_else(|| find_gateway_by_endpoint(endpoint))
            .unwrap_or_else(|| endpoint.clone());
        return Ok(GatewayContext {
            name,
            endpoint: endpoint.clone(),
        });
    }

    let name = gateway_flag
        .clone()
        .or_else(|| {
            std::env::var("OPENSHELL_GATEWAY")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .or_else(load_active_gateway)
        .ok_or_else(|| {
            miette::miette!(
                "No active gateway.\n\
                 Set one with: openshell gateway select <name>\n\
                 Or deploy a new gateway: openshell gateway start"
            )
        })?;

    let metadata = load_gateway_metadata(&name).map_err(|_| {
        miette::miette!(
            "Unknown gateway '{name}'.\n\
             Deploy it first: openshell gateway start --name {name}\n\
             Or list available gateways: openshell gateway select"
        )
    })?;

    Ok(GatewayContext {
        name: metadata.name,
        endpoint: metadata.gateway_endpoint,
    })
}

/// Resolve only the gateway name (without requiring metadata to exist).
///
/// Used by gateway commands that operate on a gateway by name but may not need
/// the gateway endpoint (e.g., `gateway start` creates the gateway).
fn resolve_gateway_name(gateway_flag: &Option<String>) -> Option<String> {
    gateway_flag
        .clone()
        .or_else(|| {
            std::env::var("OPENSHELL_GATEWAY")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .or_else(load_active_gateway)
}

/// Apply edge authentication token from local storage when the gateway uses edge auth.
///
/// When the resolved gateway has `auth_mode == "cloudflare_jwt"`, loads the
/// stored edge token from disk and sets it on the `TlsOptions`. The token is
/// always read from gateway metadata rather than supplied via a CLI flag.
fn apply_edge_auth(tls: &mut TlsOptions, gateway_name: &str) {
    if let Some(meta) = get_gateway_metadata(gateway_name)
        && meta.auth_mode.as_deref() == Some("cloudflare_jwt")
        && let Some(token) = load_edge_token(gateway_name)
    {
        tls.edge_token = Some(token);
    }
}

/// Resolve a sandbox name, falling back to the last-used sandbox for the gateway.
///
/// When `name` is `None`, looks up the last sandbox recorded for the active
/// gateway. Prints a hint when falling back so the user knows which sandbox
/// was chosen.
fn resolve_sandbox_name(name: Option<String>, gateway: &str) -> Result<String> {
    if let Some(n) = name {
        return Ok(n);
    }
    let last = load_last_sandbox(gateway).ok_or_else(|| {
        miette::miette!(
            "No sandbox name provided and no last-used sandbox.\n\
             Specify a sandbox name or connect to one first: nav sandbox connect <name>"
        )
    })?;
    eprintln!("{} Using sandbox '{}' (last used)", "→".bold(), last.bold(),);
    Ok(last)
}

// Custom root help stays hand-authored so commands can be grouped into product
// areas without relying on clap's default subcommand listing. User-facing
// commands remain visible so shell completion can suggest them at the root.
const HELP_TEMPLATE: &str = "\
{about-with-newline}
\x1b[1mUSAGE\x1b[0m
  openshell <command> <subcommand> [flags]

\x1b[1mSANDBOX COMMANDS\x1b[0m
  sandbox:     Manage sandboxes
  forward:     Manage port forwarding to a sandbox
  logs:        View sandbox logs
  policy:      Manage sandbox policy
  settings:    Manage sandbox and global settings
  provider:    Manage provider configuration

\x1b[1mGATEWAY COMMANDS\x1b[0m
  gateway:     Manage the gateway lifecycle
  status:      Show gateway status and information
  inference:   Manage inference configuration
  doctor:      Diagnose gateway issues

\x1b[1mADDITIONAL COMMANDS\x1b[0m
  term:        Launch the OpenShell interactive TUI
  completions: Generate shell completions
  ssh-proxy:   SSH proxy (used by ProxyCommand)
  help:        Print this message or the help of the given subcommand(s)

\x1b[1mFLAGS\x1b[0m
{options}

\x1b[1mEXAMPLES\x1b[0m
  $ openshell sandbox create
  $ openshell gateway start
  $ openshell logs my-sandbox

\x1b[1mLEARN MORE\x1b[0m
  Use `openshell <command> --help` for more information about a command.
";

// Help template for subcommands (sandbox, gateway, etc.)
const SUBCOMMAND_HELP_TEMPLATE: &str = "\
{about-with-newline}
\x1b[1mUSAGE\x1b[0m
  {usage}

\x1b[1mCOMMANDS\x1b[0m
{subcommands}

\x1b[1mFLAGS\x1b[0m
{options}
{after-help}";

// Help template for leaf commands (sandbox create, provider list, etc.)
const LEAF_HELP_TEMPLATE: &str = "\
{about-with-newline}
\x1b[1mUSAGE\x1b[0m
  {usage}

{all-args}
{after-help}";

const SANDBOX_EXAMPLES: &str = "\x1b[1mALIAS\x1b[0m
  sb

\x1b[1mEXAMPLES\x1b[0m
  $ openshell sandbox create
  $ openshell sandbox create --from python
  $ openshell sandbox connect my-sandbox
  $ openshell sandbox list
  $ openshell sandbox delete my-sandbox
";

const FORWARD_EXAMPLES: &str = "\x1b[1mALIAS\x1b[0m
  fwd

\x1b[1mEXAMPLES\x1b[0m
  $ openshell forward start 8080
  $ openshell forward start 3000 my-sandbox
  $ openshell forward stop 8080
  $ openshell forward list
";

const LOGS_EXAMPLES: &str = "\x1b[1mALIAS\x1b[0m
  lg

\x1b[1mEXAMPLES\x1b[0m
  $ openshell logs my-sandbox
  $ openshell logs my-sandbox --tail
  $ openshell logs --since 5m
  $ openshell logs --source sandbox --level debug
";

const POLICY_EXAMPLES: &str = "\x1b[1mALIAS\x1b[0m
  pol

\x1b[1mEXAMPLES\x1b[0m
  $ openshell policy get my-sandbox
  $ openshell policy set my-sandbox --policy policy.yaml
  $ openshell policy set --global --policy policy.yaml
  $ openshell policy delete --global
  $ openshell policy list my-sandbox
";

const SETTINGS_EXAMPLES: &str = "\x1b[1mEXAMPLES\x1b[0m
  $ openshell settings get my-sandbox
  $ openshell settings get --global
  $ openshell settings set my-sandbox --key log_level --value debug
  $ openshell settings set --global --key log_level --value warn
  $ openshell settings set --global --key dummy_bool --value yes
  $ openshell settings set --global --key dummy_int --value 42
  $ openshell settings delete --global --key log_level
";

const PROVIDER_EXAMPLES: &str = "\x1b[1mEXAMPLES\x1b[0m
  $ openshell provider create --name openai --type openai --credential OPENAI_API_KEY
  $ openshell provider create --name anthropic --type anthropic --from-existing
  $ openshell provider list
  $ openshell provider get openai
  $ openshell provider delete openai
";

const GATEWAY_EXAMPLES: &str = "\x1b[1mALIAS\x1b[0m
  gw

\x1b[1mEXAMPLES\x1b[0m
  $ openshell gateway start
  $ openshell gateway start --name my-gateway --port 9090
  $ openshell gateway stop
  $ openshell gateway select my-gateway
  $ openshell gateway info
";

const INFERENCE_EXAMPLES: &str = "\x1b[1mEXAMPLES\x1b[0m
  $ openshell inference set --provider openai --model gpt-4
  $ openshell inference get
  $ openshell inference update --model gpt-4-turbo
";

const DOCTOR_HELP: &str = "\x1b[1mALIAS\x1b[0m
  dr

\x1b[1mEXAMPLES\x1b[0m
  $ openshell doctor check
  $ openshell doctor logs --lines 100
  $ openshell doctor exec -- kubectl get pods -A
  $ openshell doctor llm.txt

\x1b[1mAI AGENT USAGE\x1b[0m
  If you are a coding agent (LLM) diagnosing a gateway issue, run:

    openshell doctor llm.txt

  This prints a detailed diagnostic prompt with step-by-step instructions
  for debugging gateway clusters using `openshell doctor logs` and
  `openshell doctor exec`.
";

/// `OpenShell` CLI - agent execution and management.
#[derive(Parser, Debug)]
#[command(name = "openshell")]
#[command(author, version = openshell_core::VERSION, about, long_about = None)]
#[command(propagate_version = true)]
#[command(help_template = HELP_TEMPLATE)]
#[command(disable_help_subcommand = true)]
#[command(disable_help_flag = true, disable_version_flag = true)]
struct Cli {
    /// Gateway name to operate on (resolved from stored metadata).
    #[arg(
        long,
        short = 'g',
        global = true,
        env = "OPENSHELL_GATEWAY",
        help_heading = "GATEWAY FLAGS",
        add = ArgValueCompleter::new(completers::complete_gateway_names)
    )]
    gateway: Option<String>,

    /// Gateway endpoint URL (e.g. <https://gateway.example.com>).
    /// Connects directly without looking up gateway metadata.
    #[arg(
        long,
        global = true,
        env = "OPENSHELL_GATEWAY_ENDPOINT",
        help_heading = "GATEWAY FLAGS"
    )]
    gateway_endpoint: Option<String>,

    /// Increase verbosity (-v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count, global = true, help_heading = "GLOBAL FLAGS")]
    verbose: u8,

    /// Print help.
    #[arg(short = 'h', long, action = clap::ArgAction::Help, global = true, help_heading = "GLOBAL FLAGS")]
    help: (),

    /// Print version.
    #[arg(short = 'V', long, action = clap::ArgAction::Version, global = true, help_heading = "GLOBAL FLAGS")]
    version: (),

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    // ===================================================================
    // SANDBOX COMMANDS
    // ===================================================================
    /// Manage sandboxes.
    #[command(alias = "sb", after_help = SANDBOX_EXAMPLES, help_template = SUBCOMMAND_HELP_TEMPLATE)]
    Sandbox {
        #[command(subcommand)]
        command: Option<SandboxCommands>,
    },

    /// Manage port forwarding to a sandbox.
    #[command(alias = "fwd", after_help = FORWARD_EXAMPLES, help_template = SUBCOMMAND_HELP_TEMPLATE)]
    Forward {
        #[command(subcommand)]
        command: Option<ForwardCommands>,
    },

    /// View sandbox logs.
    #[command(alias = "lg", after_help = LOGS_EXAMPLES, help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Logs {
        /// Sandbox name (defaults to last-used sandbox).
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,

        /// Number of log lines to return.
        #[arg(short, default_value_t = 200)]
        n: u32,

        /// Stream live logs.
        #[arg(long)]
        tail: bool,

        /// Only show logs from this duration ago (e.g. 5m, 1h, 30s).
        #[arg(long)]
        since: Option<String>,

        /// Filter by log source: "gateway", "sandbox", or "all" (default).
        /// Can be specified multiple times: --source gateway --source sandbox
        #[arg(long, default_value = "all")]
        source: Vec<String>,

        /// Minimum log level to display: error, warn, info (default), debug, trace.
        #[arg(long, default_value = "")]
        level: String,
    },

    /// Manage sandbox policy.
    #[command(alias = "pol", after_help = POLICY_EXAMPLES, help_template = SUBCOMMAND_HELP_TEMPLATE)]
    Policy {
        #[command(subcommand)]
        command: Option<PolicyCommands>,
    },

    /// Manage sandbox and gateway settings.
    #[command(after_help = SETTINGS_EXAMPLES, help_template = SUBCOMMAND_HELP_TEMPLATE)]
    Settings {
        #[command(subcommand)]
        command: Option<SettingsCommands>,
    },

    /// Manage network rules for a sandbox.
    #[command(visible_alias = "rl", hide = true, help_template = SUBCOMMAND_HELP_TEMPLATE)]
    Rule {
        #[command(subcommand)]
        command: Option<DraftCommands>,
    },

    /// Manage provider configuration.
    #[command(after_help = PROVIDER_EXAMPLES, help_template = SUBCOMMAND_HELP_TEMPLATE)]
    Provider {
        #[command(subcommand)]
        command: Option<ProviderCommands>,
    },

    // ===================================================================
    // GATEWAY COMMANDS
    // ===================================================================
    /// Manage the gateway lifecycle.
    #[command(alias = "gw", after_help = GATEWAY_EXAMPLES, help_template = SUBCOMMAND_HELP_TEMPLATE)]
    Gateway {
        #[command(subcommand)]
        command: Option<GatewayCommands>,
    },

    /// Show gateway status and information.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Status,

    /// Manage inference configuration.
    #[command(after_help = INFERENCE_EXAMPLES, help_template = SUBCOMMAND_HELP_TEMPLATE)]
    Inference {
        #[command(subcommand)]
        command: Option<InferenceCommands>,
    },

    // ===================================================================
    // DIAGNOSTIC COMMANDS
    // ===================================================================
    /// Diagnose gateway issues.
    ///
    /// Inspect logs, run commands inside the gateway container, and get
    /// AI-assisted debugging guidance. If you are a coding agent, run
    /// `openshell doctor llm.txt` for a full diagnostic prompt.
    #[command(visible_alias = "dr", hide = true, after_help = DOCTOR_HELP, help_template = SUBCOMMAND_HELP_TEMPLATE)]
    Doctor {
        #[command(subcommand)]
        command: Option<DoctorCommands>,
    },

    // ===================================================================
    // ADDITIONAL COMMANDS
    // ===================================================================
    /// Launch the `OpenShell` interactive TUI.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Term {
        /// Color theme for the TUI: auto, dark, or light.
        #[arg(long, default_value = "auto", env = "OPENSHELL_THEME")]
        theme: openshell_tui::ThemeMode,
    },

    /// Generate shell completions.
    #[command(after_long_help = COMPLETIONS_HELP, help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Completions {
        /// Shell to generate completions for.
        shell: CompletionShell,
    },

    /// SSH proxy (used by `ProxyCommand`).
    ///
    /// Two mutually exclusive modes:
    ///
    /// **Token mode** (used internally by `sandbox connect`):
    ///   `openshell ssh-proxy --gateway <url> --sandbox-id <id> --token <token>`
    ///
    /// **Name mode** (for use in `~/.ssh/config`):
    ///   `openshell ssh-proxy --gateway <name> --name <sandbox-name>`
    #[command(hide = true, help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    SshProxy {
        /// Gateway URL (e.g., <https://gw.example.com:443/proxy/connect>).
        /// Required in token mode. In name mode, can be a gateway name.
        #[arg(long, short = 'g')]
        gateway: Option<String>,

        /// Sandbox id. Required in token mode.
        #[arg(long)]
        sandbox_id: Option<String>,

        /// SSH session token. Required in token mode.
        #[arg(long)]
        token: Option<String>,

        /// Gateway endpoint URL. Used in name mode. Deprecated: prefer --gateway.
        #[arg(long)]
        server: Option<String>,

        /// Gateway name. Used with --name to resolve gateway from metadata.
        #[arg(long)]
        gateway_name: Option<String>,

        /// Sandbox name. Used in name mode.
        #[arg(long)]
        name: Option<String>,
    },
}

#[derive(Clone, Debug, ValueEnum)]
enum CompletionShell {
    Bash,
    Fish,
    Zsh,
    Powershell,
}

impl std::fmt::Display for CompletionShell {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bash => write!(f, "bash"),
            Self::Fish => write!(f, "fish"),
            Self::Zsh => write!(f, "zsh"),
            Self::Powershell => write!(f, "powershell"),
        }
    }
}

const COMPLETIONS_HELP: &str = "\
Generate shell completion scripts for OpenShell CLI.

Supported shells: bash, fish, zsh, powershell.

The script is output on stdout, allowing you to redirect the output to the file of your choosing.

The exact config file locations might vary based on your system. Make sure to restart your
shell before testing whether completions are working.

\x1b[1mBASH\x1b[0m

First, ensure that you install `bash-completion` using your package manager.

  mkdir -p ~/.local/share/bash-completion/completions
  openshell completions bash > ~/.local/share/bash-completion/completions/openshell

On macOS with Homebrew (install bash-completion first):

  mkdir -p $(brew --prefix)/etc/bash_completion.d
  openshell completions bash > $(brew --prefix)/etc/bash_completion.d/openshell.bash-completion

\x1b[1mFISH\x1b[0m

  mkdir -p ~/.config/fish/completions
  openshell completions fish > ~/.config/fish/completions/openshell.fish

\x1b[1mZSH\x1b[0m

  mkdir -p ~/.zfunc
  openshell completions zsh > ~/.zfunc/_openshell

Then add the following to your .zshrc before compinit:

  fpath+=~/.zfunc

\x1b[1mPOWERSHELL\x1b[0m

   openshell completions powershell >> $PROFILE

If no profile exists yet, create one first:

   New-Item -Path $PROFILE -Type File -Force
";

fn normalize_completion_script(output: Vec<u8>, executable: &std::path::Path) -> Result<String> {
    let script = String::from_utf8(output)
        .map_err(|e| miette::miette!("generated completions were not valid UTF-8: {e}"))?;
    Ok(script.replace(executable.to_string_lossy().as_ref(), "openshell"))
}

#[derive(Clone, Debug, ValueEnum)]
enum CliProviderType {
    Claude,
    Opencode,
    Codex,
    Generic,
    Openai,
    Anthropic,
    Nvidia,
    Gitlab,
    Github,
    Outlook,
}

#[derive(Clone, Debug, ValueEnum)]
enum CliEditor {
    Vscode,
    Cursor,
}

impl From<CliEditor> for openshell_cli::ssh::Editor {
    fn from(value: CliEditor) -> Self {
        match value {
            CliEditor::Vscode => Self::Vscode,
            CliEditor::Cursor => Self::Cursor,
        }
    }
}

impl CliProviderType {
    fn as_str(&self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Opencode => "opencode",
            Self::Codex => "codex",
            Self::Generic => "generic",
            Self::Openai => "openai",
            Self::Anthropic => "anthropic",
            Self::Nvidia => "nvidia",
            Self::Gitlab => "gitlab",
            Self::Github => "github",
            Self::Outlook => "outlook",
        }
    }
}

#[derive(Subcommand, Debug)]
enum ProviderCommands {
    /// Create a provider config.
    #[command(group = clap::ArgGroup::new("cred_source").required(true).args(["from_existing", "credentials"]), help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Create {
        /// Provider name.
        #[arg(long)]
        name: String,

        /// Provider type.
        #[arg(long = "type", value_enum)]
        provider_type: CliProviderType,

        /// Load provider credentials/config from existing local state.
        #[arg(long, conflicts_with = "credentials")]
        from_existing: bool,

        /// Provider credential pair (`KEY=VALUE`) or env lookup key (`KEY`).
        #[arg(
            long = "credential",
            value_name = "KEY[=VALUE]",
            conflicts_with = "from_existing"
        )]
        credentials: Vec<String>,

        /// Provider config key/value pair.
        #[arg(long = "config", value_name = "KEY=VALUE")]
        config: Vec<String>,
    },

    /// Fetch a provider by name.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Get {
        /// Provider name.
        #[arg(add = ArgValueCompleter::new(completers::complete_provider_names))]
        name: String,
    },

    /// List providers.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    List {
        /// Maximum number of providers to return.
        #[arg(long, default_value_t = 100)]
        limit: u32,

        /// Offset into the provider list.
        #[arg(long, default_value_t = 0)]
        offset: u32,

        /// Print only provider names, one per line.
        #[arg(long)]
        names: bool,
    },

    /// Update an existing provider's credentials or config.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Update {
        /// Provider name.
        #[arg(add = ArgValueCompleter::new(completers::complete_provider_names))]
        name: String,

        /// Re-discover credentials from existing local state (e.g. env vars, config files).
        #[arg(long, conflicts_with = "credentials")]
        from_existing: bool,

        /// Provider credential pair (`KEY=VALUE`) or env lookup key (`KEY`).
        #[arg(
            long = "credential",
            value_name = "KEY[=VALUE]",
            conflicts_with = "from_existing"
        )]
        credentials: Vec<String>,

        /// Provider config key/value pair.
        #[arg(long = "config", value_name = "KEY=VALUE")]
        config: Vec<String>,
    },

    /// Delete providers by name.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Delete {
        /// Provider names.
        #[arg(required = true, num_args = 1.., value_name = "NAME", add = ArgValueCompleter::new(completers::complete_provider_names))]
        names: Vec<String>,
    },
}

// -----------------------------------------------------------------------
// Gateway commands (replaces the old `cluster` / `cluster admin` groups)
// -----------------------------------------------------------------------

#[derive(Subcommand, Debug)]
enum GatewayCommands {
    /// Deploy/start the gateway.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Start {
        /// Gateway name.
        #[arg(long, default_value = "openshell", env = "OPENSHELL_GATEWAY")]
        name: String,

        /// SSH destination for remote deployment (e.g., user@hostname).
        #[arg(long)]
        remote: Option<String>,

        /// Path to SSH private key for remote deployment.
        #[arg(long, value_hint = ValueHint::FilePath)]
        ssh_key: Option<String>,

        /// Host port to map to the gateway (default: 8080).
        #[arg(long, default_value_t = openshell_bootstrap::DEFAULT_GATEWAY_PORT)]
        port: u16,

        /// Override the gateway host written into cluster metadata.
        ///
        /// By default, local clusters advertise 127.0.0.1. Set this when
        /// the client cannot reach the Docker host at 127.0.0.1 — for
        /// example in CI containers, WSL, or when Docker runs on a
        /// remote host. Common values: `host.docker.internal`, a LAN IP,
        /// or a hostname.
        #[arg(long)]
        gateway_host: Option<String>,

        /// Destroy and recreate the gateway from scratch if one already exists.
        ///
        /// Without this flag, an interactive prompt asks whether to recreate;
        /// in non-interactive mode the existing gateway is reused silently.
        #[arg(long)]
        recreate: bool,

        /// Listen on plaintext HTTP instead of mTLS.
        ///
        /// Use when the gateway sits behind a reverse proxy (e.g., Cloudflare
        /// Tunnel) that terminates TLS at the edge.
        #[arg(long)]
        plaintext: bool,

        /// Disable gateway authentication (mTLS client certificate requirement).
        ///
        /// The server still listens on TLS, but clients are not required to
        /// present a certificate. Use when a reverse proxy (e.g., Cloudflare
        /// Tunnel) terminates TLS and cannot forward client certs.
        /// Ignored when --plaintext is set.
        #[arg(long)]
        disable_gateway_auth: bool,

        /// Username for authenticating with the container image registry.
        ///
        /// Defaults to `__token__` when `--registry-token` is set (the
        /// standard convention for GHCR PAT-based auth). Only needed for
        /// private registries — public GHCR repos pull without auth.
        #[arg(long, env = "OPENSHELL_REGISTRY_USERNAME")]
        registry_username: Option<String>,

        /// Authentication token for pulling container images from the registry.
        ///
        /// For GHCR, this is a GitHub personal access token (PAT) with
        /// `read:packages` scope. Only needed for private registries —
        /// public GHCR repos pull without auth. Used to pull the cluster
        /// bootstrap image and passed into the k3s cluster so it can pull
        /// server, sandbox, and community images at runtime.
        #[arg(long, env = "OPENSHELL_REGISTRY_TOKEN")]
        registry_token: Option<String>,

        /// Enable NVIDIA GPU passthrough.
        ///
        /// Passes all host GPUs into the cluster container and deploys the
        /// NVIDIA k8s-device-plugin so Kubernetes workloads can request
        /// `nvidia.com/gpu` resources. Requires NVIDIA drivers and the
        /// NVIDIA Container Toolkit on the host.
        ///
        /// When enabled, OpenShell auto-selects CDI when the Docker daemon has
        /// CDI enabled and falls back to Docker's NVIDIA GPU request path
        /// (`--gpus all`) otherwise.
        #[arg(long)]
        gpu: bool,
    },

    /// Stop the gateway (preserves state).
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Stop {
        /// Gateway name (defaults to active gateway).
        #[arg(long, env = "OPENSHELL_GATEWAY", add = ArgValueCompleter::new(completers::complete_gateway_names))]
        name: Option<String>,

        /// Override SSH destination (auto-resolved from gateway metadata).
        #[arg(long)]
        remote: Option<String>,

        /// Path to SSH private key for remote gateway.
        #[arg(long, value_hint = ValueHint::FilePath)]
        ssh_key: Option<String>,
    },

    /// Destroy the gateway and its state.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Destroy {
        /// Gateway name (defaults to active gateway).
        #[arg(long, env = "OPENSHELL_GATEWAY", add = ArgValueCompleter::new(completers::complete_gateway_names))]
        name: Option<String>,

        /// Override SSH destination (auto-resolved from gateway metadata).
        #[arg(long)]
        remote: Option<String>,

        /// Path to SSH private key for remote gateway.
        #[arg(long, value_hint = ValueHint::FilePath)]
        ssh_key: Option<String>,
    },

    /// Add an existing gateway.
    ///
    /// Registers a gateway endpoint so it appears in `openshell gateway select`.
    ///
    /// Without extra flags the gateway is treated as an edge-authenticated
    /// (cloud) gateway and a browser is opened for authentication.
    ///
    /// Pass `--remote <ssh-dest>` to register a remote mTLS gateway whose
    /// Docker daemon is reachable over SSH. Pass `--local` to register a
    /// local mTLS gateway running in Docker on this machine. In both cases
    /// the CLI extracts mTLS certificates from the running container
    /// automatically.
    ///
    /// An `ssh://` endpoint (e.g., `ssh://user@host:8080`) is shorthand
    /// for `--remote user@host` with the endpoint derived from the URL.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Add {
        /// Gateway endpoint URL (e.g., `https://10.0.0.5:8080` or `ssh://user@host:8080`).
        endpoint: String,

        /// Gateway name (auto-derived from the endpoint hostname when omitted).
        #[arg(long)]
        name: Option<String>,

        /// Register a remote mTLS gateway accessible via SSH.
        #[arg(long, conflicts_with = "local")]
        remote: Option<String>,

        /// SSH private key for the remote host (used with `--remote` or `ssh://`).
        #[arg(long, value_hint = ValueHint::FilePath)]
        ssh_key: Option<String>,

        /// Register a local mTLS gateway running in Docker on this machine.
        #[arg(long, conflicts_with = "remote")]
        local: bool,
    },

    /// Authenticate with an edge-authenticated gateway.
    ///
    /// Opens a browser for the edge proxy's login flow and stores the
    /// token locally. Use this to re-authenticate when a token expires.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Login {
        /// Gateway name (defaults to the active gateway).
        #[arg(add = ArgValueCompleter::new(completers::complete_gateway_names))]
        name: Option<String>,
    },

    /// Select the active gateway.
    ///
    /// When called without a name, opens an interactive chooser on a TTY and
    /// lists available gateways in non-interactive mode.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Select {
        /// Gateway name (omit to choose interactively or list in non-interactive mode).
        #[arg(add = ArgValueCompleter::new(completers::complete_gateway_names))]
        name: Option<String>,
    },

    /// Show gateway deployment details.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Info {
        /// Gateway name (defaults to active gateway).
        #[arg(long, env = "OPENSHELL_GATEWAY", add = ArgValueCompleter::new(completers::complete_gateway_names))]
        name: Option<String>,
    },
}

// -----------------------------------------------------------------------
// Inference commands
// -----------------------------------------------------------------------

#[derive(Subcommand, Debug)]
enum InferenceCommands {
    /// Set gateway-level inference provider and model.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Set {
        /// Provider name.
        #[arg(long, add = ArgValueCompleter::new(completers::complete_provider_names))]
        provider: String,

        /// Model identifier to force for generation calls.
        #[arg(long)]
        model: String,

        /// Configure the system inference route instead of the user-facing
        /// route. System inference is used by platform functions (e.g. the
        /// agent harness) and is not accessible to user code.
        #[arg(long)]
        system: bool,

        /// Skip endpoint verification before saving the route.
        #[arg(long)]
        no_verify: bool,

        /// Request timeout in seconds for inference calls (0 = default 60s).
        #[arg(long, default_value_t = 0)]
        timeout: u64,
    },

    /// Update gateway-level inference configuration (partial update).
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Update {
        /// Provider name (unchanged if omitted).
        #[arg(long, add = ArgValueCompleter::new(completers::complete_provider_names))]
        provider: Option<String>,

        /// Model identifier (unchanged if omitted).
        #[arg(long)]
        model: Option<String>,

        /// Target the system inference route.
        #[arg(long)]
        system: bool,

        /// Skip endpoint verification before saving the route.
        #[arg(long)]
        no_verify: bool,

        /// Request timeout in seconds for inference calls (0 = default 60s, unchanged if omitted).
        #[arg(long)]
        timeout: Option<u64>,
    },

    /// Get gateway-level inference provider and model.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Get {
        /// Show the system inference route instead of the user-facing route.
        /// When omitted, both routes are displayed.
        #[arg(long)]
        system: bool,
    },
}

// -----------------------------------------------------------------------
// Doctor (diagnostic) commands
// -----------------------------------------------------------------------

#[derive(Subcommand, Debug)]
enum DoctorCommands {
    /// Fetch logs from the gateway container.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Logs {
        /// Gateway name (defaults to active gateway).
        #[arg(long, env = "OPENSHELL_GATEWAY")]
        name: Option<String>,

        /// Number of log lines to return (default: all).
        #[arg(short, long)]
        lines: Option<usize>,

        /// Stream live logs (follow mode).
        #[arg(long)]
        tail: bool,

        /// Override SSH destination for remote gateways.
        #[arg(long)]
        remote: Option<String>,

        /// Path to SSH private key for remote gateways.
        #[arg(long, value_hint = ValueHint::FilePath)]
        ssh_key: Option<String>,
    },

    /// Run a command inside the gateway container.
    ///
    /// Launches an interactive `docker exec` session in the gateway's k3s
    /// container with KUBECONFIG pre-configured.  When the gateway is remote,
    /// the session is tunnelled over SSH automatically.
    ///
    /// Examples:
    ///   openshell doctor exec -- kubectl get pods -A
    ///   openshell doctor exec -- k9s
    ///   openshell doctor exec -- sh
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Exec {
        /// Gateway name (defaults to active gateway).
        #[arg(long, env = "OPENSHELL_GATEWAY")]
        name: Option<String>,

        /// Override SSH destination for remote gateways.
        #[arg(long)]
        remote: Option<String>,

        /// Path to SSH private key for remote gateways.
        #[arg(long, value_hint = ValueHint::FilePath)]
        ssh_key: Option<String>,

        /// Command and arguments to run inside the container.
        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },

    /// Print a diagnostic prompt for AI-assisted gateway debugging.
    ///
    /// Outputs a system prompt that a coding agent can use to autonomously
    /// diagnose gateway issues using `openshell doctor logs` and
    /// `openshell doctor exec`.
    ///
    /// Examples:
    ///   openshell doctor llm.txt
    ///   openshell doctor llm.txt | pbcopy
    #[command(name = "llm.txt", help_template = LEAF_HELP_TEMPLATE)]
    LlmTxt,

    /// Validate system prerequisites for running a gateway.
    ///
    /// Checks that a Docker-compatible runtime is installed, running, and
    /// reachable. Reports version info and socket path. Use this to verify
    /// your environment before running `openshell gateway start`.
    ///
    /// Examples:
    ///   openshell doctor check
    #[command(help_template = LEAF_HELP_TEMPLATE)]
    Check,
}

#[derive(Subcommand, Debug)]
enum SandboxCommands {
    /// Create a sandbox.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Create {
        /// Optional sandbox name (auto-generated when omitted).
        #[arg(long)]
        name: Option<String>,

        /// Sandbox source: a community sandbox name (e.g., `openclaw`), a path
        /// to a Dockerfile or directory containing one, or a full container
        /// image reference (e.g., `myregistry.com/img:tag`).
        ///
        /// Community names are resolved to
        /// `ghcr.io/nvidia/openshell-community/sandboxes/<name>:latest`
        /// (override the prefix with `OPENSHELL_COMMUNITY_REGISTRY`).
        ///
        /// When given a Dockerfile or directory, the image is built and pushed
        /// into the cluster automatically before creating the sandbox.
        #[arg(long, value_hint = ValueHint::AnyPath)]
        from: Option<String>,

        /// Upload local files into the sandbox before running.
        ///
        /// Format: `<LOCAL_PATH>[:<SANDBOX_PATH>]`.
        /// When `SANDBOX_PATH` is omitted, files are uploaded to the container
        /// working directory (`/sandbox`).
        /// `.gitignore` rules are applied by default; use `--no-git-ignore` to
        /// upload everything.
        #[arg(long, value_hint = ValueHint::AnyPath, help_heading = "UPLOAD FLAGS")]
        upload: Option<String>,

        /// Disable `.gitignore` filtering for `--upload`.
        #[arg(long, requires = "upload", help_heading = "UPLOAD FLAGS")]
        no_git_ignore: bool,

        /// Deprecated compatibility flag. Sandboxes are kept by default.
        #[arg(long, hide = true, conflicts_with = "no_keep")]
        keep: bool,

        /// Delete the sandbox after the initial command or shell exits.
        #[arg(long, conflicts_with_all = ["keep", "editor", "forward"])]
        no_keep: bool,

        /// Launch a remote editor after the sandbox is ready.
        /// Keeps the sandbox alive and installs OpenShell-managed SSH config.
        #[arg(long, value_enum, conflicts_with = "no_keep")]
        editor: Option<CliEditor>,

        /// Request GPU resources for the sandbox.
        ///
        /// When no gateway is running, auto-bootstrap starts a GPU-enabled
        /// gateway using the same automatic injection selection as
        /// `openshell gateway start --gpu`. GPU intent is also inferred
        /// automatically for known GPU-designated image names such as
        /// `nvidia-gpu`.
        #[arg(long)]
        gpu: bool,

        /// SSH destination for remote bootstrap (e.g., user@hostname).
        /// Only used when no cluster exists yet; ignored if a cluster is
        /// already active.
        #[arg(long, help_heading = "BOOTSTRAP FLAGS")]
        remote: Option<String>,

        /// Path to SSH private key for remote bootstrap.
        #[arg(long, value_hint = ValueHint::FilePath, help_heading = "BOOTSTRAP FLAGS")]
        ssh_key: Option<String>,

        /// Provider names to attach to this sandbox.
        #[arg(long = "provider")]
        providers: Vec<String>,

        /// Path to a custom sandbox policy YAML file.
        /// Overrides the built-in default and the `OPENSHELL_SANDBOX_POLICY` env var.
        #[arg(long, value_hint = ValueHint::FilePath)]
        policy: Option<String>,

        /// Forward a local port to the sandbox before the initial command or shell starts.
        /// Accepts [bind_address:]port (e.g. 8080, 0.0.0.0:8080). Keeps the sandbox alive.
        #[arg(long, conflicts_with = "no_keep")]
        forward: Option<String>,

        /// Allocate a pseudo-terminal for the remote command.
        /// Defaults to auto-detection (on when stdin and stdout are terminals).
        /// Use --tty to force a PTY even when auto-detection fails, or
        /// --no-tty to disable.
        #[arg(long, overrides_with = "no_tty")]
        tty: bool,

        /// Disable pseudo-terminal allocation.
        #[arg(long, overrides_with = "tty")]
        no_tty: bool,

        /// Auto-bootstrap a gateway if none is available (this is the default).
        #[arg(
            long,
            overrides_with = "no_bootstrap",
            help_heading = "BOOTSTRAP FLAGS",
            hide = true
        )]
        bootstrap: bool,

        /// Never bootstrap a gateway automatically; error if none is available.
        #[arg(long, overrides_with = "bootstrap", help_heading = "BOOTSTRAP FLAGS")]
        no_bootstrap: bool,

        /// Auto-create missing providers from local credentials.
        ///
        /// Without this flag, an interactive prompt asks per-provider;
        /// in non-interactive mode the command errors.
        #[arg(long, overrides_with = "no_auto_providers")]
        auto_providers: bool,

        /// Never auto-create providers; error if required providers are missing.
        #[arg(long, overrides_with = "auto_providers")]
        no_auto_providers: bool,

        /// Command to run after "--" (defaults to an interactive shell).
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Fetch a sandbox by name.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Get {
        /// Sandbox name (defaults to last-used sandbox).
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,
    },

    /// List sandboxes.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    List {
        /// Maximum number of sandboxes to return.
        #[arg(long, default_value_t = 100)]
        limit: u32,

        /// Offset into the sandbox list.
        #[arg(long, default_value_t = 0)]
        offset: u32,

        /// Print only sandbox ids (one per line).
        #[arg(long, conflicts_with = "names")]
        ids: bool,

        /// Print only sandbox names (one per line).
        #[arg(long, conflicts_with = "ids")]
        names: bool,
    },

    /// Delete a sandbox by name.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Delete {
        /// Sandbox names.
        #[arg(required_unless_present = "all", num_args = 1.., value_name = "NAME", add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        names: Vec<String>,

        /// Delete all sandboxes.
        #[arg(long, conflicts_with = "names")]
        all: bool,
    },

    /// Connect to a sandbox.
    ///
    /// When no name is given, reconnects to the last-used sandbox.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Connect {
        /// Sandbox name (defaults to last-used sandbox).
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,

        /// Launch a remote editor instead of an interactive shell.
        /// Installs OpenShell-managed SSH config if needed.
        #[arg(long, value_enum)]
        editor: Option<CliEditor>,
    },

    /// Upload local files to a sandbox.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Upload {
        /// Sandbox name.
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: String,

        /// Local path to upload.
        #[arg(value_hint = ValueHint::AnyPath)]
        local_path: String,

        /// Destination path in the sandbox (defaults to `/sandbox`).
        dest: Option<String>,

        /// Disable `.gitignore` filtering (uploads everything).
        #[arg(long)]
        no_git_ignore: bool,
    },

    /// Download files from a sandbox.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Download {
        /// Sandbox name.
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: String,

        /// Sandbox path to download.
        sandbox_path: String,

        /// Local destination (defaults to `.`).
        #[arg(value_hint = ValueHint::AnyPath)]
        dest: Option<String>,
    },

    /// Print an SSH config entry for a sandbox.
    ///
    /// Outputs a Host block suitable for appending to ~/.ssh/config,
    /// enabling tools like `VSCode` Remote-SSH to connect to the sandbox.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    SshConfig {
        /// Sandbox name (defaults to last-used sandbox).
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum DraftCommands {
    /// Show network rules for a sandbox.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Get {
        /// Sandbox name (defaults to last-used sandbox).
        name: Option<String>,

        /// Filter by status (pending, approved, rejected).
        #[arg(long)]
        status: Option<String>,
    },

    /// Approve a network rule.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Approve {
        /// Sandbox name (defaults to last-used sandbox).
        name: Option<String>,

        /// Chunk ID to approve.
        #[arg(long)]
        chunk_id: String,
    },

    /// Reject a network rule.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Reject {
        /// Sandbox name (defaults to last-used sandbox).
        name: Option<String>,

        /// Chunk ID to reject.
        #[arg(long)]
        chunk_id: String,

        /// Reason for rejection.
        #[arg(long, default_value = "")]
        reason: String,
    },

    /// Approve all pending network rules.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    ApproveAll {
        /// Sandbox name (defaults to last-used sandbox).
        name: Option<String>,

        /// Also approve security-flagged rules.
        #[arg(long)]
        include_security_flagged: bool,
    },

    /// Clear all pending network rules.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Clear {
        /// Sandbox name (defaults to last-used sandbox).
        name: Option<String>,
    },

    /// Show network rule history.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    History {
        /// Sandbox name (defaults to last-used sandbox).
        name: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCommands {
    /// Update policy on a live sandbox.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Set {
        /// Sandbox name (defaults to last-used sandbox when not using --global).
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,

        /// Path to the policy YAML file.
        #[arg(long, value_hint = ValueHint::FilePath)]
        policy: String,

        /// Apply as a gateway-global policy for all sandboxes.
        #[arg(long)]
        global: bool,

        /// Skip the confirmation prompt for global policy updates.
        #[arg(long)]
        yes: bool,

        /// Wait for the sandbox to load the policy.
        #[arg(long)]
        wait: bool,

        /// Timeout for --wait in seconds.
        #[arg(long, default_value_t = 60)]
        timeout: u64,
    },

    /// Show current active policy for a sandbox or the global policy.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Get {
        /// Sandbox name (defaults to last-used sandbox). Ignored with --global.
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,

        /// Show a specific policy revision (default: latest).
        #[arg(long = "rev", default_value_t = 0)]
        rev: u32,

        /// Print the full policy as YAML.
        #[arg(long)]
        full: bool,

        /// Show the global policy revision.
        #[arg(long)]
        global: bool,
    },

    /// List policy history for a sandbox or the global policy.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    List {
        /// Sandbox name (defaults to last-used sandbox). Ignored with --global.
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,

        /// Maximum number of revisions to return.
        #[arg(long, default_value_t = 20)]
        limit: u32,

        /// List global policy revisions.
        #[arg(long)]
        global: bool,
    },

    /// Delete the gateway-global policy lock, restoring sandbox-level policy control.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Delete {
        /// Delete the global policy setting.
        #[arg(long)]
        global: bool,

        /// Skip the confirmation prompt for global policy delete.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
enum SettingsCommands {
    /// Show effective settings for a sandbox or gateway-global scope.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Get {
        /// Sandbox name (defaults to last-used sandbox).
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,

        /// Show gateway-global settings.
        #[arg(long)]
        global: bool,

        /// Output as JSON.
        #[arg(long)]
        json: bool,
    },

    /// Set a single setting key.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Set {
        /// Sandbox name (defaults to last-used sandbox when not using --global).
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,

        /// Setting key.
        #[arg(long)]
        key: String,

        /// Setting value (string input; bool keys accept true/false/yes/no/1/0).
        #[arg(long)]
        value: String,

        /// Apply at gateway-global scope.
        #[arg(long)]
        global: bool,

        /// Skip the confirmation prompt for global setting updates.
        #[arg(long)]
        yes: bool,
    },

    /// Delete a setting key (sandbox-scoped or gateway-global).
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Delete {
        /// Sandbox name (defaults to last-used sandbox when not using --global).
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,

        /// Setting key.
        #[arg(long)]
        key: String,

        /// Delete at gateway-global scope.
        #[arg(long)]
        global: bool,

        /// Skip the confirmation prompt for global setting delete.
        #[arg(long)]
        yes: bool,
    },
}

#[derive(Subcommand, Debug)]
enum ForwardCommands {
    /// Start forwarding a local port to a sandbox.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Start {
        /// Port to forward: [bind_address:]port (e.g. 8080, 0.0.0.0:8080).
        port: String,

        /// Sandbox name (defaults to last-used sandbox).
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,

        /// Run the forward in the background and exit immediately.
        #[arg(short = 'd', long)]
        background: bool,
    },

    /// Stop a background port forward.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    Stop {
        /// Port that was forwarded.
        port: u16,

        /// Sandbox name (auto-detected from active forwards if omitted).
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,
    },

    /// List active port forwards.
    #[command(help_template = LEAF_HELP_TEMPLATE, next_help_heading = "FLAGS")]
    List,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the rustls crypto provider before completion runs — completers may
    // establish TLS connections to the gateway.
    rustls::crypto::ring::default_provider()
        .install_default()
        .map_err(|e| miette::miette!("failed to install rustls crypto provider: {e:?}"))?;

    CompleteEnv::with_factory(Cli::command).complete();

    let cli = Cli::parse();
    let tls = TlsOptions::default();

    // Set up logging based on verbosity
    let log_level = match cli.verbose {
        0 => "warn",
        1 => "info",
        2 => "debug",
        _ => "trace",
    };

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new(log_level)),
        )
        .init();

    match cli.command {
        // -----------------------------------------------------------
        // Gateway commands (was `cluster` / `cluster admin`)
        // -----------------------------------------------------------
        Some(Commands::Gateway {
            command: Some(command),
        }) => match command {
            GatewayCommands::Start {
                name,
                remote,
                ssh_key,
                port,
                gateway_host,
                recreate,
                plaintext,
                disable_gateway_auth,
                registry_username,
                registry_token,
                gpu,
            } => {
                let gpu = if gpu {
                    vec!["auto".to_string()]
                } else {
                    vec![]
                };
                run::gateway_admin_deploy(
                    &name,
                    remote.as_deref(),
                    ssh_key.as_deref(),
                    port,
                    gateway_host.as_deref(),
                    recreate,
                    plaintext,
                    disable_gateway_auth,
                    registry_username.as_deref(),
                    registry_token.as_deref(),
                    gpu,
                )
                .await?;
            }
            GatewayCommands::Stop {
                name,
                remote,
                ssh_key,
            } => {
                let name = name
                    .or_else(|| resolve_gateway_name(&cli.gateway))
                    .unwrap_or_else(|| "openshell".to_string());
                run::gateway_admin_stop(&name, remote.as_deref(), ssh_key.as_deref()).await?;
            }
            GatewayCommands::Destroy {
                name,
                remote,
                ssh_key,
            } => {
                let name = name
                    .or_else(|| resolve_gateway_name(&cli.gateway))
                    .unwrap_or_else(|| "openshell".to_string());
                run::gateway_admin_destroy(&name, remote.as_deref(), ssh_key.as_deref()).await?;
            }
            GatewayCommands::Add {
                endpoint,
                name,
                remote,
                ssh_key,
                local,
            } => {
                run::gateway_add(
                    &endpoint,
                    name.as_deref(),
                    remote.as_deref(),
                    ssh_key.as_deref(),
                    local,
                )
                .await?;
            }
            GatewayCommands::Login { name } => {
                let name = name
                    .or_else(|| resolve_gateway_name(&cli.gateway))
                    .ok_or_else(|| {
                        miette::miette!(
                            "No active gateway.\n\
                             Specify a gateway name: openshell gateway login <name>\n\
                             Or set one with: openshell gateway select <name>"
                        )
                    })?;
                run::gateway_login(&name).await?;
            }
            GatewayCommands::Select { name } => {
                run::gateway_select(name.as_deref(), &cli.gateway)?;
            }
            GatewayCommands::Info { name } => {
                let name = name
                    .or_else(|| resolve_gateway_name(&cli.gateway))
                    .unwrap_or_else(|| "openshell".to_string());
                run::gateway_admin_info(&name)?;
            }
        },

        // -----------------------------------------------------------
        // Doctor (diagnostic) commands
        // -----------------------------------------------------------
        Some(Commands::Doctor {
            command: Some(command),
        }) => match command {
            DoctorCommands::Logs {
                name,
                lines,
                tail,
                remote,
                ssh_key,
            } => {
                let name = name
                    .or_else(|| resolve_gateway_name(&cli.gateway))
                    .unwrap_or_else(|| "openshell".to_string());
                run::doctor_logs(&name, lines, tail, remote.as_deref(), ssh_key.as_deref()).await?;
            }
            DoctorCommands::Exec {
                name,
                remote,
                ssh_key,
                command,
            } => {
                let name = name
                    .or_else(|| resolve_gateway_name(&cli.gateway))
                    .unwrap_or_else(|| "openshell".to_string());
                run::doctor_exec(&name, remote.as_deref(), ssh_key.as_deref(), &command)?;
            }
            DoctorCommands::LlmTxt => {
                run::doctor_llm()?;
            }
            DoctorCommands::Check => {
                run::doctor_check().await?;
            }
        },
        Some(Commands::Doctor { command: None }) => {
            Cli::command()
                .find_subcommand_mut("doctor")
                .expect("doctor subcommand exists")
                .print_help()
                .expect("Failed to print help");
        }

        // -----------------------------------------------------------
        // Top-level status
        // -----------------------------------------------------------
        Some(Commands::Status) => {
            if let Ok(ctx) = resolve_gateway(&cli.gateway, &cli.gateway_endpoint) {
                let mut tls = tls.with_gateway_name(&ctx.name);
                apply_edge_auth(&mut tls, &ctx.name);
                run::gateway_status(&ctx.name, &ctx.endpoint, &tls).await?;
            } else {
                println!("{}", "Gateway Status".cyan().bold());
                println!();
                println!("  {} No gateway configured.", "Status:".dimmed(),);
                println!();
                println!(
                    "Deploy a gateway with: {}",
                    "openshell gateway start".dimmed()
                );
            }
        }

        // -----------------------------------------------------------
        // Top-level forward (was `sandbox forward`)
        // -----------------------------------------------------------
        Some(Commands::Forward {
            command: Some(fwd_cmd),
        }) => match fwd_cmd {
            ForwardCommands::Stop { port, name } => {
                let name = match name {
                    Some(n) => n,
                    None => match run::find_forward_by_port(port)? {
                        Some(n) => {
                            eprintln!("→ Found forward on sandbox '{n}'");
                            n
                        }
                        None => {
                            eprintln!("{} No active forward found for port {port}", "!".yellow(),);
                            return Ok(());
                        }
                    },
                };
                if run::stop_forward(&name, port)? {
                    eprintln!(
                        "{} Stopped forward of port {port} for sandbox {name}",
                        "✓".green().bold(),
                    );
                } else {
                    eprintln!(
                        "{} No active forward found for port {port} on sandbox {name}",
                        "!".yellow(),
                    );
                }
            }
            ForwardCommands::List => {
                let forwards = run::list_forwards()?;
                if forwards.is_empty() {
                    eprintln!("No active forwards.");
                } else {
                    let name_width = forwards
                        .iter()
                        .map(|f| f.sandbox.len())
                        .max()
                        .unwrap_or(7)
                        .max(7);
                    let bind_width = forwards
                        .iter()
                        .map(|f| f.bind_addr.len())
                        .max()
                        .unwrap_or(4)
                        .max(4);
                    println!(
                        "{:<nw$} {:<bw$} {:<8} {:<10} STATUS",
                        "SANDBOX",
                        "BIND",
                        "PORT",
                        "PID",
                        nw = name_width,
                        bw = bind_width,
                    );
                    for f in &forwards {
                        let status = if f.alive {
                            "running".green().to_string()
                        } else {
                            "dead".red().to_string()
                        };
                        println!(
                            "{:<nw$} {:<bw$} {:<8} {:<10} {}",
                            f.sandbox,
                            f.bind_addr,
                            f.port,
                            f.pid,
                            status,
                            nw = name_width,
                            bw = bind_width,
                        );
                    }
                }
            }
            ForwardCommands::Start {
                port,
                name,
                background,
            } => {
                let spec = openshell_core::forward::ForwardSpec::parse(&port)?;
                let ctx = resolve_gateway(&cli.gateway, &cli.gateway_endpoint)?;
                let mut tls = tls.with_gateway_name(&ctx.name);
                apply_edge_auth(&mut tls, &ctx.name);
                let name = resolve_sandbox_name(name, &ctx.name)?;
                run::sandbox_forward(&ctx.endpoint, &name, &spec, background, &tls).await?;
                if background {
                    eprintln!(
                        "{} Forwarding port {} to sandbox {name} in the background",
                        "✓".green().bold(),
                        spec.port,
                    );
                    eprintln!("  Access at: {}", spec.access_url());
                    eprintln!("  Stop with: openshell forward stop {} {name}", spec.port);
                }
            }
        },

        // -----------------------------------------------------------
        // Top-level logs (was `sandbox logs`)
        // -----------------------------------------------------------
        Some(Commands::Logs {
            name,
            n,
            tail,
            since,
            source,
            level,
        }) => {
            let ctx = resolve_gateway(&cli.gateway, &cli.gateway_endpoint)?;
            let mut tls = tls.with_gateway_name(&ctx.name);
            apply_edge_auth(&mut tls, &ctx.name);
            let name = resolve_sandbox_name(name, &ctx.name)?;
            run::sandbox_logs(
                &ctx.endpoint,
                &name,
                n,
                tail,
                since.as_deref(),
                &source,
                &level,
                &tls,
            )
            .await?;
        }

        // -----------------------------------------------------------
        // Top-level policy (was `sandbox policy`)
        // -----------------------------------------------------------
        Some(Commands::Policy {
            command: Some(policy_cmd),
        }) => {
            let ctx = resolve_gateway(&cli.gateway, &cli.gateway_endpoint)?;
            let mut tls = tls.with_gateway_name(&ctx.name);
            apply_edge_auth(&mut tls, &ctx.name);
            match policy_cmd {
                PolicyCommands::Set {
                    name,
                    policy,
                    global,
                    yes,
                    wait,
                    timeout,
                } => {
                    if global {
                        if wait {
                            return Err(miette::miette!(
                                "--wait is not supported for global policies; \
                                 global policies are effective immediately"
                            ));
                        }
                        run::sandbox_policy_set_global(
                            &ctx.endpoint,
                            &policy,
                            yes,
                            wait,
                            timeout,
                            &tls,
                        )
                        .await?;
                    } else {
                        let name = resolve_sandbox_name(name, &ctx.name)?;
                        run::sandbox_policy_set(&ctx.endpoint, &name, &policy, wait, timeout, &tls)
                            .await?;
                    }
                }
                PolicyCommands::Get {
                    name,
                    rev,
                    full,
                    global,
                } => {
                    if global {
                        run::sandbox_policy_get_global(&ctx.endpoint, rev, full, &tls).await?;
                    } else {
                        let name = resolve_sandbox_name(name, &ctx.name)?;
                        run::sandbox_policy_get(&ctx.endpoint, &name, rev, full, &tls).await?;
                    }
                }
                PolicyCommands::List {
                    name,
                    limit,
                    global,
                } => {
                    if global {
                        run::sandbox_policy_list_global(&ctx.endpoint, limit, &tls).await?;
                    } else {
                        let name = resolve_sandbox_name(name, &ctx.name)?;
                        run::sandbox_policy_list(&ctx.endpoint, &name, limit, &tls).await?;
                    }
                }
                PolicyCommands::Delete { global, yes } => {
                    if !global {
                        return Err(miette::miette!(
                            "sandbox policy delete is not supported; use --global to remove global policy lock"
                        ));
                    }
                    run::gateway_setting_delete(&ctx.endpoint, "policy", yes, &tls).await?;
                }
            }
        }

        // -----------------------------------------------------------
        // Settings commands
        // -----------------------------------------------------------
        Some(Commands::Settings {
            command: Some(settings_cmd),
        }) => {
            let ctx = resolve_gateway(&cli.gateway, &cli.gateway_endpoint)?;
            let mut tls = tls.with_gateway_name(&ctx.name);
            apply_edge_auth(&mut tls, &ctx.name);

            match settings_cmd {
                SettingsCommands::Get { name, global, json } => {
                    if global {
                        if name.is_some() {
                            return Err(miette::miette!(
                                "settings get --global does not accept a sandbox name"
                            ));
                        }
                        run::gateway_settings_get(&ctx.endpoint, json, &tls).await?;
                    } else {
                        let name = resolve_sandbox_name(name, &ctx.name)?;
                        run::sandbox_settings_get(&ctx.endpoint, &name, json, &tls).await?;
                    }
                }
                SettingsCommands::Set {
                    name,
                    key,
                    value,
                    global,
                    yes,
                } => {
                    if global {
                        run::gateway_setting_set(&ctx.endpoint, &key, &value, yes, &tls).await?;
                    } else {
                        let name = resolve_sandbox_name(name, &ctx.name)?;
                        run::sandbox_setting_set(&ctx.endpoint, &name, &key, &value, &tls).await?;
                    }
                }
                SettingsCommands::Delete {
                    name,
                    key,
                    global,
                    yes,
                } => {
                    if global {
                        run::gateway_setting_delete(&ctx.endpoint, &key, yes, &tls).await?;
                    } else {
                        let name = resolve_sandbox_name(name, &ctx.name)?;
                        run::sandbox_setting_delete(&ctx.endpoint, &name, &key, &tls).await?;
                    }
                }
            }
        }

        // -----------------------------------------------------------
        // Network rules
        // -----------------------------------------------------------
        Some(Commands::Rule {
            command: Some(draft_cmd),
        }) => {
            let ctx = resolve_gateway(&cli.gateway, &cli.gateway_endpoint)?;
            let mut tls = tls.with_gateway_name(&ctx.name);
            apply_edge_auth(&mut tls, &ctx.name);
            match draft_cmd {
                DraftCommands::Get { name, status } => {
                    let name = resolve_sandbox_name(name, &ctx.name)?;
                    run::sandbox_draft_get(&ctx.endpoint, &name, status.as_deref(), &tls).await?;
                }
                DraftCommands::Approve { name, chunk_id } => {
                    let name = resolve_sandbox_name(name, &ctx.name)?;
                    run::sandbox_draft_approve(&ctx.endpoint, &name, &chunk_id, &tls).await?;
                }
                DraftCommands::Reject {
                    name,
                    chunk_id,
                    reason,
                } => {
                    let name = resolve_sandbox_name(name, &ctx.name)?;
                    run::sandbox_draft_reject(&ctx.endpoint, &name, &chunk_id, &reason, &tls)
                        .await?;
                }
                DraftCommands::ApproveAll {
                    name,
                    include_security_flagged,
                } => {
                    let name = resolve_sandbox_name(name, &ctx.name)?;
                    run::sandbox_draft_approve_all(
                        &ctx.endpoint,
                        &name,
                        include_security_flagged,
                        &tls,
                    )
                    .await?;
                }

                DraftCommands::Clear { name } => {
                    let name = resolve_sandbox_name(name, &ctx.name)?;
                    run::sandbox_draft_clear(&ctx.endpoint, &name, &tls).await?;
                }
                DraftCommands::History { name } => {
                    let name = resolve_sandbox_name(name, &ctx.name)?;
                    run::sandbox_draft_history(&ctx.endpoint, &name, &tls).await?;
                }
            }
        }

        // -----------------------------------------------------------
        // Inference commands
        // -----------------------------------------------------------
        Some(Commands::Inference {
            command: Some(command),
        }) => {
            let ctx = resolve_gateway(&cli.gateway, &cli.gateway_endpoint)?;
            let endpoint = &ctx.endpoint;
            let mut tls = tls.with_gateway_name(&ctx.name);
            apply_edge_auth(&mut tls, &ctx.name);
            match command {
                InferenceCommands::Set {
                    provider,
                    model,
                    system,
                    no_verify,
                    timeout,
                } => {
                    let route_name = if system { "sandbox-system" } else { "" };
                    run::gateway_inference_set(
                        endpoint, &provider, &model, route_name, no_verify, timeout, &tls,
                    )
                    .await?;
                }
                InferenceCommands::Update {
                    provider,
                    model,
                    system,
                    no_verify,
                    timeout,
                } => {
                    let route_name = if system { "sandbox-system" } else { "" };
                    run::gateway_inference_update(
                        endpoint,
                        provider.as_deref(),
                        model.as_deref(),
                        route_name,
                        no_verify,
                        timeout,
                        &tls,
                    )
                    .await?;
                }
                InferenceCommands::Get { system } => {
                    let route_name = if system { Some("sandbox-system") } else { None };
                    run::gateway_inference_get(endpoint, route_name, &tls).await?;
                }
            }
        }

        // -----------------------------------------------------------
        // Sandbox commands
        // -----------------------------------------------------------
        Some(Commands::Sandbox {
            command: Some(command),
        }) => {
            match command {
                SandboxCommands::Create {
                    name,
                    from,
                    upload,
                    no_git_ignore,
                    keep,
                    no_keep,
                    editor,
                    gpu,
                    remote,
                    ssh_key,
                    providers,
                    policy,
                    forward,
                    tty,
                    no_tty,
                    bootstrap,
                    no_bootstrap,
                    auto_providers,
                    no_auto_providers,
                    command,
                } => {
                    // Resolve --tty / --no-tty into an Option<bool> override.
                    let tty_override = if no_tty {
                        Some(false)
                    } else if tty {
                        Some(true)
                    } else {
                        None // auto-detect
                    };

                    // Resolve --bootstrap / --no-bootstrap into an Option<bool>.
                    // Bootstrap is the default; --no-bootstrap opts out.
                    let bootstrap_override = if no_bootstrap {
                        Some(false)
                    } else if bootstrap {
                        Some(true)
                    } else {
                        None // auto-bootstrap (default)
                    };

                    // Resolve --auto-providers / --no-auto-providers.
                    let auto_providers_override = if no_auto_providers {
                        Some(false)
                    } else if auto_providers {
                        Some(true)
                    } else {
                        None // prompt or auto-detect
                    };

                    // Parse --upload spec into (local_path, sandbox_path, git_ignore).
                    let upload_spec = upload.as_deref().map(|s| {
                        let (local, remote) = parse_upload_spec(s);
                        (local, remote, !no_git_ignore)
                    });

                    let editor = editor.map(Into::into);
                    let forward = forward
                        .map(|s| openshell_core::forward::ForwardSpec::parse(&s))
                        .transpose()?;
                    let keep = keep || !no_keep || editor.is_some() || forward.is_some();

                    // For `sandbox create`, a missing cluster is not fatal — the
                    // bootstrap flow inside `sandbox_create` can deploy one.
                    match resolve_gateway(&cli.gateway, &cli.gateway_endpoint) {
                        Ok(ctx) => {
                            if remote.is_some() {
                                eprintln!(
                                    "{} --remote ignored: gateway '{}' is already active. \
                                     To redeploy, use: openshell gateway start",
                                    "!".yellow(),
                                    ctx.name,
                                );
                                return Ok(());
                            }
                            let endpoint = &ctx.endpoint;
                            let mut tls = tls.with_gateway_name(&ctx.name);
                            apply_edge_auth(&mut tls, &ctx.name);
                            // The user already has a configured gateway. Disable
                            // auto-bootstrap in the retry path so we don't
                            // silently replace their selected gateway with a new
                            // "openshell" gateway if the connection fails.
                            Box::pin(run::sandbox_create(
                                endpoint,
                                name.as_deref(),
                                from.as_deref(),
                                &ctx.name,
                                upload_spec.as_ref(),
                                keep,
                                gpu,
                                editor,
                                remote.as_deref(),
                                ssh_key.as_deref(),
                                &providers,
                                policy.as_deref(),
                                forward,
                                &command,
                                tty_override,
                                Some(false),
                                auto_providers_override,
                                &tls,
                            ))
                            .await?;
                        }
                        Err(_) => {
                            // No gateway configured — go straight to bootstrap.
                            Box::pin(run::sandbox_create_with_bootstrap(
                                name.as_deref(),
                                from.as_deref(),
                                upload_spec.as_ref(),
                                keep,
                                gpu,
                                editor,
                                remote.as_deref(),
                                ssh_key.as_deref(),
                                &providers,
                                policy.as_deref(),
                                forward,
                                &command,
                                tty_override,
                                bootstrap_override,
                                auto_providers_override,
                            ))
                            .await?;
                        }
                    }
                }
                SandboxCommands::Upload {
                    name,
                    local_path,
                    dest,
                    no_git_ignore,
                } => {
                    let ctx = resolve_gateway(&cli.gateway, &cli.gateway_endpoint)?;
                    let mut tls = tls.with_gateway_name(&ctx.name);
                    apply_edge_auth(&mut tls, &ctx.name);
                    let sandbox_dest = dest.as_deref().unwrap_or("/sandbox");
                    let local = std::path::Path::new(&local_path);
                    if !local.exists() {
                        return Err(miette::miette!(
                            "local path does not exist: {}",
                            local.display()
                        ));
                    }
                    eprintln!("Uploading {} -> sandbox:{}", local.display(), sandbox_dest);
                    if !no_git_ignore && let Ok((base_dir, files)) = run::git_sync_files(local) {
                        run::sandbox_sync_up_files(
                            &ctx.endpoint,
                            &name,
                            &base_dir,
                            &files,
                            sandbox_dest,
                            &tls,
                        )
                        .await?;
                        eprintln!("{} Upload complete", "✓".green().bold());
                        return Ok(());
                    }
                    // Fallback: upload without git filtering
                    run::sandbox_sync_up(&ctx.endpoint, &name, local, sandbox_dest, &tls).await?;
                    eprintln!("{} Upload complete", "✓".green().bold());
                }
                SandboxCommands::Download {
                    name,
                    sandbox_path,
                    dest,
                } => {
                    let ctx = resolve_gateway(&cli.gateway, &cli.gateway_endpoint)?;
                    let mut tls = tls.with_gateway_name(&ctx.name);
                    apply_edge_auth(&mut tls, &ctx.name);
                    let local_dest = std::path::Path::new(dest.as_deref().unwrap_or("."));
                    eprintln!(
                        "Downloading sandbox:{} -> {}",
                        sandbox_path,
                        local_dest.display()
                    );
                    run::sandbox_sync_down(&ctx.endpoint, &name, &sandbox_path, local_dest, &tls)
                        .await?;
                    eprintln!("{} Download complete", "✓".green().bold());
                }
                other => {
                    let ctx = resolve_gateway(&cli.gateway, &cli.gateway_endpoint)?;
                    let endpoint = &ctx.endpoint;
                    let mut tls = tls.with_gateway_name(&ctx.name);
                    apply_edge_auth(&mut tls, &ctx.name);
                    match other {
                        SandboxCommands::Create { .. }
                        | SandboxCommands::Upload { .. }
                        | SandboxCommands::Download { .. } => {
                            unreachable!()
                        }
                        SandboxCommands::Get { name } => {
                            let name = resolve_sandbox_name(name, &ctx.name)?;
                            run::sandbox_get(endpoint, &name, &tls).await?;
                        }
                        SandboxCommands::List {
                            limit,
                            offset,
                            ids,
                            names,
                        } => {
                            run::sandbox_list(endpoint, limit, offset, ids, names, &tls).await?;
                        }
                        SandboxCommands::Delete { names, all } => {
                            run::sandbox_delete(endpoint, &names, all, &tls, &ctx.name).await?;
                        }
                        SandboxCommands::Connect { name, editor } => {
                            let name = resolve_sandbox_name(name, &ctx.name)?;
                            if let Some(editor) = editor.map(Into::into) {
                                run::sandbox_connect_editor(
                                    endpoint, &ctx.name, &name, editor, &tls,
                                )
                                .await?;
                            } else {
                                run::sandbox_connect(endpoint, &name, &tls).await?;
                            }
                            let _ = save_last_sandbox(&ctx.name, &name);
                        }
                        SandboxCommands::SshConfig { name } => {
                            let name = resolve_sandbox_name(name, &ctx.name)?;
                            run::print_ssh_config(&ctx.name, &name);
                        }
                    }
                }
            }
        }
        Some(Commands::Provider {
            command: Some(command),
        }) => {
            let ctx = resolve_gateway(&cli.gateway, &cli.gateway_endpoint)?;
            let endpoint = &ctx.endpoint;
            let mut tls = tls.with_gateway_name(&ctx.name);
            apply_edge_auth(&mut tls, &ctx.name);

            match command {
                ProviderCommands::Create {
                    name,
                    provider_type,
                    from_existing,
                    credentials,
                    config,
                } => {
                    run::provider_create(
                        endpoint,
                        &name,
                        provider_type.as_str(),
                        from_existing,
                        &credentials,
                        &config,
                        &tls,
                    )
                    .await?;
                }
                ProviderCommands::Get { name } => {
                    run::provider_get(endpoint, &name, &tls).await?;
                }
                ProviderCommands::List {
                    limit,
                    offset,
                    names,
                } => {
                    run::provider_list(endpoint, limit, offset, names, &tls).await?;
                }
                ProviderCommands::Update {
                    name,
                    from_existing,
                    credentials,
                    config,
                } => {
                    run::provider_update(
                        endpoint,
                        &name,
                        from_existing,
                        &credentials,
                        &config,
                        &tls,
                    )
                    .await?;
                }
                ProviderCommands::Delete { names } => {
                    run::provider_delete(endpoint, &names, &tls).await?;
                }
            }
        }
        Some(Commands::Term { theme }) => {
            let ctx = resolve_gateway(&cli.gateway, &cli.gateway_endpoint)?;
            let mut tls = tls.with_gateway_name(&ctx.name);
            apply_edge_auth(&mut tls, &ctx.name);
            let channel = openshell_cli::tls::build_channel(&ctx.endpoint, &tls).await?;
            openshell_tui::run(channel, &ctx.name, &ctx.endpoint, theme).await?;
        }
        Some(Commands::Completions { shell }) => {
            let exe = std::env::current_exe()
                .map_err(|e| miette::miette!("failed to find current executable: {e}"))?;
            let output = std::process::Command::new(&exe)
                .env("COMPLETE", shell.to_string())
                .output()
                .map_err(|e| miette::miette!("failed to generate completions: {e}"))?;
            let script = normalize_completion_script(output.stdout, &exe)?;
            std::io::stdout()
                .write_all(script.as_bytes())
                .map_err(|e| miette::miette!("failed to write completions: {e}"))?;
        }
        Some(Commands::SshProxy {
            gateway,
            sandbox_id,
            token,
            server,
            gateway_name,
            name,
        }) => {
            match (gateway, sandbox_id, token, server, gateway_name, name) {
                // Token mode (existing behavior): pre-created session credentials.
                (Some(gw), Some(sid), Some(tok), _, gateway_name_opt, _) => {
                    let mut effective_tls = match gateway_name_opt {
                        Some(ref g) => tls.with_gateway_name(g),
                        None => tls,
                    };
                    if let Some(ref g) = gateway_name_opt {
                        apply_edge_auth(&mut effective_tls, g);
                    }
                    run::sandbox_ssh_proxy(&gw, &sid, &tok, &effective_tls).await?;
                }
                // Name mode with --gateway-name: resolve endpoint from metadata.
                (_, _, _, server_override, Some(g), Some(n)) => {
                    let endpoint = if let Some(srv) = server_override {
                        srv
                    } else {
                        let meta = load_gateway_metadata(&g).map_err(|_| {
                            miette::miette!(
                                "Unknown gateway '{g}'.\n\
                                  Deploy it first: openshell gateway start --name {g}\n\
                                  Or list available gateways: openshell gateway select"
                            )
                        })?;
                        meta.gateway_endpoint
                    };
                    let mut tls = tls.with_gateway_name(&g);
                    apply_edge_auth(&mut tls, &g);
                    run::sandbox_ssh_proxy_by_name(&endpoint, &n, &tls).await?;
                }
                // Legacy name mode with --server only (no --gateway-name).
                (_, _, _, Some(srv), None, Some(n)) => {
                    run::sandbox_ssh_proxy_by_name(&srv, &n, &tls).await?;
                }
                _ => {
                    return Err(miette::miette!(
                        "provide either --gateway/--sandbox-id/--token or --gateway-name/--name (or --server/--name)"
                    ));
                }
            }
        }

        // No subcommand provided - print help for the command
        Some(Commands::Sandbox { command: None }) => {
            Cli::command()
                .find_subcommand_mut("sandbox")
                .expect("sandbox subcommand exists")
                .print_help()
                .expect("Failed to print help");
        }
        Some(Commands::Forward { command: None }) => {
            Cli::command()
                .find_subcommand_mut("forward")
                .expect("forward subcommand exists")
                .print_help()
                .expect("Failed to print help");
        }
        Some(Commands::Policy { command: None }) => {
            Cli::command()
                .find_subcommand_mut("policy")
                .expect("policy subcommand exists")
                .print_help()
                .expect("Failed to print help");
        }
        Some(Commands::Settings { command: None }) => {
            Cli::command()
                .find_subcommand_mut("settings")
                .expect("settings subcommand exists")
                .print_help()
                .expect("Failed to print help");
        }
        Some(Commands::Provider { command: None }) => {
            Cli::command()
                .find_subcommand_mut("provider")
                .expect("provider subcommand exists")
                .print_help()
                .expect("Failed to print help");
        }
        Some(Commands::Gateway { command: None }) => {
            Cli::command()
                .find_subcommand_mut("gateway")
                .expect("gateway subcommand exists")
                .print_help()
                .expect("Failed to print help");
        }
        Some(Commands::Inference { command: None }) => {
            Cli::command()
                .find_subcommand_mut("inference")
                .expect("inference subcommand exists")
                .print_help()
                .expect("Failed to print help");
        }
        Some(Commands::Rule { command: None }) => {
            Cli::command()
                .find_subcommand_mut("rule")
                .expect("rule subcommand exists")
                .print_help()
                .expect("Failed to print help");
        }

        None => {
            Cli::command().print_help().expect("Failed to print help");
        }
    }

    Ok(())
}

/// Parse an upload spec like `<local>[:<remote>]` into (`local_path`, `optional_sandbox_path`).
fn parse_upload_spec(spec: &str) -> (String, Option<String>) {
    if let Some((local, remote)) = spec.split_once(':') {
        (
            local.to_string(),
            if remote.is_empty() {
                None
            } else {
                Some(remote.to_string())
            },
        )
    } else {
        (spec.to_string(), None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use openshell_bootstrap::{
        GatewayMetadata, edge_token::store_edge_token, store_gateway_metadata,
    };
    use std::ffi::OsString;
    use std::fs;

    // Tests below mutate the process-global XDG_CONFIG_HOME env var.
    // A static mutex serialises them so concurrent threads don't clobber
    // each other's environment.
    static XDG_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Helper: hold `XDG_LOCK`, set `XDG_CONFIG_HOME` to a tempdir, run `f`,
    /// then restore the original value.
    #[allow(unsafe_code)]
    fn with_tmp_xdg<F: FnOnce()>(tmp: &std::path::Path, f: F) {
        let _guard = XDG_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let orig = std::env::var("XDG_CONFIG_HOME").ok();
        unsafe {
            std::env::set_var("XDG_CONFIG_HOME", tmp);
        }
        f();
        unsafe {
            match orig {
                Some(v) => std::env::set_var("XDG_CONFIG_HOME", v),
                None => std::env::remove_var("XDG_CONFIG_HOME"),
            }
        }
    }

    fn edge_metadata(name: &str, endpoint: &str) -> GatewayMetadata {
        GatewayMetadata {
            name: name.to_string(),
            gateway_endpoint: endpoint.to_string(),
            is_remote: true,
            gateway_port: 0,
            remote_host: None,
            resolved_host: None,
            auth_mode: Some("cloudflare_jwt".to_string()),
            edge_team_domain: None,
            edge_auth_url: None,
        }
    }

    #[test]
    fn cli_debug_assert() {
        Cli::command().debug_assert();
    }

    #[test]
    fn completions_engine_returns_candidates() {
        let mut cmd = Cli::command();
        let args: Vec<OsString> = vec!["openshell".into(), "".into()];
        let candidates = clap_complete::engine::complete(&mut cmd, args, 1, None)
            .expect("completion engine failed");
        let names: Vec<String> = candidates
            .iter()
            .map(|c| c.get_value().to_string_lossy().into_owned())
            .collect();

        assert!(
            names.contains(&"sandbox".to_string()),
            "expected 'sandbox' in root candidates, got: {names:?}"
        );
        assert!(
            names.contains(&"--gateway".to_string()),
            "expected '--gateway' in root candidates, got: {names:?}"
        );
        assert!(
            !names.contains(&"lg".to_string()),
            "expected root candidates to prefer canonical command names, got: {names:?}"
        );
        assert!(
            !names.contains(&"pol".to_string()),
            "expected root candidates to prefer canonical command names, got: {names:?}"
        );
    }

    #[test]
    fn completions_subcommand_appears_in_candidates() {
        let mut cmd = Cli::command();
        let args: Vec<OsString> = vec!["openshell".into(), "comp".into()];
        let candidates = clap_complete::engine::complete(&mut cmd, args, 1, None)
            .expect("completion engine failed");
        let names: Vec<String> = candidates
            .iter()
            .map(|c| c.get_value().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.contains(&"completions".to_string()),
            "expected 'completions' in candidates, got: {names:?}"
        );
    }

    #[test]
    fn completions_policy_flag_falls_back_to_file_paths() {
        let temp = tempfile::tempdir().expect("failed to create tempdir");
        fs::write(temp.path().join("policy.yaml"), "version: 1\n")
            .expect("failed to create policy file");

        let mut cmd = Cli::command();
        let args: Vec<OsString> = vec![
            "openshell".into(),
            "sandbox".into(),
            "create".into(),
            "--policy".into(),
            "pol".into(),
        ];
        let candidates = clap_complete::engine::complete(&mut cmd, args, 4, Some(temp.path()))
            .expect("completion engine failed");
        let names: Vec<String> = candidates
            .iter()
            .map(|c| c.get_value().to_string_lossy().into_owned())
            .collect();

        assert!(
            names.contains(&"policy.yaml".to_string()),
            "expected file path completion for --policy, got: {names:?}"
        );
    }

    #[test]
    fn completions_other_path_flags_fall_back_to_path_candidates() {
        let temp = tempfile::tempdir().expect("failed to create tempdir");
        fs::write(temp.path().join("id_rsa"), "key").expect("failed to create key file");
        fs::write(temp.path().join("Dockerfile"), "FROM scratch\n")
            .expect("failed to create dockerfile");
        fs::create_dir(temp.path().join("ctx")).expect("failed to create context directory");

        let cases: Vec<(Vec<&str>, usize, &str)> = vec![
            (
                vec!["openshell", "gateway", "start", "--ssh-key", "id"],
                4,
                "id_rsa",
            ),
            (
                vec!["openshell", "sandbox", "create", "--ssh-key", "id"],
                4,
                "id_rsa",
            ),
            (
                vec!["openshell", "sandbox", "upload", "demo", "Do"],
                4,
                "Dockerfile",
            ),
            (
                vec!["openshell", "sandbox", "create", "--from", "Do"],
                4,
                "Dockerfile",
            ),
            (
                vec![
                    "openshell",
                    "sandbox",
                    "download",
                    "demo",
                    "/sandbox/file",
                    "Do",
                ],
                5,
                "Dockerfile",
            ),
        ];

        for (raw_args, index, expected) in cases {
            let mut cmd = Cli::command();
            let args: Vec<OsString> = raw_args.iter().copied().map(Into::into).collect();
            let candidates =
                clap_complete::engine::complete(&mut cmd, args, index, Some(temp.path()))
                    .expect("completion engine failed");
            let names: Vec<String> = candidates
                .iter()
                .map(|c| c.get_value().to_string_lossy().into_owned())
                .collect();

            assert!(
                names.contains(&expected.to_string()),
                "expected path completion '{expected}' for args {raw_args:?}, got: {names:?}"
            );
        }
    }

    #[test]
    fn sandbox_upload_uses_path_value_hint() {
        let cmd = Cli::command();
        let sandbox = cmd
            .get_subcommands()
            .find(|c| c.get_name() == "sandbox")
            .expect("missing sandbox subcommand");
        let upload = sandbox
            .get_subcommands()
            .find(|c| c.get_name() == "upload")
            .expect("missing sandbox upload subcommand");
        let local_path = upload
            .get_arguments()
            .find(|arg| arg.get_id() == "local_path")
            .expect("missing local_path argument");

        assert_eq!(local_path.get_value_hint(), ValueHint::AnyPath);
    }

    #[test]
    fn sandbox_upload_completion_suggests_local_paths() {
        let temp = tempfile::tempdir().expect("failed to create tempdir");
        fs::write(temp.path().join("sample.txt"), "x").expect("failed to create sample file");

        let mut cmd = Cli::command();
        let args: Vec<OsString> = vec![
            "openshell".into(),
            "sandbox".into(),
            "upload".into(),
            "demo".into(),
            "sa".into(),
        ];
        let candidates = clap_complete::engine::complete(&mut cmd, args, 4, Some(temp.path()))
            .expect("completion engine failed");

        let names: Vec<String> = candidates
            .iter()
            .map(|c| c.get_value().to_string_lossy().into_owned())
            .collect();
        assert!(
            names.iter().any(|name| name.contains("sample.txt")),
            "expected path completion for upload local_path, got: {names:?}"
        );
    }

    #[test]
    fn gateway_completion_suggests_registered_gateways() {
        let tmp = tempfile::tempdir().expect("failed to create tempdir");
        with_tmp_xdg(tmp.path(), || {
            store_gateway_metadata(
                "alpha",
                &edge_metadata("alpha", "https://alpha.example.com"),
            )
            .expect("store gateway alpha");
            store_gateway_metadata("beta", &edge_metadata("beta", "https://beta.example.com"))
                .expect("store gateway beta");

            for (raw_args, index) in [
                (vec!["openshell", "--gateway", "a"], 2),
                (vec!["openshell", "gateway", "select", "a"], 3),
                (vec!["openshell", "gateway", "info", "--name", "a"], 4),
            ] {
                let mut cmd = Cli::command();
                let args: Vec<OsString> = raw_args.iter().copied().map(Into::into).collect();
                let candidates = clap_complete::engine::complete(&mut cmd, args, index, None)
                    .expect("completion engine failed");
                let names: Vec<String> = candidates
                    .iter()
                    .map(|c| c.get_value().to_string_lossy().into_owned())
                    .collect();

                assert!(
                    names.contains(&"alpha".to_string()),
                    "expected gateway completion for args {raw_args:?}, got: {names:?}"
                );
            }
        });
    }

    #[test]
    fn global_gateway_flag_still_parses_with_subcommands() {
        let cli = Cli::try_parse_from(["openshell", "--gateway", "demo", "status"])
            .expect("global gateway flag should parse with subcommands");

        assert_eq!(cli.gateway.as_deref(), Some("demo"));
        assert!(matches!(cli.command, Some(Commands::Status)));
    }

    #[test]
    fn hidden_aliases_still_parse() {
        let cli = Cli::try_parse_from(["openshell", "lg", "sandbox-1"])
            .expect("hidden aliases should still parse");

        assert!(matches!(
            cli.command,
            Some(Commands::Logs { name: Some(ref name), .. }) if name == "sandbox-1"
        ));
    }

    #[test]
    fn inference_set_accepts_no_verify_flag() {
        let cli = Cli::try_parse_from([
            "openshell",
            "inference",
            "set",
            "--provider",
            "openai-dev",
            "--model",
            "gpt-4.1",
            "--no-verify",
        ])
        .expect("inference set should parse --no-verify");

        assert!(matches!(
            cli.command,
            Some(Commands::Inference {
                command: Some(InferenceCommands::Set {
                    no_verify: true,
                    ..
                })
            })
        ));
    }

    #[test]
    fn inference_update_accepts_no_verify_flag() {
        let cli = Cli::try_parse_from([
            "openshell",
            "inference",
            "update",
            "--provider",
            "openai-dev",
            "--no-verify",
        ])
        .expect("inference update should parse --no-verify");

        assert!(matches!(
            cli.command,
            Some(Commands::Inference {
                command: Some(InferenceCommands::Update {
                    no_verify: true,
                    ..
                })
            })
        ));
    }

    #[test]
    fn completion_script_uses_openshell_command_name() {
        let script = normalize_completion_script(
            b"/tmp/custom/openshell -- \"${words[@]}\"\n#compdef openshell\n".to_vec(),
            std::path::Path::new("/tmp/custom/openshell"),
        )
        .expect("normalize completion script");

        assert!(script.contains("openshell -- \"${words[@]}\""));
        assert!(!script.contains("/tmp/custom/openshell"));
    }

    #[test]
    fn sandbox_create_and_download_use_path_value_hints() {
        let cmd = Cli::command();
        let sandbox = cmd
            .get_subcommands()
            .find(|c| c.get_name() == "sandbox")
            .expect("missing sandbox subcommand");
        let create = sandbox
            .get_subcommands()
            .find(|c| c.get_name() == "create")
            .expect("missing create subcommand");
        let from = create
            .get_arguments()
            .find(|arg| arg.get_id() == "from")
            .expect("missing from argument");
        let download = sandbox
            .get_subcommands()
            .find(|c| c.get_name() == "download")
            .expect("missing download subcommand");
        let dest = download
            .get_arguments()
            .find(|arg| arg.get_id() == "dest")
            .expect("missing dest argument");

        assert_eq!(from.get_value_hint(), ValueHint::AnyPath);
        assert_eq!(dest.get_value_hint(), ValueHint::AnyPath);
    }

    #[test]
    fn parse_upload_spec_without_remote() {
        let (local, remote) = parse_upload_spec("./src");
        assert_eq!(local, "./src");
        assert_eq!(remote, None);
    }

    #[test]
    fn parse_upload_spec_with_remote() {
        let (local, remote) = parse_upload_spec("./src:/sandbox/src");
        assert_eq!(local, "./src");
        assert_eq!(remote, Some("/sandbox/src".to_string()));
    }

    #[test]
    fn parse_upload_spec_with_trailing_colon() {
        let (local, remote) = parse_upload_spec("./src:");
        assert_eq!(local, "./src");
        assert_eq!(remote, None);
    }

    #[test]
    fn resolve_sandbox_name_returns_explicit_name() {
        // When a name is provided, it should be returned regardless of any
        // stored last-sandbox state.
        let result = resolve_sandbox_name(Some("explicit".to_string()), "any-gateway");
        assert_eq!(result.unwrap(), "explicit");
    }

    #[test]
    fn resolve_sandbox_name_falls_back_to_last_used() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            save_last_sandbox("test-gateway", "remembered-sb").unwrap();
            let result = resolve_sandbox_name(None, "test-gateway");
            assert_eq!(result.unwrap(), "remembered-sb");
        });
    }

    #[test]
    fn resolve_sandbox_name_errors_without_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            let err = resolve_sandbox_name(None, "unknown-gateway").unwrap_err();
            let msg = err.to_string();
            assert!(
                msg.contains("nav sandbox connect"),
                "expected helpful hint in error, got: {msg}"
            );
        });
    }

    #[test]
    fn resolve_gateway_uses_stored_name_for_matching_endpoint() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            store_gateway_metadata(
                "edge-gateway",
                &edge_metadata("edge-gateway", "https://gw.example.com"),
            )
            .unwrap();

            let ctx = resolve_gateway(&None, &Some("https://gw.example.com/".to_string())).unwrap();
            assert_eq!(ctx.name, "edge-gateway");
            assert_eq!(ctx.endpoint, "https://gw.example.com/");
        });
    }

    #[test]
    fn resolve_gateway_prefers_explicit_gateway_for_direct_endpoint() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            store_gateway_metadata(
                "named-gateway",
                &edge_metadata("named-gateway", "https://stored.example.com"),
            )
            .unwrap();

            let ctx = resolve_gateway(
                &Some("named-gateway".to_string()),
                &Some("https://override.example.com".to_string()),
            )
            .unwrap();

            assert_eq!(ctx.name, "named-gateway");
            assert_eq!(ctx.endpoint, "https://override.example.com");
        });
    }

    #[test]
    fn apply_edge_auth_uses_stored_token() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            store_gateway_metadata(
                "edge-gateway",
                &edge_metadata("edge-gateway", "https://gw.example.com"),
            )
            .unwrap();
            store_edge_token("edge-gateway", "token-123").unwrap();

            let mut tls = TlsOptions::default();
            apply_edge_auth(&mut tls, "edge-gateway");

            assert_eq!(tls.edge_token.as_deref(), Some("token-123"));
        });
    }

    /// Verify the flag names the TUI uses to build its ProxyCommand are
    /// accepted by the `SshProxy` subcommand and land in the right fields.
    /// This catches drift when CLI flags are renamed or restructured.
    #[test]
    fn ssh_proxy_token_mode_flags_match_tui_proxy_command() {
        // This is the exact flag pattern constructed by the TUI in lib.rs
        // (handle_shell_connect, handle_exec, handle_port_forward).
        let cli = Cli::try_parse_from([
            "openshell",
            "ssh-proxy",
            "--gateway",
            "https://gw.example.com:8080/proxy/connect",
            "--sandbox-id",
            "sbx-123",
            "--token",
            "tok-abc",
            "--gateway-name",
            "my-gateway",
        ])
        .expect("TUI proxy command flags must be accepted by the CLI");

        match cli.command {
            Some(Commands::SshProxy {
                gateway,
                sandbox_id,
                token,
                gateway_name,
                ..
            }) => {
                assert_eq!(
                    gateway.as_deref(),
                    Some("https://gw.example.com:8080/proxy/connect"),
                    "gateway URL must land in SshProxy.gateway, not the global flag"
                );
                assert_eq!(sandbox_id.as_deref(), Some("sbx-123"));
                assert_eq!(token.as_deref(), Some("tok-abc"));
                assert_eq!(gateway_name.as_deref(), Some("my-gateway"));
            }
            other => panic!("expected SshProxy, got: {other:?}"),
        }
    }

    #[test]
    fn settings_set_global_parses_yes_flag() {
        let cli = Cli::try_parse_from([
            "openshell",
            "settings",
            "set",
            "--global",
            "--key",
            "log_level",
            "--value",
            "warn",
            "--yes",
        ])
        .expect("settings set --global should parse");

        match cli.command {
            Some(Commands::Settings {
                command:
                    Some(SettingsCommands::Set {
                        global,
                        yes,
                        key,
                        value,
                        ..
                    }),
            }) => {
                assert!(global);
                assert!(yes);
                assert_eq!(key, "log_level");
                assert_eq!(value, "warn");
            }
            other => panic!("expected settings set command, got: {other:?}"),
        }
    }

    #[test]
    fn settings_get_global_parses() {
        let cli = Cli::try_parse_from(["openshell", "settings", "get", "--global"])
            .expect("settings get --global should parse");

        match cli.command {
            Some(Commands::Settings {
                command: Some(SettingsCommands::Get { name, global, .. }),
            }) => {
                assert!(global);
                assert!(name.is_none());
            }
            other => panic!("expected settings get command, got: {other:?}"),
        }
    }

    #[test]
    fn policy_delete_global_parses() {
        let cli = Cli::try_parse_from(["openshell", "policy", "delete", "--global", "--yes"])
            .expect("policy delete --global should parse");

        match cli.command {
            Some(Commands::Policy {
                command: Some(PolicyCommands::Delete { global, yes }),
            }) => {
                assert!(global);
                assert!(yes);
            }
            other => panic!("expected policy delete command, got: {other:?}"),
        }
    }

    #[test]
    fn settings_delete_global_parses_yes_flag() {
        let cli = Cli::try_parse_from([
            "openshell",
            "settings",
            "delete",
            "--global",
            "--key",
            "log_level",
            "--yes",
        ])
        .expect("settings delete --global should parse");

        match cli.command {
            Some(Commands::Settings {
                command:
                    Some(SettingsCommands::Delete {
                        key, global, yes, ..
                    }),
            }) => {
                assert_eq!(key, "log_level");
                assert!(global);
                assert!(yes);
            }
            other => panic!("expected settings delete command, got: {other:?}"),
        }
    }
}
