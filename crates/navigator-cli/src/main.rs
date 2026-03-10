// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! NemoClaw CLI - command-line interface for NemoClaw.

use clap::{CommandFactory, Parser, Subcommand, ValueEnum, ValueHint};
use clap_complete::engine::ArgValueCompleter;
use clap_complete::env::CompleteEnv;
use miette::Result;
use owo_colors::OwoColorize;
use std::io::Write;

use navigator_bootstrap::{
    edge_token::load_edge_token, get_cluster_metadata, list_clusters, load_active_cluster,
    load_cluster_metadata, load_last_sandbox, save_last_sandbox,
};
use navigator_cli::completers;
use navigator_cli::run;
use navigator_cli::tls::TlsOptions;

/// Resolved cluster context: name + gateway endpoint.
struct GatewayContext {
    /// The cluster name (used for TLS cert directory, metadata lookup, etc.).
    name: String,
    /// The gateway endpoint URL (e.g., `https://127.0.0.1` or `https://10.0.0.5`).
    endpoint: String,
}

/// Resolve the cluster name to a [`GatewayContext`] with the gateway endpoint.
///
/// Resolution priority:
/// 1. `--gateway-endpoint` flag (direct URL, preserving metadata when available)
/// 2. `--cluster` flag (explicit name)
/// 3. `NEMOCLAW_CLUSTER` environment variable
/// 4. Active cluster from `~/.config/nemoclaw/active_cluster`
///
/// When `--gateway-endpoint` is provided, it is used directly as the endpoint.
/// If stored metadata can still identify the gateway, the stored cluster name
/// is preserved so auth and TLS materials continue to resolve correctly.
fn normalize_gateway_endpoint(endpoint: &str) -> &str {
    endpoint.trim_end_matches('/')
}

fn find_gateway_by_endpoint(endpoint: &str) -> Option<String> {
    let endpoint = normalize_gateway_endpoint(endpoint);

    if let Some(active_name) = load_active_cluster()
        && let Ok(metadata) = load_cluster_metadata(&active_name)
        && normalize_gateway_endpoint(&metadata.gateway_endpoint) == endpoint
    {
        return Some(metadata.name);
    }

    list_clusters().ok()?.into_iter().find_map(|metadata| {
        (normalize_gateway_endpoint(&metadata.gateway_endpoint) == endpoint)
            .then_some(metadata.name)
    })
}

fn resolve_gateway(
    cluster_flag: &Option<String>,
    gateway_endpoint: &Option<String>,
) -> Result<GatewayContext> {
    if let Some(endpoint) = gateway_endpoint {
        let name = cluster_flag
            .clone()
            .filter(|name| get_cluster_metadata(name).is_some())
            .or_else(|| find_gateway_by_endpoint(endpoint))
            .unwrap_or_else(|| endpoint.clone());
        return Ok(GatewayContext {
            name,
            endpoint: endpoint.clone(),
        });
    }

    let name = cluster_flag
        .clone()
        .or_else(|| {
            std::env::var("NEMOCLAW_CLUSTER")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .or_else(load_active_cluster)
        .ok_or_else(|| {
            miette::miette!(
                "No active gateway.\n\
                 Set one with: nemoclaw gateway select <name>\n\
                 Or deploy a new gateway: nemoclaw gateway start"
            )
        })?;

    let metadata = load_cluster_metadata(&name).map_err(|_| {
        miette::miette!(
            "Unknown gateway '{name}'.\n\
             Deploy it first: nemoclaw gateway start --name {name}\n\
             Or list available gateways: nemoclaw gateway select"
        )
    })?;

    Ok(GatewayContext {
        name: metadata.name,
        endpoint: metadata.gateway_endpoint,
    })
}

/// Resolve only the cluster name (without requiring metadata to exist).
///
/// Used by gateway commands that operate on a cluster by name but may not need
/// the gateway endpoint (e.g., `gateway start` creates the cluster).
fn resolve_gateway_name(cluster_flag: &Option<String>) -> Option<String> {
    cluster_flag
        .clone()
        .or_else(|| {
            std::env::var("NEMOCLAW_CLUSTER")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .or_else(load_active_cluster)
}

/// Apply edge authentication token from local storage when the cluster uses edge auth.
///
/// When the resolved cluster has `auth_mode == "cloudflare_jwt"`, loads the
/// stored edge token from disk and sets it on the `TlsOptions`. The token is
/// always read from cluster metadata rather than supplied via a CLI flag.
fn apply_edge_auth(tls: &mut TlsOptions, cluster_name: &str) {
    if let Some(meta) = get_cluster_metadata(cluster_name) {
        if meta.auth_mode.as_deref() == Some("cloudflare_jwt") {
            if let Some(token) = load_edge_token(cluster_name) {
                tls.edge_token = Some(token);
            }
        }
    }
}

/// Resolve a sandbox name, falling back to the last-used sandbox for the cluster.
///
/// When `name` is `None`, looks up the last sandbox recorded for the active
/// cluster. Prints a hint when falling back so the user knows which sandbox
/// was chosen.
fn resolve_sandbox_name(name: Option<String>, cluster: &str) -> Result<String> {
    if let Some(n) = name {
        return Ok(n);
    }
    let last = load_last_sandbox(cluster).ok_or_else(|| {
        miette::miette!(
            "No sandbox name provided and no last-used sandbox.\n\
             Specify a sandbox name or connect to one first: nav sandbox connect <name>"
        )
    })?;
    eprintln!("{} Using sandbox '{}' (last used)", "→".bold(), last.bold(),);
    Ok(last)
}

// Custom help template organized like `gh` CLI
const HELP_TEMPLATE: &str = "\
{about-with-newline}
\x1b[1mUSAGE\x1b[0m
  nemoclaw <command> <subcommand> [flags]

\x1b[1mSANDBOX COMMANDS\x1b[0m
  sandbox:     Manage sandboxes
  forward:     Manage port forwarding to a sandbox
  logs:        View sandbox logs
  policy:      Manage sandbox policy
  provider:    Manage provider configuration

\x1b[1mGATEWAY COMMANDS\x1b[0m
  gateway:     Manage the gateway lifecycle
  status:      Show gateway status and information
  inference:   Manage inference configuration

\x1b[1mADDITIONAL COMMANDS\x1b[0m
  term:        Launch the NemoClaw interactive TUI
  completions: Generate shell completions
  ssh-proxy:   SSH proxy (used by ProxyCommand)
  help:        Print this message or the help of the given subcommand(s)

\x1b[1mFLAGS\x1b[0m
{options}

\x1b[1mEXAMPLES\x1b[0m
  $ nemoclaw sandbox create
  $ nemoclaw gateway start
  $ nemoclaw logs my-sandbox

\x1b[1mLEARN MORE\x1b[0m
  Use `nemoclaw <command> --help` for more information about a command.
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

const SANDBOX_EXAMPLES: &str = "\x1b[1mALIAS\x1b[0m
  sb

\x1b[1mEXAMPLES\x1b[0m
  $ nemoclaw sandbox create
  $ nemoclaw sandbox create --from python
  $ nemoclaw sandbox connect my-sandbox
  $ nemoclaw sandbox list
  $ nemoclaw sandbox delete my-sandbox
";

const FORWARD_EXAMPLES: &str = "\x1b[1mALIAS\x1b[0m
  fwd

\x1b[1mEXAMPLES\x1b[0m
  $ nemoclaw forward start 8080
  $ nemoclaw forward start 3000 my-sandbox
  $ nemoclaw forward stop 8080
  $ nemoclaw forward list
";

const LOGS_EXAMPLES: &str = "\x1b[1mALIAS\x1b[0m
  lg

\x1b[1mEXAMPLES\x1b[0m
  $ nemoclaw logs my-sandbox
  $ nemoclaw logs my-sandbox --tail
  $ nemoclaw logs --since 5m
  $ nemoclaw logs --source sandbox --level debug
";

const POLICY_EXAMPLES: &str = "\x1b[1mALIAS\x1b[0m
  pol

\x1b[1mEXAMPLES\x1b[0m
  $ nemoclaw policy get my-sandbox
  $ nemoclaw policy set my-sandbox --policy policy.yaml
  $ nemoclaw policy list my-sandbox
";

const PROVIDER_EXAMPLES: &str = "\x1b[1mEXAMPLES\x1b[0m
  $ nemoclaw provider create --name openai --type openai --credential OPENAI_API_KEY
  $ nemoclaw provider create --name anthropic --type anthropic --from-existing
  $ nemoclaw provider list
  $ nemoclaw provider get openai
  $ nemoclaw provider delete openai
";

const GATEWAY_EXAMPLES: &str = "\x1b[1mALIAS\x1b[0m
  gw

\x1b[1mEXAMPLES\x1b[0m
  $ nemoclaw gateway start
  $ nemoclaw gateway start --name my-gateway --port 9090
  $ nemoclaw gateway stop
  $ nemoclaw gateway select my-gateway
  $ nemoclaw gateway info
";

const INFERENCE_EXAMPLES: &str = "\x1b[1mEXAMPLES\x1b[0m
  $ nemoclaw inference set --provider openai --model gpt-4
  $ nemoclaw inference get
  $ nemoclaw inference update --model gpt-4-turbo
";

/// NemoClaw CLI - agent execution and management.
#[derive(Parser, Debug)]
#[command(name = "nemoclaw")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
#[command(help_template = HELP_TEMPLATE)]
#[command(disable_help_subcommand = true)]
struct Cli {
    /// Increase verbosity (-v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Cluster name to operate on (resolved from stored metadata).
    #[arg(long, short, global = true, env = "NEMOCLAW_CLUSTER")]
    cluster: Option<String>,

    /// Gateway endpoint URL (e.g. https://gateway.example.com).
    /// Connects directly without looking up cluster metadata.
    #[arg(long, global = true, env = "NEMOCLAW_GATEWAY_ENDPOINT")]
    gateway_endpoint: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    // ===================================================================
    // SANDBOX COMMANDS
    // ===================================================================
    /// Manage sandboxes.
    #[command(visible_alias = "sb", hide = true, after_help = SANDBOX_EXAMPLES, help_template = SUBCOMMAND_HELP_TEMPLATE)]
    Sandbox {
        #[command(subcommand)]
        command: Option<SandboxCommands>,
    },

    /// Manage port forwarding to a sandbox.
    #[command(visible_alias = "fwd", hide = true, after_help = FORWARD_EXAMPLES, help_template = SUBCOMMAND_HELP_TEMPLATE)]
    Forward {
        #[command(subcommand)]
        command: Option<ForwardCommands>,
    },

    /// View sandbox logs.
    #[command(visible_alias = "lg", hide = true, after_help = LOGS_EXAMPLES)]
    Logs {
        /// Sandbox name (defaults to last-used sandbox).
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
    #[command(visible_alias = "pol", hide = true, after_help = POLICY_EXAMPLES, help_template = SUBCOMMAND_HELP_TEMPLATE)]
    Policy {
        #[command(subcommand)]
        command: Option<PolicyCommands>,
    },

    /// Manage provider configuration.
    #[command(hide = true, after_help = PROVIDER_EXAMPLES, help_template = SUBCOMMAND_HELP_TEMPLATE)]
    Provider {
        #[command(subcommand)]
        command: Option<ProviderCommands>,
    },

    // ===================================================================
    // GATEWAY COMMANDS
    // ===================================================================
    /// Manage the gateway lifecycle.
    #[command(visible_alias = "gw", hide = true, after_help = GATEWAY_EXAMPLES, help_template = SUBCOMMAND_HELP_TEMPLATE)]
    Gateway {
        #[command(subcommand)]
        command: Option<GatewayCommands>,
    },

    /// Show gateway status and information.
    #[command(hide = true)]
    Status,

    /// Manage inference configuration.
    #[command(hide = true, after_help = INFERENCE_EXAMPLES, help_template = SUBCOMMAND_HELP_TEMPLATE)]
    Inference {
        #[command(subcommand)]
        command: Option<ClusterInferenceCommands>,
    },

    // ===================================================================
    // ADDITIONAL COMMANDS
    // ===================================================================
    /// Launch the `NemoClaw` interactive TUI.
    #[command(hide = true)]
    Term,

    /// Generate shell completions.
    #[command(hide = true, after_long_help = COMPLETIONS_HELP)]
    Completions {
        /// Shell to generate completions for.
        shell: CompletionShell,
    },

    /// SSH proxy (used by `ProxyCommand`).
    ///
    /// Two mutually exclusive modes:
    ///
    /// **Token mode** (used internally by `sandbox connect`):
    ///   `nemoclaw ssh-proxy --gateway <url> --sandbox-id <id> --token <token>`
    ///
    /// **Name mode** (for use in `~/.ssh/config`):
    ///   `nemoclaw ssh-proxy --cluster <name> --name <sandbox-name>`
    #[command(hide = true)]
    SshProxy {
        /// Gateway URL (e.g., <https://gw.example.com:443/proxy/connect>).
        /// Required in token mode.
        #[arg(long)]
        gateway: Option<String>,

        /// Sandbox id. Required in token mode.
        #[arg(long)]
        sandbox_id: Option<String>,

        /// SSH session token. Required in token mode.
        #[arg(long)]
        token: Option<String>,

        /// Cluster endpoint URL. Used in name mode. Deprecated: prefer --cluster.
        #[arg(long)]
        server: Option<String>,

        /// Cluster name (resolves endpoint from stored metadata). Used in name mode.
        #[arg(long, short)]
        cluster: Option<String>,

        /// Sandbox name. Used in name mode.
        #[arg(long)]
        name: Option<String>,
    },

    /// Manage cluster (deprecated: use `gateway`).
    #[command(hide = true)]
    Cluster {
        #[command(subcommand)]
        command: ClusterCommands,
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
Generate shell completion scripts for NemoClaw CLI.

Supported shells: bash, fish, zsh, powershell.

The script is output on stdout, allowing you to redirect the output to the file of your choosing.

The exact config file locations might vary based on your system. Make sure to restart your
shell before testing whether completions are working.

## bash

First, ensure that you install `bash-completion` using your package manager.

  mkdir -p ~/.local/share/bash-completion/completions
  nemoclaw completions bash > ~/.local/share/bash-completion/completions/nemoclaw

On macOS with Homebrew (install bash-completion first):

  mkdir -p $(brew --prefix)/etc/bash_completion.d
  nemoclaw completions bash > $(brew --prefix)/etc/bash_completion.d/nemoclaw.bash-completion

## fish

  mkdir -p ~/.config/fish/completions
  nemoclaw completions fish > ~/.config/fish/completions/nemoclaw.fish

## zsh

  mkdir -p ~/.zfunc
  nemoclaw completions zsh > ~/.zfunc/_nemoclaw

Then add the following to your .zshrc before compinit:

  fpath+=~/.zfunc

## powershell

   nemoclaw completions powershell >> $PROFILE

If no profile exists yet, create one first:

   New-Item -Path $PROFILE -Type File -Force
";

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
    #[command(group = clap::ArgGroup::new("cred_source").required(true).args(["from_existing", "credentials"]))]
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
    Get {
        /// Provider name.
        #[arg(add = ArgValueCompleter::new(completers::complete_provider_names))]
        name: String,
    },

    /// List providers.
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
    Start {
        /// Gateway name.
        #[arg(long, default_value = "nemoclaw", env = "NEMOCLAW_CLUSTER")]
        name: String,

        /// Write stored kubeconfig into local kubeconfig.
        #[arg(long)]
        update_kube_config: bool,

        /// Print stored kubeconfig to stdout.
        #[arg(long)]
        get_kubeconfig: bool,

        /// SSH destination for remote deployment (e.g., user@hostname).
        #[arg(long)]
        remote: Option<String>,

        /// Path to SSH private key for remote deployment.
        #[arg(long, value_hint = ValueHint::FilePath)]
        ssh_key: Option<String>,

        /// Host port to map to the gateway (default: 8080).
        #[arg(long, default_value_t = navigator_bootstrap::DEFAULT_GATEWAY_PORT)]
        port: u16,

        /// Override the gateway host written into cluster metadata.
        ///
        /// By default, local clusters advertise 127.0.0.1. In environments
        /// where the test runner cannot reach 127.0.0.1 on the Docker host
        /// (e.g., CI containers), set this to a reachable hostname such as
        /// `host.docker.internal`.
        #[arg(long)]
        gateway_host: Option<String>,

        /// Expose the Kubernetes control plane on a host port for kubectl access.
        /// Pass without a value to auto-select a free port, or pass a specific
        /// port number. When omitted entirely, the control plane is not exposed,
        /// allowing multiple clusters to coexist without port conflicts.
        #[arg(long, num_args = 0..=1, default_missing_value = "0")]
        kube_port: Option<u16>,

        /// Destroy and recreate the gateway from scratch if one already exists.
        ///
        /// Without this flag, an interactive prompt asks what to do; in
        /// non-interactive mode the existing gateway is reused silently.
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

        /// Authentication token for pulling container images from ghcr.io.
        ///
        /// A GitHub personal access token (PAT) with `read:packages` scope.
        /// Used to pull the cluster bootstrap image and passed into the k3s
        /// cluster so it can pull server, sandbox, and community images at
        /// runtime.
        #[arg(long, env = "NEMOCLAW_REGISTRY_TOKEN")]
        registry_token: Option<String>,
    },

    /// Stop the gateway (preserves state).
    Stop {
        /// Gateway name (defaults to active gateway).
        #[arg(long, env = "NEMOCLAW_CLUSTER")]
        name: Option<String>,

        /// Override SSH destination (auto-resolved from cluster metadata).
        #[arg(long)]
        remote: Option<String>,

        /// Path to SSH private key for remote cluster.
        #[arg(long, value_hint = ValueHint::FilePath)]
        ssh_key: Option<String>,
    },

    /// Destroy the gateway and its state.
    Destroy {
        /// Gateway name (defaults to active gateway).
        #[arg(long, env = "NEMOCLAW_CLUSTER")]
        name: Option<String>,

        /// Override SSH destination (auto-resolved from cluster metadata).
        #[arg(long)]
        remote: Option<String>,

        /// Path to SSH private key for remote cluster.
        #[arg(long, value_hint = ValueHint::FilePath)]
        ssh_key: Option<String>,
    },

    /// Add an edge-authenticated gateway.
    ///
    /// Registers an external gateway endpoint that is fronted by an
    /// edge proxy (e.g., Cloudflare Access). Opens a browser for
    /// authentication and stores the token locally. After adding, the
    /// gateway appears in `nemoclaw gateway select`.
    Add {
        /// Gateway endpoint URL (e.g., `https://8080-3vdegyusg.brevlab.com`).
        endpoint: String,

        /// Gateway name (auto-derived from the endpoint hostname when omitted).
        #[arg(long)]
        name: Option<String>,

        /// Skip browser authentication (authenticate later with `gateway login`).
        #[arg(long)]
        no_auth: bool,
    },

    /// Authenticate with an edge-authenticated gateway.
    ///
    /// Opens a browser for the edge proxy's login flow and stores the
    /// token locally. Use this to re-authenticate when a token expires
    /// or to authenticate a gateway added with `--no-auth`.
    Login {
        /// Gateway name (defaults to the active gateway).
        #[arg(add = ArgValueCompleter::new(completers::complete_cluster_names))]
        name: Option<String>,
    },

    /// Select the active gateway.
    ///
    /// When called without a name, lists available gateways to choose from.
    Select {
        /// Gateway name (omit to list available gateways).
        #[arg(add = ArgValueCompleter::new(completers::complete_cluster_names))]
        name: Option<String>,
    },

    /// Show gateway deployment details.
    Info {
        /// Gateway name (defaults to active gateway).
        #[arg(long, env = "NEMOCLAW_CLUSTER")]
        name: Option<String>,
    },

    /// Print or start an SSH tunnel for kubectl access to a remote gateway.
    Tunnel {
        /// Gateway name (defaults to active gateway).
        #[arg(long, env = "NEMOCLAW_CLUSTER")]
        name: Option<String>,

        /// Override SSH destination (auto-resolved from cluster metadata).
        #[arg(long)]
        remote: Option<String>,

        /// Path to SSH private key.
        #[arg(long, value_hint = ValueHint::FilePath)]
        ssh_key: Option<String>,

        /// Only print the SSH command instead of running it.
        #[arg(long)]
        print_command: bool,
    },
}

// -----------------------------------------------------------------------
// Hidden backwards-compat: `cluster admin deploy` → `gateway start`
// -----------------------------------------------------------------------

#[derive(Subcommand, Debug)]
enum ClusterCommands {
    /// Deprecated: use `gateway start`.
    #[command(hide = true)]
    Admin {
        #[command(subcommand)]
        command: ClusterAdminCommands,
    },

    /// Manage cluster-level inference configuration.
    #[command(hide = true)]
    Inference {
        #[command(subcommand)]
        command: ClusterInferenceCommands,
    },
}

#[derive(Subcommand, Debug)]
enum ClusterInferenceCommands {
    /// Set cluster-level inference provider and model.
    Set {
        /// Provider name.
        #[arg(long, add = ArgValueCompleter::new(completers::complete_provider_names))]
        provider: String,

        /// Model identifier to force for generation calls.
        #[arg(long)]
        model: String,
    },

    /// Update cluster-level inference configuration (partial update).
    Update {
        /// Provider name (unchanged if omitted).
        #[arg(long, add = ArgValueCompleter::new(completers::complete_provider_names))]
        provider: Option<String>,

        /// Model identifier (unchanged if omitted).
        #[arg(long)]
        model: Option<String>,
    },

    /// Get cluster-level inference provider and model.
    Get,
}

#[derive(Subcommand, Debug)]
enum ClusterAdminCommands {
    /// Deprecated: use `gateway start`.
    Deploy {
        /// Cluster name.
        #[arg(long, default_value = "nemoclaw", env = "NEMOCLAW_CLUSTER")]
        name: String,

        /// Write stored kubeconfig into local kubeconfig.
        #[arg(long)]
        update_kube_config: bool,

        /// Print stored kubeconfig to stdout.
        #[arg(long)]
        get_kubeconfig: bool,

        /// SSH destination for remote deployment (e.g., user@hostname).
        #[arg(long)]
        remote: Option<String>,

        /// Path to SSH private key for remote deployment.
        #[arg(long, value_hint = ValueHint::FilePath)]
        ssh_key: Option<String>,

        /// Host port to map to the gateway (default: 8080).
        #[arg(long, default_value_t = navigator_bootstrap::DEFAULT_GATEWAY_PORT)]
        port: u16,

        /// Override the gateway host written into cluster metadata.
        #[arg(long)]
        gateway_host: Option<String>,

        /// Expose the Kubernetes control plane on a host port for kubectl access.
        #[arg(long, num_args = 0..=1, default_missing_value = "0")]
        kube_port: Option<u16>,

        /// Destroy and recreate from scratch if a cluster already exists.
        #[arg(long)]
        recreate: bool,

        /// Authentication token for pulling container images from ghcr.io.
        #[arg(long, env = "NEMOCLAW_REGISTRY_TOKEN")]
        registry_token: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum SandboxCommands {
    /// Create a sandbox.
    Create {
        /// Optional sandbox name (auto-generated when omitted).
        #[arg(long)]
        name: Option<String>,

        /// Sandbox source: a community sandbox name (e.g., `openclaw`), a path
        /// to a Dockerfile or directory containing one, or a full container
        /// image reference (e.g., `myregistry.com/img:tag`).
        ///
        /// Community names are resolved to
        /// `ghcr.io/nvidia/nemoclaw-community/sandboxes/<name>:latest`
        /// (override the prefix with `NEMOCLAW_COMMUNITY_REGISTRY`).
        ///
        /// When given a Dockerfile or directory, the image is built and pushed
        /// into the cluster automatically before creating the sandbox.
        #[arg(long)]
        from: Option<String>,

        /// Upload local files into the sandbox before running.
        ///
        /// Format: `<LOCAL_PATH>[:<SANDBOX_PATH>]`.
        /// When `SANDBOX_PATH` is omitted, files are uploaded to the container
        /// working directory (`/sandbox`).
        /// `.gitignore` rules are applied by default; use `--no-git-ignore` to
        /// upload everything.
        #[arg(long, value_hint = ValueHint::AnyPath)]
        upload: Option<String>,

        /// Disable `.gitignore` filtering for `--upload`.
        #[arg(long, requires = "upload")]
        no_git_ignore: bool,

        /// Keep the sandbox alive after non-interactive commands.
        #[arg(long)]
        keep: bool,

        /// SSH destination for remote bootstrap (e.g., user@hostname).
        /// Only used when no cluster exists yet; ignored if a cluster is
        /// already active.
        #[arg(long)]
        remote: Option<String>,

        /// Path to SSH private key for remote bootstrap.
        #[arg(long, value_hint = ValueHint::FilePath)]
        ssh_key: Option<String>,

        /// Provider names to attach to this sandbox.
        #[arg(long = "provider")]
        providers: Vec<String>,

        /// Path to a custom sandbox policy YAML file.
        /// Overrides the built-in default and the `NEMOCLAW_SANDBOX_POLICY` env var.
        #[arg(long, value_hint = ValueHint::FilePath)]
        policy: Option<String>,

        /// Forward a local port to the sandbox after the command finishes.
        /// Implies --keep for non-interactive commands.
        #[arg(long)]
        forward: Option<u16>,

        /// Allocate a pseudo-terminal for the remote command.
        /// Defaults to auto-detection (on when stdin and stdout are terminals).
        /// Use --tty to force a PTY even when auto-detection fails, or
        /// --no-tty to disable.
        #[arg(long, overrides_with = "no_tty")]
        tty: bool,

        /// Disable pseudo-terminal allocation.
        #[arg(long, overrides_with = "tty")]
        no_tty: bool,

        /// Auto-bootstrap a gateway if none is available.
        ///
        /// Without this flag, an interactive prompt asks whether to bootstrap;
        /// in non-interactive mode the command errors.
        #[arg(long, overrides_with = "no_bootstrap")]
        bootstrap: bool,

        /// Never bootstrap a gateway automatically; error if none is available.
        #[arg(long, overrides_with = "bootstrap")]
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
    Get {
        /// Sandbox name (defaults to last-used sandbox).
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,
    },

    /// List sandboxes.
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
    Delete {
        /// Sandbox names.
        #[arg(required = true, num_args = 1.., value_name = "NAME", add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        names: Vec<String>,
    },

    /// Connect to a sandbox.
    ///
    /// When no name is given, reconnects to the last-used sandbox.
    Connect {
        /// Sandbox name (defaults to last-used sandbox).
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,
    },

    /// Upload local files to a sandbox.
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
    Download {
        /// Sandbox name.
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: String,

        /// Sandbox path to download.
        sandbox_path: String,

        /// Local destination (defaults to `.`).
        dest: Option<String>,
    },

    /// Print an SSH config entry for a sandbox.
    ///
    /// Outputs a Host block suitable for appending to ~/.ssh/config,
    /// enabling tools like `VSCode` Remote-SSH to connect to the sandbox.
    SshConfig {
        /// Sandbox name (defaults to last-used sandbox).
        name: Option<String>,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCommands {
    /// Update policy on a live sandbox.
    Set {
        /// Sandbox name (defaults to last-used sandbox).
        name: Option<String>,

        /// Path to the policy YAML file.
        #[arg(long, value_hint = ValueHint::FilePath)]
        policy: String,

        /// Wait for the sandbox to load the policy.
        #[arg(long)]
        wait: bool,

        /// Timeout for --wait in seconds.
        #[arg(long, default_value_t = 60)]
        timeout: u64,
    },

    /// Show current active policy for a sandbox.
    Get {
        /// Sandbox name (defaults to last-used sandbox).
        name: Option<String>,

        /// Show a specific policy revision (default: latest).
        #[arg(long = "rev", default_value_t = 0)]
        rev: u32,

        /// Print the full policy as YAML.
        #[arg(long)]
        full: bool,
    },

    /// List policy history for a sandbox.
    List {
        /// Sandbox name (defaults to last-used sandbox).
        name: Option<String>,

        /// Maximum number of revisions to return.
        #[arg(long, default_value_t = 20)]
        limit: u32,
    },
}

#[derive(Subcommand, Debug)]
enum ForwardCommands {
    /// Start forwarding a local port to a sandbox.
    Start {
        /// Port to forward (used as both local and remote port).
        port: u16,

        /// Sandbox name (defaults to last-used sandbox).
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,

        /// Run the forward in the background and exit immediately.
        #[arg(short = 'd', long)]
        background: bool,
    },

    /// Stop a background port forward.
    Stop {
        /// Port that was forwarded.
        port: u16,

        /// Sandbox name (defaults to last-used sandbox).
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: Option<String>,
    },

    /// List active port forwards.
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
                update_kube_config,
                get_kubeconfig,
                remote,
                ssh_key,
                port,
                gateway_host,
                kube_port,
                recreate,
                plaintext,
                disable_gateway_auth,
                registry_token,
            } => {
                run::cluster_admin_deploy(
                    &name,
                    update_kube_config,
                    get_kubeconfig,
                    remote.as_deref(),
                    ssh_key.as_deref(),
                    port,
                    gateway_host.as_deref(),
                    kube_port,
                    recreate,
                    plaintext,
                    disable_gateway_auth,
                    registry_token.as_deref(),
                )
                .await?;
            }
            GatewayCommands::Stop {
                name,
                remote,
                ssh_key,
            } => {
                let name = name
                    .or_else(|| resolve_gateway_name(&cli.cluster))
                    .unwrap_or_else(|| "nemoclaw".to_string());
                run::cluster_admin_stop(&name, remote.as_deref(), ssh_key.as_deref()).await?;
            }
            GatewayCommands::Destroy {
                name,
                remote,
                ssh_key,
            } => {
                let name = name
                    .or_else(|| resolve_gateway_name(&cli.cluster))
                    .unwrap_or_else(|| "nemoclaw".to_string());
                run::cluster_admin_destroy(&name, remote.as_deref(), ssh_key.as_deref()).await?;
            }
            GatewayCommands::Add {
                endpoint,
                name,
                no_auth,
            } => {
                run::gateway_add(&endpoint, name.as_deref(), no_auth).await?;
            }
            GatewayCommands::Login { name } => {
                let name = name
                    .or_else(|| resolve_gateway_name(&cli.cluster))
                    .ok_or_else(|| {
                        miette::miette!(
                            "No active gateway.\n\
                             Specify a gateway name: nemoclaw gateway login <name>\n\
                             Or set one with: nemoclaw gateway select <name>"
                        )
                    })?;
                run::gateway_login(&name).await?;
            }
            GatewayCommands::Select { name } => {
                if let Some(name) = name {
                    run::cluster_use(&name)?;
                } else {
                    // No name provided — show available gateways.
                    run::cluster_list(&cli.cluster)?;
                    eprintln!();
                    eprintln!(
                        "Select a gateway with: {}",
                        "nemoclaw gateway select <name>".dimmed()
                    );
                }
            }
            GatewayCommands::Info { name } => {
                let name = name
                    .or_else(|| resolve_gateway_name(&cli.cluster))
                    .unwrap_or_else(|| "nemoclaw".to_string());
                run::cluster_admin_info(&name)?;
            }
            GatewayCommands::Tunnel {
                name,
                remote,
                ssh_key,
                print_command,
            } => {
                let name = name
                    .or_else(|| resolve_gateway_name(&cli.cluster))
                    .unwrap_or_else(|| "nemoclaw".to_string());
                run::cluster_admin_tunnel(
                    &name,
                    remote.as_deref(),
                    ssh_key.as_deref(),
                    print_command,
                )?;
            }
        },

        // -----------------------------------------------------------
        // Top-level status (was `cluster status`)
        // -----------------------------------------------------------
        Some(Commands::Status) => {
            if let Ok(ctx) = resolve_gateway(&cli.cluster, &cli.gateway_endpoint) {
                let mut tls = tls.with_cluster_name(&ctx.name);
                apply_edge_auth(&mut tls, &ctx.name);
                run::cluster_status(&ctx.name, &ctx.endpoint, &tls).await?;
            } else {
                println!("{}", "Gateway Status".cyan().bold());
                println!();
                println!("  {} No gateway configured.", "Status:".dimmed(),);
                println!();
                println!(
                    "Deploy a gateway with: {}",
                    "nemoclaw gateway start".dimmed()
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
                let cluster_name = resolve_gateway_name(&cli.cluster).unwrap_or_default();
                let name = resolve_sandbox_name(name, &cluster_name)?;
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
                    println!(
                        "{:<width$} {:<8} {:<10} STATUS",
                        "SANDBOX",
                        "PORT",
                        "PID",
                        width = name_width,
                    );
                    for f in &forwards {
                        let status = if f.alive {
                            "running".green().to_string()
                        } else {
                            "dead".red().to_string()
                        };
                        println!(
                            "{:<width$} {:<8} {:<10} {}",
                            f.sandbox,
                            f.port,
                            f.pid,
                            status,
                            width = name_width,
                        );
                    }
                }
            }
            ForwardCommands::Start {
                port,
                name,
                background,
            } => {
                let ctx = resolve_gateway(&cli.cluster, &cli.gateway_endpoint)?;
                let mut tls = tls.with_cluster_name(&ctx.name);
                apply_edge_auth(&mut tls, &ctx.name);
                let name = resolve_sandbox_name(name, &ctx.name)?;
                run::sandbox_forward(&ctx.endpoint, &name, port, background, &tls).await?;
                if background {
                    eprintln!(
                        "{} Forwarding port {port} to sandbox {name} in the background",
                        "✓".green().bold(),
                    );
                    eprintln!("  Access at: http://127.0.0.1:{port}/");
                    eprintln!("  Stop with: nemoclaw forward stop {port} {name}");
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
            let ctx = resolve_gateway(&cli.cluster, &cli.gateway_endpoint)?;
            let mut tls = tls.with_cluster_name(&ctx.name);
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
            let ctx = resolve_gateway(&cli.cluster, &cli.gateway_endpoint)?;
            let mut tls = tls.with_cluster_name(&ctx.name);
            apply_edge_auth(&mut tls, &ctx.name);
            match policy_cmd {
                PolicyCommands::Set {
                    name,
                    policy,
                    wait,
                    timeout,
                } => {
                    let name = resolve_sandbox_name(name, &ctx.name)?;
                    run::sandbox_policy_set(&ctx.endpoint, &name, &policy, wait, timeout, &tls)
                        .await?;
                }
                PolicyCommands::Get { name, rev, full } => {
                    let name = resolve_sandbox_name(name, &ctx.name)?;
                    run::sandbox_policy_get(&ctx.endpoint, &name, rev, full, &tls).await?;
                }
                PolicyCommands::List { name, limit } => {
                    let name = resolve_sandbox_name(name, &ctx.name)?;
                    run::sandbox_policy_list(&ctx.endpoint, &name, limit, &tls).await?;
                }
            }
        }

        // -----------------------------------------------------------
        // Inference commands
        // -----------------------------------------------------------
        Some(Commands::Inference {
            command: Some(command),
        }) => {
            let ctx = resolve_gateway(&cli.cluster, &cli.gateway_endpoint)?;
            let endpoint = &ctx.endpoint;
            let mut tls = tls.with_cluster_name(&ctx.name);
            apply_edge_auth(&mut tls, &ctx.name);
            match command {
                ClusterInferenceCommands::Set { provider, model } => {
                    run::cluster_inference_set(endpoint, &provider, &model, &tls).await?;
                }
                ClusterInferenceCommands::Update { provider, model } => {
                    run::cluster_inference_update(
                        endpoint,
                        provider.as_deref(),
                        model.as_deref(),
                        &tls,
                    )
                    .await?;
                }
                ClusterInferenceCommands::Get => {
                    run::cluster_inference_get(endpoint, &tls).await?;
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
                    let bootstrap_override = if no_bootstrap {
                        Some(false)
                    } else if bootstrap {
                        Some(true)
                    } else {
                        None // prompt or auto-detect
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

                    // For `sandbox create`, a missing cluster is not fatal — the
                    // bootstrap flow inside `sandbox_create` can deploy one.
                    match resolve_gateway(&cli.cluster, &cli.gateway_endpoint) {
                        Ok(ctx) => {
                            if remote.is_some() {
                                eprintln!(
                                    "{} --remote ignored: gateway '{}' is already active. \
                                     To redeploy, use: nemoclaw gateway start",
                                    "!".yellow(),
                                    ctx.name,
                                );
                                return Ok(());
                            }
                            let endpoint = &ctx.endpoint;
                            let mut tls = tls.with_cluster_name(&ctx.name);
                            apply_edge_auth(&mut tls, &ctx.name);
                            Box::pin(run::sandbox_create(
                                endpoint,
                                name.as_deref(),
                                from.as_deref(),
                                &ctx.name,
                                upload_spec.as_ref(),
                                keep,
                                remote.as_deref(),
                                ssh_key.as_deref(),
                                &providers,
                                policy.as_deref(),
                                forward,
                                &command,
                                tty_override,
                                bootstrap_override,
                                auto_providers_override,
                                &tls,
                            ))
                            .await?;
                        }
                        Err(_) => {
                            // No cluster configured — go straight to bootstrap.
                            Box::pin(run::sandbox_create_with_bootstrap(
                                name.as_deref(),
                                from.as_deref(),
                                upload_spec.as_ref(),
                                keep,
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
                    let ctx = resolve_gateway(&cli.cluster, &cli.gateway_endpoint)?;
                    let mut tls = tls.with_cluster_name(&ctx.name);
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
                    let ctx = resolve_gateway(&cli.cluster, &cli.gateway_endpoint)?;
                    let mut tls = tls.with_cluster_name(&ctx.name);
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
                    let ctx = resolve_gateway(&cli.cluster, &cli.gateway_endpoint)?;
                    let endpoint = &ctx.endpoint;
                    let mut tls = tls.with_cluster_name(&ctx.name);
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
                        SandboxCommands::Delete { names } => {
                            run::sandbox_delete(endpoint, &names, &tls).await?;
                        }
                        SandboxCommands::Connect { name } => {
                            let name = resolve_sandbox_name(name, &ctx.name)?;
                            let _ = save_last_sandbox(&ctx.name, &name);
                            run::sandbox_connect(endpoint, &name, &tls).await?;
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
            let ctx = resolve_gateway(&cli.cluster, &cli.gateway_endpoint)?;
            let endpoint = &ctx.endpoint;
            let mut tls = tls.with_cluster_name(&ctx.name);
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
        Some(Commands::Term) => {
            let ctx = resolve_gateway(&cli.cluster, &cli.gateway_endpoint)?;
            let mut tls = tls.with_cluster_name(&ctx.name);
            apply_edge_auth(&mut tls, &ctx.name);
            let channel = navigator_cli::tls::build_channel(&ctx.endpoint, &tls).await?;
            navigator_tui::run(channel, &ctx.name, &ctx.endpoint).await?;
        }
        Some(Commands::Completions { shell }) => {
            let exe = std::env::current_exe()
                .map_err(|e| miette::miette!("failed to find current executable: {e}"))?;
            let output = std::process::Command::new(exe)
                .env("COMPLETE", shell.to_string())
                .output()
                .map_err(|e| miette::miette!("failed to generate completions: {e}"))?;
            std::io::stdout()
                .write_all(&output.stdout)
                .map_err(|e| miette::miette!("failed to write completions: {e}"))?;
        }
        Some(Commands::SshProxy {
            gateway,
            sandbox_id,
            token,
            server,
            cluster,
            name,
        }) => {
            match (gateway, sandbox_id, token, server, cluster, name) {
                // Token mode (existing behavior): pre-created session credentials.
                (Some(gw), Some(sid), Some(tok), _, cluster_opt, _) => {
                    let mut effective_tls = match cluster_opt {
                        Some(ref c) => tls.with_cluster_name(c),
                        None => tls,
                    };
                    if let Some(ref c) = cluster_opt {
                        apply_edge_auth(&mut effective_tls, c);
                    }
                    run::sandbox_ssh_proxy(&gw, &sid, &tok, &effective_tls).await?;
                }
                // Name mode with --cluster: resolve endpoint from metadata.
                (_, _, _, server_override, Some(c), Some(n)) => {
                    let endpoint = if let Some(srv) = server_override {
                        srv
                    } else {
                        let meta = load_cluster_metadata(&c).map_err(|_| {
                            miette::miette!(
                                "Unknown gateway '{c}'.\n\
                                  Deploy it first: nemoclaw gateway start --name {c}\n\
                                  Or list available gateways: nemoclaw gateway select"
                            )
                        })?;
                        meta.gateway_endpoint
                    };
                    let mut tls = tls.with_cluster_name(&c);
                    apply_edge_auth(&mut tls, &c);
                    run::sandbox_ssh_proxy_by_name(&endpoint, &n, &tls).await?;
                }
                // Legacy name mode with --server only (no --cluster).
                (_, _, _, Some(srv), None, Some(n)) => {
                    run::sandbox_ssh_proxy_by_name(&srv, &n, &tls).await?;
                }
                _ => {
                    return Err(miette::miette!(
                        "provide either --gateway/--sandbox-id/--token or --cluster/--name (or --server/--name)"
                    ));
                }
            }
        }

        // -----------------------------------------------------------
        // Hidden backwards-compat: `cluster admin deploy`
        // -----------------------------------------------------------
        Some(Commands::Cluster { command }) => match command {
            ClusterCommands::Admin { command } => match command {
                ClusterAdminCommands::Deploy {
                    name,
                    update_kube_config,
                    get_kubeconfig,
                    remote,
                    ssh_key,
                    port,
                    gateway_host,
                    kube_port,
                    recreate,
                    registry_token,
                } => {
                    eprintln!(
                        "{} `nemoclaw cluster admin deploy` is deprecated. \
                         Use `nemoclaw gateway start` instead.",
                        "warning:".yellow().bold(),
                    );
                    run::cluster_admin_deploy(
                        &name,
                        update_kube_config,
                        get_kubeconfig,
                        remote.as_deref(),
                        ssh_key.as_deref(),
                        port,
                        gateway_host.as_deref(),
                        kube_port,
                        recreate,
                        false, // disable_tls
                        false, // disable_gateway_auth
                        registry_token.as_deref(),
                    )
                    .await?;
                }
            },
            ClusterCommands::Inference { command } => {
                let ctx = resolve_gateway(&cli.cluster, &cli.gateway_endpoint)?;
                let endpoint = &ctx.endpoint;
                let mut tls = tls.with_cluster_name(&ctx.name);
                apply_edge_auth(&mut tls, &ctx.name);
                match command {
                    ClusterInferenceCommands::Set { provider, model } => {
                        run::cluster_inference_set(endpoint, &provider, &model, &tls).await?;
                    }
                    ClusterInferenceCommands::Update { provider, model } => {
                        run::cluster_inference_update(
                            endpoint,
                            provider.as_deref(),
                            model.as_deref(),
                            &tls,
                        )
                        .await?;
                    }
                    ClusterInferenceCommands::Get => {
                        run::cluster_inference_get(endpoint, &tls).await?;
                    }
                }
            }
        },

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

        None => {
            Cli::command().print_help().expect("Failed to print help");
        }
    }

    Ok(())
}

/// Parse an upload spec like `<local>[:<remote>]` into (local_path, optional_sandbox_path).
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
    use navigator_bootstrap::{
        ClusterMetadata, edge_token::store_edge_token, store_cluster_metadata,
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

    fn edge_metadata(name: &str, endpoint: &str) -> ClusterMetadata {
        ClusterMetadata {
            name: name.to_string(),
            gateway_endpoint: endpoint.to_string(),
            is_remote: true,
            gateway_port: 0,
            kube_port: None,
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
        let args: Vec<OsString> = vec!["nemoclaw".into(), "".into()];
        let candidates = clap_complete::engine::complete(&mut cmd, args, 1, None)
            .expect("completion engine failed");
        assert!(
            !candidates.is_empty(),
            "expected subcommand completions for empty input"
        );
    }

    #[test]
    fn completions_subcommand_appears_in_candidates() {
        let mut cmd = Cli::command();
        let args: Vec<OsString> = vec!["nemoclaw".into(), "comp".into()];
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
            "nemoclaw".into(),
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
                vec!["nemoclaw", "gateway", "start", "--ssh-key", "id"],
                4,
                "id_rsa",
            ),
            (
                vec!["nemoclaw", "sandbox", "create", "--ssh-key", "id"],
                4,
                "id_rsa",
            ),
            (
                vec!["nemoclaw", "sandbox", "upload", "demo", "Do"],
                4,
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
            "nemoclaw".into(),
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
        let result = resolve_sandbox_name(Some("explicit".to_string()), "any-cluster");
        assert_eq!(result.unwrap(), "explicit");
    }

    #[test]
    fn resolve_sandbox_name_falls_back_to_last_used() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            save_last_sandbox("test-cluster", "remembered-sb").unwrap();
            let result = resolve_sandbox_name(None, "test-cluster");
            assert_eq!(result.unwrap(), "remembered-sb");
        });
    }

    #[test]
    fn resolve_sandbox_name_errors_without_fallback() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            let err = resolve_sandbox_name(None, "unknown-cluster").unwrap_err();
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
            store_cluster_metadata(
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
    fn resolve_gateway_prefers_explicit_cluster_for_direct_endpoint() {
        let tmp = tempfile::tempdir().unwrap();
        with_tmp_xdg(tmp.path(), || {
            store_cluster_metadata(
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
            store_cluster_metadata(
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
}
