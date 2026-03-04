// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! NemoClaw CLI - command-line interface for NemoClaw.

use clap::{CommandFactory, Parser, Subcommand, ValueEnum, ValueHint};
use clap_complete::engine::ArgValueCompleter;
use clap_complete::env::CompleteEnv;
use miette::Result;
use owo_colors::OwoColorize;
use std::io::Write;
use std::path::PathBuf;

use navigator_bootstrap::{load_active_cluster, load_cluster_metadata};
use navigator_cli::completers;
use navigator_cli::run;
use navigator_cli::tls::TlsOptions;

/// Resolved cluster context: name + gateway endpoint.
struct ClusterContext {
    /// The cluster name (used for TLS cert directory, metadata lookup, etc.).
    name: String,
    /// The gateway endpoint URL (e.g., `https://127.0.0.1` or `https://10.0.0.5`).
    endpoint: String,
}

/// Resolve the cluster name to a [`ClusterContext`] with the gateway endpoint.
///
/// Resolution priority:
/// 1. `--cluster` flag (explicit name)
/// 2. `NEMOCLAW_CLUSTER` environment variable
/// 3. Active cluster from `~/.config/nemoclaw/active_cluster`
///
/// Once the name is determined, loads the cluster metadata to get the endpoint.
fn resolve_cluster(cluster_flag: &Option<String>) -> Result<ClusterContext> {
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
                "No active cluster.\n\
                 Set one with: ncl cluster use <name>\n\
                 Or deploy a new cluster: ncl cluster admin deploy"
            )
        })?;

    let metadata = load_cluster_metadata(&name).map_err(|_| {
        miette::miette!(
            "Unknown cluster '{name}'.\n\
             Deploy it first: ncl cluster admin deploy --name {name}\n\
             Or list available clusters: ncl cluster list"
        )
    })?;

    Ok(ClusterContext {
        name: metadata.name,
        endpoint: metadata.gateway_endpoint,
    })
}

/// Resolve only the cluster name (without requiring metadata to exist).
///
/// Used by admin commands that operate on a cluster by name but may not need
/// the gateway endpoint (e.g., `cluster admin deploy` creates the cluster).
fn resolve_cluster_name(cluster_flag: &Option<String>) -> Option<String> {
    cluster_flag
        .clone()
        .or_else(|| {
            std::env::var("NEMOCLAW_CLUSTER")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .or_else(load_active_cluster)
}

/// NemoClaw CLI - agent execution and management.
#[derive(Parser, Debug)]
#[command(name = "nemoclaw")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Increase verbosity (-v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Cluster name to operate on (resolved from stored metadata).
    #[arg(long, short, global = true, env = "NEMOCLAW_CLUSTER")]
    cluster: Option<String>,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Manage cluster.
    Cluster {
        #[command(subcommand)]
        command: ClusterCommands,
    },

    /// Manage sandboxes.
    Sandbox {
        #[command(subcommand)]
        command: SandboxCommands,
    },

    /// Manage inference configuration.
    Inference {
        #[command(subcommand)]
        command: InferenceCommands,
    },

    /// Manage provider configuration.
    Provider {
        #[command(subcommand)]
        command: ProviderCommands,
    },

    /// Launch the Gator interactive TUI.
    Gator,

    /// Generate shell completions.
    #[command(after_long_help = COMPLETIONS_HELP)]
    Completions {
        /// Shell to generate completions for.
        shell: CompletionShell,
    },

    /// SSH proxy (used by `ProxyCommand`).
    ///
    /// Two mutually exclusive modes:
    ///
    /// **Token mode** (used internally by `sandbox connect`):
    ///   `ncl ssh-proxy --gateway <url> --sandbox-id <id> --token <token>`
    ///
    /// **Name mode** (for use in `~/.ssh/config`):
    ///   `ncl ssh-proxy --cluster <name> --name <sandbox-name>`
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

    /// Update an existing provider config.
    Update {
        /// Provider name.
        #[arg(add = ArgValueCompleter::new(completers::complete_provider_names))]
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

    /// Delete providers by name.
    Delete {
        /// Provider names.
        #[arg(required = true, num_args = 1.., value_name = "NAME", add = ArgValueCompleter::new(completers::complete_provider_names))]
        names: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum ClusterCommands {
    /// Show server status and information.
    Status,

    /// Set the active cluster.
    Use {
        /// Cluster name to make active.
        #[arg(add = ArgValueCompleter::new(completers::complete_cluster_names))]
        name: String,
    },

    /// List all provisioned clusters.
    List,

    /// Manage local development cluster lifecycle.
    Admin {
        #[command(subcommand)]
        command: ClusterAdminCommands,
    },
}

#[derive(Subcommand, Debug)]
enum ClusterAdminCommands {
    /// Provision or start a cluster (local or remote).
    Deploy {
        /// Cluster name.
        #[arg(long, default_value = "nemoclaw")]
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
    },

    /// Stop a cluster (preserves state).
    Stop {
        /// Cluster name (defaults to active cluster).
        #[arg(long)]
        name: Option<String>,

        /// Override SSH destination (auto-resolved from cluster metadata).
        #[arg(long)]
        remote: Option<String>,

        /// Path to SSH private key for remote cluster.
        #[arg(long, value_hint = ValueHint::FilePath)]
        ssh_key: Option<String>,
    },

    /// Destroy a cluster and its state.
    Destroy {
        /// Cluster name (defaults to active cluster).
        #[arg(long)]
        name: Option<String>,

        /// Override SSH destination (auto-resolved from cluster metadata).
        #[arg(long)]
        remote: Option<String>,

        /// Path to SSH private key for remote cluster.
        #[arg(long, value_hint = ValueHint::FilePath)]
        ssh_key: Option<String>,
    },

    /// Show cluster deployment details.
    Info {
        /// Cluster name (defaults to active cluster).
        #[arg(long)]
        name: Option<String>,
    },

    /// Print or start an SSH tunnel for kubectl access to a remote cluster.
    Tunnel {
        /// Cluster name (defaults to active cluster).
        #[arg(long)]
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

#[derive(Subcommand, Debug)]
enum SandboxCommands {
    /// Create a sandbox.
    Create {
        /// Optional sandbox name (auto-generated when omitted).
        #[arg(long)]
        name: Option<String>,

        /// Container image for the sandbox workload.
        /// The sandbox supervisor is side-loaded via an init container.
        #[arg(long)]
        image: Option<String>,

        /// Sync local files into the sandbox before running.
        #[arg(long)]
        sync: bool,

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

        /// Command to run after "--" (defaults to an interactive shell).
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Fetch a sandbox by name.
    Get {
        /// Sandbox name.
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: String,
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
    Connect {
        /// Sandbox name.
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: String,
    },

    /// Manage port forwarding to a sandbox.
    Forward {
        #[command(subcommand)]
        command: ForwardCommands,
    },

    /// Sync files to or from a sandbox.
    Sync {
        /// Sandbox name.
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: String,

        /// Push local files up to the sandbox.
        #[arg(long, conflicts_with = "down", value_name = "LOCAL_PATH", value_hint = ValueHint::AnyPath)]
        up: Option<String>,

        /// Pull sandbox files down to the local machine.
        #[arg(long, conflicts_with = "up", value_name = "SANDBOX_PATH")]
        down: Option<String>,

        /// Destination path (sandbox path when pushing, local path when pulling).
        /// Defaults to /sandbox for --up or . for --down.
        #[arg(value_name = "DEST")]
        dest: Option<String>,
    },

    /// Manage sandbox images.
    Image {
        #[command(subcommand)]
        command: SandboxImageCommands,
    },

    /// Manage sandbox policy.
    Policy {
        #[command(subcommand)]
        command: PolicyCommands,
    },

    /// View sandbox logs.
    Logs {
        /// Sandbox name.
        name: String,

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

    /// Print an SSH config entry for a sandbox.
    ///
    /// Outputs a Host block suitable for appending to ~/.ssh/config,
    /// enabling tools like `VSCode` Remote-SSH to connect to the sandbox.
    SshConfig {
        /// Sandbox name.
        name: String,
    },
}

#[derive(Subcommand, Debug)]
enum PolicyCommands {
    /// Update policy on a live sandbox.
    Set {
        /// Sandbox name.
        name: String,

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
        /// Sandbox name.
        name: String,

        /// Show a specific policy revision (default: latest).
        #[arg(long = "rev", default_value_t = 0)]
        rev: u32,

        /// Print the full policy as YAML.
        #[arg(long)]
        full: bool,
    },

    /// List policy history for a sandbox.
    List {
        /// Sandbox name.
        name: String,

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

        /// Sandbox name.
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: String,

        /// Run the forward in the background and exit immediately.
        #[arg(short = 'd', long)]
        background: bool,
    },

    /// Stop a background port forward.
    Stop {
        /// Port that was forwarded.
        port: u16,

        /// Sandbox name.
        #[arg(add = ArgValueCompleter::new(completers::complete_sandbox_names))]
        name: String,
    },

    /// List active port forwards.
    List,
}

#[derive(Subcommand, Debug)]
enum SandboxImageCommands {
    /// Build and push a container image into the cluster.
    Push {
        /// Path to the Dockerfile.
        #[arg(long, value_hint = ValueHint::FilePath)]
        dockerfile: PathBuf,

        /// Image name and tag (default: navigator/sandbox-custom:<timestamp>).
        #[arg(long)]
        tag: Option<String>,

        /// Build context directory (default: Dockerfile parent directory).
        #[arg(long, value_hint = ValueHint::DirPath)]
        context: Option<PathBuf>,

        /// Build argument in KEY=VALUE format (can be specified multiple times).
        #[arg(long = "build-arg", value_name = "KEY=VALUE")]
        build_args: Vec<String>,
    },
}

#[derive(Subcommand, Debug)]
enum InferenceCommands {
    /// Create an inference route.
    Create {
        /// Optional route name (auto-generated if omitted).
        #[arg(long)]
        name: Option<String>,
        #[arg(long)]
        routing_hint: String,
        #[arg(long)]
        base_url: String,
        /// Supported protocol(s). Repeat flag or pass comma-separated values.
        ///
        /// If omitted, protocols are auto-detected by probing the base URL.
        #[arg(long = "protocol", value_delimiter = ',')]
        protocols: Vec<String>,
        /// API key for the inference endpoint. Defaults to empty (for local models).
        #[arg(long, default_value = "")]
        api_key: String,
        #[arg(long)]
        model_id: String,
        #[arg(long)]
        disabled: bool,
    },

    /// Update an inference route.
    Update {
        /// Route name.
        name: String,
        #[arg(long)]
        routing_hint: String,
        #[arg(long)]
        base_url: String,
        /// Supported protocol(s). Repeat flag or pass comma-separated values.
        ///
        /// If omitted, protocols are auto-detected by probing the base URL.
        #[arg(long = "protocol", value_delimiter = ',')]
        protocols: Vec<String>,
        /// API key for the inference endpoint. Defaults to empty (for local models).
        #[arg(long, default_value = "")]
        api_key: String,
        #[arg(long)]
        model_id: String,
        #[arg(long)]
        disabled: bool,
    },

    /// Delete inference routes.
    Delete {
        /// Route names.
        #[arg(required = true, num_args = 1.., value_name = "NAME")]
        names: Vec<String>,
    },

    /// List inference routes.
    List {
        #[arg(long, default_value_t = 100)]
        limit: u32,
        #[arg(long, default_value_t = 0)]
        offset: u32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the rustls crypto provider before completion runs — completers may
    // establish TLS connections to the gateway.
    rustls::crypto::aws_lc_rs::default_provider()
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
        Some(Commands::Cluster { command }) => match command {
            ClusterCommands::Status => {
                let ctx = resolve_cluster(&cli.cluster)?;
                let endpoint = &ctx.endpoint;
                let tls = tls.with_cluster_name(&ctx.name);
                run::cluster_status(&ctx.name, endpoint, &tls).await?;
            }
            ClusterCommands::Use { name } => {
                run::cluster_use(&name)?;
            }
            ClusterCommands::List => {
                run::cluster_list(&cli.cluster)?;
            }
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
                    )
                    .await?;
                }
                ClusterAdminCommands::Stop {
                    name,
                    remote,
                    ssh_key,
                } => {
                    let name = name
                        .or_else(|| resolve_cluster_name(&cli.cluster))
                        .unwrap_or_else(|| "nemoclaw".to_string());
                    run::cluster_admin_stop(&name, remote.as_deref(), ssh_key.as_deref()).await?;
                }
                ClusterAdminCommands::Destroy {
                    name,
                    remote,
                    ssh_key,
                } => {
                    let name = name
                        .or_else(|| resolve_cluster_name(&cli.cluster))
                        .unwrap_or_else(|| "nemoclaw".to_string());
                    run::cluster_admin_destroy(&name, remote.as_deref(), ssh_key.as_deref())
                        .await?;
                }
                ClusterAdminCommands::Info { name } => {
                    let name = name
                        .or_else(|| resolve_cluster_name(&cli.cluster))
                        .unwrap_or_else(|| "nemoclaw".to_string());
                    run::cluster_admin_info(&name)?;
                }
                ClusterAdminCommands::Tunnel {
                    name,
                    remote,
                    ssh_key,
                    print_command,
                } => {
                    let name = name
                        .or_else(|| resolve_cluster_name(&cli.cluster))
                        .unwrap_or_else(|| "nemoclaw".to_string());
                    run::cluster_admin_tunnel(
                        &name,
                        remote.as_deref(),
                        ssh_key.as_deref(),
                        print_command,
                    )?;
                }
            },
        },
        Some(Commands::Sandbox { command }) => {
            match command {
                SandboxCommands::Create {
                    name,
                    image,
                    sync,
                    keep,
                    remote,
                    ssh_key,
                    providers,
                    policy,
                    forward,
                    command,
                } => {
                    // For `sandbox create`, a missing cluster is not fatal — the
                    // bootstrap flow inside `sandbox_create` can deploy one.
                    match resolve_cluster(&cli.cluster) {
                        Ok(ctx) => {
                            if remote.is_some() {
                                eprintln!(
                                    "{} --remote ignored: cluster '{}' is already active. \
                                     To redeploy, use: ncl cluster admin deploy",
                                    "!".yellow(),
                                    ctx.name,
                                );
                                return Ok(());
                            }
                            let endpoint = &ctx.endpoint;
                            let tls = tls.with_cluster_name(&ctx.name);
                            run::sandbox_create(
                                endpoint,
                                name.as_deref(),
                                image.as_deref(),
                                sync,
                                keep,
                                remote.as_deref(),
                                ssh_key.as_deref(),
                                &providers,
                                policy.as_deref(),
                                forward,
                                &command,
                                &tls,
                            )
                            .await?;
                        }
                        Err(_) => {
                            // No cluster configured — go straight to bootstrap.
                            run::sandbox_create_with_bootstrap(
                                name.as_deref(),
                                image.as_deref(),
                                sync,
                                keep,
                                remote.as_deref(),
                                ssh_key.as_deref(),
                                &providers,
                                policy.as_deref(),
                                forward,
                                &command,
                            )
                            .await?;
                        }
                    }
                }
                SandboxCommands::Forward {
                    command: ForwardCommands::Stop { port, name },
                } => {
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
                SandboxCommands::Forward {
                    command: ForwardCommands::List,
                } => {
                    let forwards = run::list_forwards()?;
                    if forwards.is_empty() {
                        eprintln!("No active forwards.");
                    } else {
                        let name_width = forwards
                            .iter()
                            .map(|f| f.sandbox.len())
                            .max()
                            .unwrap_or(7)
                            .max(7); // at least as wide as "SANDBOX"
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
                SandboxCommands::Image { command } => match command {
                    SandboxImageCommands::Push {
                        dockerfile,
                        tag,
                        context,
                        build_args,
                    } => {
                        let cluster_name = resolve_cluster_name(&cli.cluster)
                            .unwrap_or_else(|| "nemoclaw".to_string());
                        run::sandbox_image_push(
                            &dockerfile,
                            tag.as_deref(),
                            context.as_deref(),
                            &cluster_name,
                            &build_args,
                        )
                        .await?;
                    }
                },
                other => {
                    let ctx = resolve_cluster(&cli.cluster)?;
                    let endpoint = &ctx.endpoint;
                    let tls = tls.with_cluster_name(&ctx.name);
                    match other {
                        SandboxCommands::Create { .. } | SandboxCommands::Image { .. } => {
                            unreachable!()
                        }
                        SandboxCommands::Sync {
                            name,
                            up,
                            down,
                            dest,
                        } => {
                            run::sandbox_sync_command(
                                endpoint,
                                &name,
                                up.as_deref(),
                                down.as_deref(),
                                dest.as_deref(),
                                &tls,
                            )
                            .await?;
                        }
                        SandboxCommands::Get { name } => {
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
                            run::sandbox_connect(endpoint, &name, &tls).await?;
                        }
                        SandboxCommands::Forward { command: fwd } => match fwd {
                            ForwardCommands::Start {
                                port,
                                name,
                                background,
                            } => {
                                run::sandbox_forward(endpoint, &name, port, background, &tls)
                                    .await?;
                                if background {
                                    eprintln!(
                                        "{} Forwarding port {port} to sandbox {name} in the background",
                                        "✓".green().bold(),
                                    );
                                    eprintln!("  Access at: http://127.0.0.1:{port}/");
                                    eprintln!(
                                        "  Stop with: nemoclaw sandbox forward stop {port} {name}",
                                    );
                                }
                            }
                            ForwardCommands::Stop { .. } | ForwardCommands::List => unreachable!(),
                        },
                        SandboxCommands::Policy {
                            command: policy_cmd,
                        } => match policy_cmd {
                            PolicyCommands::Set {
                                name,
                                policy,
                                wait,
                                timeout,
                            } => {
                                run::sandbox_policy_set(
                                    endpoint, &name, &policy, wait, timeout, &tls,
                                )
                                .await?;
                            }
                            PolicyCommands::Get { name, rev, full } => {
                                run::sandbox_policy_get(endpoint, &name, rev, full, &tls).await?;
                            }
                            PolicyCommands::List { name, limit } => {
                                run::sandbox_policy_list(endpoint, &name, limit, &tls).await?;
                            }
                        },
                        SandboxCommands::Logs {
                            name,
                            n,
                            tail,
                            since,
                            source,
                            level,
                        } => {
                            run::sandbox_logs(
                                endpoint,
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
                        SandboxCommands::SshConfig { name } => {
                            run::print_ssh_config(&ctx.name, &name);
                        }
                    }
                }
            }
        }
        Some(Commands::Inference { command }) => {
            let ctx = resolve_cluster(&cli.cluster)?;
            let endpoint = &ctx.endpoint;
            let tls = tls.with_cluster_name(&ctx.name);

            match command {
                InferenceCommands::Create {
                    name,
                    routing_hint,
                    base_url,
                    protocols,
                    api_key,
                    model_id,
                    disabled,
                } => {
                    run::inference_route_create(
                        endpoint,
                        name.as_deref(),
                        &routing_hint,
                        &base_url,
                        &protocols,
                        &api_key,
                        &model_id,
                        !disabled,
                        &tls,
                    )
                    .await?;
                }
                InferenceCommands::Update {
                    name,
                    routing_hint,
                    base_url,
                    protocols,
                    api_key,
                    model_id,
                    disabled,
                } => {
                    run::inference_route_update(
                        endpoint,
                        &name,
                        &routing_hint,
                        &base_url,
                        &protocols,
                        &api_key,
                        &model_id,
                        !disabled,
                        &tls,
                    )
                    .await?;
                }
                InferenceCommands::Delete { names } => {
                    run::inference_route_delete(endpoint, &names, &tls).await?;
                }
                InferenceCommands::List { limit, offset } => {
                    run::inference_route_list(endpoint, limit, offset, &tls).await?;
                }
            }
        }
        Some(Commands::Provider { command }) => {
            let ctx = resolve_cluster(&cli.cluster)?;
            let endpoint = &ctx.endpoint;
            let tls = tls.with_cluster_name(&ctx.name);

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
                    provider_type,
                    from_existing,
                    credentials,
                    config,
                } => {
                    run::provider_update(
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
                ProviderCommands::Delete { names } => {
                    run::provider_delete(endpoint, &names, &tls).await?;
                }
            }
        }
        Some(Commands::Gator) => {
            let ctx = resolve_cluster(&cli.cluster)?;
            let tls = tls.with_cluster_name(&ctx.name);
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
                    let effective_tls = match cluster_opt {
                        Some(ref c) => tls.with_cluster_name(c),
                        None => tls,
                    };
                    run::sandbox_ssh_proxy(&gw, &sid, &tok, &effective_tls).await?;
                }
                // Name mode with --cluster: resolve endpoint from metadata.
                (_, _, _, server_override, Some(c), Some(n)) => {
                    let endpoint = if let Some(srv) = server_override {
                        srv
                    } else {
                        let meta = load_cluster_metadata(&c).map_err(|_| {
                            miette::miette!(
                                "Unknown cluster '{c}'.\n\
                                  Deploy it first: ncl cluster admin deploy --name {c}\n\
                                  Or list available clusters: ncl cluster list"
                            )
                        })?;
                        meta.gateway_endpoint
                    };
                    let tls = tls.with_cluster_name(&c);
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
        None => {
            Cli::command().print_help().expect("Failed to print help");
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::OsString;

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
        std::fs::write(temp.path().join("policy.yaml"), "version: 1\n")
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
        std::fs::write(temp.path().join("id_rsa"), "key").expect("failed to create key file");
        std::fs::write(temp.path().join("Dockerfile"), "FROM scratch\n")
            .expect("failed to create dockerfile");
        std::fs::create_dir(temp.path().join("ctx")).expect("failed to create context directory");

        let cases: Vec<(Vec<&str>, usize, &str)> = vec![
            (
                vec!["nemoclaw", "cluster", "admin", "deploy", "--ssh-key", "id"],
                5,
                "id_rsa",
            ),
            (
                vec!["nemoclaw", "sandbox", "create", "--ssh-key", "id"],
                4,
                "id_rsa",
            ),
            (
                vec!["nemoclaw", "sandbox", "sync", "demo", "--up", "Do"],
                5,
                "Dockerfile",
            ),
            (
                vec!["nemoclaw", "sandbox", "image", "push", "--dockerfile", "Do"],
                5,
                "Dockerfile",
            ),
            (
                vec![
                    "nemoclaw",
                    "sandbox",
                    "image",
                    "push",
                    "--dockerfile",
                    "Dockerfile",
                    "--context",
                    "c",
                ],
                7,
                "ctx/",
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
}
