//! Navigator CLI - command-line interface for Navigator.

use clap::{CommandFactory, Parser, Subcommand};
use miette::Result;
use std::path::PathBuf;

use navigator_bootstrap::{load_active_cluster, load_cluster_metadata};
use navigator_cli::run;
use navigator_cli::tls::{TlsOptions, is_https};

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
/// 2. `NAVIGATOR_CLUSTER` environment variable
/// 3. Active cluster from `~/.config/navigator/active_cluster`
///
/// Once the name is determined, loads the cluster metadata to get the endpoint.
fn resolve_cluster(cluster_flag: &Option<String>) -> Result<ClusterContext> {
    let name = cluster_flag
        .clone()
        .or_else(|| {
            std::env::var("NAVIGATOR_CLUSTER")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .or_else(load_active_cluster)
        .ok_or_else(|| {
            miette::miette!(
                "No active cluster.\n\
                 Set one with: nav cluster use <name>\n\
                 Or deploy a new cluster: nav cluster admin deploy"
            )
        })?;

    let metadata = load_cluster_metadata(&name).map_err(|_| {
        miette::miette!(
            "Unknown cluster '{name}'.\n\
             Deploy it first: nav cluster admin deploy --name {name}\n\
             Or list available clusters: nav cluster list"
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
            std::env::var("NAVIGATOR_CLUSTER")
                .ok()
                .filter(|v| !v.trim().is_empty())
        })
        .or_else(load_active_cluster)
}

/// Navigator CLI - agent execution and management.
#[derive(Parser, Debug)]
#[command(name = "navigator")]
#[command(author, version, about, long_about = None)]
#[command(propagate_version = true)]
struct Cli {
    /// Increase verbosity (-v, -vv, -vvv).
    #[arg(short, long, action = clap::ArgAction::Count, global = true)]
    verbose: u8,

    /// Cluster name to operate on (resolved from stored metadata).
    #[arg(long, short, global = true, env = "NAVIGATOR_CLUSTER")]
    cluster: Option<String>,

    /// Path to TLS CA certificate (PEM).
    #[arg(long, env = "NAVIGATOR_TLS_CA", global = true)]
    tls_ca: Option<PathBuf>,

    /// Path to TLS client certificate (PEM).
    #[arg(long, env = "NAVIGATOR_TLS_CERT", global = true)]
    tls_cert: Option<PathBuf>,

    /// Path to TLS client private key (PEM).
    #[arg(long, env = "NAVIGATOR_TLS_KEY", global = true)]
    tls_key: Option<PathBuf>,

    /// Allow http:// endpoints even when TLS settings are provided.
    #[arg(
        long,
        env = "NAVIGATOR_ALLOW_INSECURE_ACCESS",
        default_value_t = false,
        global = true
    )]
    allow_insecure_access: bool,

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

    /// SSH proxy (used by `ProxyCommand`).
    SshProxy {
        /// Gateway URL (e.g., <https://gw.example.com:443/proxy/connect>).
        #[arg(long)]
        gateway: String,

        /// Sandbox id.
        #[arg(long)]
        sandbox_id: String,

        /// SSH session token.
        #[arg(long)]
        token: String,
    },
}

#[derive(Subcommand, Debug)]
enum ClusterCommands {
    /// Show server status and information.
    Status,

    /// Set the active cluster.
    Use {
        /// Cluster name to make active.
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
        #[arg(long, default_value = "navigator")]
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
        #[arg(long)]
        ssh_key: Option<String>,
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
        #[arg(long)]
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
        #[arg(long)]
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
        #[arg(long)]
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
        /// Sync local files into the sandbox before running.
        #[arg(long)]
        sync: bool,

        /// Keep the sandbox alive after non-interactive commands.
        #[arg(long)]
        keep: bool,

        /// SSH destination for remote bootstrap (e.g., user@hostname).
        #[arg(long)]
        remote: Option<String>,

        /// Path to SSH private key for remote bootstrap.
        #[arg(long)]
        ssh_key: Option<String>,

        /// Command to run after "--" (defaults to an interactive shell).
        #[arg(trailing_var_arg = true)]
        command: Vec<String>,
    },

    /// Fetch a sandbox by id.
    Get {
        /// Sandbox id.
        id: String,
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
        #[arg(long)]
        ids: bool,
    },

    /// Delete a sandbox by id.
    Delete {
        /// Sandbox ids.
        #[arg(required = true, num_args = 1.., value_name = "ID")]
        ids: Vec<String>,
    },

    /// Connect to a sandbox.
    Connect {
        /// Sandbox id.
        id: String,
    },
}

#[derive(Subcommand, Debug)]
enum InferenceCommands {
    /// Create an inference route.
    Create {
        #[arg(long)]
        routing_hint: String,
        #[arg(long)]
        base_url: String,
        #[arg(long, default_value = "openai_chat_completions")]
        protocol: String,
        #[arg(long)]
        api_key: String,
        #[arg(long)]
        model_id: String,
        #[arg(long)]
        disabled: bool,
    },

    /// Update an inference route.
    Update {
        id: String,
        #[arg(long)]
        routing_hint: String,
        #[arg(long)]
        base_url: String,
        #[arg(long, default_value = "openai_chat_completions")]
        protocol: String,
        #[arg(long)]
        api_key: String,
        #[arg(long)]
        model_id: String,
        #[arg(long)]
        disabled: bool,
    },

    /// Delete inference routes.
    Delete {
        #[arg(required = true, num_args = 1.., value_name = "ID")]
        ids: Vec<String>,
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
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .map_err(|e| miette::miette!("failed to install rustls crypto provider: {e:?}"))?;

    let cli = Cli::parse();
    let tls = TlsOptions::new(cli.tls_ca, cli.tls_cert, cli.tls_key);

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
                if !is_https(endpoint)? && !cli.allow_insecure_access {
                    return Err(miette::miette!(
                        "https is required; use --allow-insecure-access to connect over http"
                    ));
                }
                let tls = tls.with_cluster_name(&ctx.name);
                run::cluster_status(&ctx.name, endpoint, &tls).await?;
            }
            ClusterCommands::Use { name } => {
                run::cluster_use(&name)?;
            }
            ClusterCommands::List => {
                run::cluster_list()?;
            }
            ClusterCommands::Admin { command } => match command {
                ClusterAdminCommands::Deploy {
                    name,
                    update_kube_config,
                    get_kubeconfig,
                    remote,
                    ssh_key,
                } => {
                    run::cluster_admin_deploy(
                        &name,
                        update_kube_config,
                        get_kubeconfig,
                        remote.as_deref(),
                        ssh_key.as_deref(),
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
                        .unwrap_or_else(|| "navigator".to_string());
                    run::cluster_admin_stop(&name, remote.as_deref(), ssh_key.as_deref()).await?;
                }
                ClusterAdminCommands::Destroy {
                    name,
                    remote,
                    ssh_key,
                } => {
                    let name = name
                        .or_else(|| resolve_cluster_name(&cli.cluster))
                        .unwrap_or_else(|| "navigator".to_string());
                    run::cluster_admin_destroy(&name, remote.as_deref(), ssh_key.as_deref())
                        .await?;
                }
                ClusterAdminCommands::Info { name } => {
                    let name = name
                        .or_else(|| resolve_cluster_name(&cli.cluster))
                        .unwrap_or_else(|| "navigator".to_string());
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
                        .unwrap_or_else(|| "navigator".to_string());
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
                    sync,
                    keep,
                    remote,
                    ssh_key,
                    command,
                } => {
                    // For `sandbox create`, a missing cluster is not fatal — the
                    // bootstrap flow inside `sandbox_create` can deploy one.
                    match resolve_cluster(&cli.cluster) {
                        Ok(ctx) => {
                            let endpoint = &ctx.endpoint;
                            if !is_https(endpoint)? && !cli.allow_insecure_access {
                                return Err(miette::miette!(
                                    "https is required; use --allow-insecure-access to connect over http"
                                ));
                            }
                            let tls = tls.with_cluster_name(&ctx.name);
                            run::sandbox_create(
                                endpoint,
                                sync,
                                keep,
                                remote.as_deref(),
                                ssh_key.as_deref(),
                                &command,
                                &tls,
                            )
                            .await?;
                        }
                        Err(_) => {
                            // No cluster configured — go straight to bootstrap.
                            run::sandbox_create_with_bootstrap(
                                sync,
                                keep,
                                remote.as_deref(),
                                ssh_key.as_deref(),
                                &command,
                            )
                            .await?;
                        }
                    }
                }
                other => {
                    let ctx = resolve_cluster(&cli.cluster)?;
                    let endpoint = &ctx.endpoint;
                    if !is_https(endpoint)? && !cli.allow_insecure_access {
                        return Err(miette::miette!(
                            "https is required; use --allow-insecure-access to connect over http"
                        ));
                    }
                    let tls = tls.with_cluster_name(&ctx.name);
                    match other {
                        SandboxCommands::Create { .. } => unreachable!(),
                        SandboxCommands::Get { id } => {
                            run::sandbox_get(endpoint, &id, &tls).await?;
                        }
                        SandboxCommands::List { limit, offset, ids } => {
                            run::sandbox_list(endpoint, limit, offset, ids, &tls).await?;
                        }
                        SandboxCommands::Delete { ids } => {
                            run::sandbox_delete(endpoint, &ids, &tls).await?;
                        }
                        SandboxCommands::Connect { id } => {
                            run::sandbox_connect(endpoint, &id, &tls).await?;
                        }
                    }
                }
            }
        }
        Some(Commands::Inference { command }) => {
            let ctx = resolve_cluster(&cli.cluster)?;
            let endpoint = &ctx.endpoint;
            if !is_https(endpoint)? && !cli.allow_insecure_access {
                return Err(miette::miette!(
                    "https is required; use --allow-insecure-access to connect over http"
                ));
            }
            let tls = tls.with_cluster_name(&ctx.name);

            match command {
                InferenceCommands::Create {
                    routing_hint,
                    base_url,
                    protocol,
                    api_key,
                    model_id,
                    disabled,
                } => {
                    run::inference_route_create(
                        endpoint,
                        &routing_hint,
                        &base_url,
                        &protocol,
                        &api_key,
                        &model_id,
                        !disabled,
                        &tls,
                    )
                    .await?;
                }
                InferenceCommands::Update {
                    id,
                    routing_hint,
                    base_url,
                    protocol,
                    api_key,
                    model_id,
                    disabled,
                } => {
                    run::inference_route_update(
                        endpoint,
                        &id,
                        &routing_hint,
                        &base_url,
                        &protocol,
                        &api_key,
                        &model_id,
                        !disabled,
                        &tls,
                    )
                    .await?;
                }
                InferenceCommands::Delete { ids } => {
                    run::inference_route_delete(endpoint, &ids, &tls).await?;
                }
                InferenceCommands::List { limit, offset } => {
                    run::inference_route_list(endpoint, limit, offset, &tls).await?;
                }
            }
        }
        Some(Commands::SshProxy {
            gateway,
            sandbox_id,
            token,
        }) => {
            run::sandbox_ssh_proxy(&gateway, &sandbox_id, &token, &tls).await?;
        }
        None => {
            Cli::command().print_help().expect("Failed to print help");
        }
    }

    Ok(())
}
