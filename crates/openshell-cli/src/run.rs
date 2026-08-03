// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! CLI command implementations.

pub use crate::commands::common::{
    PolicyGetView, parse_credential_expiry_cli_value, parse_env_pairs, parse_key_value_pairs,
    parse_secret_material_env_pairs, warn_credential_env_vars,
};
use crate::commands::common::{
    ProvisioningDisplay, ProvisioningStep, confirm_global_setting_delete,
    confirm_global_setting_takeover, format_epoch_ms, format_setting_value, format_timestamp,
    format_timestamp_ms, handle_platform_progress_event, is_provisioning_progress_event,
    non_empty_or, parse_cli_setting_value, parse_duration_to_ms, phase_name,
    print_policy_merge_warnings, print_sandbox_header, print_sandbox_policy,
    provisioning_timeout_message, ready_false_condition_message, scrub_git_env, short_hash,
    truncate_status_field,
};
pub use crate::commands::gateway::{
    gateway_add, gateway_info, gateway_info_not_configured, gateway_list, gateway_login,
    gateway_logout, gateway_remove, gateway_select, gateway_status, gateway_use,
};

use crate::commands::provider::inferred_provider_type;
pub use crate::commands::provider::{
    ProviderCreateCredentialSource, ProviderCreateOptions, ProviderRefreshConfigInput,
    ProviderUpdateOptions, ensure_required_providers, provider_create,
    provider_create_with_options, provider_delete, provider_get, provider_list,
    provider_list_profiles, provider_profile_delete, provider_profile_export,
    provider_profile_export_text, provider_profile_import, provider_profile_lint,
    provider_profile_update, provider_refresh_config, provider_refresh_delete,
    provider_refresh_status, provider_rotate, provider_update, sandbox_provider_attach,
    sandbox_provider_detach, sandbox_provider_list,
};

use crate::color::Colorize;
use crate::policy_update::build_policy_update_plan;
use crate::tls::{TlsOptions, grpc_client, grpc_inference_client};
use futures::StreamExt;
use indicatif::{ProgressBar, ProgressStyle};
use miette::{IntoDiagnostic, Result, WrapErr, miette};
use openshell_bootstrap::{
    GatewayMetadata, clear_last_sandbox_if_matches, get_gateway_metadata, save_last_sandbox,
};
use openshell_core::net::set_tcp_nodelay_best_effort;
use openshell_core::proto::{
    ApproveAllDraftChunksRequest, ApproveDraftChunkRequest, ClearDraftChunksRequest,
    CreateSandboxRequest, CreateSandboxTemplateRequest, CreateSshSessionRequest,
    DeleteInferenceRouteRequest, DeleteSandboxRequest, DeleteSandboxTemplateRequest,
    DeleteServiceRequest, ExecSandboxRequest, ExposeServiceRequest, GetCurrentUserRequest,
    GetDraftHistoryRequest, GetDraftPolicyRequest, GetGatewayConfigRequest,
    GetInferenceRouteRequest, GetSandboxConfigRequest, GetSandboxConfigResponse,
    GetSandboxLogsRequest, GetSandboxPolicyStatusRequest, GetSandboxRequest,
    GetSandboxTemplateRequest, GetServiceRequest, GpuResourceRequirements,
    ListSandboxPoliciesRequest, ListSandboxTemplatesRequest, ListSandboxesRequest,
    ListServicesRequest, PolicySource, PolicyStatus, RejectDraftChunkRequest, ResourceRequirements,
    RevokeSshSessionRequest, Sandbox, SandboxPhase, SandboxPolicy, SandboxResources,
    SandboxServiceLevel, SandboxSpec, SandboxStartup, SandboxTemplate, SandboxWorkloadConfig,
    SandboxWorkloadTemplate, SandboxWorkloadTemplateSpec, ServiceEndpointResponse,
    SetInferenceRouteRequest, SettingScope, StartSandboxRequest, StopSandboxRequest,
    TcpForwardFrame, TcpForwardInit, TcpRelayTarget, UpdateConfigRequest, WatchSandboxRequest,
    exec_sandbox_event, tcp_forward_init,
};
use openshell_core::settings;
use openshell_core::{ObjectId, ObjectName, ObjectWorkspace};
use std::borrow::Cow;
use std::collections::HashMap;
use std::io::{ErrorKind, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Duration, Instant};
use tonic::{Code, Status};

// Re-export SSH functions for backward compatibility
pub use crate::ssh::{Editor, print_ssh_config};
pub use crate::ssh::{
    sandbox_connect, sandbox_connect_editor, sandbox_exec, sandbox_forward, sandbox_ssh_proxy,
    sandbox_ssh_proxy_by_name, sandbox_sync_down, sandbox_sync_up, sandbox_sync_up_files,
};
pub use openshell_core::forward::{
    ForwardSpec, find_forward_by_port, list_forwards, stop_forward, stop_forwards_for_sandbox,
};

#[derive(Debug, PartialEq, Eq)]
enum SandboxUploadPlan {
    GitAware {
        base_dir: PathBuf,
        files: Vec<String>,
    },
    Regular,
    GitFilteredEmpty,
}

enum ProgressOutput {
    Interactive(ProvisioningDisplay),
    Plain,
    Silent,
}

impl ProgressOutput {
    fn as_interactive_mut(&mut self) -> Option<&mut ProvisioningDisplay> {
        match self {
            Self::Interactive(d) => Some(d),
            _ => None,
        }
    }

    fn as_interactive(&self) -> Option<&ProvisioningDisplay> {
        match self {
            Self::Interactive(d) => Some(d),
            _ => None,
        }
    }

    fn is_plain(&self) -> bool {
        matches!(self, Self::Plain)
    }
}

fn aggregate_delete_failures(resource: &str, failures: &[String]) -> Result<()> {
    if failures.is_empty() {
        Ok(())
    } else {
        Err(miette!(
            "failed to delete {} {}{}: {}",
            failures.len(),
            resource,
            if failures.len() == 1 { "" } else { "s" },
            failures.join(", ")
        ))
    }
}

#[derive(Debug, Clone)]
struct CurrentUserView {
    subject: String,
    display_name: Option<String>,
    roles: Vec<String>,
    scopes: Vec<String>,
    identity_provider: String,
}

/// Show the identity validated by the selected gateway.
pub async fn whoami(server: &str, tls: &TlsOptions, output: &str) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let identity = client
        .get_current_user(GetCurrentUserRequest {})
        .await
        .map_err(|err| match err.code() {
            Code::Unimplemented => miette!("whoami is not supported by this gateway version"),
            Code::Unauthenticated => miette!("whoami requires authentication: {err}"),
            _ => miette!("get_current_user failed: {err}"),
        })?
        .into_inner();

    let view = CurrentUserView {
        subject: identity.subject,
        display_name: (!identity.display_name.is_empty()).then_some(identity.display_name),
        roles: identity.roles,
        scopes: identity.scopes,
        identity_provider: identity.identity_provider,
    };
    print_current_user(&view, output)
}

fn print_current_user(view: &CurrentUserView, output: &str) -> Result<()> {
    if crate::output::print_output_single(output, view, current_user_to_json)? {
        return Ok(());
    }

    println!("{}", "Current User".cyan().bold());
    println!();
    println!("  {} {}", "Subject:".dimmed(), view.subject);
    if let Some(display_name) = &view.display_name {
        println!("  {} {}", "Name:".dimmed(), display_name);
    }
    println!("  {} {}", "Provider:".dimmed(), view.identity_provider);
    println!("  {} {}", "Roles:".dimmed(), view.roles.join(", "));
    println!("  {} {}", "Scopes:".dimmed(), view.scopes.join(", "));
    Ok(())
}

fn current_user_to_json(view: &CurrentUserView) -> serde_json::Value {
    serde_json::json!({
        "subject": &view.subject,
        "display_name": &view.display_name,
        "roles": &view.roles,
        "scopes": &view.scopes,
        "identity_provider": &view.identity_provider,
    })
}

/// Validate system prerequisites for running a gateway.
///
/// Checks Docker connectivity and reports the result. Returns exit code 0
/// if all checks pass, 1 otherwise.
pub fn doctor_check() -> Result<()> {
    use std::io::Write;
    let mut stdout = std::io::stdout().lock();

    writeln!(stdout, "Checking system prerequisites...\n").into_diagnostic()?;

    // --- Docker connectivity ---
    write!(stdout, "  Docker ............. ").into_diagnostic()?;
    stdout.flush().into_diagnostic()?;

    let output = Command::new("docker")
        .args(["info", "--format", "{{.ServerVersion}}"])
        .output()
        .into_diagnostic()
        .wrap_err("failed to execute docker info")?;

    if output.status.success() {
        let version = String::from_utf8_lossy(&output.stdout);
        let version_str = version.trim();
        writeln!(stdout, "ok (version {version_str})").into_diagnostic()?;

        // --- DOCKER_HOST ---
        write!(stdout, "  DOCKER_HOST ........ ").into_diagnostic()?;
        match std::env::var("DOCKER_HOST") {
            Ok(val) => writeln!(stdout, "{val}").into_diagnostic()?,
            Err(_) => writeln!(stdout, "(not set, using default socket)").into_diagnostic()?,
        }

        writeln!(stdout, "\nAll checks passed.").into_diagnostic()?;
        return Ok(());
    }

    writeln!(stdout, "FAILED").into_diagnostic()?;
    writeln!(stdout).into_diagnostic()?;
    let stderr = String::from_utf8_lossy(&output.stderr);
    Err(miette::miette!("docker info failed: {}", stderr.trim()))
}

fn sandbox_should_persist(keep: bool, forward: Option<&ForwardSpec>) -> bool {
    keep || forward.is_some()
}

fn has_main_process_result(sandbox: &Sandbox) -> bool {
    let Some(status) = sandbox.status.as_ref() else {
        return false;
    };
    if status.exit_code.is_none() {
        return false;
    }

    let phase = SandboxPhase::try_from(sandbox.phase()).unwrap_or(SandboxPhase::Unknown);
    phase != SandboxPhase::Error
        || status.conditions.iter().any(|condition| {
            condition.r#type == "Ready"
                && condition.status.eq_ignore_ascii_case("false")
                && condition.reason == "MainProcessFailed"
        })
}

fn build_sandbox_resource_limits(
    cpu: Option<&str>,
    memory: Option<&str>,
) -> Result<Option<prost_types::Struct>> {
    use prost_types::{Struct, Value, value::Kind};

    fn string_value(value: String) -> Value {
        Value {
            kind: Some(Kind::StringValue(value)),
        }
    }

    let mut limits = std::collections::BTreeMap::new();
    if let Some(cpu) = cpu {
        limits.insert("cpu".to_string(), string_value(validate_cpu_quantity(cpu)?));
    }
    if let Some(memory) = memory {
        limits.insert(
            "memory".to_string(),
            string_value(validate_memory_quantity(memory)?),
        );
    }

    if limits.is_empty() {
        return Ok(None);
    }

    let mut fields = std::collections::BTreeMap::new();
    fields.insert(
        "limits".to_string(),
        Value {
            kind: Some(Kind::StructValue(Struct { fields: limits })),
        },
    );
    Ok(Some(Struct { fields }))
}

fn parse_driver_config_json(value: &str) -> Result<prost_types::Struct> {
    let parsed: serde_json::Value = serde_json::from_str(value)
        .into_diagnostic()
        .wrap_err("--driver-config-json must be valid JSON")?;

    let serde_json::Value::Object(fields) = parsed else {
        return Err(miette!(
            "--driver-config-json must be a JSON object keyed by driver name"
        ));
    };

    openshell_core::proto_struct::json_object_to_struct(fields)
        .into_diagnostic()
        .wrap_err("--driver-config-json contains a value that cannot be represented")
}

fn validate_cpu_quantity(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(miette!("--cpu must not be empty"));
    }

    if let Some(millicores) = value.strip_suffix('m') {
        if millicores.is_empty() || !millicores.bytes().all(|b| b.is_ascii_digit()) {
            return Err(miette!(
                "invalid --cpu value '{value}': expected positive cores or millicores, for example 2, 0.5, or 500m"
            ));
        }
        let millicores = millicores.parse::<u64>().into_diagnostic()?;
        if millicores == 0 {
            return Err(miette!("--cpu must be greater than zero"));
        }
        return Ok(value.to_string());
    }

    let cores = value.parse::<f64>().map_err(|_| {
        miette!(
            "invalid --cpu value '{value}': expected positive cores or millicores, for example 2, 0.5, or 500m"
        )
    })?;
    if !cores.is_finite() || cores <= 0.0 {
        return Err(miette!("--cpu must be greater than zero"));
    }
    Ok(value.to_string())
}

fn validate_memory_quantity(value: &str) -> Result<String> {
    let value = value.trim();
    if value.is_empty() {
        return Err(miette!("--memory must not be empty"));
    }

    let number_end = value
        .find(|ch: char| !ch.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, suffix) = value.split_at(number_end);
    if number.is_empty()
        || !matches!(
            suffix,
            "" | "Ki" | "Mi" | "Gi" | "Ti" | "Pi" | "Ei" | "K" | "M" | "G" | "T" | "P" | "E"
        )
    {
        return Err(miette!(
            "invalid --memory value '{value}': expected positive bytes or a quantity such as 512Mi, 4Gi, or 8G"
        ));
    }

    let amount = number.parse::<u128>().into_diagnostic()?;
    if amount == 0 {
        return Err(miette!("--memory must be greater than zero"));
    }
    Ok(value.to_string())
}

async fn finalize_sandbox_create_session(
    server: &str,
    sandbox_name: &str,
    persist: bool,
    session_result: Result<i32>,
    workspace: &str,
    tls: &TlsOptions,
    gateway: &str,
) -> Result<i32> {
    if persist {
        return session_result;
    }

    let names = [sandbox_name.to_string()];
    if let Err(err) = sandbox_delete(server, &names, false, workspace, tls, gateway).await {
        if let Ok(exit_code) = session_result.as_ref() {
            return Err(miette::miette!(
                "sandbox command exited with status {exit_code}, but ephemeral cleanup failed: {err}"
            ));
        }
        eprintln!("Failed to delete sandbox {sandbox_name}: {err}");
    }

    session_result
}

/// Configuration for creating a sandbox via the CLI.
///
/// Infrastructure parameters (`server`, `gateway_name`, `tls`) remain positional
/// on the function signature, following the `provider_refresh_config(server, input, tls)`
/// precedent. This struct captures sandbox-specific options.
#[derive(Debug)]
pub struct SandboxCreateConfig<'a> {
    pub name: Option<&'a str>,
    pub template: Option<&'a str>,
    pub from: Option<&'a str>,
    pub uploads: &'a [(String, Option<String>, bool)],
    pub keep: bool,
    pub gpu_requirements: Option<GpuResourceRequirements>,
    pub cpu: Option<&'a str>,
    pub memory: Option<&'a str>,
    pub driver_config_json: Option<&'a str>,
    pub editor: Option<Editor>,
    pub providers: &'a [String],
    pub policy: Option<&'a str>,
    pub forward: Option<ForwardSpec>,
    pub command: &'a [String],
    pub tty_override: Option<bool>,
    pub auto_providers_override: Option<bool>,
    pub labels: HashMap<String, String>,
    pub environment: HashMap<String, String>,
    pub approval_mode: &'a str,
    pub output: &'a str,
    pub detach: bool,
}

impl Default for SandboxCreateConfig<'_> {
    fn default() -> Self {
        Self {
            name: None,
            template: None,
            from: None,
            uploads: &[],
            keep: false,
            gpu_requirements: None,
            cpu: None,
            memory: None,
            driver_config_json: None,
            editor: None,
            providers: &[],
            policy: None,
            forward: None,
            command: &[],
            tty_override: None,
            auto_providers_override: None,
            labels: HashMap::new(),
            environment: HashMap::new(),
            approval_mode: "manual",
            output: "table",
            detach: false,
        }
    }
}

/// Create a sandbox with default settings.
pub async fn sandbox_create(
    server: &str,
    gateway_name: &str,
    config: SandboxCreateConfig<'_>,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<i32> {
    let SandboxCreateConfig {
        name,
        template,
        from,
        uploads,
        keep,
        gpu_requirements,
        cpu,
        memory,
        driver_config_json,
        editor,
        providers,
        policy,
        forward,
        command,
        tty_override,
        auto_providers_override,
        labels,
        environment,
        approval_mode,
        output,
        detach,
    } = config;

    if editor.is_some() && !command.is_empty() {
        return Err(miette::miette!(
            "--editor cannot be used with a trailing command; use `openshell sandbox connect <name> --editor ...` after the sandbox is ready"
        ));
    }
    if !uploads.is_empty() && !command.is_empty() {
        return Err(miette::miette!(
            "--upload cannot be combined with a trailing main command yet because uploads complete after the canonical process starts"
        ));
    }
    if output != "table" && !command.is_empty() && !detach {
        return Err(miette::miette!(
            "structured output cannot be combined with an attached trailing command; use table output to stream the command or add --detach"
        ));
    }

    // Check port availability *before* creating the sandbox so we don't
    // leave an orphaned sandbox behind when the forward would fail.
    if let Some(ref spec) = forward {
        openshell_core::forward::check_port_available(spec)?;
    }

    let mut client = grpc_client(server, tls).await.wrap_err_with(|| {
        format!(
            "failed to connect to gateway '{gateway_name}' at {server}. \
                 Start the gateway service with the installed package manager, \
                 or register a different endpoint with `openshell gateway add <endpoint>`."
        )
    })?;
    let effective_server = server.to_string();
    let effective_tls = tls.clone();

    if template.is_some()
        && (from.is_some()
            || gpu_requirements.is_some()
            || cpu.is_some()
            || memory.is_some()
            || driver_config_json.is_some()
            || !environment.is_empty())
    {
        return Err(miette::miette!(
            "--template cannot be combined with inline workload flags"
        ));
    }

    // Resolve the --from flag into a container image reference, building from
    // a Dockerfile first if necessary. Template creates resolve workload shape
    // on the gateway and skip local image handling.
    let image: Option<String> = if template.is_some() {
        None
    } else {
        match from {
            Some(val) => {
                let resolved = resolve_from(val)?;
                match resolved {
                    ResolvedSource::Image(img) => Some(img),
                    ResolvedSource::Dockerfile {
                        dockerfile,
                        context,
                    } => {
                        let tag =
                            build_from_dockerfile(&dockerfile, &context, gateway_name).await?;
                        Some(tag)
                    }
                }
            }
            None => None,
        }
    };
    let inferred_types: Vec<String> = inferred_provider_type(command).into_iter().collect();
    let configured_providers = ensure_required_providers(
        &mut client,
        providers,
        &inferred_types,
        auto_providers_override,
        workspace,
    )
    .await?;

    let policy = load_sandbox_policy(policy)?;
    let resource_limits = if template.is_none() {
        build_sandbox_resource_limits(cpu, memory)?
    } else {
        None
    };
    let driver_config = if template.is_none() {
        driver_config_json
            .map(parse_driver_config_json)
            .transpose()?
    } else {
        None
    };

    let inline_template = if image.is_some() || resource_limits.is_some() || driver_config.is_some()
    {
        Some(SandboxTemplate {
            image: image.unwrap_or_default(),
            resources: resource_limits,
            driver_config,
            ..SandboxTemplate::default()
        })
    } else {
        None
    };

    let resource_requirements = gpu_requirements.map(|gpu| ResourceRequirements { gpu: Some(gpu) });

    let main_terminal = tty_override
        .unwrap_or_else(|| std::io::stdin().is_terminal() && std::io::stdout().is_terminal());
    let main_command = if command.is_empty() {
        vec!["/bin/bash".to_string(), "-l".to_string()]
    } else {
        command.to_vec()
    };
    let persist = sandbox_should_persist(keep, forward.as_ref());
    let create_detaches = detach
        || (persist
            && command.is_empty()
            && (!std::io::stdin().is_terminal() || !std::io::stdout().is_terminal()));
    let await_main_process_attachment = output == "table" && editor.is_none() && !create_detaches;
    let annotations = if persist {
        HashMap::new()
    } else {
        HashMap::from([(
            "openshell.nvidia.com/retention".to_string(),
            "ephemeral".to_string(),
        )])
    };
    let request = CreateSandboxRequest {
        spec: Some(SandboxSpec {
            resource_requirements,
            environment: if template.is_none() {
                environment
            } else {
                HashMap::new()
            },
            policy,
            providers: configured_providers,
            template: inline_template,
            command: main_command,
            tty: main_terminal,
            ..SandboxSpec::default()
        }),
        name: name.unwrap_or_default().to_string(),
        labels,
        annotations,
        workspace: workspace.to_string(),
        await_main_process_attachment,
        workload_template_name: template.unwrap_or_default().to_string(),
    };

    let response = match client.create_sandbox(request).await {
        Ok(resp) => resp,
        Err(status) if status.code() == Code::AlreadyExists => {
            return Err(miette::miette!(
                "{}\n\nhint: delete it first with: openshell sandbox delete <name>\n      or use a different name",
                status.message()
            ));
        }
        Err(status) => return Err(miette::miette!(status.to_string())),
    };
    let sandbox = response
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox missing from response"))?;

    let interactive = std::io::stdout().is_terminal();
    let sandbox_name = if sandbox.object_name().is_empty() {
        "unknown".to_string()
    } else {
        sandbox.object_name().to_string()
    };

    // Record this sandbox as the last-used for the active gateway only when it
    // is expected to persist beyond the initial session.
    if persist && let Some(gateway) = effective_tls.gateway_name() {
        let _ = save_last_sandbox(gateway, workspace, &sandbox_name);
    }

    // Persist `--approval-mode` as a sandbox-scoped setting now that the
    // sandbox exists. `manual` is the implicit default (no setting needed);
    // any other value is written so it survives sandbox restarts and can be
    // flipped later via `openshell settings set <name> proposal_approval_mode`.
    // If the write fails the sandbox still runs in default `manual` — surface
    // the recovery command so the user can retry.
    if approval_mode != "manual" {
        let setting = parse_cli_setting_value(settings::PROPOSAL_APPROVAL_MODE_KEY, approval_mode)?;
        match client
            .update_config(UpdateConfigRequest {
                name: sandbox_name.clone(),
                setting_key: settings::PROPOSAL_APPROVAL_MODE_KEY.to_string(),
                setting_value: Some(setting),
                workspace: workspace.to_string(),
                ..Default::default()
            })
            .await
        {
            Ok(_) => {}
            Err(status) => {
                eprintln!(
                    "{} failed to set approval mode '{approval_mode}' on sandbox '{sandbox_name}': {}\n  retry with: openshell settings set {sandbox_name} proposal_approval_mode {approval_mode}",
                    "warning:".yellow().bold(),
                    status.message(),
                );
            }
        }
    }

    let structured_output = output != "table";

    // Set up display — interactive terminals get a step-based checklist with
    // spinners; non-interactive (pipes / CI) get timestamped lines;
    // structured output suppresses all stdout progress.
    let mut display = if structured_output {
        ProgressOutput::Silent
    } else if interactive {
        ProgressOutput::Interactive(ProvisioningDisplay::new())
    } else {
        ProgressOutput::Plain
    };

    if structured_output {
        eprintln!("Provisioning sandbox (structured output on stdout)...");
    } else {
        // Print header
        print_sandbox_header(&sandbox, display.as_interactive());

        // Set initial active step on the spinner.
        match &mut display {
            ProgressOutput::Interactive(d) => {
                d.set_active_step(ProvisioningStep::RequestingSandbox);
            }
            ProgressOutput::Plain => {
                let ts = format_timestamp(Duration::ZERO);
                println!("  {} Requesting compute...", ts.dimmed());
            }
            ProgressOutput::Silent => {}
        }
    }

    // Non-interactive mode: track start time for timestamps.
    let provision_start = Instant::now();

    // Don't use stop_on_terminal on the server — the Kubernetes CRD may
    // briefly report a stale Ready status before the controller reconciles
    // a newly created sandbox.  Instead we handle termination client-side:
    // we wait until we have observed at least one non-Ready phase followed
    // by Ready (a genuine Provisioning → Ready transition).
    let sandbox_id = if sandbox.object_id().is_empty() {
        "unknown".to_string()
    } else {
        sandbox.object_id().to_string()
    };
    let mut stream = client
        .watch_sandbox(WatchSandboxRequest {
            id: sandbox_id.clone(),
            follow_status: true,
            follow_logs: true,
            follow_events: true,
            log_tail_lines: 200,
            event_tail: 50,
            stop_on_terminal: false,
            log_since_ms: 0,
            log_sources: vec!["gateway".to_string()],
            log_min_level: String::new(),
        })
        .await
        .into_diagnostic()?
        .into_inner();

    let mut last_phase = sandbox.phase();
    let mut last_sandbox = sandbox.clone();
    let mut last_error_reason = String::new();
    let mut last_condition_message = ready_false_condition_message(sandbox.status.as_ref());
    // Track whether we have seen a non-Ready phase during the watch.
    let mut saw_non_ready = SandboxPhase::try_from(sandbox.phase()) != Ok(SandboxPhase::Ready);
    let provision_timeout = Duration::from_secs(
        std::env::var("OPENSHELL_PROVISION_TIMEOUT")
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(300),
    );
    let mut provisioning_idle_deadline = Instant::now() + provision_timeout;
    // Track whether we saw the gateway become ready (from log messages).
    let mut saw_gateway_ready = false;

    loop {
        // Timeout only when provisioning goes idle. VM first-create can spend
        // longer than the default timeout pulling and preparing large images,
        // but only recognized progress events extend the idle deadline. Logs
        // and generic status churn must not keep a stuck sandbox alive forever.
        let remaining = provisioning_idle_deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            let timeout_message = provisioning_timeout_message(
                provision_timeout.as_secs(),
                resource_requirements.as_ref(),
                last_condition_message.as_deref(),
            );
            if let Some(d) = display.as_interactive_mut() {
                d.finish_error(&timeout_message);
            }
            if display.is_plain() {
                println!();
            }
            return Err(miette::miette!(timeout_message));
        }

        let maybe_item = tokio::time::timeout(remaining, stream.next()).await;

        let item = match maybe_item {
            Ok(Some(item)) => item,
            Ok(None) => break, // stream ended
            Err(_elapsed) => {
                // Timeout fired — the stream was idle for too long.
                let timeout_message = provisioning_timeout_message(
                    provision_timeout.as_secs(),
                    resource_requirements.as_ref(),
                    last_condition_message.as_deref(),
                );
                if let Some(d) = display.as_interactive_mut() {
                    d.finish_error(&timeout_message);
                }
                if display.is_plain() {
                    println!();
                }
                return Err(miette::miette!(timeout_message));
            }
        };

        let evt = item.into_diagnostic()?;
        match evt.payload {
            Some(openshell_core::proto::sandbox_stream_event::Payload::Sandbox(s)) => {
                let phase = SandboxPhase::try_from(s.phase()).unwrap_or(SandboxPhase::Unknown);
                last_phase = s.phase();
                last_sandbox = s.clone();
                if let Some(message) = ready_false_condition_message(s.status.as_ref()) {
                    last_condition_message = Some(message);
                }

                if phase != SandboxPhase::Ready {
                    saw_non_ready = true;
                }

                let main_process_result = has_main_process_result(&s);
                if matches!(
                    phase,
                    SandboxPhase::Completed | SandboxPhase::Error | SandboxPhase::Stopped
                ) && main_process_result
                {
                    if let Some(d) = display.as_interactive_mut() {
                        d.clear();
                    }
                    break;
                }

                // Capture infrastructure error reasons only after excluding a
                // canonical-command result, which must attach and drain output.
                if phase == SandboxPhase::Error
                    && let Some(status) = &s.status
                {
                    for condition in &status.conditions {
                        if condition.r#type == "Ready"
                            && condition.status.eq_ignore_ascii_case("false")
                        {
                            last_error_reason =
                                format!("{}: {}", condition.reason, condition.message);
                        }
                    }
                    break;
                }

                // Only accept Ready as terminal after we've observed a
                // non-Ready phase, proving the controller has reconciled.
                if saw_non_ready && phase == SandboxPhase::Ready {
                    if let Some(d) = display.as_interactive_mut() {
                        d.clear();
                    }
                    break;
                }
            }
            Some(openshell_core::proto::sandbox_stream_event::Payload::Log(line)) => {
                // Detect gateway readiness from log messages.
                if !saw_gateway_ready && line.message.contains("listening") {
                    saw_gateway_ready = true;
                }
            }
            Some(openshell_core::proto::sandbox_stream_event::Payload::Event(ev)) => {
                let extends_timeout = is_provisioning_progress_event(&ev);
                // Silent mode suppresses all progress output; only update
                // the deadline when applicable.
                let handled = match &mut display {
                    ProgressOutput::Interactive(d) => {
                        handle_platform_progress_event(&ev, Some(d), provision_start)
                    }
                    ProgressOutput::Plain => {
                        handle_platform_progress_event(&ev, None, provision_start)
                    }
                    ProgressOutput::Silent => false,
                };
                if handled {
                    if extends_timeout {
                        provisioning_idle_deadline = Instant::now() + provision_timeout;
                    }
                    continue;
                }
                if extends_timeout {
                    provisioning_idle_deadline = Instant::now() + provision_timeout;
                }

                if let Some(d) = display.as_interactive_mut()
                    && !ev.message.is_empty()
                {
                    d.set_active_detail(&ev.message);
                }
            }
            Some(openshell_core::proto::sandbox_stream_event::Payload::Warning(w)) => {
                match &display {
                    ProgressOutput::Interactive(d) => {
                        d.println(&format!("  {} {}", "!".yellow().bold(), w.message.yellow()));
                    }
                    ProgressOutput::Plain | ProgressOutput::Silent => {
                        let ts = format_timestamp(provision_start.elapsed());
                        eprintln!("  {} {} {}", ts.dimmed(), "WARN".yellow(), w.message);
                    }
                }
            }
            Some(openshell_core::proto::sandbox_stream_event::Payload::DraftPolicyUpdate(_))
            | None => {
                // Draft policy updates are handled in the draft panel, not during provisioning.
            }
        }
    }

    // If we exited the loop without hitting the Ready break, finish the display.
    let final_phase = SandboxPhase::try_from(last_phase).unwrap_or(SandboxPhase::Unknown);
    let final_has_main_process_result = has_main_process_result(&last_sandbox);
    if !(matches!(
        final_phase,
        SandboxPhase::Ready | SandboxPhase::Completed | SandboxPhase::Stopped
    ) || final_phase == SandboxPhase::Error && final_has_main_process_result)
        && let Some(d) = display.as_interactive_mut()
    {
        if final_phase == SandboxPhase::Error {
            let msg = if last_error_reason.is_empty() {
                "Sandbox entered error phase".to_string()
            } else {
                format!("Error: {last_error_reason}")
            };
            d.finish_error(&msg);
        } else {
            d.finish_error("Provisioning stream ended unexpectedly");
        }
    }
    drop(display);
    let _ = std::io::stdout().flush();
    let _ = std::io::stderr().flush();

    match final_phase {
        SandboxPhase::Ready => {
            drop(stream);
            drop(client);

            let upload_count = uploads.len();
            for (idx, (local_path, sandbox_path, git_ignore)) in uploads.iter().enumerate() {
                let dest = sandbox_path.as_deref();
                let dest_display = dest.unwrap_or("~");
                if upload_count > 1 {
                    eprintln!(
                        "  {} Uploading [{}/{}] files to {dest_display}...",
                        "\u{2022}".dimmed(),
                        idx + 1,
                        upload_count,
                    );
                } else {
                    eprintln!(
                        "  {} Uploading files to {dest_display}...",
                        "\u{2022}".dimmed(),
                    );
                }
                let local = Path::new(local_path);
                match sandbox_upload_plan(local, *git_ignore)? {
                    SandboxUploadPlan::GitAware { base_dir, files } => {
                        sandbox_sync_up_files(
                            &effective_server,
                            &sandbox_name,
                            &base_dir,
                            &files,
                            local,
                            dest,
                            &effective_tls,
                            workspace,
                        )
                        .await?;
                    }
                    SandboxUploadPlan::GitFilteredEmpty => {
                        eprintln!(
                            "  {} .gitignore filtering excluded all files in {}; uploading unfiltered",
                            "⚠".yellow().bold(),
                            local.display(),
                        );
                        sandbox_sync_up(
                            &effective_server,
                            &sandbox_name,
                            local,
                            dest,
                            &effective_tls,
                            workspace,
                        )
                        .await?;
                    }
                    SandboxUploadPlan::Regular => {
                        sandbox_sync_up(
                            &effective_server,
                            &sandbox_name,
                            local,
                            dest,
                            &effective_tls,
                            workspace,
                        )
                        .await?;
                    }
                }
                eprintln!("  {} Files uploaded", "\u{2713}".green().bold());
            }

            // If --forward was requested, start the background port forward
            // *before* running the command so that long-running processes
            // (e.g. a web gateway) are reachable immediately.
            if let Some(ref spec) = forward {
                sandbox_forward(
                    &effective_server,
                    &sandbox_name,
                    spec,
                    true, // background
                    &effective_tls,
                    workspace,
                )
                .await?;
                eprintln!(
                    "  {} Forwarding port {} to sandbox {sandbox_name} in the background\n",
                    "\u{2713}".green().bold(),
                    spec.port,
                );
                eprintln!("  Access at: {}", spec.access_url());
                eprintln!(
                    "  Stop with: openshell forward stop {} {sandbox_name}",
                    spec.port,
                );
            }

            if structured_output {
                crate::output::print_output_single(output, &last_sandbox, sandbox_to_json)?;
                return Ok(0);
            }

            if let Some(editor) = editor {
                let ssh_gateway_name = effective_tls.gateway_name().unwrap_or(gateway_name);
                sandbox_connect_editor(
                    &effective_server,
                    ssh_gateway_name,
                    &sandbox_name,
                    editor,
                    &effective_tls,
                    workspace,
                )
                .await?;
                return Ok(0);
            }

            // An explicit trailing command is foreground regardless of TTY
            // detection. Only --detach opts out. Scratch shells retain the
            // non-interactive implicit-detach behavior.
            if detach
                || (persist
                    && command.is_empty()
                    && (!std::io::stdin().is_terminal() || !std::io::stdout().is_terminal()))
            {
                return Ok(0);
            }

            let connect_result = if persist {
                sandbox_connect(&effective_server, &sandbox_name, &effective_tls, workspace).await
            } else {
                crate::ssh::sandbox_connect_without_exec(
                    &effective_server,
                    &sandbox_name,
                    &effective_tls,
                    workspace,
                )
                .await
            };

            finalize_sandbox_create_session(
                &effective_server,
                &sandbox_name,
                persist,
                connect_result,
                workspace,
                &effective_tls,
                gateway_name,
            )
            .await
        }
        SandboxPhase::Completed | SandboxPhase::Stopped | SandboxPhase::Error
            if final_has_main_process_result =>
        {
            drop(stream);
            drop(client);
            if detach {
                return Ok(0);
            }
            let connect_result = crate::ssh::sandbox_connect_terminal_main(
                &effective_server,
                &sandbox_name,
                &effective_tls,
                workspace,
            )
            .await;
            finalize_sandbox_create_session(
                &effective_server,
                &sandbox_name,
                persist,
                connect_result,
                workspace,
                &effective_tls,
                gateway_name,
            )
            .await
        }
        SandboxPhase::Error => {
            drop(stream);
            drop(client);
            let create_result = if last_error_reason.is_empty() {
                Err(miette::miette!(
                    "sandbox entered error phase while provisioning"
                ))
            } else {
                Err(miette::miette!(
                    "sandbox entered error phase while provisioning: {}",
                    last_error_reason
                ))
            };
            finalize_sandbox_create_session(
                &effective_server,
                &sandbox_name,
                persist,
                create_result,
                workspace,
                &effective_tls,
                gateway_name,
            )
            .await
        }
        _ => Err(miette::miette!(
            "sandbox provisioning stream ended before reaching terminal phase"
        )),
    }
}

/// Resolved source for the `--from` flag on `sandbox create`.
#[derive(Debug)]
enum ResolvedSource {
    /// A ready-to-use container image reference.
    Image(String),
    /// A Dockerfile that must be built before creating the sandbox.
    Dockerfile {
        dockerfile: PathBuf,
        context: PathBuf,
    },
}

/// Classify the `--from` value into an image reference or a Dockerfile that
/// needs building.
///
/// Resolution order:
/// 1. Existing file whose name contains "Dockerfile" → build from file.
/// 2. Existing directory that contains a `Dockerfile` → build from directory.
/// 3. Missing explicit local paths → local error, not image pull.
/// 4. Value contains `/`, `:`, or `.` → treat as a full image reference.
/// 5. Otherwise → community sandbox name, expanded via the registry prefix.
fn resolve_from(value: &str) -> Result<ResolvedSource> {
    let path = Path::new(value);

    // 1. Existing file that looks like a Dockerfile.
    if path.is_file() {
        if filename_looks_like_dockerfile(path) {
            let dockerfile = path
                .canonicalize()
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to resolve path: {}", path.display()))?;
            let context = dockerfile
                .parent()
                .ok_or_else(|| miette::miette!("Dockerfile has no parent directory"))?
                .to_path_buf();
            return Ok(ResolvedSource::Dockerfile {
                dockerfile,
                context,
            });
        }

        if value_looks_like_local_source(value) {
            return Err(miette::miette!(
                "local --from file is not a Dockerfile: {}",
                path.display()
            ));
        }
    }

    // 2. Existing directory containing a Dockerfile.
    if path.is_dir() {
        let candidate = path.join("Dockerfile");
        if candidate.is_file() {
            let context = path
                .canonicalize()
                .into_diagnostic()
                .wrap_err_with(|| format!("failed to resolve path: {}", path.display()))?;
            let dockerfile = context.join("Dockerfile");
            return Ok(ResolvedSource::Dockerfile {
                dockerfile,
                context,
            });
        }
        return Err(miette::miette!(
            "No Dockerfile found in directory: {}",
            path.display()
        ));
    }

    if path.exists() {
        return Err(miette::miette!(
            "local --from path is not a regular file or directory: {}",
            path.display()
        ));
    }

    // 3. Missing explicit local paths should fail locally. Otherwise values
    // like `./Dockerfile` reach the gateway as image references and fail as
    // Docker pull errors.
    if value_looks_like_local_source(value) {
        return Err(miette::miette!(
            "local --from path does not exist: {}\n\
             Use an existing Dockerfile, a directory containing Dockerfile, or a container image reference.",
            path.display()
        ));
    }

    // 4. Full image reference or community sandbox name — delegate to shared
    //    resolution in openshell-core.
    Ok(ResolvedSource::Image(
        openshell_core::image::resolve_community_image(value),
    ))
}

fn filename_looks_like_dockerfile(path: &Path) -> bool {
    let name = path
        .file_name()
        .map(|n| n.to_string_lossy())
        .unwrap_or_default();
    let lower = name.to_lowercase();
    lower.contains("dockerfile") || lower.ends_with(".dockerfile")
}

fn value_looks_like_local_source(value: &str) -> bool {
    value_is_explicit_local_path(value) || value_looks_like_bare_dockerfile_name(value)
}

fn value_is_explicit_local_path(value: &str) -> bool {
    let path = Path::new(value);
    path.is_absolute()
        || matches!(value, "." | "..")
        || value.starts_with("./")
        || value.starts_with("../")
        || value.starts_with("~/")
}

fn value_looks_like_bare_dockerfile_name(value: &str) -> bool {
    !value.contains('/') && !value.contains(':') && filename_looks_like_dockerfile(Path::new(value))
}

fn dockerfile_sources_supported_for_gateway(metadata: Option<&GatewayMetadata>) -> bool {
    !metadata.is_some_and(|metadata| metadata.is_remote)
}

/// Build a Dockerfile and return the local Docker tag.
///
/// Package-managed local gateways use the same Docker daemon that the CLI
/// builds into, so the tag is passed through directly and the active compute
/// driver resolves it.
async fn build_from_dockerfile(
    dockerfile: &Path,
    context: &Path,
    gateway_name: &str,
) -> Result<String> {
    let metadata = get_gateway_metadata(gateway_name);
    if !dockerfile_sources_supported_for_gateway(metadata.as_ref()) {
        return Err(miette!(
            "local Dockerfile sources are only supported for local gateways; gateway '{}' is remote",
            gateway_name
        ));
    }

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let tag = format!("openshell/sandbox-from:{timestamp}");

    eprintln!(
        "Building image {} from {}",
        tag.cyan(),
        dockerfile.display()
    );
    eprintln!("  {} {}", "Context:".dimmed(), context.display());
    eprintln!("  {} {}", "Gateway:".dimmed(), gateway_name);
    eprintln!();

    let mut on_log = |msg: String| {
        eprintln!("  {msg}");
    };

    openshell_bootstrap::build::build_local_image(
        dockerfile,
        &tag,
        context,
        &HashMap::new(),
        &mut on_log,
    )
    .await?;

    eprintln!();
    eprintln!(
        "{} Image {} is available in the local Docker daemon for gateway '{}'.",
        "✓".green().bold(),
        tag.cyan(),
        gateway_name,
    );
    eprintln!();

    Ok(tag)
}

/// Load sandbox policy YAML.
///
/// Resolution order: `--policy` flag > `OPENSHELL_SANDBOX_POLICY` env var.
/// Returns `None` when no policy source is configured, allowing the server
/// to apply its own default.
fn load_sandbox_policy(cli_path: Option<&str>) -> Result<Option<SandboxPolicy>> {
    openshell_policy::load_sandbox_policy(cli_path)
}

/// Sync files to or from a sandbox.
///
/// Dispatches to `sandbox_sync_up` or `sandbox_sync_down` based on the
/// `--up` / `--down` flags.
pub async fn sandbox_sync_command(
    server: &str,
    name: &str,
    up: Option<&str>,
    down: Option<&str>,
    dest: Option<&str>,
    tls: &TlsOptions,
    workspace: &str,
) -> Result<()> {
    match (up, down) {
        (Some(local_path), None) => {
            let local = Path::new(local_path);
            if !local.exists() {
                return Err(miette::miette!(
                    "local path does not exist: {}",
                    local.display()
                ));
            }
            let dest_display = dest.unwrap_or("~");
            eprintln!("Syncing {} -> sandbox:{}", local.display(), dest_display);
            sandbox_sync_up(server, name, local, dest, tls, workspace).await?;
            eprintln!("{} Sync complete", "✓".green().bold());
        }
        (None, Some(sandbox_path)) => {
            let local_dest = dest.unwrap_or(".");
            eprintln!("Syncing sandbox:{sandbox_path} -> {local_dest}");
            sandbox_sync_down(server, name, sandbox_path, local_dest, tls, workspace).await?;
            eprintln!("{} Sync complete", "✓".green().bold());
        }
        _ => {
            return Err(miette::miette!(
                "specify either --up <local-path> or --down <sandbox-path>"
            ));
        }
    }
    Ok(())
}

/// Fetch a sandbox by name.
///
/// Policy always comes from [`GetSandboxConfig`] (effective active policy, sandbox
/// or global). With `policy_only`, prints only that YAML to stdout; otherwise
/// prints sandbox metadata and the same policy with formatted YAML.
pub async fn sandbox_get(
    server: &str,
    name: &str,
    policy_only: bool,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let response = client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;
    let sandbox = response
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox missing from response"))?;

    let sandbox_id = if sandbox.object_id().is_empty() {
        return Err(miette::miette!("sandbox missing metadata"));
    } else {
        sandbox.object_id().to_string()
    };

    let config = client
        .get_sandbox_config(GetSandboxConfigRequest { sandbox_id })
        .await
        .into_diagnostic()?
        .into_inner();

    if policy_only {
        let Some(ref policy) = config.policy else {
            return Err(miette::miette!(
                "no active policy configured for this sandbox"
            ));
        };
        let yaml_str = openshell_policy::serialize_sandbox_policy(policy)
            .wrap_err("failed to serialize policy to YAML")?;
        print!("{yaml_str}");
        return Ok(());
    }

    let detail_json = sandbox_detail_to_json(&sandbox, &config)?;
    if crate::output::print_output_single(output, &detail_json, Clone::clone)? {
        return Ok(());
    }

    println!("{}", "Sandbox:".cyan().bold());
    println!();
    let id = if sandbox.object_id().is_empty() {
        "unknown"
    } else {
        sandbox.object_id()
    };
    let name = if sandbox.object_name().is_empty() {
        "unknown"
    } else {
        sandbox.object_name()
    };
    println!("  {} {}", "Id:".dimmed(), id);
    println!("  {} {}", "Name:".dimmed(), name);
    println!("  {} {}", "Phase:".dimmed(), phase_name(sandbox.phase()));
    if let Some(exit_code) = sandbox.status.as_ref().and_then(|status| status.exit_code) {
        println!("  {} {}", "Exit Code:".dimmed(), exit_code);
    }
    println!(
        "  {} {}",
        "Resource version:".dimmed(),
        sandbox.metadata.as_ref().map_or(0, |m| m.resource_version)
    );

    // Display labels if present
    if let Some(metadata) = &sandbox.metadata
        && !metadata.labels.is_empty()
    {
        println!("  {} ", "Labels:".dimmed());
        let mut labels: Vec<_> = metadata.labels.iter().collect();
        labels.sort_by_key(|(k, _)| *k);
        for (key, value) in labels {
            println!("    {key}: {value}");
        }
    }

    if let Some(metadata) = &sandbox.metadata
        && !metadata.annotations.is_empty()
    {
        println!("  {} ", "Annotations:".dimmed());
        let mut annotations: Vec<_> = metadata.annotations.iter().collect();
        annotations.sort_by_key(|(k, _)| *k);
        for (key, value) in annotations {
            println!("    {key}: {value}");
        }
    }

    if let Some(provenance) = &sandbox.created_from_workload_template {
        println!(
            "  {} {}@{}",
            "Workload template:".dimmed(),
            provenance.name,
            provenance.resource_version
        );
    }

    let policy_from_global = config.policy_source == PolicySource::Global as i32;
    println!(
        "  {} {}",
        "Policy source:".dimmed(),
        if policy_from_global {
            "global"
        } else {
            "sandbox"
        }
    );
    let revision = if policy_from_global {
        if config.global_policy_version > 0 {
            Some(config.global_policy_version)
        } else if config.version > 0 {
            Some(config.version)
        } else {
            None
        }
    } else if config.version > 0 {
        Some(config.version)
    } else {
        None
    };
    if let Some(rev) = revision {
        println!("  {} {}", "Revision:".dimmed(), rev);
    }

    if let Some(ref policy) = config.policy {
        println!();
        print_sandbox_policy(policy);
    }

    Ok(())
}

/// Maximum stdin payload size (4 MiB). Prevents the CLI from reading unbounded
/// data into memory before the server rejects an oversized message.
const MAX_STDIN_PAYLOAD: usize = 4 * 1024 * 1024;

fn local_terminal_size() -> Option<(u32, u32)> {
    crossterm::terminal::size()
        .ok()
        .map(|(cols, rows)| (u32::from(cols), u32::from(rows)))
}

/// Execute a command in a running sandbox via gRPC, streaming output to the terminal.
///
/// Returns the remote command's exit code, or an error if the event stream
/// closes before the command reports an exit status.
#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub async fn sandbox_exec_grpc(
    server: &str,
    name: &str,
    command: &[String],
    workdir: Option<&str>,
    timeout_seconds: u32,
    tty_override: Option<bool>,
    environment: &HashMap<String, String>,
    no_login_shell: bool,
    tls: &TlsOptions,
    workspace: &str,
) -> Result<i32> {
    let mut client = grpc_client(server, tls).await?;

    // Resolve sandbox name to id.
    let sandbox = client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox not found"))?;

    // Verify the sandbox is ready before issuing the exec.
    if SandboxPhase::try_from(sandbox.phase()) != Ok(SandboxPhase::Ready) {
        return Err(miette::miette!(
            "sandbox '{}' is not ready (phase: {}); wait for it to reach Ready state",
            name,
            phase_name(sandbox.phase())
        ));
    }

    // Read stdin if piped (not a TTY), using spawn_blocking to avoid blocking
    // the async runtime. Cap the read at MAX_STDIN_PAYLOAD + 1 so we never
    // buffer more than the limit into memory.
    let stdin_payload = if std::io::stdin().is_terminal() {
        Vec::new()
    } else {
        tokio::task::spawn_blocking(|| {
            let limit = (MAX_STDIN_PAYLOAD + 1) as u64;
            let mut buf = Vec::new();
            std::io::stdin()
                .take(limit)
                .read_to_end(&mut buf)
                .into_diagnostic()?;
            if buf.len() > MAX_STDIN_PAYLOAD {
                return Err(miette::miette!(
                    "stdin payload exceeds {} byte limit; pipe smaller inputs or use `sandbox upload`",
                    MAX_STDIN_PAYLOAD
                ));
            }
            Ok(buf)
        })
        .await
        .into_diagnostic()?? // first ? unwraps JoinError, second ? unwraps Result
    };

    // Resolve TTY mode: explicit --tty / --no-tty wins, otherwise auto-detect.
    let tty = tty_override
        .unwrap_or_else(|| std::io::stdin().is_terminal() && std::io::stdout().is_terminal());

    if tty && std::io::stdin().is_terminal() {
        return sandbox_exec_interactive_grpc(
            client,
            &sandbox,
            command,
            workdir,
            timeout_seconds,
            environment,
            no_login_shell,
        )
        .await;
    }

    let (cols, rows) = if tty {
        local_terminal_size().unwrap_or_default()
    } else {
        (0, 0)
    };

    // Make the streaming gRPC call.
    let mut stream = client
        .exec_sandbox(ExecSandboxRequest {
            sandbox_id: sandbox.object_id().to_string(),
            command: command.to_vec(),
            workdir: workdir.unwrap_or_default().to_string(),
            environment: environment.clone(),
            timeout_seconds,
            stdin: stdin_payload,
            tty,
            cols,
            rows,
            no_login_shell,
        })
        .await
        .into_diagnostic()?
        .into_inner();

    // Stream output to terminal in real-time.
    let mut exit_code = 0i32;
    let mut exit_seen = false;
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();

    while let Some(event) = stream.next().await {
        let event = event.into_diagnostic()?;
        match event.payload {
            Some(exec_sandbox_event::Payload::Stdout(out)) => {
                let mut handle = stdout.lock();
                handle.write_all(&out.data).into_diagnostic()?;
                handle.flush().into_diagnostic()?;
            }
            Some(exec_sandbox_event::Payload::Stderr(err)) => {
                let mut handle = stderr.lock();
                handle.write_all(&err.data).into_diagnostic()?;
                handle.flush().into_diagnostic()?;
            }
            Some(exec_sandbox_event::Payload::Exit(exit)) => {
                exit_code = exit.exit_code;
                exit_seen = true;
            }
            None => {}
        }
    }

    // A stream that closes without an Exit event means we never observed the
    // command's outcome. The server treats the same condition as a relay
    // failure; mirror that here so exit 0 stays meaningful.
    if !exit_seen {
        return Err(miette::miette!(
            "sandbox exec relay closed before the command reported an exit status"
        ));
    }

    Ok(exit_code)
}

pub async fn service_forward_tcp(
    server: &str,
    name: &str,
    local: Option<&str>,
    target_host: &str,
    target_port: u16,
    tls: &TlsOptions,
    workspace: &str,
) -> Result<()> {
    let (bind_addr, bind_port) = parse_tcp_forward_spec(local, target_port)?;
    let mut client = grpc_client(server, tls).await?;

    let sandbox = fetch_ready_sandbox_for_forward(&mut client, name, workspace).await?;

    let listener = tokio::net::TcpListener::bind((bind_addr.as_str(), bind_port))
        .await
        .into_diagnostic()
        .wrap_err_with(|| format!("failed to bind local forward on {bind_addr}:{bind_port}"))?;
    let local_addr = listener
        .local_addr()
        .into_diagnostic()
        .wrap_err("failed to read local forward address")?;
    eprintln!(
        "{} Forwarding {} -> {}:{} in sandbox {} via gRPC",
        "✓".green().bold(),
        local_addr,
        target_host,
        target_port,
        name,
    );

    let sandbox_id = sandbox.object_id().to_string();
    let (fatal_tx, mut fatal_rx) = tokio::sync::mpsc::channel::<String>(1);
    let mut health_check = tokio::time::interval(Duration::from_secs(2));
    health_check.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            Some(reason) = fatal_rx.recv() => {
                return Err(miette::miette!("service forward stopped: {reason}"));
            }

            _ = health_check.tick() => {
                fetch_ready_sandbox_for_forward(&mut client, name, workspace).await?;
            }

            accepted = listener.accept() => {
                let (socket, peer) = accepted
                    .into_diagnostic()
                    .wrap_err("failed to accept local forward connection")?;
                set_tcp_nodelay_best_effort(&socket);
                let mut client = client.clone();
                let sandbox_id = sandbox_id.clone();
                let target_host = target_host.to_string();
                let service_id = format!("service-forward:{name}:{target_host}:{target_port}");
                let fatal_tx = fatal_tx.clone();
                tokio::spawn(async move {
                    let token = match create_forward_session_token(&mut client, &sandbox_id).await {
                        Ok(token) => token,
                        Err(err) => {
                            tracing::warn!(peer = %peer, error = %err, "service forward session creation failed");
                            if err.fatal {
                                let _ = fatal_tx.send(err.message).await;
                            }
                            return;
                        }
                    };
                    if let Err(err) = forward_one_tcp_connection(
                        &mut client,
                        socket,
                        sandbox_id,
                        target_host,
                        target_port,
                        service_id,
                        token.clone(),
                    )
                    .await
                    {
                        tracing::warn!(peer = %peer, error = %err, "service forward connection failed");
                        if err.fatal {
                            let _ = fatal_tx.send(err.message).await;
                        }
                    }
                    let _ = client
                        .revoke_ssh_session(RevokeSshSessionRequest { token })
                        .await;
                });
            }
        }
    }
}

async fn create_forward_session_token(
    client: &mut crate::tls::GrpcClient,
    sandbox_id: &str,
) -> std::result::Result<String, ForwardTcpConnectionError> {
    let response = client
        .create_ssh_session(CreateSshSessionRequest {
            sandbox_id: sandbox_id.to_string(),
        })
        .await
        .map_err(ForwardTcpConnectionError::from_status)?;
    Ok(response.into_inner().token)
}

async fn fetch_ready_sandbox_for_forward(
    client: &mut crate::tls::GrpcClient,
    name: &str,
    workspace: &str,
) -> Result<Sandbox> {
    let response = match client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
    {
        Ok(response) => response,
        Err(status) if status.code() == Code::NotFound => {
            return Err(miette::miette!(
                "sandbox '{name}' no longer exists; stopping service forward"
            ));
        }
        Err(status) => return Err(status).into_diagnostic(),
    };

    let sandbox = response
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox '{name}' not found"))?;

    if SandboxPhase::try_from(sandbox.phase()) != Ok(SandboxPhase::Ready) {
        return Err(miette::miette!(
            "sandbox '{}' is no longer ready (phase: {}); stopping service forward",
            name,
            phase_name(sandbox.phase())
        ));
    }

    Ok(sandbox)
}

#[derive(Debug)]
struct ForwardTcpConnectionError {
    message: String,
    fatal: bool,
}

impl ForwardTcpConnectionError {
    fn transient(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
            fatal: false,
        }
    }

    fn from_status(status: Status) -> Self {
        let fatal = matches!(status.code(), Code::NotFound | Code::FailedPrecondition);
        Self {
            message: status.to_string(),
            fatal,
        }
    }
}

impl std::fmt::Display for ForwardTcpConnectionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for ForwardTcpConnectionError {}

fn parse_tcp_forward_spec(local: Option<&str>, default_port: u16) -> Result<(String, u16)> {
    let Some(spec) = local else {
        return Ok(("127.0.0.1".to_string(), default_port));
    };

    if let Some(pos) = spec.rfind(':') {
        let addr = &spec[..pos];
        let port_str = &spec[pos + 1..];
        if let Ok(port) = port_str.parse::<u16>() {
            if addr.is_empty() {
                return Err(miette::miette!("bind address is required before ':'"));
            }
            return Ok((addr.to_string(), port));
        }
    }

    let port: u16 = spec.parse().map_err(|_| {
        miette::miette!("invalid local forward spec '{spec}': expected [bind_address:]port")
    })?;
    Ok(("127.0.0.1".to_string(), port))
}

async fn forward_one_tcp_connection(
    client: &mut crate::tls::GrpcClient,
    socket: tokio::net::TcpStream,
    sandbox_id: String,
    target_host: String,
    target_port: u16,
    service_id: String,
    authorization_token: String,
) -> std::result::Result<(), ForwardTcpConnectionError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_stream::wrappers::ReceiverStream;

    let (tx, rx) = tokio::sync::mpsc::channel::<TcpForwardFrame>(16);
    tx.send(TcpForwardFrame {
        payload: Some(openshell_core::proto::tcp_forward_frame::Payload::Init(
            TcpForwardInit {
                sandbox_id,
                service_id,
                target: Some(tcp_forward_init::Target::Tcp(TcpRelayTarget {
                    host: target_host,
                    port: u32::from(target_port),
                })),
                authorization_token,
            },
        )),
    })
    .await
    .map_err(|_| ForwardTcpConnectionError::transient("failed to initialize forward stream"))?;

    let mut response = match client.forward_tcp(ReceiverStream::new(rx)).await {
        Ok(response) => response.into_inner(),
        Err(status) => {
            let err = ForwardTcpConnectionError::from_status(status);
            drain_and_shutdown_local_socket(socket).await;
            return Err(err);
        }
    };

    let (mut local_read, mut local_write) = socket.into_split();

    let to_gateway = tokio::spawn(async move {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            let n = local_read.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            if tx
                .send(TcpForwardFrame {
                    payload: Some(openshell_core::proto::tcp_forward_frame::Payload::Data(
                        buf[..n].to_vec(),
                    )),
                })
                .await
                .is_err()
            {
                break;
            }
        }
        Ok::<(), std::io::Error>(())
    });

    while let Some(frame) = response
        .message()
        .await
        .map_err(ForwardTcpConnectionError::from_status)?
    {
        let Some(openshell_core::proto::tcp_forward_frame::Payload::Data(data)) = frame.payload
        else {
            continue;
        };
        if data.is_empty() {
            continue;
        }
        local_write
            .write_all(&data)
            .await
            .map_err(|err| ForwardTcpConnectionError::transient(err.to_string()))?;
    }

    let _ = local_write.shutdown().await;
    to_gateway.abort();
    Ok(())
}

async fn drain_and_shutdown_local_socket(mut socket: tokio::net::TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = [0u8; 4096];
    while matches!(
        tokio::time::timeout(Duration::from_millis(25), socket.read(&mut buf)).await,
        Ok(Ok(n)) if n != 0
    ) {}
    let _ = socket.shutdown().await;
}

struct RawModeGuard;

impl Drop for RawModeGuard {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

#[cfg(unix)]
struct TaskGuard(tokio::task::JoinHandle<()>);

#[cfg(unix)]
impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.0.abort();
    }
}

async fn sandbox_exec_interactive_grpc(
    mut client: crate::tls::GrpcClient,
    sandbox: &Sandbox,
    command: &[String],
    workdir: Option<&str>,
    timeout_seconds: u32,
    environment: &HashMap<String, String>,
    no_login_shell: bool,
) -> Result<i32> {
    #[cfg(unix)]
    use openshell_core::proto::ExecSandboxWindowResize;
    use openshell_core::proto::{ExecSandboxInput, exec_sandbox_input};
    use tokio_stream::wrappers::ReceiverStream;

    let (cols, rows) = local_terminal_size().unwrap_or((80, 24));

    let (input_tx, input_rx) = tokio::sync::mpsc::channel::<ExecSandboxInput>(4096);

    // Send the start message with exec metadata.
    input_tx
        .send(ExecSandboxInput {
            payload: Some(exec_sandbox_input::Payload::Start(ExecSandboxRequest {
                sandbox_id: sandbox.object_id().to_string(),
                command: command.to_vec(),
                workdir: workdir.unwrap_or_default().to_string(),
                environment: environment.clone(),
                no_login_shell,
                timeout_seconds,
                stdin: Vec::new(),
                tty: true,
                cols,
                rows,
            })),
        })
        .await
        .into_diagnostic()?;

    let mut stream = client
        .exec_sandbox_interactive(ReceiverStream::new(input_rx))
        .await
        .into_diagnostic()?
        .into_inner();

    // Enable raw mode so keystrokes are forwarded immediately.
    crossterm::terminal::enable_raw_mode().into_diagnostic()?;
    let raw_guard = RawModeGuard;

    // Stdin reader on a detached OS thread. Using std::thread (not
    // spawn_blocking) so the tokio runtime shutdown doesn't wait for a
    // thread blocked on stdin.read(). The thread exits when the channel
    // closes (blocking_send returns Err) or stdin hits EOF.
    let stdin_tx = input_tx.clone();
    std::thread::spawn(move || {
        let mut stdin = std::io::stdin().lock();
        let mut buf = [0u8; 4096];
        loop {
            match stdin.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    if stdin_tx
                        .blocking_send(ExecSandboxInput {
                            payload: Some(exec_sandbox_input::Payload::Stdin(buf[..n].to_vec())),
                        })
                        .is_err()
                    {
                        break;
                    }
                }
            }
        }
    });

    // SIGWINCH handler: forward terminal resize events.
    #[cfg(unix)]
    let resize_task = {
        let resize_tx = input_tx.clone();
        tokio::spawn(async move {
            let mut sig =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::window_change())
                    .expect("failed to register SIGWINCH handler");
            while sig.recv().await.is_some() {
                if let Some((cols, rows)) = local_terminal_size() {
                    let msg = ExecSandboxInput {
                        payload: Some(exec_sandbox_input::Payload::Resize(
                            ExecSandboxWindowResize { cols, rows },
                        )),
                    };
                    if resize_tx.send(msg).await.is_err() {
                        break;
                    }
                }
            }
        })
    };
    #[cfg(unix)]
    let _resize_guard = TaskGuard(resize_task);

    let mut exit_code = 0i32;
    let mut exit_seen = false;
    let stdout = std::io::stdout();
    let stderr = std::io::stderr();

    while let Some(event) = stream.next().await {
        let event = event.into_diagnostic()?;
        match event.payload {
            Some(exec_sandbox_event::Payload::Stdout(out)) => {
                let mut handle = stdout.lock();
                handle.write_all(&out.data).into_diagnostic()?;
                handle.flush().into_diagnostic()?;
            }
            Some(exec_sandbox_event::Payload::Stderr(err)) => {
                let mut handle = stderr.lock();
                handle.write_all(&err.data).into_diagnostic()?;
                handle.flush().into_diagnostic()?;
            }
            Some(exec_sandbox_event::Payload::Exit(exit)) => {
                exit_code = exit.exit_code;
                exit_seen = true;
                break;
            }
            None => {}
        }
    }

    drop(input_tx);

    // Drop the raw mode guard to restore the terminal before returning.
    drop(raw_guard);

    // A stream that closes without an Exit event means we never observed the
    // command's outcome. Treat it as a relay failure rather than reporting a
    // successful (0) exit.
    if !exit_seen {
        return Err(miette::miette!(
            "sandbox exec relay closed before the command reported an exit status"
        ));
    }

    Ok(exit_code)
}

/// List sandboxes.
#[allow(clippy::too_many_arguments)]
pub async fn sandbox_list(
    server: &str,
    limit: u32,
    offset: u32,
    ids_only: bool,
    names_only: bool,
    label_selector: Option<&str>,
    output: &str,
    workspace: &str,
    all_workspaces: bool,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let response = client
        .list_sandboxes(ListSandboxesRequest {
            limit,
            offset,
            label_selector: label_selector.unwrap_or("").to_string(),
            workspace: if all_workspaces {
                String::new()
            } else {
                workspace.to_string()
            },
            all_workspaces,
        })
        .await
        .into_diagnostic()?;

    let sandboxes = response.into_inner().sandboxes;

    if crate::output::print_output_collection(output, &sandboxes, sandbox_to_json)? {
        return Ok(());
    }

    if sandboxes.is_empty() {
        if !ids_only && !names_only {
            println!("No sandboxes found.");
        }
        return Ok(());
    }

    if ids_only {
        for sandbox in sandboxes {
            println!("{}", sandbox.object_id());
        }
        return Ok(());
    }

    if names_only {
        for sandbox in &sandboxes {
            if all_workspaces {
                println!("{}/{}", sandbox.object_workspace(), sandbox.object_name());
            } else {
                println!("{}", sandbox.object_name());
            }
        }
        return Ok(());
    }

    // Calculate column widths
    let name_width = sandboxes
        .iter()
        .map(|s| s.object_name().len())
        .max()
        .unwrap_or(4)
        .max(4);
    let created_width = 19; // "YYYY-MM-DD HH:MM:SS"
    let ws_width = if all_workspaces {
        sandboxes
            .iter()
            .map(|s| s.object_workspace().len())
            .max()
            .unwrap_or(9)
            .max(9)
    } else {
        0
    };

    // Print header
    if all_workspaces {
        println!(
            "{:<ws_width$}  {:<name_width$}  {:<created_width$}  {}",
            "WORKSPACE".bold(),
            "NAME".bold(),
            "CREATED".bold(),
            "PHASE".bold(),
        );
    } else {
        println!(
            "{:<name_width$}  {:<created_width$}  {}",
            "NAME".bold(),
            "CREATED".bold(),
            "PHASE".bold(),
        );
    }

    // Print rows
    for sandbox in sandboxes {
        let phase = phase_name(sandbox.phase());
        let phase_colored = match SandboxPhase::try_from(sandbox.phase()) {
            Ok(SandboxPhase::Ready | SandboxPhase::Completed) => phase.green().to_string(),
            Ok(SandboxPhase::Error) => phase.red().to_string(),
            Ok(SandboxPhase::Stopped)
                if sandbox
                    .status
                    .as_ref()
                    .is_some_and(|status| status.exit_code.is_some()) =>
            {
                phase.red().to_string()
            }
            Ok(SandboxPhase::Provisioning) => phase.yellow().to_string(),
            Ok(SandboxPhase::Deleting) => phase.dimmed().to_string(),
            _ => phase.to_string(),
        };
        let created = format_epoch_ms(sandbox.metadata.as_ref().map_or(0, |m| m.created_at_ms));
        if all_workspaces {
            println!(
                "{:<ws_width$}  {:<name_width$}  {:<created_width$}  {}",
                sandbox.object_workspace().to_string(),
                sandbox.object_name().to_string(),
                created,
                phase_colored,
            );
        } else {
            println!(
                "{:<name_width$}  {:<created_width$}  {}",
                sandbox.object_name().to_string(),
                created,
                phase_colored,
            );
        }
    }

    Ok(())
}

fn sandbox_to_json(sandbox: &Sandbox) -> serde_json::Value {
    let meta = sandbox.metadata.as_ref();
    let labels = meta.map_or_else(|| serde_json::json!({}), |m| serde_json::json!(m.labels));
    let annotations = meta.map_or_else(
        || serde_json::json!({}),
        |m| serde_json::json!(m.annotations),
    );
    let created_from_workload_template =
        sandbox
            .created_from_workload_template
            .as_ref()
            .map(|provenance| {
                serde_json::json!({
                    "name": provenance.name,
                    "resource_version": provenance.resource_version,
                })
            });
    serde_json::json!({
        "id": sandbox.object_id(),
        "name": sandbox.object_name(),
        "workspace": sandbox.object_workspace(),
        "labels": labels,
        "annotations": annotations,
        "resource_version": meta.map_or(0, |m| m.resource_version),
        "created_at": format_epoch_ms(meta.map_or(0, |m| m.created_at_ms)),
        "phase": phase_name(sandbox.phase()),
        "current_policy_version": sandbox.current_policy_version(),
        "exit_code": sandbox.status.as_ref().and_then(|status| status.exit_code),
        "created_from_workload_template": created_from_workload_template,
    })
}

fn sandbox_detail_to_json(
    sandbox: &Sandbox,
    config: &GetSandboxConfigResponse,
) -> Result<serde_json::Value> {
    let mut value = sandbox_to_json(sandbox);
    let obj = value
        .as_object_mut()
        .expect("sandbox_to_json returns object");

    let policy_source = if config.policy_source == PolicySource::Global as i32 {
        "global"
    } else {
        "sandbox"
    };
    obj.insert("policy_source".into(), serde_json::json!(policy_source));

    let policy_from_global = config.policy_source == PolicySource::Global as i32;
    let revision = if policy_from_global {
        if config.global_policy_version > 0 {
            Some(config.global_policy_version)
        } else if config.version > 0 {
            Some(config.version)
        } else {
            None
        }
    } else if config.version > 0 {
        Some(config.version)
    } else {
        None
    };
    obj.insert("revision".into(), serde_json::json!(revision));

    let policy_json = match config.policy.as_ref() {
        Some(p) => openshell_policy::sandbox_policy_to_json_value(p)
            .wrap_err("failed to convert policy to JSON")?,
        None => serde_json::Value::Null,
    };
    obj.insert("policy".into(), policy_json);

    Ok(value)
}

#[allow(clippy::too_many_arguments, clippy::implicit_hasher)]
pub async fn sandbox_template_create(
    server: &str,
    name: &str,
    image: Option<&str>,
    cpu: Option<&str>,
    memory: Option<&str>,
    gpu_requirements: Option<GpuResourceRequirements>,
    driver_config_json: Option<&str>,
    ready_within: Option<&str>,
    max_burst: Option<u32>,
    labels: HashMap<String, String>,
    annotations: HashMap<String, String>,
    environment: HashMap<String, String>,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let resources = if cpu.is_some() || memory.is_some() || gpu_requirements.is_some() {
        Some(SandboxResources {
            cpu: cpu
                .map(validate_cpu_quantity)
                .transpose()?
                .unwrap_or_default(),
            memory: memory
                .map(validate_memory_quantity)
                .transpose()?
                .unwrap_or_default(),
            gpu: gpu_requirements,
        })
    } else {
        None
    };
    let driver_config = driver_config_json
        .map(parse_driver_config_json)
        .transpose()?;
    let desired_service_level = build_template_service_level(ready_within, max_burst)?;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .create_sandbox_template(CreateSandboxTemplateRequest {
            template: Some(SandboxWorkloadTemplate {
                metadata: Some(openshell_core::proto::datamodel::v1::ObjectMeta {
                    id: String::new(),
                    name: name.to_string(),
                    created_at_ms: 0,
                    labels,
                    resource_version: 0,
                    annotations,
                    workspace: String::new(),
                    deletion_timestamp_ms: 0,
                }),
                spec: Some(SandboxWorkloadTemplateSpec {
                    workload: Some(SandboxWorkloadConfig {
                        image: image.unwrap_or_default().to_string(),
                        environment,
                        resources,
                    }),
                    driver_config,
                    desired_service_level,
                }),
            }),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;

    let template = response
        .into_inner()
        .template
        .ok_or_else(|| miette!("sandbox template missing from response"))?;
    if crate::output::print_output_single(output, &template, sandbox_template_to_json)? {
        return Ok(());
    }
    println!(
        "{} Created sandbox template {}",
        "✓".green().bold(),
        template.object_name().bold()
    );
    Ok(())
}

fn build_template_service_level(
    ready_within: Option<&str>,
    max_burst: Option<u32>,
) -> Result<Option<SandboxServiceLevel>> {
    if ready_within.is_none() && max_burst.is_none() {
        return Ok(None);
    }
    let ready_within = ready_within
        .map(parse_duration_to_ms)
        .transpose()?
        .map(|ms| {
            if ms <= 0 {
                Err(miette!("--ready-within must be greater than zero"))
            } else {
                Ok(duration_ms_to_proto(ms))
            }
        })
        .transpose()?;
    Ok(Some(SandboxServiceLevel {
        startup: Some(SandboxStartup {
            ready_within,
            max_burst: max_burst.unwrap_or_default(),
        }),
    }))
}

fn duration_ms_to_proto(ms: i64) -> prost_types::Duration {
    prost_types::Duration {
        seconds: ms / 1_000,
        nanos: i32::try_from((ms % 1_000) * 1_000_000)
            .expect("duration millisecond remainder fits in protobuf nanos"),
    }
}

pub async fn sandbox_template_get(
    server: &str,
    name: &str,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_sandbox_template(GetSandboxTemplateRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;
    let template = response
        .into_inner()
        .template
        .ok_or_else(|| miette!("sandbox template missing from response"))?;

    if crate::output::print_output_single(output, &template, sandbox_template_to_json)? {
        return Ok(());
    }

    print_sandbox_template_detail(&template);
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn sandbox_template_list(
    server: &str,
    limit: u32,
    offset: u32,
    label_selector: Option<&str>,
    names_only: bool,
    output: &str,
    workspace: &str,
    all_workspaces: bool,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .list_sandbox_templates(ListSandboxTemplatesRequest {
            limit,
            offset,
            workspace: if all_workspaces {
                String::new()
            } else {
                workspace.to_string()
            },
            all_workspaces,
            label_selector: label_selector.unwrap_or_default().to_string(),
        })
        .await
        .into_diagnostic()?;
    let templates = response.into_inner().templates;

    if crate::output::print_output_collection(output, &templates, sandbox_template_to_json)? {
        return Ok(());
    }

    if templates.is_empty() {
        if !names_only {
            println!("No sandbox templates found.");
        }
        return Ok(());
    }

    if names_only {
        for template in &templates {
            if all_workspaces {
                println!("{}/{}", template.object_workspace(), template.object_name());
            } else {
                println!("{}", template.object_name());
            }
        }
        return Ok(());
    }

    print_sandbox_template_table(&templates, all_workspaces);
    Ok(())
}

pub async fn sandbox_template_delete(
    server: &str,
    names: &[String],
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    for name in names {
        let response = client
            .delete_sandbox_template(DeleteSandboxTemplateRequest {
                name: name.clone(),
                workspace: workspace.to_string(),
            })
            .await
            .into_diagnostic()?;
        if response.into_inner().deleted {
            println!("{} Deleted sandbox template {name}", "✓".green().bold());
        } else {
            println!("Sandbox template {name} not found.");
        }
    }
    Ok(())
}

fn sandbox_template_to_json(template: &SandboxWorkloadTemplate) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    obj.insert("id".to_string(), serde_json::json!(template.object_id()));
    obj.insert(
        "name".to_string(),
        serde_json::json!(template.object_name()),
    );
    obj.insert(
        "workspace".to_string(),
        serde_json::json!(template.object_workspace()),
    );

    if let Some(metadata) = &template.metadata {
        if metadata.resource_version != 0 {
            obj.insert(
                "resource_version".to_string(),
                serde_json::json!(metadata.resource_version),
            );
        }
        if metadata.created_at_ms != 0 {
            obj.insert(
                "created_at".to_string(),
                serde_json::json!(format_epoch_ms(metadata.created_at_ms)),
            );
        }
        if !metadata.labels.is_empty() {
            obj.insert("labels".to_string(), serde_json::json!(metadata.labels));
        }
        if !metadata.annotations.is_empty() {
            obj.insert(
                "annotations".to_string(),
                serde_json::json!(metadata.annotations),
            );
        }
    }

    if let Some(spec) = &template.spec {
        if let Some(workload) = &spec.workload {
            obj.insert("image".to_string(), serde_json::json!(workload.image));
            if !workload.environment.is_empty() {
                obj.insert(
                    "environment".to_string(),
                    serde_json::json!(workload.environment),
                );
            }
            if let Some(resources) = &workload.resources {
                let mut resources_json = serde_json::Map::new();
                if !resources.cpu.is_empty() {
                    resources_json.insert("cpu".to_string(), serde_json::json!(resources.cpu));
                }
                if !resources.memory.is_empty() {
                    resources_json
                        .insert("memory".to_string(), serde_json::json!(resources.memory));
                }
                if let Some(gpu) = &resources.gpu {
                    let value = gpu
                        .count
                        .map_or_else(|| serde_json::json!("default"), serde_json::Value::from);
                    resources_json.insert("gpu".to_string(), value);
                }
                if !resources_json.is_empty() {
                    obj.insert(
                        "resources".to_string(),
                        serde_json::Value::Object(resources_json),
                    );
                }
            }
        }
        if let Some(driver_config) = &spec.driver_config {
            obj.insert(
                "driver_config".to_string(),
                openshell_core::proto_struct::struct_to_json_value(driver_config),
            );
        }
        if let Some(service_level) = &spec.desired_service_level
            && let Some(startup) = &service_level.startup
        {
            let mut startup_json = serde_json::Map::new();
            if let Some(ready_within) = &startup.ready_within {
                startup_json.insert(
                    "ready_within_ms".to_string(),
                    serde_json::json!(duration_to_ms(ready_within)),
                );
            }
            if startup.max_burst != 0 {
                startup_json.insert(
                    "max_burst".to_string(),
                    serde_json::json!(startup.max_burst),
                );
            }
            if !startup_json.is_empty() {
                obj.insert(
                    "startup".to_string(),
                    serde_json::Value::Object(startup_json),
                );
            }
        }
    }

    serde_json::Value::Object(obj)
}

fn print_sandbox_template_detail(template: &SandboxWorkloadTemplate) {
    println!("{}", "Sandbox template:".cyan().bold());
    println!();
    println!("  {} {}", "Name:".dimmed(), template.object_name());
    println!(
        "  {} {}",
        "Workspace:".dimmed(),
        template.object_workspace()
    );
    if let Some(metadata) = &template.metadata {
        println!("  {} {}", "Id:".dimmed(), metadata.id);
        println!(
            "  {} {}",
            "Resource version:".dimmed(),
            metadata.resource_version
        );
        if metadata.created_at_ms != 0 {
            println!(
                "  {} {}",
                "Created:".dimmed(),
                format_epoch_ms(metadata.created_at_ms)
            );
        }
        let labels = labels_display(&metadata.labels);
        println!(
            "  {} {}",
            "Labels:".dimmed(),
            non_empty_or(&labels, "<none>")
        );
    }
    if let Some(spec) = &template.spec
        && let Some(workload) = &spec.workload
    {
        println!(
            "  {} {}",
            "Image:".dimmed(),
            non_empty_or(&workload.image, "<default>")
        );
        println!(
            "  {} {}",
            "Environment:".dimmed(),
            workload.environment.len()
        );
        if let Some(resources) = &workload.resources {
            println!(
                "  {} {}",
                "CPU:".dimmed(),
                non_empty_or(&resources.cpu, "<default>")
            );
            println!(
                "  {} {}",
                "Memory:".dimmed(),
                non_empty_or(&resources.memory, "<default>")
            );
            println!(
                "  {} {}",
                "GPU:".dimmed(),
                template_resources_gpu_display(resources).unwrap_or_else(|| "<none>".to_string())
            );
        }
    }
    if let Some(startup) = template_startup(template) {
        println!(
            "  {} {}",
            "Ready within:".dimmed(),
            startup
                .ready_within
                .as_ref()
                .map_or_else(|| "<default>".to_string(), duration_display)
        );
        println!(
            "  {} {}",
            "Max burst:".dimmed(),
            if startup.max_burst == 0 {
                "<default>".to_string()
            } else {
                startup.max_burst.to_string()
            }
        );
    }
}

fn print_sandbox_template_table(templates: &[SandboxWorkloadTemplate], show_workspace: bool) {
    let name_width = templates
        .iter()
        .map(|template| template.object_name().len())
        .max()
        .unwrap_or(4)
        .max(4);
    let workspace_width = if show_workspace {
        templates
            .iter()
            .map(|template| template.object_workspace().len())
            .max()
            .unwrap_or(9)
            .max(9)
    } else {
        0
    };
    let image_width = templates
        .iter()
        .map(|template| template_image(template).len())
        .max()
        .unwrap_or(5)
        .clamp(5, 48);

    if show_workspace {
        println!(
            "{:<workspace_width$}  {:<name_width$}  {:<image_width$}  {:<10}  {:<10}  {:<5}  {:<12}  {:<5}  {}",
            "WORKSPACE".bold(),
            "NAME".bold(),
            "IMAGE".bold(),
            "CPU".bold(),
            "MEMORY".bold(),
            "GPU".bold(),
            "READY".bold(),
            "BURST".bold(),
            "LABELS".bold(),
        );
    } else {
        println!(
            "{:<name_width$}  {:<image_width$}  {:<10}  {:<10}  {:<5}  {:<12}  {:<5}  {}",
            "NAME".bold(),
            "IMAGE".bold(),
            "CPU".bold(),
            "MEMORY".bold(),
            "GPU".bold(),
            "READY".bold(),
            "BURST".bold(),
            "LABELS".bold(),
        );
    }

    for template in templates {
        let resources = template_resources(template);
        let cpu = resources
            .map(|resources| resources.cpu.as_str())
            .filter(|cpu| !cpu.is_empty())
            .unwrap_or("-");
        let memory = resources
            .map(|resources| resources.memory.as_str())
            .filter(|memory| !memory.is_empty())
            .unwrap_or("-");
        let gpu = resources
            .and_then(template_resources_gpu_display)
            .unwrap_or_else(|| "-".to_string());
        let image = truncate_status_field(&template_image(template), image_width);
        let startup = template_startup(template);
        let ready = startup
            .and_then(|startup| startup.ready_within.as_ref())
            .map_or_else(|| "-".to_string(), duration_display);
        let burst = startup
            .map(|startup| startup.max_burst)
            .filter(|burst| *burst != 0)
            .map_or_else(|| "-".to_string(), |burst| burst.to_string());
        let labels = template
            .metadata
            .as_ref()
            .map_or_else(String::new, |metadata| labels_display(&metadata.labels));

        if show_workspace {
            println!(
                "{:<workspace_width$}  {:<name_width$}  {:<image_width$}  {:<10}  {:<10}  {:<5}  {:<12}  {:<5}  {}",
                template.object_workspace(),
                template.object_name(),
                image,
                cpu,
                memory,
                gpu,
                ready,
                burst,
                labels,
            );
        } else {
            println!(
                "{:<name_width$}  {:<image_width$}  {:<10}  {:<10}  {:<5}  {:<12}  {:<5}  {}",
                template.object_name(),
                image,
                cpu,
                memory,
                gpu,
                ready,
                burst,
                labels,
            );
        }
    }
}

fn template_image(template: &SandboxWorkloadTemplate) -> String {
    template
        .spec
        .as_ref()
        .and_then(|spec| spec.workload.as_ref())
        .map_or_else(
            || "<default>".to_string(),
            |workload| non_empty_or(&workload.image, "<default>").to_string(),
        )
}

fn template_resources(template: &SandboxWorkloadTemplate) -> Option<&SandboxResources> {
    template
        .spec
        .as_ref()
        .and_then(|spec| spec.workload.as_ref())
        .and_then(|workload| workload.resources.as_ref())
}

fn template_resources_gpu_display(resources: &SandboxResources) -> Option<String> {
    if let Some(gpu) = &resources.gpu {
        return Some(
            gpu.count
                .map_or_else(|| "default".to_string(), |count| count.to_string()),
        );
    }
    None
}

fn template_startup(template: &SandboxWorkloadTemplate) -> Option<&SandboxStartup> {
    template
        .spec
        .as_ref()
        .and_then(|spec| spec.desired_service_level.as_ref())
        .and_then(|service_level| service_level.startup.as_ref())
}

fn duration_to_ms(duration: &prost_types::Duration) -> i64 {
    duration.seconds.saturating_mul(1_000) + i64::from(duration.nanos / 1_000_000)
}

fn duration_display(duration: &prost_types::Duration) -> String {
    let total_ms = duration_to_ms(duration);
    if total_ms % 3_600_000 == 0 {
        format!("{}h", total_ms / 3_600_000)
    } else if total_ms % 60_000 == 0 {
        format!("{}m", total_ms / 60_000)
    } else if total_ms % 1_000 == 0 {
        format!("{}s", total_ms / 1_000)
    } else {
        format!("{total_ms}ms")
    }
}

fn labels_display(labels: &HashMap<String, String>) -> String {
    let mut pairs = labels
        .iter()
        .map(|(key, value)| format!("{key}={value}"))
        .collect::<Vec<_>>();
    pairs.sort();
    pairs.join(", ")
}

/// Delete a sandbox by name, or all sandboxes when `all` is true.
pub async fn sandbox_delete(
    server: &str,
    names: &[String],
    all: bool,
    workspace: &str,
    tls: &TlsOptions,
    gateway: &str,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let names_to_delete: Vec<String> = if all {
        // Fetch all sandboxes (use a large page size).
        let response = client
            .list_sandboxes(ListSandboxesRequest {
                limit: 1000,
                offset: 0,
                label_selector: String::new(),
                workspace: workspace.to_string(),
                all_workspaces: false,
            })
            .await
            .into_diagnostic()?;
        let sandboxes = response.into_inner().sandboxes;
        if sandboxes.is_empty() {
            println!("No sandboxes to delete.");
            return Ok(());
        }
        sandboxes
            .into_iter()
            .map(|s| s.object_name().to_string())
            .collect()
    } else {
        names.to_vec()
    };

    let mut failures = Vec::new();
    for name in &names_to_delete {
        // Stop any background port forwards for this sandbox before deleting.
        if let Ok(stopped) = stop_forwards_for_sandbox(name) {
            for port in stopped {
                eprintln!(
                    "{} Stopped forward of port {port} for sandbox {name}",
                    "✓".green().bold(),
                );
            }
        }

        let response = match client
            .delete_sandbox(DeleteSandboxRequest {
                name: name.clone(),
                workspace: workspace.to_string(),
            })
            .await
        {
            Ok(response) => response,
            Err(status) if status.code() == Code::NotFound => {
                clear_last_sandbox_if_matches(gateway, workspace, name);
                println!("{} Sandbox {name} already deleted", "✓".green().bold());
                continue;
            }
            Err(status) => {
                eprintln!(
                    "{} Failed to delete sandbox {name}: {status}",
                    "!".red().bold()
                );
                failures.push(name.clone());
                continue;
            }
        };

        let deleted = response.into_inner().deleted;
        if deleted {
            clear_last_sandbox_if_matches(gateway, workspace, name);
            println!("{} Deleted sandbox {name}", "✓".green().bold());
        } else {
            println!("{} Sandbox {name} not found", "!".yellow());
        }
    }

    aggregate_delete_failures("sandbox", &failures)
}

/// Stop a sandbox while retaining its persistent workspace.
pub async fn sandbox_stop(
    server: &str,
    name: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    if let Ok(stopped) = stop_forwards_for_sandbox(name) {
        for port in stopped {
            eprintln!(
                "{} Stopped forward of port {port} for sandbox {name}",
                "✓".green().bold(),
            );
        }
    }

    let mut client = grpc_client(server, tls).await?;
    let sandbox = client
        .stop_sandbox(StopSandboxRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette!("gateway returned no sandbox after stop"))?;
    wait_for_lifecycle_phase(&mut client, sandbox, SandboxPhase::Stopped).await?;
    println!("{} Stopped sandbox {name}", "✓".green().bold());
    Ok(())
}

/// Start a stopped sandbox and wait until it is ready.
pub async fn sandbox_start(
    server: &str,
    name: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let sandbox = client
        .start_sandbox(StartSandboxRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette!("gateway returned no sandbox after start"))?;
    wait_for_lifecycle_phase(&mut client, sandbox, SandboxPhase::Ready).await?;
    println!("{} Started sandbox {name}", "✓".green().bold());
    Ok(())
}

async fn wait_for_lifecycle_phase(
    client: &mut crate::tls::GrpcClient,
    sandbox: Sandbox,
    target: SandboxPhase,
) -> Result<Sandbox> {
    let current = SandboxPhase::try_from(sandbox.phase()).unwrap_or(SandboxPhase::Unknown);
    if current == target {
        return Ok(sandbox);
    }
    if current == SandboxPhase::Error {
        let detail = ready_false_condition_message(sandbox.status.as_ref())
            .unwrap_or_else(|| "sandbox entered Error".to_string());
        return Err(miette!("{detail} while waiting for {target:?}"));
    }

    let timeout = Duration::from_secs(
        std::env::var("OPENSHELL_LIFECYCLE_TIMEOUT")
            .ok()
            .and_then(|value| value.parse().ok())
            .unwrap_or(300),
    );
    let sandbox_id = sandbox.object_id().to_string();
    let mut stream = client
        .watch_sandbox(WatchSandboxRequest {
            id: sandbox_id,
            follow_status: true,
            follow_logs: false,
            follow_events: false,
            log_tail_lines: 0,
            event_tail: 0,
            stop_on_terminal: false,
            log_since_ms: 0,
            log_sources: Vec::new(),
            log_min_level: String::new(),
        })
        .await
        .into_diagnostic()?
        .into_inner();

    let deadline = Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return Err(miette!(
                "timed out after {}s waiting for sandbox to reach {target:?}",
                timeout.as_secs()
            ));
        }
        let event = tokio::time::timeout(remaining, stream.next())
            .await
            .map_err(|_| {
                miette!(
                    "timed out after {}s waiting for sandbox to reach {target:?}",
                    timeout.as_secs()
                )
            })?
            .ok_or_else(|| miette!("sandbox watch ended before reaching {target:?}"))?
            .into_diagnostic()?;
        if let Some(openshell_core::proto::sandbox_stream_event::Payload::Sandbox(sandbox)) =
            event.payload
        {
            let phase = SandboxPhase::try_from(sandbox.phase()).unwrap_or(SandboxPhase::Unknown);
            if phase == target {
                return Ok(sandbox);
            }
            if phase == SandboxPhase::Error {
                let detail = ready_false_condition_message(sandbox.status.as_ref())
                    .unwrap_or_else(|| "sandbox entered Error".to_string());
                return Err(miette!(detail));
            }
        }
    }
}

pub async fn service_expose(
    server: &str,
    sandbox: &str,
    service: &str,
    target_port: u16,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .expose_service(ExposeServiceRequest {
            sandbox: sandbox.to_string(),
            service: service.to_string(),
            target_port: u32::from(target_port),
            domain: true,
            workspace: workspace.to_string(),
        })
        .await
        .map_err(service_expose_status_error)?
        .into_inner();

    if service.is_empty() {
        println!(
            "{} Exposed sandbox {} -> 127.0.0.1:{}",
            "✓".green().bold(),
            sandbox.bold(),
            target_port,
        );
    } else {
        println!(
            "{} Exposed service {} on sandbox {} -> 127.0.0.1:{}",
            "✓".green().bold(),
            service.bold(),
            sandbox.bold(),
            target_port,
        );
    }
    if !response.url.is_empty() {
        let url = service_url_for_gateway(&response.url, server);
        println!("  URL: {}", url.cyan());
    }
    Ok(())
}

fn service_expose_status_error(status: Status) -> miette::Report {
    service_status_error("expose service", "sandbox:write", status)
}

#[allow(clippy::too_many_arguments)] // user-facing CLI command
pub async fn service_list(
    server: &str,
    sandbox: Option<&str>,
    limit: u32,
    offset: u32,
    workspace: &str,
    all_workspaces: bool,
    output: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .list_services(ListServicesRequest {
            sandbox: sandbox.unwrap_or_default().to_string(),
            limit,
            offset,
            workspace: if all_workspaces {
                String::new()
            } else {
                workspace.to_string()
            },
            all_workspaces,
        })
        .await
        .map_err(|status| service_status_error("list services", "sandbox:read", status))?
        .into_inner();

    let services = response
        .services
        .iter()
        .filter_map(|response| service_endpoint_to_json(response, server))
        .collect::<Vec<_>>();
    if crate::output::print_output_collection(output, &services, Clone::clone)? {
        return Ok(());
    }

    if response.services.is_empty() {
        if let Some(sandbox) = sandbox {
            println!("No services exposed for sandbox {sandbox}.");
        } else {
            println!("No services exposed.");
        }
        return Ok(());
    }

    print_service_endpoint_table(&response.services, server, all_workspaces);
    Ok(())
}

pub async fn service_get(
    server: &str,
    sandbox: &str,
    service: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_service(GetServiceRequest {
            sandbox: sandbox.to_string(),
            service: service.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .map_err(|status| service_status_error("get service", "sandbox:read", status))?
        .into_inner();

    print_service_endpoint_table(&[response], server, false);
    Ok(())
}

pub async fn service_delete(
    server: &str,
    sandbox: &str,
    service: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .delete_service(DeleteServiceRequest {
            sandbox: sandbox.to_string(),
            service: service.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .map_err(|status| service_status_error("delete service", "sandbox:write", status))?
        .into_inner();

    if !response.deleted {
        return Err(miette!("delete service failed: service endpoint not found"));
    }

    if service.is_empty() {
        println!(
            "{} Deleted exposed sandbox {}",
            "✓".green().bold(),
            sandbox.bold(),
        );
    } else {
        println!(
            "{} Deleted service {} on sandbox {}",
            "✓".green().bold(),
            service.bold(),
            sandbox.bold(),
        );
    }
    Ok(())
}

fn service_status_error(action: &str, required_scope: &str, status: Status) -> miette::Report {
    let message = status.message();
    match status.code() {
        Code::PermissionDenied => {
            miette!("{action} failed: permission denied (requires {required_scope})")
        }
        Code::Unauthenticated => miette!("{action} failed: authentication required"),
        Code::NotFound if message == "sandbox not found" => {
            miette!("{action} failed: sandbox not found")
        }
        Code::NotFound if message == "service endpoint not found" => {
            miette!("{action} failed: service endpoint not found")
        }
        Code::InvalidArgument if !message.is_empty() => {
            miette!("{action} failed: invalid request: {message}")
        }
        _ => miette!("{action} failed: {status}"),
    }
}

fn print_service_endpoint_table(
    services: &[ServiceEndpointResponse],
    gateway_endpoint: &str,
    all_workspaces: bool,
) {
    let rows = services
        .iter()
        .filter_map(|response| {
            let endpoint = response.endpoint.as_ref()?;
            let workspace = endpoint
                .metadata
                .as_ref()
                .map_or("", |m| m.workspace.as_str());
            let service = service_display_name(&endpoint.service_name).to_string();
            let target = format!("127.0.0.1:{}", endpoint.target_port);
            let url = if response.url.is_empty() {
                String::new()
            } else {
                service_url_for_gateway(&response.url, gateway_endpoint)
            };
            Some((
                workspace.to_string(),
                endpoint.sandbox_name.clone(),
                service,
                target,
                url,
            ))
        })
        .collect::<Vec<_>>();

    if rows.is_empty() {
        return;
    }

    let ws_width = if all_workspaces {
        rows.iter()
            .map(|(ws, _, _, _, _)| ws.len())
            .max()
            .unwrap_or(9)
            .max(9)
    } else {
        0
    };
    let sandbox_width = rows
        .iter()
        .map(|(_, sandbox, _, _, _)| sandbox.len())
        .max()
        .unwrap_or(7)
        .max(7);
    let service_width = rows
        .iter()
        .map(|(_, _, service, _, _)| service.len())
        .max()
        .unwrap_or(7)
        .max(7);
    let target_width = rows
        .iter()
        .map(|(_, _, _, target, _)| target.len())
        .max()
        .unwrap_or(6)
        .max(6);

    if all_workspaces {
        println!(
            "{:<ws_width$}  {:<sandbox_width$}  {:<service_width$}  {:<target_width$}  {}",
            "WORKSPACE".bold(),
            "SANDBOX".bold(),
            "SERVICE".bold(),
            "TARGET".bold(),
            "URL".bold(),
        );
    } else {
        println!(
            "{:<sandbox_width$}  {:<service_width$}  {:<target_width$}  {}",
            "SANDBOX".bold(),
            "SERVICE".bold(),
            "TARGET".bold(),
            "URL".bold(),
        );
    }

    for (workspace, sandbox, service, target, url) in rows {
        if all_workspaces {
            println!(
                "{workspace:<ws_width$}  {sandbox:<sandbox_width$}  {service:<service_width$}  {target:<target_width$}  {url}"
            );
        } else {
            println!(
                "{sandbox:<sandbox_width$}  {service:<service_width$}  {target:<target_width$}  {url}"
            );
        }
    }
}

fn service_endpoint_to_json(
    response: &ServiceEndpointResponse,
    gateway_endpoint: &str,
) -> Option<serde_json::Value> {
    let endpoint = response.endpoint.as_ref()?;
    let workspace = endpoint
        .metadata
        .as_ref()
        .map_or("", |metadata| metadata.workspace.as_str());
    let url = if response.url.is_empty() {
        String::new()
    } else {
        service_url_for_gateway(&response.url, gateway_endpoint)
    };

    Some(serde_json::json!({
        "workspace": workspace,
        "sandbox": endpoint.sandbox_name,
        "service": endpoint.service_name,
        "target_port": endpoint.target_port,
        "url": url,
    }))
}

fn service_display_name(service: &str) -> &str {
    if service.is_empty() { "-" } else { service }
}

/// Read gcloud Application Default Credentials from disk.
///
/// Returns `(client_id, client_secret, refresh_token)`.
///
/// Checks `GOOGLE_APPLICATION_CREDENTIALS` first; falls back to
/// `$CLOUDSDK_CONFIG/application_default_credentials.json` when set, then to
/// `~/.config/gcloud/application_default_credentials.json`.
fn service_url_for_gateway(service_url: &str, gateway_endpoint: &str) -> String {
    let (Ok(mut service_url), Ok(gateway_endpoint)) = (
        url::Url::parse(service_url),
        url::Url::parse(gateway_endpoint),
    ) else {
        return service_url.to_string();
    };

    if service_url
        .set_port(gateway_endpoint.port_or_known_default())
        .is_err()
    {
        return service_url.to_string();
    }

    service_url.to_string()
}

// ---------------------------------------------------------------------------
// Workspace commands
// ---------------------------------------------------------------------------

pub async fn workspace_create(
    server: &str,
    name: &str,
    label_args: &[String],
    tls: &TlsOptions,
) -> Result<()> {
    use openshell_core::proto::CreateWorkspaceRequest;

    let labels = label_args
        .iter()
        .filter_map(|arg| {
            let (k, v) = arg.split_once('=')?;
            Some((k.to_string(), v.to_string()))
        })
        .collect::<HashMap<String, String>>();

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .create_workspace(CreateWorkspaceRequest {
            name: name.to_string(),
            labels,
        })
        .await
        .into_diagnostic()?;

    let workspace = response
        .into_inner()
        .workspace
        .ok_or_else(|| miette!("workspace missing from response"))?;

    println!(
        "{} Created workspace {}",
        "✓".green().bold(),
        workspace.object_name().bold()
    );

    Ok(())
}

pub async fn workspace_get(server: &str, name: &str, tls: &TlsOptions) -> Result<()> {
    use openshell_core::proto::GetWorkspaceRequest;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_workspace(GetWorkspaceRequest {
            name: name.to_string(),
        })
        .await
        .into_diagnostic()?;

    let workspace = response
        .into_inner()
        .workspace
        .ok_or_else(|| miette!("workspace missing from response"))?;

    println!("{}", "Workspace:".cyan().bold());
    println!();
    println!("  {} {}", "Name:".dimmed(), workspace.object_name());
    if let Some(meta) = &workspace.metadata {
        println!("  {} {}", "Id:".dimmed(), meta.id);
        println!(
            "  {} {}",
            "Resource version:".dimmed(),
            meta.resource_version
        );
        if meta.created_at_ms != 0 {
            println!(
                "  {} {}",
                "Created:".dimmed(),
                format_epoch_ms(meta.created_at_ms)
            );
        }
        if !meta.labels.is_empty() {
            println!(
                "  {} {}",
                "Labels:".dimmed(),
                meta.labels
                    .iter()
                    .map(|(k, v)| format!("{k}={v}"))
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }

    Ok(())
}

pub async fn workspace_list(
    server: &str,
    limit: u32,
    offset: u32,
    label_selector: &str,
    output: &str,
    tls: &TlsOptions,
) -> Result<()> {
    use openshell_core::proto::ListWorkspacesRequest;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .list_workspaces(ListWorkspacesRequest {
            limit,
            offset,
            label_selector: label_selector.to_string(),
        })
        .await
        .into_diagnostic()?;
    let workspaces = response.into_inner().workspaces;

    if crate::output::print_output_collection(output, &workspaces, workspace_to_json)? {
        return Ok(());
    }

    if workspaces.is_empty() {
        println!("No workspaces found.");
        return Ok(());
    }

    let name_width = workspaces
        .iter()
        .map(|w| w.object_name().len())
        .max()
        .unwrap_or(4)
        .max(4);

    println!(
        "{:<name_width$}  {:<12}  {:<20}  {}",
        "NAME".bold(),
        "STATUS".bold(),
        "CREATED".bold(),
        "LABELS".bold(),
    );

    for workspace in &workspaces {
        let status = workspace_phase_display(workspace);
        let created = workspace
            .metadata
            .as_ref()
            .map_or_else(String::new, |m| format_epoch_ms(m.created_at_ms));
        let labels = workspace.metadata.as_ref().map_or_else(String::new, |m| {
            m.labels
                .iter()
                .map(|(k, v)| format!("{k}={v}"))
                .collect::<Vec<_>>()
                .join(", ")
        });
        println!(
            "{:<name_width$}  {:<12}  {:<20}  {}",
            workspace.object_name(),
            status,
            created,
            labels,
        );
    }

    Ok(())
}

pub async fn workspace_delete(server: &str, names: &[String], tls: &TlsOptions) -> Result<()> {
    use openshell_core::proto::DeleteWorkspaceRequest;

    let mut client = grpc_client(server, tls).await?;
    for name in names {
        let response = client
            .delete_workspace(DeleteWorkspaceRequest { name: name.clone() })
            .await
            .into_diagnostic()?;
        if response.into_inner().deleted {
            println!("{} Deleted workspace {name}", "✓".green().bold());
        } else {
            println!("{} Workspace {name} not found", "!".yellow());
        }
    }
    Ok(())
}

pub async fn workspace_member_add(
    server: &str,
    workspace: &str,
    subject: &str,
    role: &str,
    tls: &TlsOptions,
) -> Result<()> {
    use openshell_core::proto::{AddWorkspaceMemberRequest, WorkspaceRole};

    let role_val = match role.to_lowercase().as_str() {
        "user" => WorkspaceRole::User,
        "admin" => WorkspaceRole::Admin,
        _ => {
            return Err(miette!(
                "invalid role '{}': must be 'user' or 'admin'",
                role
            ));
        }
    };

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .add_workspace_member(AddWorkspaceMemberRequest {
            workspace: workspace.to_string(),
            principal_subject: subject.to_string(),
            role: role_val.into(),
        })
        .await
        .into_diagnostic()?;

    let member = response
        .into_inner()
        .member
        .ok_or_else(|| miette!("member missing from response"))?;

    println!(
        "{} Added {} to workspace {} as {}",
        "✓".green().bold(),
        member.principal_subject.bold(),
        workspace.bold(),
        role,
    );

    Ok(())
}

pub async fn workspace_member_remove(
    server: &str,
    workspace: &str,
    subject: &str,
    tls: &TlsOptions,
) -> Result<()> {
    use openshell_core::proto::RemoveWorkspaceMemberRequest;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .remove_workspace_member(RemoveWorkspaceMemberRequest {
            workspace: workspace.to_string(),
            principal_subject: subject.to_string(),
        })
        .await
        .into_diagnostic()?;

    if response.into_inner().removed {
        println!(
            "{} Removed {} from workspace {}",
            "✓".green().bold(),
            subject.bold(),
            workspace.bold(),
        );
    } else {
        println!(
            "{} Member {} not found in workspace {}",
            "!".yellow(),
            subject,
            workspace,
        );
    }

    Ok(())
}

pub async fn workspace_member_list(
    server: &str,
    workspace: &str,
    limit: u32,
    offset: u32,
    output: &str,
    tls: &TlsOptions,
) -> Result<()> {
    use openshell_core::proto::ListWorkspaceMembersRequest;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .list_workspace_members(ListWorkspaceMembersRequest {
            workspace: workspace.to_string(),
            limit,
            offset,
        })
        .await
        .into_diagnostic()?;
    let members = response.into_inner().members;

    if crate::output::print_output_collection(output, &members, workspace_member_to_json)? {
        return Ok(());
    }

    if members.is_empty() {
        println!("No members found in workspace {workspace}.");
        return Ok(());
    }

    let subject_width = members
        .iter()
        .map(|m| m.principal_subject.len())
        .max()
        .unwrap_or(7)
        .max(7);

    println!("{:<subject_width$}  {}", "SUBJECT".bold(), "ROLE".bold());

    for member in &members {
        let role_str = workspace_member_role_name(member.role);
        println!("{:<subject_width$}  {}", member.principal_subject, role_str);
    }

    Ok(())
}

fn workspace_member_role_name(role: i32) -> &'static str {
    use openshell_core::proto::WorkspaceRole;

    match WorkspaceRole::try_from(role) {
        Ok(WorkspaceRole::Admin) => "admin",
        Ok(WorkspaceRole::User) => "user",
        _ => "unknown",
    }
}

fn workspace_member_to_json(member: &openshell_core::proto::WorkspaceMember) -> serde_json::Value {
    serde_json::json!({
        "subject": member.principal_subject,
        "role": workspace_member_role_name(member.role),
    })
}

fn workspace_phase_str(workspace: &openshell_core::proto::Workspace) -> &'static str {
    use openshell_core::proto::datamodel::v1::WorkspacePhase;
    let phase = workspace
        .status
        .as_ref()
        .and_then(|s| WorkspacePhase::try_from(s.phase).ok())
        .unwrap_or(WorkspacePhase::Active);
    match phase {
        WorkspacePhase::Terminating => "Terminating",
        _ => "Active",
    }
}

fn workspace_phase_display(workspace: &openshell_core::proto::Workspace) -> String {
    let s = workspace_phase_str(workspace);
    if s == "Terminating" {
        s.yellow().to_string()
    } else {
        s.to_string()
    }
}

fn workspace_to_json(workspace: &openshell_core::proto::Workspace) -> serde_json::Value {
    let mut obj = serde_json::Map::new();
    if let Some(meta) = &workspace.metadata {
        obj.insert("name".to_string(), serde_json::json!(meta.name));
        obj.insert("id".to_string(), serde_json::json!(meta.id));
        obj.insert(
            "resource_version".to_string(),
            serde_json::json!(meta.resource_version),
        );
        if meta.created_at_ms != 0 {
            obj.insert(
                "created_at".to_string(),
                serde_json::json!(format_epoch_ms(meta.created_at_ms)),
            );
        }
        if !meta.labels.is_empty() {
            obj.insert("labels".to_string(), serde_json::json!(meta.labels));
        }
    }
    obj.insert(
        "status".to_string(),
        serde_json::json!(workspace_phase_str(workspace)),
    );
    serde_json::Value::Object(obj)
}

#[allow(clippy::too_many_arguments)]
pub async fn gateway_inference_set(
    server: &str,
    provider_name: &str,
    model_id: &str,
    route_name: &str,
    no_verify: bool,
    timeout_secs: u64,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let progress = if std::io::stdout().is_terminal() {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg} ({elapsed})")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        spinner.set_message("Configuring inference...");
        spinner.enable_steady_tick(Duration::from_millis(120));
        Some(spinner)
    } else {
        None
    };

    let mut client = grpc_inference_client(server, tls).await?;
    let response = client
        .set_inference_route(SetInferenceRouteRequest {
            provider_name: provider_name.to_string(),
            model_id: model_id.to_string(),
            route_name: route_name.to_string(),
            verify: false,
            no_verify,
            timeout_secs,
            workspace: workspace.to_string(),
        })
        .await;

    if let Some(progress) = &progress {
        progress.finish_and_clear();
    }

    let response = response.map_err(format_inference_status)?;

    let configured = response.into_inner();
    let label = if configured.route_name == "sandbox-system" {
        "System inference configured:"
    } else {
        "Inference configured:"
    };
    println!("{}", label.cyan().bold());
    println!();
    println!("  {} {}", "Workspace:".dimmed(), configured.workspace);
    println!("  {} {}", "Route:".dimmed(), configured.route_name);
    println!("  {} {}", "Provider:".dimmed(), configured.provider_name);
    println!("  {} {}", "Model:".dimmed(), configured.model_id);
    println!("  {} {}", "Version:".dimmed(), configured.version);
    print_timeout(configured.timeout_secs);
    if configured.validation_performed {
        println!("  {}", "Validated Endpoints:".dimmed());
        for endpoint in configured.validated_endpoints {
            println!("    - {} ({})", endpoint.url, endpoint.protocol);
        }
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
pub async fn gateway_inference_update(
    server: &str,
    provider_name: Option<&str>,
    model_id: Option<&str>,
    route_name: &str,
    no_verify: bool,
    timeout_secs: Option<u64>,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    if provider_name.is_none() && model_id.is_none() && timeout_secs.is_none() {
        return Err(miette::miette!(
            "at least one of --provider, --model, or --timeout must be specified"
        ));
    }

    let mut client = grpc_inference_client(server, tls).await?;

    // Fetch current config to use as base for the partial update.
    let current = client
        .get_inference_route(GetInferenceRouteRequest {
            route_name: route_name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner();

    let provider = provider_name.unwrap_or(&current.provider_name);
    let model = model_id.unwrap_or(&current.model_id);
    let timeout = timeout_secs.unwrap_or(current.timeout_secs);

    let progress = if std::io::stdout().is_terminal() {
        let spinner = ProgressBar::new_spinner();
        spinner.set_style(
            ProgressStyle::with_template("{spinner:.cyan} {msg} ({elapsed})")
                .unwrap_or_else(|_| ProgressStyle::default_spinner()),
        );
        spinner.set_message("Configuring inference...");
        spinner.enable_steady_tick(Duration::from_millis(120));
        Some(spinner)
    } else {
        None
    };

    let response = client
        .set_inference_route(SetInferenceRouteRequest {
            provider_name: provider.to_string(),
            model_id: model.to_string(),
            route_name: route_name.to_string(),
            verify: false,
            no_verify,
            timeout_secs: timeout,
            workspace: workspace.to_string(),
        })
        .await;

    if let Some(progress) = &progress {
        progress.finish_and_clear();
    }

    let response = response.map_err(format_inference_status)?;

    let configured = response.into_inner();
    let label = if configured.route_name == "sandbox-system" {
        "System inference updated:"
    } else {
        "Inference updated:"
    };
    println!("{}", label.cyan().bold());
    println!();
    println!("  {} {}", "Workspace:".dimmed(), configured.workspace);
    println!("  {} {}", "Route:".dimmed(), configured.route_name);
    println!("  {} {}", "Provider:".dimmed(), configured.provider_name);
    println!("  {} {}", "Model:".dimmed(), configured.model_id);
    println!("  {} {}", "Version:".dimmed(), configured.version);
    print_timeout(configured.timeout_secs);
    if configured.validation_performed {
        println!("  {}", "Validated Endpoints:".dimmed());
        for endpoint in configured.validated_endpoints {
            println!("    - {} ({})", endpoint.url, endpoint.protocol);
        }
    }
    Ok(())
}

pub async fn gateway_inference_get(
    server: &str,
    route_name: Option<&str>,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_inference_client(server, tls).await?;

    if let Some(name) = route_name {
        // Show a single route (--system was specified).
        let response = client
            .get_inference_route(GetInferenceRouteRequest {
                route_name: name.to_string(),
                workspace: workspace.to_string(),
            })
            .await
            .into_diagnostic()?;

        let configured = response.into_inner();
        let label = if name == "sandbox-system" {
            "System inference:"
        } else {
            "Inference:"
        };
        println!("{}", label.cyan().bold());
        println!();
        println!("  {} {}", "Workspace:".dimmed(), configured.workspace);
        println!("  {} {}", "Provider:".dimmed(), configured.provider_name);
        println!("  {} {}", "Model:".dimmed(), configured.model_id);
        println!("  {} {}", "Version:".dimmed(), configured.version);
        print_timeout(configured.timeout_secs);
    } else {
        // Show both routes by default.
        print_inference_route(&mut client, "Inference", "", workspace).await;
        println!();
        print_inference_route(&mut client, "System inference", "sandbox-system", workspace).await;
    }
    Ok(())
}

pub async fn gateway_inference_delete(
    server: &str,
    route_name: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_inference_client(server, tls).await?;

    let response = client
        .delete_inference_route(DeleteInferenceRouteRequest {
            route_name: route_name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;

    let label = if route_name == "sandbox-system" {
        "System inference route"
    } else {
        "Inference route"
    };

    if response.into_inner().deleted {
        println!("{label} deleted.");
    } else {
        println!("{label} not found (already deleted).");
    }
    Ok(())
}

async fn print_inference_route(
    client: &mut crate::tls::GrpcInferenceClient,
    label: &str,
    route_name: &str,
    workspace: &str,
) {
    match client
        .get_inference_route(GetInferenceRouteRequest {
            route_name: route_name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
    {
        Ok(response) => {
            let configured = response.into_inner();
            println!("{}", format!("{label}:").cyan().bold());
            println!();
            println!("  {} {}", "Workspace:".dimmed(), configured.workspace);
            println!("  {} {}", "Provider:".dimmed(), configured.provider_name);
            println!("  {} {}", "Model:".dimmed(), configured.model_id);
            println!("  {} {}", "Version:".dimmed(), configured.version);
            print_timeout(configured.timeout_secs);
        }
        Err(e) if e.code() == Code::NotFound => {
            println!("{}", format!("{label}:").cyan().bold());
            println!();
            println!("  {}", "Not configured".dimmed());
        }
        Err(e) => {
            println!("{}", format!("{label}:").cyan().bold());
            println!();
            println!("  {} {}", "Error:".red(), e.message());
        }
    }
}

fn print_timeout(timeout_secs: u64) {
    if timeout_secs == 0 {
        println!("  {} {}s (default)", "Timeout:".dimmed(), 60);
    } else {
        println!("  {} {}s", "Timeout:".dimmed(), timeout_secs);
    }
}

fn format_inference_status(status: Status) -> miette::Report {
    let message = status.message().trim();

    if message.is_empty() {
        return miette::miette!("inference configuration failed ({})", status.code());
    }

    miette::miette!("{message}")
}

pub fn git_repo_root(local_path: &Path) -> Result<PathBuf> {
    let git_dir = if local_path.is_dir() {
        local_path
    } else {
        local_path
            .parent()
            .ok_or_else(|| miette::miette!("path has no parent: {}", local_path.display()))?
    };
    let mut command = Command::new("git");
    scrub_git_env(&mut command);
    let output = command
        .args(["rev-parse", "--show-toplevel"])
        .current_dir(git_dir)
        .output()
        .into_diagnostic()
        .wrap_err("failed to run git rev-parse")?;

    if !output.status.success() {
        return Err(miette::miette!(
            "git rev-parse --show-toplevel failed with status {}",
            output.status
        ));
    }

    let root = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if root.is_empty() {
        return Err(miette::miette!(
            "git rev-parse returned empty repository root"
        ));
    }

    Ok(PathBuf::from(root))
}

pub fn git_sync_files(local_path: &Path) -> Result<(PathBuf, Vec<String>)> {
    let repo_root = std::fs::canonicalize(git_repo_root(local_path)?)
        .into_diagnostic()
        .wrap_err("failed to canonicalize git repository root")?;
    let local_path = if local_path.is_absolute() {
        local_path.to_path_buf()
    } else {
        std::env::current_dir()
            .into_diagnostic()
            .wrap_err("failed to resolve current directory")?
            .join(local_path)
    };
    let local_path = std::fs::canonicalize(local_path)
        .into_diagnostic()
        .wrap_err("failed to canonicalize local upload path")?;
    let relative_path = local_path
        .strip_prefix(&repo_root)
        .into_diagnostic()
        .wrap_err_with(|| {
            format!(
                "local path '{}' is not inside git repository '{}'",
                local_path.display(),
                repo_root.display()
            )
        })?;

    let is_file = local_path.is_file();
    let base_dir = if is_file {
        local_path
            .parent()
            .map(Path::to_path_buf)
            .ok_or_else(|| miette::miette!("path has no parent: {}", local_path.display()))?
    } else {
        local_path.clone()
    };
    let pathspec = if relative_path.as_os_str().is_empty() {
        None
    } else {
        Some(relative_path.to_string_lossy().into_owned())
    };

    let mut command = Command::new("git");
    scrub_git_env(&mut command);
    let output = command
        .args(["ls-files", "-co", "--exclude-standard", "-z"])
        .args(pathspec.as_deref())
        .current_dir(&repo_root)
        .output()
        .into_diagnostic()
        .wrap_err("failed to run git ls-files")?;

    if !output.status.success() {
        return Err(miette::miette!(
            "git ls-files failed with status {}",
            output.status
        ));
    }

    let mut files = Vec::new();
    for entry in output.stdout.split(|byte| *byte == 0) {
        if entry.is_empty() {
            continue;
        }
        let repo_relative = Path::new(std::str::from_utf8(entry).into_diagnostic()?);
        let path = if is_file {
            repo_relative
                .file_name()
                .map(PathBuf::from)
                .ok_or_else(|| {
                    miette::miette!("path has no file name: {}", repo_relative.display())
                })?
        } else if relative_path.as_os_str().is_empty() {
            repo_relative.to_path_buf()
        } else {
            repo_relative
                .strip_prefix(relative_path)
                .into_diagnostic()?
                .to_path_buf()
        };
        if path.as_os_str().is_empty() {
            continue;
        }
        files.push(path.to_string_lossy().into_owned());
    }

    Ok((base_dir, files))
}

fn sandbox_upload_plan(local_path: &Path, git_ignore: bool) -> Result<SandboxUploadPlan> {
    let metadata = std::fs::symlink_metadata(local_path).map_err(|err| {
        if err.kind() == ErrorKind::NotFound {
            miette::miette!("local path does not exist: {}", local_path.display())
        } else {
            miette::miette!(
                "failed to inspect local upload path: {}",
                local_path.display()
            )
        }
    })?;

    if git_ignore
        && !metadata.file_type().is_symlink()
        && let Ok((base_dir, files)) = git_sync_files(local_path)
    {
        if files.is_empty() {
            return Ok(SandboxUploadPlan::GitFilteredEmpty);
        }
        return Ok(SandboxUploadPlan::GitAware { base_dir, files });
    }

    Ok(SandboxUploadPlan::Regular)
}

/// Upload a local path to a sandbox.
///
/// Symlink sources, including dangling links, bypass Git-aware filtering so
/// the tar upload preserves the link instead of dereferencing its target.
pub async fn sandbox_upload(
    server: &str,
    name: &str,
    local_path: &Path,
    sandbox_path: Option<&str>,
    git_ignore: bool,
    tls: &TlsOptions,
    workspace: &str,
) -> Result<()> {
    let upload_plan = sandbox_upload_plan(local_path, git_ignore)?;
    let dest_display = sandbox_path.unwrap_or("~");
    eprintln!(
        "Uploading {} -> sandbox:{}",
        local_path.display(),
        dest_display
    );

    match upload_plan {
        SandboxUploadPlan::GitAware { base_dir, files } => {
            sandbox_sync_up_files(
                server,
                name,
                &base_dir,
                &files,
                local_path,
                sandbox_path,
                tls,
                workspace,
            )
            .await?;
        }
        SandboxUploadPlan::GitFilteredEmpty => {
            eprintln!(
                "{} .gitignore filtering excluded all files in {}; uploading unfiltered",
                "⚠".yellow().bold(),
                local_path.display(),
            );
            sandbox_sync_up(server, name, local_path, sandbox_path, tls, workspace).await?;
        }
        SandboxUploadPlan::Regular => {
            sandbox_sync_up(server, name, local_path, sandbox_path, tls, workspace).await?;
        }
    }

    eprintln!("{} Upload complete", "✓".green().bold());
    Ok(())
}

// ---------------------------------------------------------------------------
// Sandbox policy commands
// ---------------------------------------------------------------------------

pub async fn sandbox_policy_set_global(
    server: &str,
    policy_path: &str,
    yes: bool,
    wait: bool,
    _timeout_secs: u64,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    if wait {
        return Err(miette::miette!(
            "--wait is only supported for sandbox-scoped policy updates"
        ));
    }

    confirm_global_setting_takeover("policy", yes)?;

    let policy = load_sandbox_policy(Some(policy_path))?
        .ok_or_else(|| miette::miette!("No policy loaded from {policy_path}"))?;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .update_config(UpdateConfigRequest {
            name: String::new(),
            policy: Some(policy),
            global: true,
            workspace: workspace.to_string(),
            ..Default::default()
        })
        .await
        .into_diagnostic()?
        .into_inner();

    eprintln!(
        "{} Global policy configured (hash: {}, settings revision: {})",
        "✓".green().bold(),
        if response.policy_hash.len() >= 12 {
            &response.policy_hash[..12]
        } else {
            &response.policy_hash
        },
        response.settings_revision,
    );
    Ok(())
}

pub async fn sandbox_settings_get(
    server: &str,
    name: &str,
    json: bool,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let sandbox = client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox not found"))?;

    let response = client
        .get_sandbox_config(GetSandboxConfigRequest {
            sandbox_id: sandbox.object_id().to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner();

    if json {
        let obj = settings_to_json_sandbox(name, workspace, &response);
        println!("{}", serde_json::to_string_pretty(&obj).into_diagnostic()?);
        return Ok(());
    }

    let policy_source = if response.policy_source == PolicySource::Global as i32 {
        "global"
    } else {
        "sandbox"
    };

    println!("Sandbox:       {name}");
    println!("Config Rev:    {}", response.config_revision);
    println!("Policy Source: {policy_source}");
    println!("Policy Hash:   {}", response.policy_hash);

    if response.settings.is_empty() {
        println!("Settings:      No settings available.");
        return Ok(());
    }

    println!("Settings:");
    let mut keys: Vec<_> = response.settings.keys().cloned().collect();
    keys.sort();
    for key in keys {
        if let Some(setting) = response.settings.get(&key) {
            let scope = match SettingScope::try_from(setting.scope) {
                Ok(SettingScope::Global) => "global",
                Ok(SettingScope::Sandbox) => "sandbox",
                _ => "unset",
            };
            println!(
                "  {} = {} ({})",
                key,
                format_setting_value(setting.value.as_ref()),
                scope
            );
        }
    }

    Ok(())
}

pub async fn gateway_settings_get(server: &str, json: bool, tls: &TlsOptions) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .get_gateway_config(GetGatewayConfigRequest {})
        .await
        .into_diagnostic()?
        .into_inner();

    if json {
        let obj = settings_to_json_global(&response);
        println!("{}", serde_json::to_string_pretty(&obj).into_diagnostic()?);
        return Ok(());
    }

    println!("Scope:         global");
    println!("Settings Rev:  {}", response.settings_revision);

    if response.settings.is_empty() {
        println!("Settings:      No settings available.");
        return Ok(());
    }

    println!("Settings:");
    let mut keys: Vec<_> = response.settings.keys().cloned().collect();
    keys.sort();
    for key in keys {
        if let Some(setting) = response.settings.get(&key) {
            println!("  {} = {}", key, format_setting_value(Some(setting)));
        }
    }
    Ok(())
}

fn settings_to_json_sandbox(
    name: &str,
    workspace: &str,
    response: &GetSandboxConfigResponse,
) -> serde_json::Value {
    let policy_source = if response.policy_source == PolicySource::Global as i32 {
        "global"
    } else {
        "sandbox"
    };

    let mut settings = serde_json::Map::new();
    let mut keys: Vec<_> = response.settings.keys().cloned().collect();
    keys.sort();
    for key in keys {
        if let Some(setting) = response.settings.get(&key) {
            let scope = match SettingScope::try_from(setting.scope) {
                Ok(SettingScope::Global) => "global",
                Ok(SettingScope::Sandbox) => "sandbox",
                _ => "unset",
            };
            settings.insert(
                key,
                serde_json::json!({
                    "value": format_setting_value(setting.value.as_ref()),
                    "scope": scope,
                }),
            );
        }
    }

    serde_json::json!({
        "sandbox": name,
        "workspace": workspace,
        "config_revision": response.config_revision,
        "policy_source": policy_source,
        "policy_hash": response.policy_hash,
        "settings": settings,
    })
}

fn settings_to_json_global(
    response: &openshell_core::proto::GetGatewayConfigResponse,
) -> serde_json::Value {
    let mut settings = serde_json::Map::new();
    let mut keys: Vec<_> = response.settings.keys().cloned().collect();
    keys.sort();
    for key in keys {
        if let Some(setting) = response.settings.get(&key) {
            settings.insert(key, serde_json::json!(format_setting_value(Some(setting))));
        }
    }

    serde_json::json!({
        "scope": "global",
        "settings_revision": response.settings_revision,
        "settings": settings,
    })
}

pub async fn gateway_setting_set(
    server: &str,
    key: &str,
    value: &str,
    yes: bool,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let setting_value = parse_cli_setting_value(key, value)?;
    confirm_global_setting_takeover(key, yes)?;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .update_config(UpdateConfigRequest {
            name: String::new(),
            setting_key: key.to_string(),
            setting_value: Some(setting_value),
            global: true,
            workspace: workspace.to_string(),
            ..Default::default()
        })
        .await
        .into_diagnostic()?
        .into_inner();

    println!(
        "{} Set global setting {}={} (revision {})",
        "✓".green().bold(),
        key,
        value,
        response.settings_revision
    );
    Ok(())
}

pub async fn sandbox_setting_set(
    server: &str,
    name: &str,
    key: &str,
    value: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let setting_value = parse_cli_setting_value(key, value)?;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .update_config(UpdateConfigRequest {
            name: name.to_string(),
            setting_key: key.to_string(),
            setting_value: Some(setting_value),
            workspace: workspace.to_string(),
            ..Default::default()
        })
        .await
        .into_diagnostic()?
        .into_inner();

    println!(
        "{} Set sandbox setting {}={} for {} (revision {})",
        "✓".green().bold(),
        key,
        value,
        name,
        response.settings_revision
    );
    Ok(())
}

pub async fn gateway_setting_delete(
    server: &str,
    key: &str,
    yes: bool,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    confirm_global_setting_delete(key, yes)?;

    let mut client = grpc_client(server, tls).await?;
    let response = client
        .update_config(UpdateConfigRequest {
            name: String::new(),
            setting_key: key.to_string(),
            delete_setting: true,
            global: true,
            workspace: workspace.to_string(),
            ..Default::default()
        })
        .await
        .into_diagnostic()?
        .into_inner();

    if response.deleted {
        println!(
            "{} Deleted global setting {} (revision {})",
            "✓".green().bold(),
            key,
            response.settings_revision
        );
    } else {
        println!("{} Global setting {} not found", "!".yellow(), key);
    }
    Ok(())
}

pub async fn sandbox_setting_delete(
    server: &str,
    name: &str,
    key: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let response = client
        .update_config(UpdateConfigRequest {
            name: name.to_string(),
            setting_key: key.to_string(),
            delete_setting: true,
            workspace: workspace.to_string(),
            ..Default::default()
        })
        .await
        .into_diagnostic()?
        .into_inner();

    if response.deleted {
        println!(
            "{} Deleted sandbox setting {} for {} (revision {})",
            "✓".green().bold(),
            key,
            name,
            response.settings_revision
        );
    } else {
        println!(
            "{} Sandbox setting {} not found for {}",
            "!".yellow(),
            key,
            name,
        );
    }
    Ok(())
}

pub async fn sandbox_policy_set(
    server: &str,
    name: &str,
    policy_path: &str,
    wait: bool,
    timeout_secs: u64,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let policy = load_sandbox_policy(Some(policy_path))?
        .ok_or_else(|| miette::miette!("No policy loaded from {policy_path}"))?;

    let mut client = grpc_client(server, tls).await?;

    // Get current version so we can detect no-ops.
    let current_version = client
        .get_sandbox_policy_status(GetSandboxPolicyStatusRequest {
            name: name.to_string(),
            version: 0,
            global: false,
            workspace: workspace.to_string(),
        })
        .await
        .ok()
        .and_then(|r| r.into_inner().revision)
        .map_or(0, |r| r.version);

    let response = client
        .update_config(UpdateConfigRequest {
            name: name.to_string(),
            policy: Some(policy),
            workspace: workspace.to_string(),
            ..Default::default()
        })
        .await
        .into_diagnostic()?;

    let resp = response.into_inner();

    if resp.version == current_version {
        eprintln!(
            "{} Policy unchanged (version {}, hash: {})",
            "·".dimmed(),
            resp.version,
            &resp.policy_hash[..12]
        );
        return Ok(());
    }

    eprintln!(
        "{} Policy version {} submitted (hash: {})",
        "✓".green().bold(),
        resp.version,
        &resp.policy_hash[..12]
    );

    if !wait {
        return Ok(());
    }

    // Poll for status until loaded, failed, or timeout.
    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if Instant::now() > deadline {
            eprintln!(
                "{} Timeout waiting for policy version {} to load",
                "✗".red().bold(),
                resp.version
            );
            std::process::exit(124);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;

        let status_resp = client
            .get_sandbox_policy_status(GetSandboxPolicyStatusRequest {
                name: name.to_string(),
                version: resp.version,
                global: false,
                workspace: workspace.to_string(),
            })
            .await
            .into_diagnostic()?;

        let inner = status_resp.into_inner();
        if let Some(rev) = &inner.revision {
            let status = PolicyStatus::try_from(rev.status).unwrap_or(PolicyStatus::Unspecified);
            match status {
                PolicyStatus::Loaded => {
                    eprintln!(
                        "{} Policy version {} loaded (active version: {})",
                        "✓".green().bold(),
                        rev.version,
                        inner.active_version
                    );
                    return Ok(());
                }
                PolicyStatus::Failed => {
                    eprintln!(
                        "{} Policy version {} failed to load: {}",
                        "✗".red().bold(),
                        rev.version,
                        rev.load_error
                    );
                    std::process::exit(1);
                }
                PolicyStatus::Superseded => {
                    eprintln!(
                        "{} Policy version {} was superseded (active version: {})",
                        "⚠".yellow().bold(),
                        rev.version,
                        inner.active_version
                    );
                    return Ok(());
                }
                _ => {} // still pending, keep polling
            }
        }
    }
}

#[allow(clippy::too_many_arguments)]
pub async fn sandbox_policy_update(
    server: &str,
    name: &str,
    add_endpoints: &[String],
    remove_endpoints: &[String],
    add_deny: &[String],
    add_allow: &[String],
    remove_rules: &[String],
    binaries: &[String],
    rule_name: Option<&str>,
    dry_run: bool,
    wait: bool,
    timeout_secs: u64,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    if dry_run && wait {
        return Err(miette!("--wait cannot be combined with --dry-run"));
    }

    let plan = build_policy_update_plan(
        add_endpoints,
        remove_endpoints,
        add_deny,
        add_allow,
        remove_rules,
        binaries,
        rule_name,
    )?;

    let mut client = grpc_client(server, tls).await?;
    let sandbox = client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette!("sandbox not found"))?;

    let sandbox_id = if sandbox.object_id().is_empty() {
        return Err(miette!("sandbox missing metadata"));
    } else {
        sandbox.object_id().to_string()
    };

    let current = client
        .get_sandbox_config(GetSandboxConfigRequest { sandbox_id })
        .await
        .into_diagnostic()?
        .into_inner();

    if current.policy_source == PolicySource::Global as i32 {
        return Err(miette!(
            "policy is managed globally; delete the global policy before using `openshell policy update`"
        ));
    }

    let merged = openshell_policy::merge_policy(
        current.policy.clone().unwrap_or_default(),
        &plan.preview_operations,
    )
    .map_err(|error| miette!("{error}"))?;

    if dry_run {
        eprintln!(
            "{} Dry run preview for {} incremental policy operation(s)",
            "✓".green().bold(),
            plan.preview_operations.len()
        );
        print_policy_merge_warnings(&merged.warnings);
        print_sandbox_policy(&merged.policy);
        return Ok(());
    }

    let current_version = current.version;
    let current_hash = current.policy_hash.clone();
    let response = client
        .update_config(UpdateConfigRequest {
            name: name.to_string(),
            merge_operations: plan.merge_operations,
            workspace: workspace.to_string(),
            ..Default::default()
        })
        .await
        .into_diagnostic()?
        .into_inner();

    print_policy_merge_warnings(&merged.warnings);

    if response.version == current_version && response.policy_hash == current_hash {
        eprintln!(
            "{} Policy unchanged (version {}, hash: {})",
            "·".dimmed(),
            response.version,
            short_hash(&response.policy_hash)
        );
        return Ok(());
    }

    eprintln!(
        "{} Policy version {} submitted (hash: {})",
        "✓".green().bold(),
        response.version,
        short_hash(&response.policy_hash)
    );

    if !wait {
        return Ok(());
    }

    let deadline = Instant::now() + Duration::from_secs(timeout_secs);
    loop {
        if Instant::now() > deadline {
            eprintln!(
                "{} Timeout waiting for policy version {} to load",
                "✗".red().bold(),
                response.version
            );
            std::process::exit(124);
        }

        tokio::time::sleep(Duration::from_secs(1)).await;

        let status_resp = client
            .get_sandbox_policy_status(GetSandboxPolicyStatusRequest {
                name: name.to_string(),
                version: response.version,
                global: false,
                workspace: workspace.to_string(),
            })
            .await
            .into_diagnostic()?;

        let inner = status_resp.into_inner();
        if let Some(rev) = &inner.revision {
            let status = PolicyStatus::try_from(rev.status).unwrap_or(PolicyStatus::Unspecified);
            match status {
                PolicyStatus::Loaded => {
                    eprintln!(
                        "{} Policy version {} loaded (active version: {})",
                        "✓".green().bold(),
                        rev.version,
                        inner.active_version
                    );
                    return Ok(());
                }
                PolicyStatus::Failed => {
                    eprintln!(
                        "{} Policy version {} failed to load: {}",
                        "✗".red().bold(),
                        rev.version,
                        rev.load_error
                    );
                    std::process::exit(1);
                }
                PolicyStatus::Superseded => {
                    eprintln!(
                        "{} Policy version {} was superseded (active version: {})",
                        "⚠".yellow().bold(),
                        rev.version,
                        inner.active_version
                    );
                    return Ok(());
                }
                _ => {}
            }
        }
    }
}

pub async fn sandbox_policy_get(
    server: &str,
    name: &str,
    version: u32,
    view: PolicyGetView,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut stdout = Vec::new();
    let mut stderr = Vec::new();
    sandbox_policy_get_to_writer(
        server,
        name,
        version,
        view,
        output,
        workspace,
        tls,
        (&mut stdout, &mut stderr),
    )
    .await?;

    {
        let mut terminal_stdout = std::io::stdout().lock();
        terminal_stdout.write_all(&stdout).into_diagnostic()?;
    }
    {
        let mut terminal_stderr = std::io::stderr().lock();
        terminal_stderr.write_all(&stderr).into_diagnostic()?;
    }

    Ok(())
}

#[doc(hidden)]
#[allow(clippy::too_many_arguments)]
pub async fn sandbox_policy_get_to_writer<W, E>(
    server: &str,
    name: &str,
    version: u32,
    view: PolicyGetView,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
    writers: (&mut W, &mut E),
) -> Result<()>
where
    W: Write + Send,
    E: Write + Send,
{
    if version == 0 {
        return sandbox_policy_get_effective_to_writer(
            server, name, view, output, workspace, tls, writers,
        )
        .await;
    }

    let (stdout, stderr) = writers;
    let mut client = grpc_client(server, tls).await?;

    let status_resp = client
        .get_sandbox_policy_status(GetSandboxPolicyStatusRequest {
            name: name.to_string(),
            version,
            global: false,
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;

    let inner = status_resp.into_inner();
    if let Some(rev) = inner.revision {
        let status = PolicyStatus::try_from(rev.status).unwrap_or(PolicyStatus::Unspecified);
        match output {
            "json" => {
                let obj = policy_revision_to_json(
                    "sandbox",
                    Some(name),
                    Some(inner.active_version),
                    &rev,
                    status,
                    view,
                )?;
                writeln!(
                    stdout,
                    "{}",
                    serde_json::to_string_pretty(&obj).into_diagnostic()?
                )
                .into_diagnostic()?;
                return Ok(());
            }
            "table" => {}
            _ => return Err(miette!("unsupported output format: {output}")),
        }

        writeln!(stdout, "Version:      {}", rev.version).into_diagnostic()?;
        writeln!(stdout, "Hash:         {}", rev.policy_hash).into_diagnostic()?;
        writeln!(stdout, "Status:       {status:?}").into_diagnostic()?;
        writeln!(stdout, "Active:       {}", inner.active_version).into_diagnostic()?;
        if rev.created_at_ms > 0 {
            writeln!(stdout, "Created:      {} ms", rev.created_at_ms).into_diagnostic()?;
        }
        if rev.loaded_at_ms > 0 {
            writeln!(stdout, "Loaded:       {} ms", rev.loaded_at_ms).into_diagnostic()?;
        }
        if !rev.load_error.is_empty() {
            writeln!(stdout, "Error:        {}", rev.load_error).into_diagnostic()?;
        }

        if view.includes_policy() {
            if let Some(ref policy) = rev.policy {
                writeln!(stdout, "---").into_diagnostic()?;
                let policy = policy_for_view(policy, view);
                let yaml_str = openshell_policy::serialize_sandbox_policy(policy.as_ref())
                    .wrap_err("failed to serialize policy to YAML")?;
                write!(stdout, "{yaml_str}").into_diagnostic()?;
            } else {
                writeln!(stderr, "Policy payload not available for this version")
                    .into_diagnostic()?;
            }
        }
    } else {
        writeln!(stderr, "No policy history found for sandbox '{name}'").into_diagnostic()?;
    }

    Ok(())
}

async fn sandbox_policy_get_effective_to_writer<W, E>(
    server: &str,
    name: &str,
    view: PolicyGetView,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
    writers: (&mut W, &mut E),
) -> Result<()>
where
    W: Write + Send,
    E: Write + Send,
{
    let (stdout, _stderr) = writers;
    let mut client = grpc_client(server, tls).await?;

    let sandbox = client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette!("sandbox missing from response"))?;
    let sandbox_id = sandbox.object_id();
    if sandbox_id.is_empty() {
        return Err(miette!("sandbox missing metadata"));
    }

    let config = client
        .get_sandbox_config(GetSandboxConfigRequest {
            sandbox_id: sandbox_id.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner();
    let policy = config
        .policy
        .as_ref()
        .ok_or_else(|| miette!("no active policy configured for sandbox '{name}'"))?;
    let policy_source =
        PolicySource::try_from(config.policy_source).unwrap_or(PolicySource::Sandbox);
    let policy_source_label = match policy_source {
        PolicySource::Global => "global",
        PolicySource::Sandbox => "sandbox",
        PolicySource::Unspecified => "unspecified",
    };
    let version = if policy_source == PolicySource::Global && config.global_policy_version > 0 {
        config.global_policy_version
    } else {
        config.version
    };

    match output {
        "json" => {
            let mut obj = serde_json::Map::new();
            obj.insert("scope".to_string(), serde_json::json!("sandbox"));
            obj.insert("sandbox".to_string(), serde_json::json!(name));
            obj.insert("version".to_string(), serde_json::json!(version));
            obj.insert("active_version".to_string(), serde_json::json!(version));
            obj.insert("hash".to_string(), serde_json::json!(config.policy_hash));
            obj.insert("status".to_string(), serde_json::json!("effective"));
            obj.insert(
                "config_revision".to_string(),
                serde_json::json!(config.config_revision),
            );
            obj.insert(
                "policy_source".to_string(),
                serde_json::json!(policy_source_label),
            );
            if config.global_policy_version > 0 {
                obj.insert(
                    "global_policy_version".to_string(),
                    serde_json::json!(config.global_policy_version),
                );
            }
            if view.includes_policy() {
                let policy = policy_for_view(policy, view);
                obj.insert(
                    "policy".to_string(),
                    openshell_policy::sandbox_policy_to_json_value(policy.as_ref())?,
                );
            }
            writeln!(
                stdout,
                "{}",
                serde_json::to_string_pretty(&serde_json::Value::Object(obj)).into_diagnostic()?
            )
            .into_diagnostic()?;
        }
        "table" => {
            writeln!(stdout, "Version:      {version}").into_diagnostic()?;
            writeln!(stdout, "Hash:         {}", config.policy_hash).into_diagnostic()?;
            writeln!(stdout, "Status:       Effective").into_diagnostic()?;
            writeln!(stdout, "Source:       {policy_source_label}").into_diagnostic()?;
            writeln!(stdout, "Config rev:   {}", config.config_revision).into_diagnostic()?;
            if config.global_policy_version > 0 {
                writeln!(stdout, "Global:       {}", config.global_policy_version)
                    .into_diagnostic()?;
            }
            if view.includes_policy() {
                writeln!(stdout, "---").into_diagnostic()?;
                let policy = policy_for_view(policy, view);
                let yaml_str = openshell_policy::serialize_sandbox_policy(policy.as_ref())
                    .wrap_err("failed to serialize policy to YAML")?;
                write!(stdout, "{yaml_str}").into_diagnostic()?;
            }
        }
        _ => return Err(miette!("unsupported output format: {output}")),
    }

    Ok(())
}

pub async fn sandbox_policy_get_global(
    server: &str,
    version: u32,
    view: PolicyGetView,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let status_resp = client
        .get_sandbox_policy_status(GetSandboxPolicyStatusRequest {
            name: String::new(),
            version,
            global: true,
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;

    let inner = status_resp.into_inner();
    if let Some(rev) = inner.revision {
        let status = PolicyStatus::try_from(rev.status).unwrap_or(PolicyStatus::Unspecified);
        match output {
            "json" => {
                let obj = policy_revision_to_json("global", None, None, &rev, status, view)?;
                println!("{}", serde_json::to_string_pretty(&obj).into_diagnostic()?);
                return Ok(());
            }
            "table" => {}
            _ => return Err(miette!("unsupported output format: {output}")),
        }

        println!("Scope:        global");
        println!("Version:      {}", rev.version);
        println!("Hash:         {}", rev.policy_hash);
        println!("Status:       {status:?}");
        if rev.created_at_ms > 0 {
            println!("Created:      {} ms", rev.created_at_ms);
        }
        if rev.loaded_at_ms > 0 {
            println!("Loaded:       {} ms", rev.loaded_at_ms);
        }

        if view.includes_policy() {
            if let Some(ref policy) = rev.policy {
                println!("---");
                let policy = policy_for_view(policy, view);
                let yaml_str = openshell_policy::serialize_sandbox_policy(policy.as_ref())
                    .wrap_err("failed to serialize policy to YAML")?;
                print!("{yaml_str}");
            } else {
                eprintln!("Policy payload not available for this version");
            }
        }
    } else {
        eprintln!("No global policy history found");
    }

    Ok(())
}

fn policy_status_json_name(status: PolicyStatus) -> &'static str {
    match status {
        PolicyStatus::Unspecified => "unspecified",
        PolicyStatus::Pending => "pending",
        PolicyStatus::Loaded => "loaded",
        PolicyStatus::Failed => "failed",
        PolicyStatus::Superseded => "superseded",
    }
}

fn policy_revision_to_json(
    scope: &str,
    sandbox: Option<&str>,
    active_version: Option<u32>,
    rev: &openshell_core::proto::SandboxPolicyRevision,
    status: PolicyStatus,
    view: PolicyGetView,
) -> Result<serde_json::Value> {
    let mut obj = serde_json::Map::new();
    obj.insert("scope".to_string(), serde_json::json!(scope));
    if let Some(sandbox) = sandbox {
        obj.insert("sandbox".to_string(), serde_json::json!(sandbox));
    }
    obj.insert("version".to_string(), serde_json::json!(rev.version));
    obj.insert("hash".to_string(), serde_json::json!(rev.policy_hash));
    obj.insert(
        "status".to_string(),
        serde_json::json!(policy_status_json_name(status)),
    );
    if let Some(active_version) = active_version {
        obj.insert(
            "active_version".to_string(),
            serde_json::json!(active_version),
        );
    }
    if rev.created_at_ms > 0 {
        obj.insert(
            "created_at_ms".to_string(),
            serde_json::json!(rev.created_at_ms),
        );
    }
    if rev.loaded_at_ms > 0 {
        obj.insert(
            "loaded_at_ms".to_string(),
            serde_json::json!(rev.loaded_at_ms),
        );
    }
    if !rev.load_error.is_empty() {
        obj.insert("load_error".to_string(), serde_json::json!(rev.load_error));
    }
    if !rev.provenance.is_empty() {
        obj.insert("provenance".to_string(), serde_json::json!(rev.provenance));
    }
    if view.includes_policy() {
        let policy = match rev.policy.as_ref() {
            Some(policy) => {
                let policy = policy_for_view(policy, view);
                openshell_policy::sandbox_policy_to_json_value(policy.as_ref())?
            }
            None => serde_json::Value::Null,
        };
        obj.insert("policy".to_string(), policy);
    }
    Ok(serde_json::Value::Object(obj))
}

fn policy_for_view(policy: &SandboxPolicy, view: PolicyGetView) -> Cow<'_, SandboxPolicy> {
    if view != PolicyGetView::Base {
        return Cow::Borrowed(policy);
    }

    let mut base_policy = policy.clone();
    base_policy
        .network_policies
        .retain(|name, _| !openshell_policy::is_provider_rule_name(name));
    Cow::Owned(base_policy)
}

pub async fn sandbox_policy_list(
    server: &str,
    name: &str,
    limit: u32,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let resp = client
        .list_sandbox_policies(ListSandboxPoliciesRequest {
            name: name.to_string(),
            limit,
            offset: 0,
            global: false,
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;

    let revisions = resp.into_inner().revisions;
    let structured = policy_revision_list_json("sandbox", Some(name), &revisions)?;
    if crate::output::print_output_collection(output, &structured, Clone::clone)? {
        return Ok(());
    }

    if revisions.is_empty() {
        eprintln!("No policy history found for sandbox '{name}'");
        return Ok(());
    }

    print_policy_revision_table(&revisions);
    Ok(())
}

pub async fn sandbox_policy_list_global(
    server: &str,
    limit: u32,
    output: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let resp = client
        .list_sandbox_policies(ListSandboxPoliciesRequest {
            name: String::new(),
            limit,
            offset: 0,
            global: true,
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;

    let revisions = resp.into_inner().revisions;
    let structured = policy_revision_list_json("global", None, &revisions)?;
    if crate::output::print_output_collection(output, &structured, Clone::clone)? {
        return Ok(());
    }

    if revisions.is_empty() {
        eprintln!("No global policy history found");
        return Ok(());
    }

    print_policy_revision_table(&revisions);
    Ok(())
}

fn policy_revision_list_json(
    scope: &str,
    sandbox: Option<&str>,
    revisions: &[openshell_core::proto::SandboxPolicyRevision],
) -> Result<Vec<serde_json::Value>> {
    revisions
        .iter()
        .map(|revision| {
            let status =
                PolicyStatus::try_from(revision.status).unwrap_or(PolicyStatus::Unspecified);
            policy_revision_to_json(
                scope,
                sandbox,
                None,
                revision,
                status,
                PolicyGetView::Metadata,
            )
        })
        .collect()
}

fn print_policy_revision_table(revisions: &[openshell_core::proto::SandboxPolicyRevision]) {
    println!(
        "{:<8} {:<14} {:<12} {:<24} ERROR",
        "VERSION", "HASH", "STATUS", "CREATED"
    );
    for rev in revisions {
        let status = PolicyStatus::try_from(rev.status).unwrap_or(PolicyStatus::Unspecified);
        let hash_short = if rev.policy_hash.len() >= 12 {
            &rev.policy_hash[..12]
        } else {
            &rev.policy_hash
        };
        let error_short = if rev.load_error.len() > 40 {
            format!("{}...", &rev.load_error[..40])
        } else {
            rev.load_error.clone()
        };
        println!(
            "{:<8} {:<14} {:<12} {:<24} {}",
            rev.version,
            hash_short,
            format!("{status:?}"),
            rev.created_at_ms,
            error_short,
        );
    }
}

// ---------------------------------------------------------------------------
// Sandbox logs command
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)] // user-facing CLI command
pub async fn sandbox_logs(
    server: &str,
    name: &str,
    lines: u32,
    tail: bool,
    since: Option<&str>,
    sources: &[String],
    level: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    // Resolve sandbox name to id.
    let sandbox = client
        .get_sandbox(GetSandboxRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .sandbox
        .ok_or_else(|| miette::miette!("sandbox not found"))?;

    // Normalize "all" to empty list (server treats empty as "no filter").
    let source_filter: Vec<String> = sources
        .iter()
        .filter(|s| s.as_str() != "all")
        .cloned()
        .collect();

    let since_ms = if let Some(s) = since {
        let dur_ms = parse_duration_to_ms(s)?;
        let now_ms = i64::try_from(
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .into_diagnostic()?
                .as_millis(),
        )
        .into_diagnostic()?;
        now_ms - dur_ms
    } else {
        0
    };

    if tail {
        // Streaming mode: use WatchSandbox.
        let mut stream = client
            .watch_sandbox(WatchSandboxRequest {
                id: sandbox.object_id().to_string(),
                follow_status: false,
                follow_logs: true,
                follow_events: false,
                log_tail_lines: lines,
                event_tail: 0,
                stop_on_terminal: false,
                log_since_ms: since_ms,
                log_sources: source_filter,
                log_min_level: level.to_uppercase(),
            })
            .await
            .into_diagnostic()?
            .into_inner();

        while let Some(event) = stream.next().await {
            let event = event.into_diagnostic()?;
            if let Some(openshell_core::proto::sandbox_stream_event::Payload::Log(log)) =
                event.payload
            {
                print_log_line(&log);
            }
        }
    } else {
        // One-shot mode: use GetSandboxLogs.
        let resp = client
            .get_sandbox_logs(GetSandboxLogsRequest {
                sandbox_id: sandbox.object_id().to_string(),
                lines,
                since_ms,
                sources: source_filter,
                min_level: level.to_uppercase(),
                workspace: workspace.to_string(),
            })
            .await
            .into_diagnostic()?;

        let inner = resp.into_inner();

        if since_ms > 0 && inner.buffer_total > 0 {
            eprintln!(
                "Warning: log buffer contains only the last {} lines; --since results may be incomplete.",
                inner.buffer_total
            );
        }

        for log in &inner.logs {
            print_log_line(log);
        }
    }

    Ok(())
}

fn print_log_line(log: &openshell_core::proto::SandboxLogLine) {
    println!("{}", format_log_line(log));
}

fn format_log_line(log: &openshell_core::proto::SandboxLogLine) -> String {
    let source = if log.source.is_empty() {
        "gateway"
    } else {
        &log.source
    };
    let secs = log.timestamp_ms / 1000;
    let millis = log.timestamp_ms % 1000;
    if log.fields.is_empty() {
        format!(
            "[{secs}.{millis:03}] [{source:<7}] [{:<5}] [{}] {}",
            log.level, log.target, log.message
        )
    } else {
        let mut fields_str = String::new();
        let mut entries: Vec<_> = log.fields.iter().collect();
        entries.sort_by_key(|(k, _)| k.as_str());
        for (k, v) in entries {
            if !fields_str.is_empty() {
                fields_str.push(' ');
            }
            fields_str.push_str(k);
            fields_str.push('=');
            fields_str.push_str(v);
        }
        format!(
            "[{secs}.{millis:03}] [{source:<7}] [{:<5}] [{}] {} {}",
            log.level, log.target, log.message, fields_str
        )
    }
}

// ---------------------------------------------------------------------------
// Network rule commands
// ---------------------------------------------------------------------------

/// Show network rules for a sandbox.
pub async fn sandbox_draft_get(
    server: &str,
    name: &str,
    status_filter: Option<&str>,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let response = client
        .get_draft_policy(GetDraftPolicyRequest {
            name: name.to_string(),
            status_filter: status_filter.unwrap_or("").to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;

    let inner = response.into_inner();

    if inner.chunks.is_empty() {
        println!("No network rules for sandbox '{name}'");
        return Ok(());
    }

    println!(
        "{}  (version {}, {} chunk{})",
        "Network Rules:".cyan().bold(),
        inner.draft_version,
        inner.chunks.len(),
        if inner.chunks.len() == 1 { "" } else { "s" }
    );
    println!();

    for chunk in &inner.chunks {
        let status_colored = match chunk.status.as_str() {
            "pending" => chunk.status.yellow().to_string(),
            "approved" => chunk.status.green().to_string(),
            "rejected" => chunk.status.red().to_string(),
            _ => chunk.status.clone(),
        };

        println!("  {} {}", "Chunk:".dimmed(), chunk.id);
        println!("  {} {}", "Status:".dimmed(), status_colored);
        println!("  {} {}", "Rule:".dimmed(), chunk.rule_name);
        if !chunk.binary.is_empty() {
            println!("  {} {}", "Binary:".dimmed(), chunk.binary);
        }
        println!(
            "  {} {:.0}%",
            "Confidence:".dimmed(),
            chunk.confidence * 100.0
        );
        println!("  {} {}", "Rationale:".dimmed(), chunk.rationale);

        if !chunk.security_notes.is_empty() {
            println!(
                "  {} {}",
                "Security:".dimmed(),
                chunk.security_notes.yellow()
            );
        }
        if !chunk.validation_result.is_empty() {
            println!(
                "  {} {}",
                "Prover:".dimmed(),
                chunk.validation_result.cyan()
            );
        }
        if !chunk.application_error.is_empty() {
            println!(
                "  {} {}",
                "Application:".dimmed(),
                chunk.application_error.red()
            );
        }
        if !chunk.candidate_effective_policy_hash.is_empty() {
            println!(
                "  {} {}",
                "Candidate:".dimmed(),
                &chunk.candidate_effective_policy_hash
                    [..12.min(chunk.candidate_effective_policy_hash.len())]
            );
        }

        if let Some(ref rule) = chunk.proposed_rule {
            println!("  {} {}", "Endpoints:".dimmed(), format_endpoints(rule));
            if !rule.binaries.is_empty() {
                let bins: Vec<&str> = rule.binaries.iter().map(|b| b.path.as_str()).collect();
                println!("  {} {}", "Binaries:".dimmed(), bins.join(", "));
            }
        }

        if chunk.hit_count > 1 {
            println!(
                "  {} {} (first seen {}, last seen {})",
                "Hits:".dimmed(),
                chunk.hit_count,
                format_epoch_ms(chunk.first_seen_ms),
                format_epoch_ms(chunk.last_seen_ms),
            );
        }
        println!();
    }

    Ok(())
}

/// Approve a network rule.
pub async fn sandbox_draft_approve(
    server: &str,
    name: &str,
    chunk_id: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let review_token = client
        .get_draft_policy(GetDraftPolicyRequest {
            name: name.to_string(),
            status_filter: String::new(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .chunks
        .into_iter()
        .find(|chunk| chunk.id == chunk_id)
        .ok_or_else(|| miette::miette!("draft chunk '{chunk_id}' not found"))?
        .review_token;

    let response = client
        .approve_draft_chunk(ApproveDraftChunkRequest {
            name: name.to_string(),
            chunk_id: chunk_id.to_string(),
            workspace: workspace.to_string(),
            review_token,
        })
        .await
        .into_diagnostic()?;

    let inner = response.into_inner();
    println!(
        "{} Chunk approved. Policy version: {}, hash: {}",
        "OK".green().bold(),
        inner.policy_version,
        &inner.policy_hash[..12.min(inner.policy_hash.len())]
    );

    Ok(())
}

/// Reject a network rule.
pub async fn sandbox_draft_reject(
    server: &str,
    name: &str,
    chunk_id: &str,
    reason: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    client
        .reject_draft_chunk(RejectDraftChunkRequest {
            name: name.to_string(),
            chunk_id: chunk_id.to_string(),
            reason: reason.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;

    println!("{} Chunk rejected.", "OK".green().bold());

    Ok(())
}

/// Approve all pending network rules.
pub async fn sandbox_draft_approve_all(
    server: &str,
    name: &str,
    include_security_flagged: bool,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;
    let approvals = client
        .get_draft_policy(GetDraftPolicyRequest {
            name: name.to_string(),
            status_filter: "pending".to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?
        .into_inner()
        .chunks
        .into_iter()
        .map(|chunk| openshell_core::proto::DraftChunkApproval {
            chunk_id: chunk.id,
            review_token: chunk.review_token,
        })
        .collect();

    let response = client
        .approve_all_draft_chunks(ApproveAllDraftChunksRequest {
            name: name.to_string(),
            include_security_flagged,
            workspace: workspace.to_string(),
            approvals,
        })
        .await
        .into_diagnostic()?;

    let inner = response.into_inner();
    println!(
        "{} {} chunk(s) approved, {} skipped. Policy version: {}",
        "OK".green().bold(),
        inner.chunks_approved,
        inner.chunks_skipped,
        inner.policy_version,
    );

    Ok(())
}

/// Clear all pending network rules.
pub async fn sandbox_draft_clear(
    server: &str,
    name: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let response = client
        .clear_draft_chunks(ClearDraftChunksRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;

    let inner = response.into_inner();
    println!(
        "{} {} pending chunk(s) cleared.",
        "OK".green().bold(),
        inner.chunks_cleared,
    );

    Ok(())
}

/// Show network rule history.
pub async fn sandbox_draft_history(
    server: &str,
    name: &str,
    workspace: &str,
    tls: &TlsOptions,
) -> Result<()> {
    let mut client = grpc_client(server, tls).await?;

    let response = client
        .get_draft_history(GetDraftHistoryRequest {
            name: name.to_string(),
            workspace: workspace.to_string(),
        })
        .await
        .into_diagnostic()?;

    let inner = response.into_inner();

    if inner.entries.is_empty() {
        println!("No rule history for sandbox '{name}'");
        return Ok(());
    }

    println!("{}", "Rule History:".cyan().bold());
    println!();

    for entry in &inner.entries {
        let event_colored = match entry.event_type.as_str() {
            "proposed" => entry.event_type.yellow().to_string(),
            "approved" => entry.event_type.green().to_string(),
            "rejected" => entry.event_type.red().to_string(),
            _ => entry.event_type.clone(),
        };

        println!(
            "  {} {} [{}] {}",
            format_timestamp_ms(entry.timestamp_ms).dimmed(),
            event_colored,
            entry.chunk_id.get(..8).unwrap_or(&entry.chunk_id),
            entry.description,
        );
    }

    Ok(())
}

/// Format a `NetworkPolicyRule`'s endpoints as a compact string.
fn format_endpoints(rule: &openshell_core::proto::NetworkPolicyRule) -> String {
    rule.endpoints
        .iter()
        .map(format_endpoint)
        .collect::<Vec<_>>()
        .join(", ")
}

/// Render an endpoint as `host:port [layer, …allows…, …denies…]` so a reader
/// can tell L4-only access apart from a method/path-scoped L7 grant. The L7
/// fields (`protocol: rest`, `rules`, `access`) materially change what gets
/// allowed; surfacing them in the default text output is what makes
/// `openshell rule get` useful for approval review.
fn format_endpoint(endpoint: &openshell_core::proto::NetworkEndpoint) -> String {
    let host_port = if endpoint.port > 0 {
        format!("{}:{}", endpoint.host, endpoint.port)
    } else {
        endpoint.host.clone()
    };

    let mut tags: Vec<String> = Vec::new();
    let layer_tag = if endpoint.protocol.eq_ignore_ascii_case("rest") {
        "L7 rest"
    } else if endpoint.protocol.is_empty() {
        "L4"
    } else {
        endpoint.protocol.as_str()
    };
    tags.push(layer_tag.to_string());

    if !endpoint.access.is_empty() {
        tags.push(format!("access={}", endpoint.access));
    }

    for r in &endpoint.rules {
        if let Some(allow) = &r.allow {
            let method = non_empty_or(&allow.method, "*");
            let path = non_empty_or(&allow.path, "*");
            tags.push(format!("allow {method} {path}"));
        }
    }
    for r in &endpoint.deny_rules {
        let method = non_empty_or(&r.method, "*");
        let path = non_empty_or(&r.path, "*");
        tags.push(format!("deny {method} {path}"));
    }

    format!("{host_port} [{}]", tags.join(", "))
}

#[cfg(test)]
mod tests {
    use super::{
        PolicyGetView, ProvisioningStep, build_sandbox_resource_limits,
        dockerfile_sources_supported_for_gateway, format_endpoint, format_log_line, git_sync_files,
        has_main_process_result, parse_cli_setting_value, parse_credential_expiry_cli_value,
        parse_driver_config_json, parse_secret_material_env_pairs, policy_revision_list_json,
        policy_revision_to_json, provisioning_timeout_message, ready_false_condition_message,
        resolve_from, sandbox_should_persist, sandbox_upload_plan, service_endpoint_to_json,
        service_expose_status_error, service_url_for_gateway, workspace_member_to_json,
    };
    use crate::TEST_ENV_LOCK;
    use crate::commands::common::{
        parse_credential_expiry_pairs, parse_credential_pairs, progress_step_from_metadata,
    };
    use crate::test_utils::EnvVarGuard;
    use std::fs;
    use std::path::Path;
    use std::process::Command;
    use tonic::Status;

    use openshell_bootstrap::GatewayMetadata;
    use openshell_core::progress::{
        PROGRESS_STEP_PULLING_IMAGE, PROGRESS_STEP_REQUESTING_SANDBOX,
        PROGRESS_STEP_STARTING_SANDBOX,
    };
    use openshell_core::proto::{
        GetSandboxConfigResponse, GpuResourceRequirements, PolicySource, PolicyStatus,
        ResourceRequirements, Sandbox, SandboxCondition, SandboxPhase, SandboxPolicy,
        SandboxPolicyRevision, SandboxResources, SandboxStatus, SandboxWorkloadConfig,
        SandboxWorkloadTemplate, SandboxWorkloadTemplateProvenance, SandboxWorkloadTemplateSpec,
        ServiceEndpoint, ServiceEndpointResponse, WorkspaceMember, WorkspaceRole,
        datamodel::v1::ObjectMeta,
    };

    #[test]
    fn policy_revision_json_includes_revision_provenance() {
        let revision = SandboxPolicyRevision {
            version: 2,
            policy_hash: "hash".to_string(),
            provenance: std::collections::HashMap::from([(
                "openshell.nvidia.com/policy-signature".to_string(),
                "signed".to_string(),
            )]),
            ..Default::default()
        };

        let json = policy_revision_to_json(
            "sandbox",
            Some("example"),
            Some(2),
            &revision,
            PolicyStatus::Pending,
            PolicyGetView::Metadata,
        )
        .unwrap();

        assert_eq!(
            json["provenance"]["openshell.nvidia.com/policy-signature"],
            "signed"
        );
    }

    #[test]
    fn policy_list_json_reuses_metadata_contract() {
        let load_error = "policy failed after checking café.example/非常に長いパス";
        let revisions = vec![SandboxPolicyRevision {
            version: 7,
            policy_hash: "0123456789abcdef".to_string(),
            status: PolicyStatus::Failed as i32,
            load_error: load_error.to_string(),
            created_at_ms: 100,
            loaded_at_ms: 200,
            policy: Some(SandboxPolicy::default()),
            provenance: std::collections::HashMap::from([(
                "source".to_string(),
                "provider-composition".to_string(),
            )]),
        }];

        let values = policy_revision_list_json("sandbox", Some("dev"), &revisions)
            .expect("policy list JSON");

        assert_eq!(
            values[0],
            serde_json::json!({
                "scope": "sandbox",
                "sandbox": "dev",
                "version": 7,
                "hash": "0123456789abcdef",
                "status": "failed",
                "created_at_ms": 100,
                "loaded_at_ms": 200,
                "load_error": load_error,
                "provenance": {"source": "provider-composition"},
            })
        );
        assert!(values[0].get("policy").is_none());
        assert!(values[0].get("active_version").is_none());

        let unknown = policy_revision_list_json(
            "global",
            None,
            &[SandboxPolicyRevision {
                version: 8,
                status: 999,
                ..Default::default()
            }],
        )
        .expect("global policy list JSON");
        assert_eq!(unknown[0]["scope"], "global");
        assert_eq!(unknown[0]["status"], "unspecified");
        assert!(unknown[0].get("sandbox").is_none());
    }

    #[test]
    fn service_endpoint_json_has_raw_fields_and_normalized_url() {
        let response = ServiceEndpointResponse {
            endpoint: Some(ServiceEndpoint {
                metadata: Some(ObjectMeta {
                    workspace: "team-a".to_string(),
                    ..Default::default()
                }),
                sandbox_name: "api".to_string(),
                service_name: String::new(),
                target_port: 8080,
                ..Default::default()
            }),
            url: "https://api.openshell.localhost:3000/".to_string(),
        };

        let value = service_endpoint_to_json(&response, "https://gateway.example:17670")
            .expect("service endpoint JSON");
        assert_eq!(
            value,
            serde_json::json!({
                "workspace": "team-a",
                "sandbox": "api",
                "service": "",
                "target_port": 8080,
                "url": "https://api.openshell.localhost:17670/",
            })
        );
        assert!(service_endpoint_to_json(&ServiceEndpointResponse::default(), "unused").is_none());
    }

    #[test]
    fn workspace_member_json_uses_stable_role_names() {
        for (role, expected) in [
            (WorkspaceRole::Admin as i32, "admin"),
            (WorkspaceRole::User as i32, "user"),
            (999, "unknown"),
        ] {
            let value = workspace_member_to_json(&WorkspaceMember {
                metadata: Some(ObjectMeta {
                    id: "internal-id".to_string(),
                    ..Default::default()
                }),
                principal_subject: "oidc-subject".to_string(),
                role,
            });
            assert_eq!(
                value,
                serde_json::json!({"subject": "oidc-subject", "role": expected})
            );
            assert!(!value.to_string().contains("internal-id"));
        }
    }

    #[test]
    fn parse_credential_pairs_accepts_key_value_form() {
        let parsed = parse_credential_pairs(&["API_KEY=abc123".to_string()]).expect("parse");
        assert_eq!(parsed.get("API_KEY"), Some(&"abc123".to_string()));
    }

    #[test]
    fn parse_credential_pairs_reads_value_from_environment_for_key_only_form() {
        let _guard = EnvVarGuard::set("NAV_PARSE_CREDENTIAL_TEST_KEY", "from-env");

        let parsed =
            parse_credential_pairs(&["NAV_PARSE_CREDENTIAL_TEST_KEY".to_string()]).expect("parse");
        assert_eq!(
            parsed.get("NAV_PARSE_CREDENTIAL_TEST_KEY"),
            Some(&"from-env".to_string())
        );
    }

    #[test]
    fn parse_credential_pairs_rejects_missing_environment_for_key_only_form() {
        let _guard = EnvVarGuard::unset("NAV_PARSE_CREDENTIAL_MISSING");

        let err = parse_credential_pairs(&["NAV_PARSE_CREDENTIAL_MISSING".to_string()])
            .expect_err("missing env should error");
        assert!(err.to_string().contains(
            "requires local env var 'NAV_PARSE_CREDENTIAL_MISSING' to be set to a non-empty value"
        ));
    }

    #[test]
    fn parse_credential_pairs_rejects_empty_environment_for_key_only_form() {
        let _guard = EnvVarGuard::set("NAV_PARSE_CREDENTIAL_EMPTY", "");

        let err = parse_credential_pairs(&["NAV_PARSE_CREDENTIAL_EMPTY".to_string()])
            .expect_err("empty env should error");
        assert!(err.to_string().contains(
            "requires local env var 'NAV_PARSE_CREDENTIAL_EMPTY' to be set to a non-empty value"
        ));
    }

    #[test]
    fn parse_secret_material_env_pairs_reads_value_from_named_environment_variable() {
        let _guard = EnvVarGuard::set("NAV_PARSE_SME_NAMED", "pem-material");

        let parsed =
            parse_secret_material_env_pairs(&["private_key=NAV_PARSE_SME_NAMED".to_string()])
                .expect("parse");
        assert_eq!(parsed.get("private_key"), Some(&"pem-material".to_string()));
    }

    #[test]
    fn parse_secret_material_env_pairs_defaults_env_name_to_key() {
        let _guard = EnvVarGuard::set("NAV_PARSE_SME_KEY_ONLY", "key-only-material");

        let parsed = parse_secret_material_env_pairs(&["NAV_PARSE_SME_KEY_ONLY".to_string()])
            .expect("parse");
        assert_eq!(
            parsed.get("NAV_PARSE_SME_KEY_ONLY"),
            Some(&"key-only-material".to_string())
        );
    }

    #[test]
    fn parse_secret_material_env_pairs_rejects_missing_environment() {
        let _guard = EnvVarGuard::unset("NAV_PARSE_SME_MISSING");

        let err =
            parse_secret_material_env_pairs(&["private_key=NAV_PARSE_SME_MISSING".to_string()])
                .expect_err("missing env should error");
        assert!(err.to_string().contains(
            "requires local env var 'NAV_PARSE_SME_MISSING' to be set to a non-empty value"
        ));
    }

    #[test]
    fn parse_secret_material_env_pairs_rejects_empty_environment_value() {
        let _guard = EnvVarGuard::set("NAV_PARSE_SME_EMPTY", "   ");

        let err = parse_secret_material_env_pairs(&["private_key=NAV_PARSE_SME_EMPTY".to_string()])
            .expect_err("blank env should error");
        assert!(err.to_string().contains(
            "requires local env var 'NAV_PARSE_SME_EMPTY' to be set to a non-empty value"
        ));
    }

    #[test]
    fn parse_secret_material_env_pairs_rejects_empty_key() {
        let err = parse_secret_material_env_pairs(&["=NAV_PARSE_SME_NO_KEY".to_string()])
            .expect_err("empty key should error");
        assert!(err.to_string().contains("key cannot be empty"));
    }

    #[test]
    fn parse_secret_material_env_pairs_rejects_duplicate_keys() {
        let _guard = EnvVarGuard::set("NAV_PARSE_SME_DUP", "value");

        let err = parse_secret_material_env_pairs(&[
            "private_key=NAV_PARSE_SME_DUP".to_string(),
            "private_key=NAV_PARSE_SME_DUP".to_string(),
        ])
        .expect_err("duplicate key should error");
        assert!(
            err.to_string()
                .contains("key 'private_key' supplied more than once")
        );
    }

    #[test]
    fn parse_credential_expiry_pairs_accepts_epoch_millis_and_rfc3339() {
        let parsed = parse_credential_expiry_pairs(&[
            "API_TOKEN=1767225600000".to_string(),
            "MS_GRAPH_ACCESS_TOKEN=2026-01-01T00:00:00Z".to_string(),
        ])
        .expect("parse");

        assert_eq!(parsed.get("API_TOKEN"), Some(&1_767_225_600_000));
        assert_eq!(
            parsed.get("MS_GRAPH_ACCESS_TOKEN"),
            Some(&1_767_225_600_000)
        );
    }

    #[test]
    fn parse_credential_expiry_pairs_accepts_zero_to_clear_expiry() {
        let parsed =
            parse_credential_expiry_pairs(&["API_TOKEN=0".to_string()]).expect("parse zero");

        assert_eq!(parsed.get("API_TOKEN"), Some(&0));
    }

    #[test]
    fn parse_credential_expiry_rejects_invalid_timestamp() {
        let err = parse_credential_expiry_pairs(&["API_TOKEN=next-week".to_string()])
            .expect_err("invalid timestamp should error");

        assert!(
            err.to_string()
                .contains("must be a Unix epoch millisecond timestamp or RFC3339 timestamp")
        );
    }

    #[test]
    fn parse_credential_expiry_cli_value_accepts_rfc3339_offsets() {
        let parsed = parse_credential_expiry_cli_value("2026-01-01T01:00:00+01:00")
            .expect("parse RFC3339 with offset");

        assert_eq!(parsed, 1_767_225_600_000);
    }

    #[test]
    fn progress_step_metadata_values_map_to_cli_steps() {
        assert_eq!(
            progress_step_from_metadata(PROGRESS_STEP_REQUESTING_SANDBOX),
            Some(ProvisioningStep::RequestingSandbox)
        );
        assert_eq!(
            progress_step_from_metadata(PROGRESS_STEP_PULLING_IMAGE),
            Some(ProvisioningStep::PullingSandboxImage)
        );
        assert_eq!(
            progress_step_from_metadata(PROGRESS_STEP_STARTING_SANDBOX),
            Some(ProvisioningStep::StartingSandbox)
        );
        assert_eq!(progress_step_from_metadata("driver-private-step"), None);
    }

    #[test]
    fn parse_cli_setting_value_parses_bool_aliases() {
        let yes_value = parse_cli_setting_value("ocsf_json_enabled", "yes").expect("parse yes");
        assert_eq!(
            yes_value.value,
            Some(openshell_core::proto::setting_value::Value::BoolValue(true))
        );

        let zero_value = parse_cli_setting_value("ocsf_json_enabled", "0").expect("parse 0");
        assert_eq!(
            zero_value.value,
            Some(openshell_core::proto::setting_value::Value::BoolValue(
                false
            ))
        );
    }

    #[test]
    fn parse_cli_setting_value_rejects_invalid_bool() {
        let err = parse_cli_setting_value("ocsf_json_enabled", "maybe")
            .expect_err("invalid bool should fail");
        assert!(err.to_string().contains("invalid bool value"));
    }

    #[test]
    fn parse_cli_setting_value_rejects_unknown_key() {
        let err =
            parse_cli_setting_value("unknown_key", "value").expect_err("unknown key should fail");
        assert!(err.to_string().contains("unknown setting key"));
    }

    #[test]
    fn build_sandbox_resource_limits_sets_limits_only() {
        let resources = build_sandbox_resource_limits(Some("500m"), Some("2Gi"))
            .expect("resource limits should parse")
            .expect("resource limits should be present");

        let limits = resources
            .fields
            .get("limits")
            .and_then(|value| value.kind.as_ref())
            .and_then(|kind| match kind {
                prost_types::value::Kind::StructValue(inner) => Some(inner),
                _ => None,
            })
            .expect("limits should be a struct");

        assert_eq!(
            limits
                .fields
                .get("cpu")
                .and_then(|value| value.kind.as_ref())
                .and_then(|kind| match kind {
                    prost_types::value::Kind::StringValue(value) => Some(value.as_str()),
                    _ => None,
                }),
            Some("500m")
        );
        assert_eq!(
            limits
                .fields
                .get("memory")
                .and_then(|value| value.kind.as_ref())
                .and_then(|kind| match kind {
                    prost_types::value::Kind::StringValue(value) => Some(value.as_str()),
                    _ => None,
                }),
            Some("2Gi")
        );
        assert!(!resources.fields.contains_key("requests"));
    }

    #[test]
    fn build_sandbox_resource_limits_rejects_invalid_quantities() {
        assert!(build_sandbox_resource_limits(Some("0"), None).is_err());
        assert!(build_sandbox_resource_limits(Some("half"), None).is_err());
        assert!(build_sandbox_resource_limits(None, Some("0Gi")).is_err());
        assert!(build_sandbox_resource_limits(None, Some("1.5Gi")).is_err());
    }

    #[test]
    fn parse_driver_config_json_accepts_driver_keyed_object() {
        let config =
            parse_driver_config_json(r#"{"kubernetes":{"pod":{"node_selector":{"pool":"gpu"}}}}"#)
                .expect("driver config should parse");

        let kubernetes = config
            .fields
            .get("kubernetes")
            .and_then(|value| value.kind.as_ref())
            .and_then(|kind| match kind {
                prost_types::value::Kind::StructValue(inner) => Some(inner),
                _ => None,
            })
            .expect("kubernetes block should be a struct");
        let pod = kubernetes
            .fields
            .get("pod")
            .and_then(|value| value.kind.as_ref())
            .and_then(|kind| match kind {
                prost_types::value::Kind::StructValue(inner) => Some(inner),
                _ => None,
            })
            .expect("pod block should be a struct");

        assert!(pod.fields.contains_key("node_selector"));
    }

    #[test]
    fn parse_driver_config_json_rejects_non_object() {
        let err = parse_driver_config_json(r#"["kubernetes"]"#)
            .expect_err("top-level array should be rejected");

        assert!(
            err.to_string().contains("keyed by driver name"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn parse_driver_config_json_rejects_invalid_json() {
        let err = parse_driver_config_json(r#"{"kubernetes":"#)
            .expect_err("invalid JSON should be rejected");

        assert!(
            err.to_string().contains("must be valid JSON"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn sandbox_should_persist_defaults_to_persistent() {
        assert!(sandbox_should_persist(true, None));
    }

    #[test]
    fn sandbox_should_not_persist_when_no_keep_is_set() {
        assert!(!sandbox_should_persist(false, None));
    }

    #[test]
    fn sandbox_should_persist_when_forward_is_requested() {
        let spec = openshell_core::forward::ForwardSpec::new(8080);
        assert!(sandbox_should_persist(false, Some(&spec)));
    }

    #[test]
    fn infrastructure_error_with_observed_exit_is_not_a_main_process_result() {
        let mut sandbox = Sandbox {
            status: Some(SandboxStatus {
                exit_code: Some(137),
                conditions: vec![SandboxCondition {
                    r#type: "Ready".to_string(),
                    status: "False".to_string(),
                    reason: "ComputeResourceMissing".to_string(),
                    message: "sandbox runtime disappeared".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Error as i32);

        assert!(!has_main_process_result(&sandbox));
    }

    #[test]
    fn main_process_failed_condition_identifies_command_result() {
        let mut sandbox = Sandbox {
            status: Some(SandboxStatus {
                exit_code: Some(7),
                conditions: vec![SandboxCondition {
                    r#type: "Ready".to_string(),
                    status: "False".to_string(),
                    reason: "MainProcessFailed".to_string(),
                    message: "canonical main process exited with status 7".to_string(),
                    ..Default::default()
                }],
                ..Default::default()
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Error as i32);

        assert!(has_main_process_result(&sandbox));
    }

    #[test]
    fn resolve_from_classifies_existing_dockerfile_path() {
        let temp = tempfile::tempdir().expect("failed to create tempdir");
        let dockerfile = temp.path().join("Dockerfile");
        fs::write(&dockerfile, "FROM scratch\n").expect("failed to write Dockerfile");

        match resolve_from(dockerfile.to_str().expect("temp path is not UTF-8"))
            .expect("expected Dockerfile source")
        {
            super::ResolvedSource::Dockerfile {
                dockerfile: resolved,
                context,
            } => {
                assert_eq!(
                    resolved,
                    dockerfile
                        .canonicalize()
                        .expect("failed to canonicalize Dockerfile")
                );
                assert_eq!(
                    context,
                    temp.path()
                        .canonicalize()
                        .expect("failed to canonicalize context")
                );
            }
            super::ResolvedSource::Image(image) => {
                panic!("expected Dockerfile source, got image {image}");
            }
        }
    }

    #[test]
    fn resolve_from_rejects_missing_explicit_dockerfile_path() {
        let temp = tempfile::tempdir().expect("failed to create tempdir");
        let missing = temp.path().join("Dockerfile");

        let err = resolve_from(missing.to_str().expect("temp path is not UTF-8"))
            .expect_err("expected missing Dockerfile path to be rejected");

        assert!(
            err.to_string().contains("local --from path does not exist"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn resolve_from_keeps_dockerfile_named_image_refs_as_images() {
        let image_ref = "ghcr.io/acme/dockerfile-runner:latest";

        match resolve_from(image_ref).expect("expected image source") {
            super::ResolvedSource::Image(image) => assert_eq!(image, image_ref),
            super::ResolvedSource::Dockerfile { .. } => {
                panic!("expected image ref, got Dockerfile source");
            }
        }
    }

    #[test]
    fn dockerfile_sources_are_rejected_for_remote_gateways() {
        let metadata = GatewayMetadata {
            name: "remote".to_string(),
            gateway_endpoint: "https://gateway.example.com".to_string(),
            is_remote: true,
            gateway_port: 443,
            remote_host: Some("user@gateway.example.com".to_string()),
            resolved_host: Some("gateway.example.com".to_string()),
            auth_mode: None,
            edge_team_domain: None,
            edge_auth_url: None,
            vm_driver_state_dir: None,
            ..Default::default()
        };

        assert!(!dockerfile_sources_supported_for_gateway(Some(&metadata)));
    }

    #[test]
    fn dockerfile_sources_are_allowed_for_local_gateways() {
        let metadata = GatewayMetadata {
            name: "local".to_string(),
            gateway_endpoint: "http://127.0.0.1:8080".to_string(),
            is_remote: false,
            gateway_port: 8080,
            remote_host: None,
            resolved_host: None,
            auth_mode: None,
            edge_team_domain: None,
            edge_auth_url: None,
            vm_driver_state_dir: None,
            ..Default::default()
        };

        assert!(dockerfile_sources_supported_for_gateway(Some(&metadata)));
        assert!(dockerfile_sources_supported_for_gateway(None));
    }

    #[test]
    fn service_url_for_gateway_uses_external_gateway_port() {
        assert_eq!(
            service_url_for_gateway(
                "https://quiet-flamingo--notebook.navigator.openshell.localhost:8080/",
                "https://127.0.0.1:31886"
            ),
            "https://quiet-flamingo--notebook.navigator.openshell.localhost:31886/"
        );
    }

    #[test]
    fn service_url_for_gateway_omits_default_external_port() {
        assert_eq!(
            service_url_for_gateway(
                "https://quiet-flamingo--notebook.navigator.openshell.localhost:8080/",
                "https://gateway.example.com"
            ),
            "https://quiet-flamingo--notebook.navigator.openshell.localhost/"
        );
    }

    #[test]
    fn service_url_for_gateway_preserves_service_scheme() {
        assert_eq!(
            service_url_for_gateway(
                "http://quiet-flamingo--notebook.navigator.openshell.localhost:8080/",
                "https://127.0.0.1:31886"
            ),
            "http://quiet-flamingo--notebook.navigator.openshell.localhost:31886/"
        );
    }

    #[test]
    fn service_url_for_gateway_uses_gateway_default_port() {
        assert_eq!(
            service_url_for_gateway(
                "http://quiet-flamingo--notebook.navigator.openshell.localhost:8080/",
                "https://gateway.example.com"
            ),
            "http://quiet-flamingo--notebook.navigator.openshell.localhost:443/"
        );
    }

    #[test]
    fn service_expose_status_error_mentions_required_scope() {
        let report = service_expose_status_error(Status::permission_denied(
            "scope 'sandbox:write' required",
        ));

        assert_eq!(
            report.to_string(),
            "expose service failed: permission denied (requires sandbox:write)"
        );
    }

    #[test]
    fn ready_false_condition_message_prefers_reason_and_message() {
        let status = SandboxStatus {
            sandbox_name: "gpu".to_string(),
            agent_pod: "gpu-pod".to_string(),
            conditions: vec![SandboxCondition {
                r#type: "Ready".to_string(),
                status: "False".to_string(),
                reason: "Unschedulable".to_string(),
                message: "Another GPU sandbox may already be using the available GPU.".to_string(),
                last_transition_time: String::new(),
            }],
            ..Default::default()
        };

        assert_eq!(
            ready_false_condition_message(Some(&status)).as_deref(),
            Some("Unschedulable: Another GPU sandbox may already be using the available GPU.")
        );
    }

    #[test]
    fn ready_false_condition_message_ignores_non_ready_conditions() {
        let status = SandboxStatus {
            sandbox_name: "gpu".to_string(),
            agent_pod: "gpu-pod".to_string(),
            conditions: vec![SandboxCondition {
                r#type: "Scheduled".to_string(),
                status: "True".to_string(),
                reason: "Scheduled".to_string(),
                message: "Sandbox scheduled".to_string(),
                last_transition_time: String::new(),
            }],
            ..Default::default()
        };

        assert!(ready_false_condition_message(Some(&status)).is_none());
    }

    #[test]
    fn provisioning_timeout_message_includes_condition_and_gpu_hint() {
        let resource_requirements = ResourceRequirements {
            gpu: Some(GpuResourceRequirements { count: None }),
        };
        let message = provisioning_timeout_message(
            120,
            Some(&resource_requirements),
            Some("DependenciesNotReady: Pod exists with phase: Pending; Service Exists"),
        );

        assert!(message.contains("sandbox provisioning timed out after 120s"));
        assert!(message.contains("Last reported status: DependenciesNotReady: Pod exists with phase: Pending; Service Exists"));
        assert!(message.contains("available GPU is already in use by another sandbox"));
    }

    #[test]
    fn provisioning_timeout_message_omits_gpu_hint_for_non_gpu_requests() {
        let message = provisioning_timeout_message(120, None, None);

        assert_eq!(message, "sandbox provisioning timed out after 120s");
    }

    #[test]
    fn provisioning_timeout_message_omits_gpu_hint_without_gpu_requirements() {
        let resource_requirements = ResourceRequirements { gpu: None };
        let message = provisioning_timeout_message(120, Some(&resource_requirements), None);

        assert_eq!(message, "sandbox provisioning timed out after 120s");
    }

    fn init_git_repo(path: &Path) {
        let mut command = Command::new("git");
        super::scrub_git_env(&mut command);
        let status = command
            .args(["init"])
            .current_dir(path)
            .status()
            .expect("git init");
        assert!(status.success(), "git init should succeed");
    }

    #[test]
    fn git_sync_files_scopes_single_file_to_requested_path() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let repo = tmpdir.path().join("repo");
        fs::create_dir_all(repo.join("nested")).expect("create repo");
        init_git_repo(&repo);

        fs::write(repo.join("tracked.txt"), "tracked").expect("write tracked.txt");
        fs::write(repo.join("nested/other.txt"), "other").expect("write other.txt");

        let result = git_sync_files(&repo.join("tracked.txt"));
        let (base_dir, files) = result.expect("git_sync_files should succeed");
        assert_eq!(
            base_dir,
            fs::canonicalize(&repo).expect("canonicalize repo path")
        );
        assert_eq!(files, vec!["tracked.txt"]);
    }

    #[test]
    fn git_sync_files_scopes_directory_to_requested_subtree() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let repo = tmpdir.path().join("repo");
        fs::create_dir_all(repo.join("nested/inner")).expect("create repo");
        init_git_repo(&repo);

        fs::write(repo.join("nested/file.txt"), "file").expect("write file.txt");
        fs::write(repo.join("nested/inner/child.txt"), "child").expect("write child.txt");
        fs::write(repo.join("top.txt"), "top").expect("write top.txt");

        let result = git_sync_files(&repo.join("nested"));
        let (base_dir, mut files) = result.expect("git_sync_files should succeed");
        files.sort();

        assert_eq!(
            base_dir,
            fs::canonicalize(repo.join("nested")).expect("canonicalize nested path")
        );
        assert_eq!(files, vec!["file.txt", "inner/child.txt"]);
    }

    #[test]
    fn sandbox_upload_plan_errors_for_missing_local_path() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let missing = tmpdir.path().join("missing");

        let err = sandbox_upload_plan(&missing, false).expect_err("missing path should error");

        assert!(
            err.to_string().contains("local path does not exist"),
            "expected missing-path error, got: {err}"
        );
    }

    #[test]
    fn sandbox_upload_plan_errors_for_missing_local_path_with_git_ignore() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let repo = tmpdir.path().join("repo");
        fs::create_dir_all(&repo).expect("create repo");
        init_git_repo(&repo);
        let missing = repo.join("missing");

        let err = sandbox_upload_plan(&missing, true).expect_err("missing path should error");

        assert!(
            err.to_string().contains("local path does not exist"),
            "expected missing-path error, got: {err}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_upload_plan_uses_regular_upload_for_symlinks() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let repo = tmpdir.path().join("repo");
        fs::create_dir_all(repo.join("real-dir")).expect("create repo");
        init_git_repo(&repo);
        fs::write(repo.join("real-dir/file.txt"), "file").expect("write file.txt");
        std::os::unix::fs::symlink("real-dir", repo.join("link-dir")).expect("create symlink");

        let plan = sandbox_upload_plan(&repo.join("link-dir"), true)
            .expect("symlink upload should be planned");

        assert_eq!(plan, super::SandboxUploadPlan::Regular);
    }

    #[cfg(unix)]
    #[test]
    fn sandbox_upload_plan_accepts_dangling_symlinks() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let link = tmpdir.path().join("dangling-link");
        std::os::unix::fs::symlink("missing-target", &link).expect("create symlink");

        let plan =
            sandbox_upload_plan(&link, true).expect("dangling symlink upload should be planned");

        assert_eq!(plan, super::SandboxUploadPlan::Regular);
    }

    #[test]
    fn sandbox_upload_plan_falls_back_when_all_files_gitignored() {
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let repo = tmpdir.path().join("repo");
        fs::create_dir_all(repo.join("runs")).expect("create repo");
        init_git_repo(&repo);
        fs::write(repo.join(".gitignore"), "runs/\n").expect("write .gitignore");
        fs::write(repo.join("runs/test.json"), r#"{"key":"value"}"#).expect("write test.json");

        let plan =
            sandbox_upload_plan(&repo.join("runs"), true).expect("upload plan should succeed");

        assert_eq!(
            plan,
            super::SandboxUploadPlan::GitFilteredEmpty,
            "gitignored directory should fall back with GitFilteredEmpty"
        );
    }

    #[test]
    fn git_sync_files_ignores_inherited_git_env() {
        let _lock = TEST_ENV_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let tmpdir = tempfile::tempdir().expect("create tmpdir");
        let repo = tmpdir.path().join("repo");
        fs::create_dir_all(repo.join("nested")).expect("create repo");
        init_git_repo(&repo);

        fs::write(repo.join("nested/file.txt"), "file").expect("write file.txt");
        fs::write(repo.join("top.txt"), "top").expect("write top.txt");

        let _git_dir = EnvVarGuard::set("GIT_DIR", "/tmp/not-the-test-repo/.git");
        let _git_work_tree = EnvVarGuard::set("GIT_WORK_TREE", "/tmp/not-the-test-repo");

        let result = git_sync_files(&repo.join("nested"));
        let (base_dir, files) = result.expect("git_sync_files should succeed");

        assert_eq!(
            base_dir,
            fs::canonicalize(repo.join("nested")).expect("canonicalize nested path")
        );
        assert_eq!(files, vec!["file.txt"]);
    }

    #[test]
    fn format_endpoint_distinguishes_l4_from_l7_rest() {
        use openshell_core::proto::{L7Allow, L7DenyRule, L7Rule, NetworkEndpoint};

        let l4 = NetworkEndpoint {
            host: "host.example.test".to_string(),
            port: 443,
            ..Default::default()
        };
        assert_eq!(format_endpoint(&l4), "host.example.test:443 [L4]");

        let l7_readonly = NetworkEndpoint {
            host: "host.example.test".to_string(),
            port: 443,
            protocol: "rest".to_string(),
            access: "read-only".to_string(),
            ..Default::default()
        };
        assert_eq!(
            format_endpoint(&l7_readonly),
            "host.example.test:443 [L7 rest, access=read-only]"
        );

        let l7_scoped = NetworkEndpoint {
            host: "host.example.test".to_string(),
            port: 443,
            protocol: "rest".to_string(),
            rules: vec![L7Rule {
                allow: Some(L7Allow {
                    method: "PUT".to_string(),
                    path: "/v1/example/resource".to_string(),
                    ..Default::default()
                }),
            }],
            deny_rules: vec![L7DenyRule {
                method: "DELETE".to_string(),
                path: "/v1/example/resource".to_string(),
                ..Default::default()
            }],
            ..Default::default()
        };
        assert_eq!(
            format_endpoint(&l7_scoped),
            "host.example.test:443 [L7 rest, allow PUT /v1/example/resource, deny DELETE /v1/example/resource]"
        );
    }

    #[test]
    fn sandbox_template_to_json_includes_metadata_labels_and_annotations() {
        let template = SandboxWorkloadTemplate {
            metadata: Some(ObjectMeta {
                id: "template-123".to_string(),
                name: "gpu-kata".to_string(),
                labels: std::collections::HashMap::from([(
                    "team".to_string(),
                    "runtime".to_string(),
                )]),
                annotations: std::collections::HashMap::from([(
                    "owner".to_string(),
                    "platform".to_string(),
                )]),
                workspace: "default".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };

        let json = super::sandbox_template_to_json(&template);

        assert_eq!(json["labels"]["team"], "runtime");
        assert_eq!(json["annotations"]["owner"], "platform");
    }

    #[test]
    fn sandbox_template_to_json_formats_default_gpu_like_display_output() {
        let template = SandboxWorkloadTemplate {
            spec: Some(SandboxWorkloadTemplateSpec {
                workload: Some(SandboxWorkloadConfig {
                    resources: Some(SandboxResources {
                        gpu: Some(GpuResourceRequirements { count: None }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let json = super::sandbox_template_to_json(&template);

        assert_eq!(json["resources"]["gpu"], "default");
    }

    #[test]
    fn sandbox_template_to_json_preserves_explicit_gpu_count_as_number() {
        let template = SandboxWorkloadTemplate {
            spec: Some(SandboxWorkloadTemplateSpec {
                workload: Some(SandboxWorkloadConfig {
                    resources: Some(SandboxResources {
                        gpu: Some(GpuResourceRequirements { count: Some(2) }),
                        ..Default::default()
                    }),
                    ..Default::default()
                }),
                ..Default::default()
            }),
            ..Default::default()
        };

        let json = super::sandbox_template_to_json(&template);

        assert_eq!(json["resources"]["gpu"], 2);
    }

    #[test]
    fn sandbox_detail_to_json_includes_policy_fields() {
        let mut sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: "sb-123".to_string(),
                name: "test-sb".to_string(),
                resource_version: 5,
                created_at_ms: 1_609_459_200_000,
                ..Default::default()
            }),
            created_from_workload_template: Some(SandboxWorkloadTemplateProvenance {
                name: "gpu-kata".to_string(),
                resource_version: "7".to_string(),
            }),
            ..Default::default()
        };
        sandbox.set_phase(SandboxPhase::Ready as i32);
        sandbox.set_current_policy_version(2);

        let config = GetSandboxConfigResponse {
            policy_source: PolicySource::Global as i32,
            global_policy_version: 3,
            ..Default::default()
        };

        let json = super::sandbox_detail_to_json(&sandbox, &config).unwrap();

        assert_eq!(json["id"], "sb-123");
        assert_eq!(json["name"], "test-sb");
        assert_eq!(json["phase"], "Ready");
        assert_eq!(json["policy_source"], "global");
        assert_eq!(json["revision"], 3);
        assert!(json["policy"].is_null());
        assert_eq!(json["created_from_workload_template"]["name"], "gpu-kata");
        assert_eq!(
            json["created_from_workload_template"]["resource_version"],
            "7"
        );
    }

    #[test]
    fn sandbox_detail_to_json_sandbox_source_without_policy() {
        let sandbox = Sandbox {
            metadata: Some(ObjectMeta {
                id: "sb-456".to_string(),
                name: "no-policy-sb".to_string(),
                ..Default::default()
            }),
            ..Default::default()
        };
        let config = GetSandboxConfigResponse {
            policy_source: PolicySource::Sandbox as i32,
            version: 0,
            ..Default::default()
        };

        let json = super::sandbox_detail_to_json(&sandbox, &config).unwrap();

        assert_eq!(json["policy_source"], "sandbox");
        assert!(json["revision"].is_null());
        assert!(json["policy"].is_null());
    }

    fn log_line(
        level: &str,
        target: &str,
        message: &str,
        source: &str,
        fields: &[(&str, &str)],
    ) -> openshell_core::proto::SandboxLogLine {
        openshell_core::proto::SandboxLogLine {
            sandbox_id: "sb-1".to_string(),
            timestamp_ms: 1_234_567,
            level: level.to_string(),
            target: target.to_string(),
            message: message.to_string(),
            source: source.to_string(),
            fields: fields
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
                .collect(),
        }
    }

    #[test]
    fn format_log_line_without_fields() {
        let log = log_line("INFO", "openshell_server", "hello world", "sandbox", &[]);
        assert_eq!(
            format_log_line(&log),
            "[1234.567] [sandbox] [INFO ] [openshell_server] hello world"
        );
    }

    #[test]
    fn format_log_line_empty_source_defaults_to_gateway() {
        let log = log_line("WARN", "t", "msg", "", &[]);
        assert_eq!(
            format_log_line(&log),
            "[1234.567] [gateway] [WARN ] [t] msg"
        );
    }

    #[test]
    fn format_log_line_pads_source_and_level() {
        let log = log_line("OCSF", "ocsf", "NET:OPEN", "gateway", &[]);
        assert_eq!(
            format_log_line(&log),
            "[1234.567] [gateway] [OCSF ] [ocsf] NET:OPEN"
        );

        let short_source = log_line("ERROR", "t", "m", "vm", &[]);
        assert_eq!(
            format_log_line(&short_source),
            "[1234.567] [vm     ] [ERROR] [t] m"
        );
    }

    #[test]
    fn format_log_line_sorts_fields_alphabetically() {
        let log = log_line(
            "INFO",
            "ocsf",
            "CONNECT",
            "sandbox",
            &[("dst_port", "443"), ("action", "allow"), ("dst_host", "x")],
        );
        assert_eq!(
            format_log_line(&log),
            "[1234.567] [sandbox] [INFO ] [ocsf] CONNECT action=allow dst_host=x dst_port=443"
        );
    }

    #[test]
    fn format_log_line_keeps_empty_field_values() {
        let log = log_line("INFO", "t", "m", "sandbox", &[("a", ""), ("b", "1")]);
        assert_eq!(
            format_log_line(&log),
            "[1234.567] [sandbox] [INFO ] [t] m a= b=1"
        );
    }

    #[test]
    fn format_log_line_renders_empty_target_as_empty_brackets() {
        let log = log_line("INFO", "", "m", "sandbox", &[]);
        assert_eq!(format_log_line(&log), "[1234.567] [sandbox] [INFO ] [] m");
    }

    #[test]
    fn format_log_line_zero_pads_millis() {
        let mut log = log_line("INFO", "t", "m", "sandbox", &[]);
        log.timestamp_ms = 1_000_007;
        assert_eq!(format_log_line(&log), "[1000.007] [sandbox] [INFO ] [t] m");

        log.timestamp_ms = 0;
        assert_eq!(format_log_line(&log), "[0.000] [sandbox] [INFO ] [t] m");
    }

    #[test]
    fn format_log_line_preserves_message_verbatim() {
        // OCSF shorthand must pass through unchanged.
        let message = "NET:OPEN [MED] DENIED /usr/bin/curl(4711) -> api.example.com:443";
        let log = log_line("OCSF", "ocsf", message, "sandbox", &[]);
        assert!(format_log_line(&log).ends_with(message));
    }
}
