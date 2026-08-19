// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes")]

use std::time::Instant;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use openshell_e2e::harness::cli::{run_cli, sandbox_names, wait_for_sandbox_exec_contains};
use openshell_e2e::harness::kubernetes::{
    dump_namespace_diagnostics, has_crd, items, kubectl_json, wait_for_resource_absent_by_label,
    wait_for_resource_by_label,
};
use serde_json::Value;

const EXTENSIONS_GROUP: &str = "extensions.agents.x-k8s.io";
const AGENTS_GROUP: &str = "agents.x-k8s.io";
const CLAIM_KIND: &str = "sandboxclaims.extensions.agents.x-k8s.io";
const WARM_POOL_KIND: &str = "sandboxwarmpools.extensions.agents.x-k8s.io";
const TEMPLATE_KIND: &str = "sandboxtemplates.extensions.agents.x-k8s.io";
const SANDBOX_KIND: &str = "sandboxes.agents.x-k8s.io";

const LABEL_ENABLED: &str = "openshell.ai/enabled";
const LABEL_MANAGED_BY: &str = "openshell.ai/managed-by";
const LABEL_TEMPLATE_ID: &str = "openshell.ai/warm-pool-template-id";
const LABEL_ALLOCATION: &str = "openshell.ai/allocation";
const LABEL_SANDBOX_NAME: &str = "openshell.ai/sandbox-name";
const LABEL_SANDBOX_WORKSPACE: &str = "openshell.ai/sandbox-workspace";

#[derive(Clone, Copy)]
enum TemplateCase {
    Default,
    Env,
    Cpu,
}

struct GeneratedTemplate {
    source_name: String,
    selector: String,
    template_name: String,
    warm_pool_name: String,
}

struct TestContext {
    namespace: String,
    templates: Vec<String>,
    sandboxes: Vec<String>,
}

impl TestContext {
    fn new(namespace: String) -> Self {
        Self {
            namespace,
            templates: Vec::new(),
            sandboxes: Vec::new(),
        }
    }

    async fn cleanup(&mut self) {
        for sandbox in self.sandboxes.iter().rev() {
            let _ = run_cli(&["sandbox", "delete", sandbox]).await;
        }
        for template in self.templates.iter().rev() {
            let _ = run_cli(&["sandbox", "template", "delete", template]).await;
        }
    }
}

#[tokio::test]
async fn kubernetes_warm_pool_templates_claim_and_fallback() {
    if !env_flag("OPENSHELL_E2E_KUBE_WARM_POOL") {
        eprintln!(
            "Skipping Kubernetes warm-pool e2e test: set OPENSHELL_E2E_KUBE_WARM_POOL=1 to enable"
        );
        return;
    }

    let namespace =
        std::env::var("OPENSHELL_E2E_SANDBOX_NAMESPACE").unwrap_or_else(|_| "openshell".into());
    let strict = env_flag("OPENSHELL_E2E_KUBE_WARM_POOL_STRICT");
    if let Err(err) = ensure_required_crds(strict).await {
        if strict {
            panic!("{err}");
        }
        eprintln!("Skipping Kubernetes warm-pool e2e test: {err}");
        return;
    }

    let mut ctx = TestContext::new(namespace);
    let result = run_warm_pool_e2e(&mut ctx).await;
    if let Err(err) = result {
        dump_namespace_diagnostics(&ctx.namespace).await;
        ctx.cleanup().await;
        panic!("{err}");
    }
    ctx.cleanup().await;
}

async fn run_warm_pool_e2e(ctx: &mut TestContext) -> Result<(), String> {
    let template_suffix = unique_template_suffix();
    let sandbox_suffix = unique_sandbox_suffix();

    let default_template = create_and_assert_template(
        ctx,
        &format!("openshell-wp-e2e-default-{template_suffix}"),
        TemplateCase::Default,
    )
    .await?;
    let env_template = create_and_assert_template(
        ctx,
        &format!("openshell-wp-e2e-env-{template_suffix}"),
        TemplateCase::Env,
    )
    .await?;
    let cpu_template = create_and_assert_template(
        ctx,
        &format!("openshell-wp-e2e-cpu-{template_suffix}"),
        TemplateCase::Cpu,
    )
    .await?;

    create_and_assert_claimed(
        ctx,
        &format!("wpd-{sandbox_suffix}"),
        &[],
        "warm-pool-ok",
        &default_template,
    )
    .await?;
    create_and_assert_claimed(
        ctx,
        &format!("wpe-{sandbox_suffix}"),
        &[],
        "env-ok",
        &env_template,
    )
    .await?;
    create_and_assert_claimed(
        ctx,
        &format!("wpc-{sandbox_suffix}"),
        &[],
        "cpu-ok",
        &cpu_template,
    )
    .await?;

    create_and_assert_direct_fallback(ctx, &format!("wpf-{sandbox_suffix}")).await?;
    delete_template_and_assert_gc(ctx, &env_template, &[&default_template, &cpu_template]).await?;

    Ok(())
}

async fn ensure_required_crds(strict: bool) -> Result<(), String> {
    let required = [
        ("sandboxes", AGENTS_GROUP),
        ("sandboxclaims", EXTENSIONS_GROUP),
        ("sandboxtemplates", EXTENSIONS_GROUP),
        ("sandboxwarmpools", EXTENSIONS_GROUP),
    ];
    let mut missing = Vec::new();
    for (plural, group) in required {
        if !has_crd(plural, group).await {
            missing.push(format!("{plural}.{group}"));
        }
    }
    if missing.is_empty() {
        Ok(())
    } else if strict {
        Err(format!(
            "required Agent Sandbox CRDs are missing in strict mode: {}",
            missing.join(", ")
        ))
    } else {
        Err(format!(
            "required Agent Sandbox CRDs are missing: {}",
            missing.join(", ")
        ))
    }
}

async fn create_and_assert_template(
    ctx: &mut TestContext,
    name: &str,
    case: TemplateCase,
) -> Result<GeneratedTemplate, String> {
    ctx.templates.push(name.to_string());
    let mut args = vec![
        "sandbox",
        "template",
        "create",
        name,
        "--ready-within",
        "1s",
        "--max-burst",
        "1",
        "--output",
        "json",
    ];
    match case {
        TemplateCase::Default => {}
        TemplateCase::Env => args.extend_from_slice(&["--env", "FOO=bar"]),
        TemplateCase::Cpu => args.extend_from_slice(&["--cpu", "0.2"]),
    }
    let (output, code) = run_cli(&args).await;
    if code != 0 {
        return Err(format!(
            "sandbox template create for {name} failed with exit {code}; output:\n{output}"
        ));
    }
    let source: Value = serde_json::from_str(&output)
        .map_err(|err| format!("parse sandbox template create JSON for {name}: {err}\n{output}"))?;
    let source_id = source["id"]
        .as_str()
        .or_else(|| source["metadata"]["id"].as_str())
        .ok_or_else(|| format!("sandbox template {name} JSON is missing metadata.id: {source}"))?
        .to_string();

    let selector =
        format!("{LABEL_MANAGED_BY}=openshell-kubernetes-driver,{LABEL_TEMPLATE_ID}={source_id}");
    let template = single_labelled_resource(&ctx.namespace, TEMPLATE_KIND, &selector).await?;
    let warm_pool = single_labelled_resource(&ctx.namespace, WARM_POOL_KIND, &selector).await?;

    let template_name = object_name(&template)?;
    let warm_pool_name = object_name(&warm_pool)?;
    if template_name != warm_pool_name {
        return Err(format!(
            "generated resource names should match for source {name}; template={template_name}, warm_pool={warm_pool_name}"
        ));
    }

    assert_generated_labels(&template, name)?;
    assert_generated_labels(&warm_pool, name)?;
    if warm_pool["spec"]["sandboxTemplateRef"]["name"].as_str() != Some(&template_name) {
        return Err(format!(
            "SandboxWarmPool/{warm_pool_name} does not reference SandboxTemplate/{template_name}: {warm_pool}"
        ));
    }
    assert_template_invariants(&template, case)?;
    wait_for_warm_pool_ready(&ctx.namespace, &warm_pool_name, Duration::from_secs(120)).await?;

    Ok(GeneratedTemplate {
        source_name: name.to_string(),
        selector,
        template_name,
        warm_pool_name,
    })
}

async fn single_labelled_resource(
    namespace: &str,
    kind: &str,
    selector: &str,
) -> Result<Value, String> {
    let list =
        wait_for_resource_by_label(namespace, kind, selector, Duration::from_secs(120)).await?;
    let list_items = items(&list);
    if list_items.len() != 1 {
        return Err(format!(
            "expected exactly one {kind} with selector {selector}, got {}: {list}",
            list_items.len()
        ));
    }
    Ok(list_items[0].clone())
}

async fn wait_for_warm_pool_ready(
    namespace: &str,
    name: &str,
    timeout: Duration,
) -> Result<(), String> {
    let deadline = Instant::now() + timeout;
    let mut last_observation: Option<Value>;

    loop {
        match kubectl_json(&["get", WARM_POOL_KIND, name, "-n", namespace, "-o", "json"]).await {
            Ok(value) if warm_pool_ready(&value) => return Ok(()),
            Ok(value) => last_observation = Some(value),
            Err(err) => last_observation = Some(serde_json::json!({ "error": err })),
        }

        if Instant::now() >= deadline {
            let last_observation =
                last_observation.unwrap_or_else(|| serde_json::json!("<no observation>"));
            return Err(format!(
                "SandboxWarmPool/{name} did not become ready within {}s. Last observation:\n{}",
                timeout.as_secs(),
                serde_json::to_string_pretty(&last_observation)
                    .unwrap_or_else(|_| last_observation.to_string())
            ));
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

fn warm_pool_ready(value: &Value) -> bool {
    let desired = value["spec"]["replicas"].as_u64().unwrap_or(1);
    if desired == 0 {
        return true;
    }

    if status_condition_is_true(value, "Ready") || status_condition_is_true(value, "Available") {
        return true;
    }

    for path in [
        "/status/readyReplicas",
        "/status/availableReplicas",
        "/status/currentReadyReplicas",
    ] {
        if value
            .pointer(path)
            .and_then(Value::as_u64)
            .is_some_and(|ready| ready >= desired)
        {
            return true;
        }
    }

    false
}

fn status_condition_is_true(value: &Value, condition_type: &str) -> bool {
    value["status"]["conditions"]
        .as_array()
        .into_iter()
        .flatten()
        .any(|condition| {
            condition["type"].as_str() == Some(condition_type)
                && condition["status"]
                    .as_str()
                    .is_some_and(|status| status.eq_ignore_ascii_case("true"))
        })
}

async fn create_and_assert_claimed(
    ctx: &mut TestContext,
    sandbox_name: &str,
    extra_create_args: &[&str],
    marker: &str,
    template: &GeneratedTemplate,
) -> Result<(), String> {
    ctx.sandboxes.push(sandbox_name.to_string());
    let mut args = vec![
        "sandbox",
        "create",
        "--name",
        sandbox_name,
        "--no-tty",
        "--template",
        &template.source_name,
    ];
    args.extend_from_slice(extra_create_args);
    args.extend_from_slice(&["--", "echo", marker]);
    let (output, code) = run_cli(&args).await;
    if code != 0 || !output.contains(marker) {
        return Err(format!(
            "sandbox create for {sandbox_name} did not succeed through warm pool (exit {code}); expected marker {marker:?}. Output:\n{output}"
        ));
    }

    let claim = wait_for_claim(ctx, sandbox_name).await?;
    if claim["metadata"]["labels"][LABEL_ALLOCATION].as_str() != Some("sandbox-claim") {
        return Err(format!(
            "SandboxClaim for {sandbox_name} is missing allocation label: {claim}"
        ));
    }
    if claim["metadata"]["labels"][LABEL_SANDBOX_WORKSPACE].as_str() != Some("default") {
        return Err(format!(
            "SandboxClaim for {sandbox_name} is not in default workspace: {claim}"
        ));
    }
    if claim["spec"]["warmPoolRef"]["name"].as_str() != Some(&template.warm_pool_name) {
        return Err(format!(
            "SandboxClaim for {sandbox_name} used wrong warm pool; expected {}, claim: {claim}",
            template.warm_pool_name
        ));
    }

    let names = sandbox_names().await?;
    if !names.iter().any(|name| name == sandbox_name) {
        return Err(format!(
            "sandbox list --names did not include claimed sandbox {sandbox_name}; names={names:?}"
        ));
    }
    wait_for_sandbox_exec_contains(
        sandbox_name,
        &["echo", "claimed-ok"],
        "claimed-ok",
        Duration::from_secs(120),
    )
    .await?;

    Ok(())
}

async fn wait_for_claim(ctx: &TestContext, sandbox_name: &str) -> Result<Value, String> {
    let selector = format!("{LABEL_ALLOCATION}=sandbox-claim,{LABEL_SANDBOX_NAME}={sandbox_name}");
    single_labelled_resource(&ctx.namespace, CLAIM_KIND, &selector).await
}

async fn create_and_assert_direct_fallback(
    ctx: &mut TestContext,
    sandbox_name: &str,
) -> Result<(), String> {
    ctx.sandboxes.push(sandbox_name.to_string());
    let args = [
        "sandbox",
        "create",
        "--name",
        sandbox_name,
        "--no-tty",
        "--env",
        "FOO=baz",
        "--",
        "echo",
        "fallback-ok",
    ];
    let (output, code) = run_cli(&args).await;
    if code != 0 || !output.contains("fallback-ok") {
        return Err(format!(
            "fallback sandbox create failed (exit {code}); output:\n{output}"
        ));
    }

    let claim_selector =
        format!("{LABEL_ALLOCATION}=sandbox-claim,{LABEL_SANDBOX_NAME}={sandbox_name}");
    let claims = kubectl_json(&[
        "get",
        CLAIM_KIND,
        "-n",
        &ctx.namespace,
        "-l",
        &claim_selector,
        "-o",
        "json",
    ])
    .await?;
    if !items(&claims).is_empty() {
        return Err(format!(
            "fallback sandbox {sandbox_name} unexpectedly allocated through SandboxClaim: {claims}"
        ));
    }

    let sandbox_selector =
        format!("{LABEL_MANAGED_BY}=openshell,{LABEL_SANDBOX_NAME}={sandbox_name}");
    let sandbox = single_labelled_resource(&ctx.namespace, SANDBOX_KIND, &sandbox_selector).await?;
    if object_name(&sandbox)? != format!("default--{sandbox_name}") {
        return Err(format!(
            "fallback sandbox used unexpected direct Sandbox name: {sandbox}"
        ));
    }

    Ok(())
}

async fn delete_template_and_assert_gc(
    ctx: &mut TestContext,
    deleted: &GeneratedTemplate,
    remaining: &[&GeneratedTemplate],
) -> Result<(), String> {
    let (output, code) = run_cli(&["sandbox", "template", "delete", &deleted.source_name]).await;
    if code != 0 {
        return Err(format!(
            "sandbox template delete for {} failed with exit {code}; output:\n{output}",
            deleted.source_name
        ));
    }
    wait_for_resource_absent_by_label(
        &ctx.namespace,
        WARM_POOL_KIND,
        &deleted.selector,
        Duration::from_secs(120),
    )
    .await?;
    wait_for_resource_absent_by_label(
        &ctx.namespace,
        TEMPLATE_KIND,
        &deleted.selector,
        Duration::from_secs(120),
    )
    .await?;

    for expected in remaining {
        let template =
            single_labelled_resource(&ctx.namespace, TEMPLATE_KIND, &expected.selector).await?;
        let warm_pool =
            single_labelled_resource(&ctx.namespace, WARM_POOL_KIND, &expected.selector).await?;
        if object_name(&template)? != expected.template_name
            || object_name(&warm_pool)? != expected.warm_pool_name
        {
            return Err(format!(
                "generated resources for template {} changed while deleting {}",
                expected.source_name, deleted.source_name
            ));
        }
    }

    Ok(())
}

fn assert_generated_labels(obj: &Value, source_name: &str) -> Result<(), String> {
    let labels = obj["metadata"]["labels"]
        .as_object()
        .ok_or_else(|| format!("generated object is missing metadata.labels: {obj}"))?;
    if labels.get(LABEL_ENABLED).and_then(Value::as_str) != Some("true") {
        return Err(format!(
            "generated object is missing {LABEL_ENABLED}=true: {obj}"
        ));
    }
    if labels.get(LABEL_MANAGED_BY).and_then(Value::as_str) != Some("openshell-kubernetes-driver") {
        return Err(format!(
            "generated object is missing driver manager label: {obj}"
        ));
    }
    if labels
        .get(LABEL_TEMPLATE_ID)
        .and_then(Value::as_str)
        .is_none_or(str::is_empty)
    {
        return Err(format!(
            "generated object for source {source_name} is missing template id label: {obj}"
        ));
    }
    Ok(())
}

fn assert_template_invariants(template: &Value, case: TemplateCase) -> Result<(), String> {
    if template["spec"]["podTemplate"]["spec"]["dnsPolicy"].as_str() != Some("ClusterFirst") {
        return Err(format!(
            "generated SandboxTemplate must set pod dnsPolicy=ClusterFirst: {template}"
        ));
    }

    let agent = agent_container(template)?;
    let image = agent["image"]
        .as_str()
        .ok_or_else(|| format!("agent container is missing image: {template}"))?;
    if image.is_empty() {
        return Err(format!(
            "agent container image must not be empty: {template}"
        ));
    }

    let env = agent["env"].as_array().map_or(&[][..], Vec::as_slice);
    for reserved in ["OPENSHELL_SANDBOX_ID", "OPENSHELL_SANDBOX"] {
        if env
            .iter()
            .any(|entry| entry["name"].as_str() == Some(reserved))
        {
            return Err(format!(
                "warm-pool template must not include reserved env {reserved}: {template}"
            ));
        }
    }

    match case {
        TemplateCase::Default => {}
        TemplateCase::Env => {
            let foo = env
                .iter()
                .find(|entry| entry["name"].as_str() == Some("FOO"))
                .and_then(|entry| entry["value"].as_str());
            if foo != Some("bar") {
                return Err(format!(
                    "env warm-pool template did not include FOO=bar: {template}"
                ));
            }
        }
        TemplateCase::Cpu => {
            let resources = &agent["resources"];
            if resources["limits"]["cpu"].as_str() != Some("0.2")
                || resources["requests"]["cpu"].as_str() != Some("0.2")
            {
                return Err(format!(
                    "CPU warm-pool template did not render cpu requests/limits=0.2: {template}"
                ));
            }
        }
    }

    Ok(())
}

fn agent_container(template: &Value) -> Result<&Value, String> {
    let containers = template["spec"]["podTemplate"]["spec"]["containers"]
        .as_array()
        .ok_or_else(|| format!("SandboxTemplate is missing pod containers: {template}"))?;
    containers
        .iter()
        .find(|container| container["name"].as_str() == Some("agent"))
        .ok_or_else(|| format!("SandboxTemplate is missing agent container: {template}"))
}

fn object_name(obj: &Value) -> Result<String, String> {
    obj["metadata"]["name"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| format!("object is missing metadata.name: {obj}"))
}

fn unique_template_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let value = (nanos ^ u128::from(std::process::id())) & 0xffff_ffff;
    format!("{value:08x}")
}

fn unique_sandbox_suffix() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let value = (nanos ^ u128::from(std::process::id())) & 0x00ff_ffff;
    format!("{value:06x}")
}

fn env_flag(name: &str) -> bool {
    std::env::var(name).is_ok_and(|value| {
        value == "1" || value.eq_ignore_ascii_case("true") || value.eq_ignore_ascii_case("yes")
    })
}
