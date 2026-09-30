// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Kubernetes helpers for the HA operation inventory: the gateway Deployment,
//! Ready pods, scaling, pod loss, per-pod port-forwards, the lane guards, and
//! the single read of the supervisor-session owner record.

use std::collections::HashMap;
use std::fmt;
use std::process::Stdio;
use std::time::Duration;

use base64::Engine as _;
use openshell_e2e::harness::port::{find_free_port, wait_for_port};
use serde_json::Value;
use tokio::process::{Child, Command};

pub const OWNER_SCHEMA_CHANGED: &str = "owner record schema changed:";
/// Freshness window of an owner record (`OWNER_TTL`, `supervisor_owner.rs:15`).
const OWNER_TTL_MS: i64 = 45_000;
const PEER_ENDPOINT: &str = "OPENSHELL_PEER_ENDPOINT";
const PEER_OPT_OUT: &str = "OPENSHELL_PEER_ALLOW_INSECURE_TRANSPORT";
const KUBECTL_TIMEOUT: Duration = Duration::from_secs(60);
/// Covers `rollout status --timeout=300s` and `delete --timeout=120s`.
const SLOW_KUBECTL_TIMEOUT: Duration = Duration::from_secs(330);

#[derive(Clone)]
pub struct KubeTarget {
    context: String,
    namespace: String,
    deployment: String,
    postgres: String,
}

impl KubeTarget {
    pub fn from_env() -> Result<Self, String> {
        let context = std::env::var("OPENSHELL_E2E_KUBE_CONTEXT").map_err(
            |_| "OPENSHELL_E2E_KUBE_CONTEXT is not set; run through e2e/rust/e2e-kubernetes.sh",
        )?;
        let env_or = |name: &str, default: &str| {
            std::env::var(name)
                .ok()
                .filter(|value| !value.trim().is_empty())
                .unwrap_or_else(|| default.to_string())
        };
        let release = env_or("OPENSHELL_E2E_KUBE_RELEASE", "openshell");
        let postgres = env_or(
            "OPENSHELL_E2E_KUBE_POSTGRES_DEPLOYMENT",
            "openshell-e2e-postgres",
        );
        Ok(Self {
            context,
            namespace: env_or("OPENSHELL_E2E_KUBE_NAMESPACE", "openshell"),
            deployment: format!("deployment/{release}"),
            postgres: format!("deployment/{postgres}"),
        })
    }

    pub async fn kubectl(&self, args: &[&str]) -> Result<String, String> {
        self.kubectl_for(args, KUBECTL_TIMEOUT).await
    }

    async fn kubectl_for(&self, args: &[&str], timeout: Duration) -> Result<String, String> {
        let mut cmd = Command::new("kubectl");
        cmd.args(["--context", &self.context, "-n", &self.namespace])
            .args(args)
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(timeout, cmd.output())
            .await
            .map_err(|_| format!("kubectl {args:?} timed out after {timeout:?}"))?
            .map_err(|err| format!("failed to spawn kubectl {args:?}: {err}"))?;
        let stdout = String::from_utf8_lossy(&output.stdout).into_owned();
        if output.status.success() {
            return Ok(stdout);
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let code = output.status.code();
        Err(format!(
            "kubectl {args:?} failed with exit {code:?}:\n{stdout}{stderr}"
        ))
    }

    /// Env of the gateway container (`valueFrom` entries map to "") and a
    /// selector from `.spec.selector.matchLabels`, so certgen Job pods never
    /// count as gateway pods.
    pub async fn gateway(&self) -> Result<(HashMap<String, String>, String), String> {
        let json = self.kubectl(&["get", &self.deployment, "-o", "json"]).await;
        let json = json.map_err(|err| format!("{}: {err}", missing_endpoint()))?;
        let deployment: Value = serde_json::from_str(&json)
            .map_err(|err| format!("failed to parse the gateway Deployment: {err}"))?;
        let spec = &deployment["spec"];
        let containers = spec["template"]["spec"]["containers"].as_array();
        let gateway = containers
            .into_iter()
            .flatten()
            .find(|container| container["name"] == "openshell-gateway");
        let env = gateway
            .and_then(|container| container["env"].as_array())
            .into_iter()
            .flatten()
            .filter_map(|var| {
                let value = var["value"].as_str().unwrap_or_default().to_string();
                Some((var["name"].as_str()?.to_string(), value))
            })
            .collect();
        let labels = spec["selector"]["matchLabels"]
            .as_object()
            .into_iter()
            .flatten();
        let mut labels = labels
            .map(|(key, value)| format!("{key}={}", value.as_str().unwrap_or_default()))
            .collect::<Vec<_>>();
        if labels.is_empty() {
            return Err("gateway Deployment has no spec.selector.matchLabels".to_string());
        }
        labels.sort();
        Ok((env, labels.join(",")))
    }

    /// Names of the gateway pods that are Ready and not terminating, sorted.
    pub async fn ready_pods(&self, selector: &str) -> Result<Vec<String>, String> {
        let json = self
            .kubectl(&["get", "pods", "-l", selector, "-o", "json"])
            .await?;
        let pods: Value = serde_json::from_str(&json)
            .map_err(|err| format!("failed to parse gateway pods: {err}"))?;
        let ready = |pod: &&Value| {
            let conditions = pod["status"]["conditions"].as_array().into_iter().flatten();
            pod["metadata"]["deletionTimestamp"].is_null()
                && conditions
                    .into_iter()
                    .any(|cond| cond["type"] == "Ready" && cond["status"] == "True")
        };
        let items = pods["items"].as_array().into_iter().flatten();
        let mut names = items
            .filter(ready)
            .filter_map(|pod| pod["metadata"]["name"].as_str().map(str::to_string))
            .collect::<Vec<_>>();
        names.sort();
        Ok(names)
    }

    pub async fn scale(&self, replicas: usize) -> Result<(), String> {
        let replicas = format!("--replicas={replicas}");
        self.kubectl(&["scale", &self.deployment, &replicas])
            .await?;
        let status = ["rollout", "status", &self.deployment, "--timeout=180s"];
        self.kubectl_for(&status, SLOW_KUBECTL_TIMEOUT)
            .await
            .map(drop)
    }

    pub async fn rollout_restart(&self) -> Result<(), String> {
        self.kubectl(&["rollout", "restart", &self.deployment])
            .await?;
        let status = ["rollout", "status", &self.deployment, "--timeout=300s"];
        self.kubectl_for(&status, SLOW_KUBECTL_TIMEOUT)
            .await
            .map(drop)
    }

    /// Graceful waits for the pod to go; forced is `--grace-period=0 --force`.
    pub async fn delete_pod(&self, pod: &str, forced: bool) -> Result<(), String> {
        let flags: &[&str] = if forced {
            &["--grace-period=0", "--force", "--wait=false"]
        } else {
            &["--wait=true", "--timeout=120s"]
        };
        let args = [&["delete", "pod", pod], flags].concat();
        self.kubectl_for(&args, SLOW_KUBECTL_TIMEOUT)
            .await
            .map(drop)
    }

    pub async fn secret(&self, secret: &str, key: &str) -> Result<Vec<u8>, String> {
        let path = format!("jsonpath={{.data.{}}}", key.replace('.', "\\."));
        let encoded = self
            .kubectl(&["get", "secret", secret, "-o", &path])
            .await?;
        let data = base64::engine::general_purpose::STANDARD.decode(encoded.trim());
        data.ok()
            .filter(|data| !data.is_empty())
            .ok_or_else(|| format!("secret {secret} has no usable {key}"))
    }
}

fn missing_endpoint() -> String {
    format!("HA operation inventory needs a Deployment with {PEER_ENDPOINT}")
}

/// Check the gateway env against the lane; `Ok(true)` when peers use https.
///
/// The TLS lane must render the full peer contract (https endpoint, CA,
/// server name, client certificate) and no plaintext opt-out. A plaintext
/// peer endpoint must come with the opt-out, which proves its plumbing.
pub fn lane_guard(env: &HashMap<String, String>, pod_tls_lane: bool) -> Result<bool, String> {
    let get = |name: &str| env.get(name).map_or("", |value| value.trim());
    let endpoint = get(PEER_ENDPOINT);
    if endpoint.is_empty() {
        return Err(missing_endpoint());
    }
    let https = endpoint.starts_with("https://");
    let opted_out = get(PEER_OPT_OUT).eq_ignore_ascii_case("true");
    let mut problems = Vec::new();
    if pod_tls_lane {
        if !https {
            problems.push(format!("{PEER_ENDPOINT}={endpoint} is not https://"));
        }
        let tls = [
            "OPENSHELL_PEER_TLS_CA_FILE",
            "OPENSHELL_PEER_TLS_SERVER_NAME",
            "OPENSHELL_PEER_TLS_CERT_FILE",
        ];
        for name in tls.into_iter().filter(|name| get(name).is_empty()) {
            problems.push(format!("{name} is not set"));
        }
        if env.contains_key(PEER_OPT_OUT) {
            problems.push(format!("{PEER_OPT_OUT} is set"));
        }
    } else if !https && (!endpoint.starts_with("http://") || !opted_out) {
        problems.push(format!(
            "{PEER_ENDPOINT}={endpoint} needs {PEER_OPT_OUT}=true"
        ));
    }
    if problems.is_empty() {
        Ok(https)
    } else {
        let lane = if pod_tls_lane { "TLS" } else { "plaintext" };
        Err(format!(
            "{lane} lane guard failed on the gateway Deployment: {}",
            problems.join("; ")
        ))
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnerRow {
    pub replica: String,
    pub peer_endpoint: String,
    pub connection_epoch: u64,
    pub age_ms: i64,
}

impl OwnerRow {
    pub fn is_fresh(&self) -> bool {
        self.age_ms < OWNER_TTL_MS
    }
}

/// `<pod>@<epoch>`, as printed in summary lines and failures.
impl fmt::Display for OwnerRow {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}@{}", self.replica, self.connection_epoch)
    }
}

fn schema_changed(got: &str) -> String {
    format!(
        "{OWNER_SCHEMA_CHANGED} expected owner_replica_id|owner_peer_endpoint|connection_epoch|age_ms from objects/supervisor_session_owner (crates/openshell-server/src/supervisor_owner.rs), got: {got}"
    )
}

/// Parse `psql -AtX -F '|'` output: empty means no owner; otherwise exactly
/// one `pod|endpoint|epoch|age_ms` line.
pub fn parse_owner_row(stdout: &str) -> Result<Option<OwnerRow>, String> {
    let line = stdout.trim();
    if line.is_empty() {
        return Ok(None);
    }
    let fields = line.split('|').collect::<Vec<_>>();
    let row = match fields[..] {
        [replica, endpoint, epoch, age] if !replica.is_empty() && !endpoint.is_empty() => {
            let numbers = epoch.parse().ok().zip(age.parse().ok());
            numbers.map(|(connection_epoch, age_ms)| OwnerRow {
                replica: replica.to_string(),
                peer_endpoint: endpoint.to_string(),
                connection_epoch,
                age_ms,
            })
        }
        _ => None,
    };
    row.map(Some).ok_or_else(|| schema_changed(line))
}

/// Read the supervisor-session owner of `sandbox_id`.
///
/// No public API exposes the owner, so this is the only code that reads
/// private gateway persistence: the `objects` row with
/// `object_type = 'supervisor_session_owner'` and
/// `id = 'supervisor-owner:<sandbox_id>'`, whose payload is the JSON
/// `OwnerPayload` (`crates/openshell-server/src/supervisor_owner.rs`:13-19,
/// :39-48). A psql `ERROR:` or an unparseable row fails with
/// [`OWNER_SCHEMA_CHANGED`] instead of looking like an HA failure; other
/// kubectl failures are retried twice.
pub async fn owner_row(kube: &KubeTarget, sandbox_id: &str) -> Result<Option<OwnerRow>, String> {
    if sandbox_id.is_empty()
        || !sandbox_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-')
    {
        return Err(format!("unexpected sandbox id {sandbox_id:?}"));
    }
    let payload = "convert_from(payload, 'UTF8')::jsonb";
    let sql = format!(
        "SELECT {payload} ->> 'owner_replica_id', {payload} ->> 'owner_peer_endpoint', \
         {payload} ->> 'connection_epoch', \
         (extract(epoch FROM clock_timestamp()) * 1000)::bigint - updated_at_ms \
         FROM objects WHERE object_type = 'supervisor_session_owner' \
         AND id = 'supervisor-owner:{sandbox_id}'"
    );
    let psql = "-c postgres -- psql -U openshell -d openshell -v ON_ERROR_STOP=1 -AtX -F | -c";
    let mut args = vec!["exec", &kube.postgres];
    args.extend(psql.split_whitespace());
    args.push(&sql);
    let mut tries = 0;
    loop {
        tries += 1;
        match kube.kubectl(&args).await {
            Ok(stdout) => return parse_owner_row(&stdout),
            Err(err) => {
                if let Some(line) = err.lines().find(|line| line.contains("ERROR:")) {
                    return Err(schema_changed(line.trim()));
                }
                if tries == 3 {
                    return Err(err);
                }
            }
        }
        tokio::time::sleep(Duration::from_secs(2)).await;
    }
}

/// `kubectl port-forward pod/<pod>` to the gateway port on a free local port.
pub struct PortForward {
    pub port: u16,
    child: Child,
}

impl PortForward {
    pub async fn start(kube: &KubeTarget, pod: &str) -> Result<Self, String> {
        let port = find_free_port();
        let mut child = Command::new("kubectl")
            .args([
                "--context",
                &kube.context,
                "-n",
                &kube.namespace,
                "port-forward",
            ])
            .args([format!("pod/{pod}"), format!("{port}:8080")])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|err| format!("failed to start kubectl port-forward for {pod}: {err}"))?;
        match wait_for_port("127.0.0.1", port, Duration::from_secs(30)).await {
            Ok(()) => Ok(Self { port, child }),
            Err(err) => {
                let _ = child.kill().await;
                Err(format!("port-forward to {pod} did not become ready: {err}"))
            }
        }
    }

    pub fn is_alive(&mut self) -> bool {
        matches!(self.child.try_wait(), Ok(None))
    }
}
