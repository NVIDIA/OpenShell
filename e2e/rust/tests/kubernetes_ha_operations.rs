// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

#![cfg(feature = "e2e-kubernetes-ha")]

//! HA operation inventory across the gateway lifecycle.
//!
//! One long-lived sandbox is kept across gateway scale-up, scale-down,
//! graceful and forced loss of the replica that owns its supervisor session,
//! and a rolling restart. After each disruption a recovery gate waits for the
//! expected Ready pods, a fresh owner record, and a Ready sandbox. Then each
//! HA-tested operation class runs through a replica that does not own the
//! session, so it must cross the peer path; the owner `(replica,
//! connection_epoch)` is read before and after the block to prove that.
//! Every command uses a per-pod port-forward, never the configured gateway,
//! and the client speaks TLS whenever the gateway pods do.

#[path = "kubernetes_ha_operations/kube.rs"]
mod kube;
#[path = "kubernetes_ha_operations/ops.rs"]
mod ops;

use std::time::{Duration, Instant};

use kube::{KubeTarget, OwnerRow};
use ops::{Fail, Ops};

const BUDGET_ENV: &str = "OPENSHELL_E2E_KUBE_HA_OPS_BUDGET_SECS";
const DEFAULT_BUDGET_SECS: u64 = 1020;
/// nextest kills this test after 60 s x 20 (`.config/nextest.toml`).
const NEXTEST_KILL: Duration = Duration::from_secs(1200);
/// Room left after teardown for the summary line before the kill.
const KILL_MARGIN: Duration = Duration::from_secs(10);
const DIAGNOSTICS_TIMEOUT: Duration = Duration::from_secs(60);
const TEARDOWN_RESERVE: Duration = Duration::from_secs(110);
/// The largest budget that still leaves diagnostics and teardown their time
/// before the kill. Raise nextest's `terminate-after` to allow more.
const MAX_BUDGET_SECS: u64 = NEXTEST_KILL.as_secs()
    - DIAGNOSTICS_TIMEOUT.as_secs()
    - TEARDOWN_RESERVE.as_secs()
    - KILL_MARGIN.as_secs();
const SCALE_GATE: Duration = Duration::from_secs(180);
/// Graceful owner loss and rolling restart.
const LOSS_GATE: Duration = Duration::from_secs(180);
/// A stale owner record can live up to `OWNER_TTL` (45 s), plus reconnect backoff.
const FORCED_LOSS_GATE: Duration = Duration::from_secs(240);
/// Longer than the kubelet stop grace plus one release round-trip.
const FORCED_PATH_SETTLE: Duration = Duration::from_secs(5);
const GATE_PROBE_TIMEOUT: Duration = Duration::from_secs(20);

/// `OPENSHELL_E2E_KUBE_HA_OPS_BUDGET_SECS` as a positive number of seconds
/// up to `MAX_BUDGET_SECS`, or the default when unset.
fn test_budget(raw: Option<&str>) -> Result<Duration, String> {
    let Some(raw) = raw else {
        return Ok(Duration::from_secs(DEFAULT_BUDGET_SECS));
    };
    match raw.trim().parse::<u64>() {
        Ok(secs) if secs > MAX_BUDGET_SECS => Err(format!(
            "{BUDGET_ENV} must be at most {MAX_BUDGET_SECS} seconds so diagnostics and teardown \
             finish before nextest's {}s kill, got {raw:?}",
            NEXTEST_KILL.as_secs()
        )),
        Ok(secs) if secs > 0 => Ok(Duration::from_secs(secs)),
        _ => Err(format!(
            "{BUDGET_ENV} must be a positive integer number of seconds, got {raw:?}"
        )),
    }
}

/// An owner change is a new replica or a new supervisor connection; a
/// missing record counts as moved.
fn owner_moved(before: &OwnerRow, after: Option<&OwnerRow>) -> bool {
    after.is_none_or(|after| {
        after.replica != before.replica || after.connection_epoch != before.connection_epoch
    })
}

/// The pod a block runs through: never the `owner`, a pod not in `old` when
/// there is one, otherwise the first other pod.
fn pick_via<'a>(pods: &'a [String], owner: &str, old: &[String]) -> Option<&'a String> {
    let mut others = pods.iter().filter(|pod| *pod != owner);
    let preferred = others.clone().find(|pod| !old.contains(pod));
    preferred.or_else(|| others.next())
}

/// Per-phase record behind the `ha-ops summary` line.
struct PhaseLog {
    id: &'static str,
    started: Instant,
    owner: String,
    via: String,
    forced_path: &'static str,
    gate: Duration,
    ops: Vec<String>,
}

impl PhaseLog {
    fn new(id: &'static str) -> Self {
        Self {
            id,
            started: Instant::now(),
            owner: "-".to_string(),
            via: "-".to_string(),
            forced_path: "-",
            gate: Duration::ZERO,
            ops: Vec::new(),
        }
    }

    fn summary(&self, duration: Duration) -> String {
        let ops = self.ops.join(",");
        let ops = if ops.is_empty() { "-" } else { &ops };
        format!(
            "ha-ops summary phase={} owner={} via={} forced_path={} gate_s={} duration_s={} ops={ops}",
            self.id,
            self.owner,
            self.via,
            self.forced_path,
            self.gate.as_secs(),
            duration.as_secs()
        )
    }
}

struct Inventory {
    kube: KubeTarget,
    selector: String,
    https: bool,
    ops: Ops,
    sandbox_id: String,
    /// Ready gateway pods after the last gate.
    pods: Vec<String>,
    started: Instant,
    log: PhaseLog,
}

impl Inventory {
    /// Lane guards and the per-pod client; creates nothing.
    async fn prepare() -> Result<Self, String> {
        let started = Instant::now();
        let kube = KubeTarget::from_env()?;
        let pod_tls = std::env::var("OPENSHELL_E2E_KUBE_POD_TLS");
        let pod_tls = matches!(
            pod_tls.as_deref(),
            Ok("1" | "true" | "TRUE" | "yes" | "YES")
        );
        let (env, selector) = kube.gateway().await?;
        let https = kube::lane_guard(&env, pod_tls)?;
        let ops = Ops::new(ops::Client::new(kube.clone(), https).await?)?;
        let scheme = if https { "https" } else { "http" };
        println!("ha-ops lane: {scheme} peers, sandbox {}", ops.sandbox);
        Ok(Self {
            kube,
            selector,
            https,
            ops,
            sandbox_id: String::new(),
            pods: Vec::new(),
            started,
            log: PhaseLog::new("setup"),
        })
    }

    /// Print the running phase's summary line and start `id`.
    fn switch(&mut self, id: &'static str) {
        println!("{}", self.log.summary(self.log.started.elapsed()));
        self.log = PhaseLog::new(id);
    }

    /// The phases in order. Op ids are frozen for the summary lines; `V+`
    /// attaches the provider and `V-` detaches it.
    async fn execute(&mut self) -> Result<(), String> {
        self.setup().await?;

        self.switch("p0-baseline");
        let ops = ["C", "E1", "E2", "F1", "F2", "F3", "P", "V+"];
        Box::pin(self.checked_block(2, SCALE_GATE, &[], &[], &ops)).await?;

        self.switch("p1-scale-up");
        let old = self.pods.clone();
        self.kube.scale(3).await?;
        // Through the new pod, unless it owns the session.
        let ops = ["C", "E1", "E2", "F3"];
        Box::pin(self.checked_block(3, SCALE_GATE, &[], &old, &ops)).await?;

        self.switch("p2-scale-down");
        self.kube.scale(2).await?;
        let ops = ["C", "E1", "F1", "P"];
        Box::pin(self.checked_block(2, SCALE_GATE, &[], &[], &ops)).await?;

        self.switch("p3-owner-graceful");
        let owner = self.owner_pod().await?;
        self.kube.delete_pod(&owner, false).await?;
        let ops = ["C", "E1", "E2", "F1", "F3", "V-"];
        Box::pin(self.checked_block(2, LOSS_GATE, &[owner], &[], &ops)).await?;

        self.switch("p4-owner-forced");
        let owner = self.owner_pod().await?;
        self.kube.delete_pod(&owner, true).await?;
        // Whether the old replica released its record on the way out; logged,
        // never asserted, since the gate accepts either path. Only a schema
        // change fails here; a failed read is logged as `-`.
        tokio::time::sleep(FORCED_PATH_SETTLE).await;
        self.log.forced_path = match kube::owner_row(&self.kube, &self.sandbox_id).await {
            Ok(row) if row.as_ref().is_some_and(|row| row.replica == owner) => "stale",
            Ok(_) => "released",
            Err(err) if err.starts_with(kube::OWNER_SCHEMA_CHANGED) => return Err(err),
            Err(_) => "-",
        };
        let ops = ["C", "E1", "E2", "F2", "F3", "P", "V+"];
        Box::pin(self.checked_block(2, FORCED_LOSS_GATE, &[owner], &[], &ops)).await?;

        self.switch("p5-rollout");
        let old = self.pods.clone();
        self.kube.rollout_restart().await?;
        let ops = ["C", "E1", "E2", "F1", "F2", "F3", "P", "V-", "N"];
        Box::pin(self.checked_block(2, LOSS_GATE, &old, &[], &ops)).await
    }

    /// Two Ready gateway pods, then the long-lived sandbox and provider.
    async fn setup(&mut self) -> Result<(), String> {
        self.kube.scale(2).await?;
        let (kube, selector) = (&self.kube, &self.selector);
        self.pods = ops::poll("two Ready gateway pods", SCALE_GATE, async || {
            let pods = kube.ready_pods(selector).await.map_err(Fail::transient)?;
            if pods.len() == 2 {
                Ok(pods)
            } else {
                Err(Fail::transient(format!("Ready gateway pods {pods:?}")))
            }
        })
        .await?;
        self.log.gate = self.log.started.elapsed();
        self.log.via.clone_from(&self.pods[0]);
        self.sandbox_id = self.ops.setup(&self.pods[0]).await?;
        Ok(())
    }

    async fn owner_pod(&self) -> Result<String, String> {
        kube::owner_row(&self.kube, &self.sandbox_id)
            .await?
            .map(|row| row.replica)
            .ok_or_else(|| format!("{}: the sandbox has no owner record", self.log.id))
    }

    /// Recovery gate, the non-owner block, then the owner-stability check.
    /// The block proves the peer path only if the owner `(replica, epoch)`
    /// did not move while it ran, so a move re-runs the gate and the block
    /// once. `forbidden` pods may neither be Ready nor own the session; the
    /// block prefers a pod not in `old`.
    async fn checked_block(
        &mut self,
        expected: usize,
        gate_timeout: Duration,
        forbidden: &[String],
        old: &[String],
        ops: &[&str],
    ) -> Result<(), String> {
        let phase = self.log.id;
        let mut rerun = false;
        loop {
            let before = self.recover(expected, gate_timeout, forbidden).await?;
            self.block(&before, old, ops, rerun).await?;
            let after = kube::owner_row(&self.kube, &self.sandbox_id).await?;
            if !owner_moved(&before, after.as_ref()) {
                return Ok(());
            }
            let after = after.map_or_else(|| "none".to_string(), |row| row.to_string());
            if rerun {
                return Err(format!(
                    "{phase}: sandbox owner moved during the non-owner operation block twice ({before} -> {after}); cannot prove peer routing"
                ));
            }
            println!(
                "ha-ops {phase}: owner moved ({before} -> {after}); re-running the block once"
            );
            rerun = true;
        }
    }

    /// Wait for `expected` Ready gateway pods (none forbidden), a fresh owner
    /// among them on the lane's peer scheme, and a Ready sandbox seen through
    /// the owner. The gate makes the operations after it deterministic.
    async fn recover(
        &mut self,
        expected: usize,
        timeout: Duration,
        forbidden: &[String],
    ) -> Result<OwnerRow, String> {
        let started = Instant::now();
        let scheme = if self.https { "https://" } else { "http://" };
        let (kube, selector, id) = (&self.kube, &self.selector, &self.sandbox_id);
        let get = format!("sandbox get {} -o json", self.ops.sandbox);
        let client = &mut self.ops.client;
        let gate = ops::poll("recovery gate", timeout, async || {
            let pods = kube.ready_pods(selector).await.map_err(Fail::transient)?;
            if pods.len() != expected || pods.iter().any(|pod| forbidden.contains(pod)) {
                let want = format!("want {expected} outside {forbidden:?}");
                return Err(Fail::transient(format!(
                    "Ready gateway pods {pods:?}, {want}"
                )));
            }
            let owner = match kube::owner_row(kube, id).await {
                Ok(Some(owner)) => owner,
                Ok(None) => return Err(Fail::transient("no owner record")),
                Err(err) if err.starts_with(kube::OWNER_SCHEMA_CHANGED) => {
                    return Err(Fail::fatal(err));
                }
                Err(err) => return Err(Fail::transient(err)),
            };
            if !owner.peer_endpoint.starts_with(scheme) {
                let endpoint = &owner.peer_endpoint;
                let err = format!("lane guard: owner {owner} advertises {endpoint}, not {scheme}");
                return Err(Fail::fatal(err));
            }
            if !owner.is_fresh()
                || !pods.contains(&owner.replica)
                || forbidden.contains(&owner.replica)
            {
                let age = owner.age_ms;
                let err = format!("owner {owner} (age {age} ms), Ready gateway pods {pods:?}");
                return Err(Fail::transient(err));
            }
            let sandbox = client.json(&owner.replica, &get, GATE_PROBE_TIMEOUT).await;
            let sandbox = sandbox.map_err(|fail| Fail::transient(fail.msg))?;
            if sandbox["phase"] != "Ready" {
                let phase = &sandbox["phase"];
                return Err(Fail::transient(format!(
                    "sandbox phase {phase} through the owner"
                )));
            }
            Ok((pods, owner))
        })
        .await;
        let (pods, owner) = gate.map_err(|err| format!("{}: {err}", self.log.id))?;
        self.log.gate += started.elapsed();
        self.ops.client.retain(&pods);
        self.pods = pods;
        Ok(owner)
    }

    /// Run `ops` through a Ready pod that does not own the session,
    /// preferring one not in `old`, and record their attempts.
    async fn block(
        &mut self,
        owner: &OwnerRow,
        old: &[String],
        ops: &[&str],
        rerun: bool,
    ) -> Result<(), String> {
        let phase = self.log.id;
        let via = pick_via(&self.pods, &owner.replica, old).cloned();
        let via =
            via.ok_or_else(|| format!("{phase}: no Ready pod other than the owner {owner}"))?;
        // A second pod: checks P and runs N across two pods.
        let other = self.pods.iter().find(|pod| **pod != via).cloned();
        let other = other.ok_or_else(|| format!("{phase}: no Ready pod other than {via}"))?;
        self.log.owner = owner.to_string();
        self.log.via.clone_from(&via);
        let at = ops::Target {
            phase,
            pods: &self.pods,
            via: &via,
            other: &other,
            rerun,
        };
        for &op in ops {
            // The rerun undoes the first block's provider change first, so its
            // own V is a fresh mutation too.
            let undo = match op {
                "V+" if rerun => Some("V-"),
                "V-" if rerun => Some("V+"),
                _ => None,
            };
            for op in undo.into_iter().chain([op]) {
                let (attempts, result) = self.ops.run(op, &at).await;
                let id = op.trim_end_matches(['+', '-']);
                self.log.ops.push(format!("{id}:{attempts}"));
                result?;
            }
        }
        Ok(())
    }

    /// Owner record, pods, and gateway logs, peer transport lines first.
    async fn diagnostics(&self) -> String {
        let owner = kube::owner_row(&self.kube, &self.sandbox_id).await;
        let pods = self.kube.kubectl(&["get", "pods", "-o", "wide"]).await;
        let logs = [
            "logs",
            "--tail=80",
            "--prefix",
            "--all-containers",
            "-l",
            &self.selector,
        ];
        let logs = self.kube.kubectl(&logs).await.unwrap_or_else(|err| err);
        let peer = logs
            .lines()
            .filter(|line| line.contains("gateway peer") || line.contains("OPENSHELL_PEER_"));
        let peer = peer.collect::<Vec<_>>().join("\n");
        let pods = pods.unwrap_or_else(|err| err);
        format!(
            "--- owner record ---\n{owner:?}\n--- pods ---\n{pods}\n\
             --- gateway logs matching gateway peer|OPENSHELL_PEER_ ---\n{peer}\n\
             --- gateway logs ---\n{logs}"
        )
    }

    /// Always runs: delete everything this test created through any Ready
    /// pod, restore two replicas, and stop every port-forward.
    async fn teardown(&mut self) {
        self.switch("teardown");
        let pods = self
            .kube
            .ready_pods(&self.selector)
            .await
            .unwrap_or_default();
        let failed = self.ops.cleanup(&pods).await;
        if !failed.is_empty() {
            eprintln!("ha-ops teardown: not deleted: {failed:?}");
        }
        if let Err(err) = self.kube.scale(2).await {
            eprintln!("ha-ops teardown: failed to restore two gateway replicas: {err}");
        }
        self.ops.client.retain(&[]);
        println!("{}", self.log.summary(self.log.started.elapsed()));
    }
}

#[tokio::test]
async fn ha_operation_inventory_survives_gateway_lifecycle() {
    let budget = std::env::var(BUDGET_ENV).ok();
    let budget = test_budget(budget.as_deref()).unwrap_or_else(|err| panic!("{err}"));
    let mut inventory = Inventory::prepare()
        .await
        .unwrap_or_else(|err| panic!("{err}"));
    // The budget bounds the whole run, so diagnostics and teardown still fit
    // under nextest's kill; dropping the run kills any in-flight CLI group.
    let left = budget.saturating_sub(inventory.started.elapsed());
    let result = match tokio::time::timeout(left, Box::pin(inventory.execute())).await {
        Ok(result) => result,
        Err(_) => Err(format!(
            "HA operation inventory exceeded its {}s budget ({BUDGET_ENV}) in {}",
            budget.as_secs(),
            inventory.log.id
        )),
    };
    if let Err(err) = &result {
        // Print the cause first: diagnostics and teardown can stall on a
        // degraded cluster, and nextest's kill would drop it.
        eprintln!("=== ha-ops failure ===\n{err}");
        match tokio::time::timeout(DIAGNOSTICS_TIMEOUT, inventory.diagnostics()).await {
            Ok(diagnostics) => eprintln!("=== ha-ops diagnostics ===\n{diagnostics}"),
            Err(_) => eprintln!(
                "=== ha-ops diagnostics timed out after {}s ===",
                DIAGNOSTICS_TIMEOUT.as_secs()
            ),
        }
    }
    let left = NEXTEST_KILL.saturating_sub(inventory.started.elapsed() + KILL_MARGIN);
    if tokio::time::timeout(left, Box::pin(inventory.teardown()))
        .await
        .is_err()
    {
        eprintln!(
            "ha-ops teardown: stopped after {}s to finish before nextest's kill",
            left.as_secs()
        );
    }
    if let Err(err) = result {
        panic!("{err}");
    }
}

// ---------------------------------------------------------------------------
// Pure helpers (`unit_*`, run without a cluster)
// ---------------------------------------------------------------------------

fn owner(replica: &str, connection_epoch: u64) -> OwnerRow {
    let row = "gw|https://10.0.0.7:8080|0|1000";
    let row = kube::parse_owner_row(row).unwrap().unwrap();
    let replica = replica.to_string();
    OwnerRow {
        replica,
        connection_epoch,
        ..row
    }
}

#[test]
fn unit_sandbox_names_fit_routable_limit() {
    // `MAX_ROUTABLE_NAME_LEN` (`crates/openshell-server/src/grpc/mod.rs`).
    const MAX_ROUTABLE_NAME_LEN: usize = 19;
    let first = ops::fresh_name("k3x9q2", "p5-rollout", &[]);
    assert_eq!(first, "ha-n-k3x9q2-p5a1");
    for _ in 0..20 {
        let run = ops::run_id();
        let mut names = vec![ops::sandbox_name(&run)];
        for phase in ["p0-", "p1-", "p2-", "p3-", "p4-", "p5-"].repeat(9) {
            let name = ops::fresh_name(&run, phase, &names);
            assert!(!names.contains(&name), "{name} reused");
            names.push(name);
        }
        for name in names {
            let dns = |b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-';
            let label = name.bytes().all(dns) && !name.starts_with('-') && !name.ends_with('-');
            assert!(label && name.len() <= MAX_ROUTABLE_NAME_LEN, "{name}");
        }
    }
}

#[test]
fn unit_owner_row_parses_psql_output() {
    assert_eq!(kube::parse_owner_row("\n  \n"), Ok(None));
    let row = kube::parse_owner_row("gw-a|https://10.0.0.7:8080|42|1234\n");
    let want = OwnerRow {
        age_ms: 1234,
        ..owner("gw-a", 42)
    };
    assert_eq!(row, Ok(Some(want.clone())));
    assert!(want.is_fresh());
    assert!(
        !OwnerRow {
            age_ms: 45_000,
            ..want
        }
        .is_fresh()
    );
    for bad in [
        "gw-a|https://10.0.0.7:8080|42",
        "gw-a|https://10.0.0.7:8080|forty-two|1234",
        "|https://10.0.0.7:8080|42|1234",
        "gw-a||42|1234",
        "gw-a|https://x|1|2\ngw-b|https://y|3|4",
    ] {
        assert_eq!(
            kube::parse_owner_row(bad).unwrap_err(),
            format!(
                "owner record schema changed: expected owner_replica_id|owner_peer_endpoint|connection_epoch|age_ms from objects/supervisor_session_owner (crates/openshell-server/src/supervisor_owner.rs), got: {bad}"
            )
        );
    }
}

#[test]
fn unit_is_transient_markers_and_hard_fail_precedence() {
    let transient = |output: &str| ops::is_transient(output, false);
    for marker in [
        "unavailable",
        "transport error",
        "connection refused",
        "connection reset",
        "broken pipe",
        "timed out",
        "deadline exceeded",
        "sandbox is not ready",
        "supervisor session not connected",
        "error trying to connect",
    ] {
        assert!(transient(&format!("Error: {marker}.")), "{marker}");
    }
    assert!(transient("\x1b[31mstatus: UNAVAILABLE\x1b[0m"));
    assert!(
        ops::is_transient("", true),
        "an attempt timeout is transient"
    );
    for fatal in ["status: InvalidArgument", "status: AlreadyExists", "closed"] {
        assert!(!transient(fatal), "{fatal}");
    }
    // Hard-fail markers win over transient markers and timeouts.
    for hard in [
        "status: Unavailable: gateway peer transport refused an http:// peer",
        "Gateway Peer Transport Refused: timed out",
        "openshell_peer_tls_ca_file is required: connection refused",
    ] {
        assert!(!ops::is_transient(hard, true), "{hard}");
    }
}

#[test]
fn unit_owner_moved_compares_replica_and_epoch() {
    let before = owner("gw-a", 7);
    let older = OwnerRow {
        age_ms: 30_000,
        ..owner("gw-a", 7)
    };
    assert!(!owner_moved(&before, Some(&older)));
    assert!(owner_moved(&before, Some(&owner("gw-a", 8))));
    assert!(owner_moved(&before, Some(&owner("gw-b", 7))));
    assert!(owner_moved(&before, None));
}

#[test]
fn unit_pick_via_skips_owner_and_prefers_new_pod() {
    let pods = ["gw-a", "gw-b", "gw-c"].map(str::to_string);
    let old = ["gw-a", "gw-b"].map(str::to_string);
    let via = |owner: &str, old: &[String]| pick_via(&pods, owner, old).cloned();
    assert_eq!(via("gw-c", &old), Some("gw-a".to_string()));
    assert_eq!(via("gw-a", &old), Some("gw-c".to_string()));
    assert_eq!(via("gw-a", &[]), Some("gw-b".to_string()));
    assert_eq!(pick_via(&pods[..1], "gw-a", &[]), None);
    assert_eq!(ops::policy_key("p0-baseline"), "ha_ops_p0_baseline");
}

#[test]
fn unit_lane_guards() {
    let guard = |vars: &[&str], pod_tls: bool| {
        let vars = vars.iter().filter_map(|var| var.split_once('='));
        let env = vars
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect();
        kube::lane_guard(&env, pod_tls)
    };
    let https = "OPENSHELL_PEER_ENDPOINT=https://$(OPENSHELL_POD_IP):8080";
    let http = "OPENSHELL_PEER_ENDPOINT=http://$(OPENSHELL_POD_IP):8080";
    let ca = "OPENSHELL_PEER_TLS_CA_FILE=/etc/openshell-tls/server/ca.crt";
    let name = "OPENSHELL_PEER_TLS_SERVER_NAME=openshell.openshell.svc.cluster.local";
    let cert = "OPENSHELL_PEER_TLS_CERT_FILE=/etc/openshell-tls/peer-client/tls.crt";
    let opt_out = "OPENSHELL_PEER_ALLOW_INSECURE_TRANSPORT=true";
    assert_eq!(guard(&[https, ca, name, cert], true), Ok(true));
    assert_eq!(guard(&[https], false), Ok(true));
    assert_eq!(guard(&[http, opt_out], false), Ok(false));
    for (vars, pod_tls, want) in [
        (
            &[https, ca, name][..],
            true,
            "OPENSHELL_PEER_TLS_CERT_FILE is not set",
        ),
        (
            &[https, ca, name, cert, opt_out],
            true,
            "ALLOW_INSECURE_TRANSPORT is set",
        ),
        (&[http, ca, name, cert], true, "is not https://"),
        (
            &[http],
            false,
            "needs OPENSHELL_PEER_ALLOW_INSECURE_TRANSPORT=true",
        ),
        (
            &[],
            false,
            "needs a Deployment with OPENSHELL_PEER_ENDPOINT",
        ),
    ] {
        let err = guard(vars, pod_tls).unwrap_err();
        assert!(err.contains(want), "{err}");
    }
}

#[tokio::test]
async fn unit_output_survives_pipes_closing_before_the_timeout() {
    // The group outlives one or both pipes, so the kill path resumes a
    // collector that has partly or fully finished.
    for script in [
        "echo marker >&2; exec 1>&-; sleep 60",
        "echo marker >&2; exec 1>&- 2>&-; sleep 60",
    ] {
        let child = tokio::process::Command::new("bash")
            .args(["-c", script])
            .process_group(0)
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .expect("spawn bash");
        let out = ops::output(child, Duration::from_secs(1)).await;
        assert!(out.timed_out, "{script}");
        assert!(out.text.contains("marker"), "{script}: {}", out.text);
    }
}

#[test]
fn unit_budget_and_summary_line() {
    assert_eq!(test_budget(None), Ok(Duration::from_secs(1020)));
    assert_eq!(test_budget(Some("600")), Ok(Duration::from_secs(600)));
    assert_eq!(test_budget(Some("1020")), Ok(Duration::from_secs(1020)));
    let err = test_budget(Some("1021")).unwrap_err();
    assert!(err.contains("at most 1020 seconds"), "{err}");
    for bad in ["", "0", "abc", "-5"] {
        let err = format!("{BUDGET_ENV} must be a positive integer number of seconds, got {bad:?}");
        assert_eq!(test_budget(Some(bad)), Err(err));
    }
    let mut log = PhaseLog::new("p4-owner-forced");
    assert_eq!(
        log.summary(Duration::from_secs(3)),
        "ha-ops summary phase=p4-owner-forced owner=- via=- forced_path=- gate_s=0 duration_s=3 ops=-"
    );
    (log.owner, log.via) = (owner("gw-b", 9).to_string(), "gw-a".to_string());
    (log.forced_path, log.gate) = ("stale", Duration::from_millis(61_900));
    log.ops = ["C:1", "E1:2", "V:1"].map(str::to_string).to_vec();
    assert_eq!(
        log.summary(Duration::from_secs(125)),
        "ha-ops summary phase=p4-owner-forced owner=gw-b@9 via=gw-a forced_path=stale gate_s=61 duration_s=125 ops=C:1,E1:2,V:1"
    );
}
