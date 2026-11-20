// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! A Docker or Podman supervisor writes OCSF audit records to its container's
//! stderr, so an operator can collect them without reading files in the
//! container.
//!
//! Conformance can't run this: it reads the supervisor container's own output
//! through the gateway's container engine, which only container drivers have.

use std::time::Duration;

use container_engine_support::Engine;
use host_server_support::{HttpRecorder, TEST_HOST};
use sandbox_clients_support::{Request, connect, http};
use testkit::policy;
use testkit::sdk::raw::proto;
use testkit::sdk::raw::proto::setting_value::Value as SettingValue;
use testkit::{Context, Error, PYTHON_BINARIES, Poll, ResultExt as _};

const JSON_SETTING: &str = "ocsf_json_enabled";
const JSON_MARKER: &str = " OCSF-JSON ";
/// An endpoint the policy doesn't allow, for a Network Activity denial.
const DENIED_HOST: &str = "1.1.1.1";
const DENIED_PORT: u16 = 443;
/// Classes the traffic must produce: Network Activity for the denied
/// connect, HTTP Activity for the denied POST, and SSH Activity for the exec
/// sessions that run the clients.
const REQUIRED_CLASSES: [u64; 3] = [4001, 4002, 4007];
/// How long the setting may take to reach the supervisor, which polls for it.
const JSON_TIMEOUT: Duration = Duration::from_secs(40);

/// OCSF JSON is opt-in. With `ocsf_json_enabled`, the supervisor writes each
/// event as one ` OCSF-JSON <record>` line on stderr, never stdout, next to the
/// shorthand line. Denied TCP, a POST the L7 policy denies, and the exec
/// sessions produce Network, HTTP and SSH Activity records. Every record
/// conforms to the OCSF schema and names the sandbox's container and image.
/// The logs the gateway collects keep only the shorthand.
#[testkit::test]
async fn network_events_are_json_on_supervisor_stderr_only(cx: &mut Context) -> testkit::Result {
    let driver = cx.compute_driver().await?;
    testkit::ensure!(
        matches!(driver.as_str(), "docker" | "podman"),
        "this suite needs a Docker or Podman gateway; the gateway uses {driver}"
    );
    let engine = Engine::from_env()?;
    let server = HttpRecorder::start("ocsf").await?;
    let allowed = l7_policy(server.port)?;
    let image = testkit::python_image();
    let sandbox = cx
        .sandbox("oc")
        .image(&image)
        .command(["sleep", "infinity"])
        .policy(allowed)
        // The shorthand layer logs at info. Podman's supervisor defaults to
        // warn, where Docker's follows the gateway's level.
        .log_level("info")
        .create_ready()
        .await?;
    let supervisor = engine
        .container_for_role(sandbox.name(), "supervisor")
        .await?;
    let workload = engine.container_for_role(sandbox.name(), "sandbox").await?;
    let image_uid = engine.inspect_container(&workload, "{{.Image}}").await?;

    let before = engine.logs(&supervisor).await?;
    testkit::ensure!(
        json_records(&before.stderr)?.is_empty(),
        "the supervisor wrote OCSF JSON before {JSON_SETTING} was set:\n{}",
        before.stderr
    );

    sandbox
        .set_setting(JSON_SETTING, SettingValue::BoolValue(true))
        .await?;
    let post = Request::new("POST", "/allowed").body("x");
    let (logs, records) = testkit::poll_until(
        "JSON Network, HTTP and SSH Activity on the supervisor's stderr",
        JSON_TIMEOUT,
        Duration::from_secs(1),
        async || {
            connect(&sandbox, DENIED_HOST, DENIED_PORT).await?;
            let denied = http(&sandbox, TEST_HOST, server.port, &post).await?;
            testkit::ensure!(
                denied.status() == Some(403),
                "the L7 policy did not deny the POST: {denied:?}"
            );
            let logs = engine.logs(&supervisor).await?;
            testkit::ensure!(
                !logs.stdout.contains(JSON_MARKER),
                "the supervisor wrote OCSF JSON to stdout:\n{}",
                logs.stdout
            );
            let records = json_records(&logs.stderr)?;
            let missing: Vec<u64> = REQUIRED_CLASSES
                .into_iter()
                .filter(|class| !records.iter().any(|record| record["class_uid"] == *class))
                .collect();
            Ok(
                if missing.is_empty() && records.iter().any(is_denied_connect) {
                    Poll::Ready((logs, records))
                } else {
                    Poll::Pending(format!(
                        "missing classes {missing:?}; stderr:\n{}",
                        logs.stderr
                    ))
                },
            )
        },
    )
    .await?;
    testkit::ensure!(
        logs.stderr.contains(" OCSF NET:OPEN "),
        "the shorthand NET:OPEN line is missing from the supervisor's stderr:\n{}",
        logs.stderr
    );

    for record in &records {
        check_record(record, sandbox.name(), &image, &image_uid)
            .context(format!("OCSF record {record}"))?;
    }

    let gateway_logs = sandbox
        .logs_until("NET:OPEN", |logs| logs.contains("NET:OPEN"))
        .await?;
    testkit::ensure!(
        !gateway_logs.contains("OCSF-JSON"),
        "the logs the gateway collects contain OCSF JSON:\n{gateway_logs}"
    );
    Ok(())
}

/// Lets the image's Python reach the server on `port` with an enforced L7
/// rule that allows only `GET /allowed`, so a POST is an HTTP Activity denial.
fn l7_policy(port: u16) -> testkit::Result<proto::SandboxPolicy> {
    policy::base_with(&format!(
        r"network_policies:
  ocsf_l7:
    name: ocsf_l7
    endpoints:
      - host: {TEST_HOST}
        port: {port}
        protocol: rest
        enforcement: enforce
        rules:
          - allow:
              method: GET
              path: /allowed
    binaries: {binaries}
",
        binaries = policy::binaries_yaml(PYTHON_BINARIES),
    ))
}

/// The JSON records in `stderr`, one per ` OCSF-JSON ` line. Each must be a
/// whole JSON object with no terminal escapes.
fn json_records(stderr: &str) -> testkit::Result<Vec<serde_json::Value>> {
    stderr
        .lines()
        .filter_map(|line| line.split_once(JSON_MARKER).map(|(_, payload)| payload))
        .map(|payload| {
            testkit::ensure!(
                !payload.contains('\x1b'),
                "an OCSF JSON line has terminal escapes: {payload:?}"
            );
            serde_json::from_str(payload).context(format!("parse OCSF JSON line {payload:?}"))
        })
        .collect()
}

fn is_denied_connect(record: &serde_json::Value) -> bool {
    record["class_uid"] == 4001
        && record["dst_endpoint"]["port"] == DENIED_PORT
        && record["action"] == "Denied"
}

fn check_record(
    record: &serde_json::Value,
    sandbox: &str,
    image: &str,
    image_uid: &str,
) -> testkit::Result {
    testkit::ensure!(
        record["metadata"]["version"] == "1.8.0",
        "metadata.version is not 1.8.0"
    );
    testkit::ensure!(
        record["metadata"]["uid"]
            .as_str()
            .is_some_and(|uid| !uid.is_empty()),
        "metadata.uid is empty"
    );
    testkit::ensure!(
        record.get("container").is_none(),
        "the container is at the top level, not under device"
    );
    let container = &record["device"]["container"];
    testkit::ensure!(
        container["name"] == sandbox,
        "device.container.name is not {sandbox}"
    );
    testkit::ensure!(
        container["image"]["name"] == image,
        "device.container.image.name is not {image}"
    );
    let uid = container["image"]["uid"]
        .as_str()
        .ok_or_else(|| Error::msg("device.container.image.uid is missing"))?;
    testkit::ensure!(
        uid.trim_start_matches("sha256:") == image_uid.trim_start_matches("sha256:"),
        "device.container.image.uid is not the workload image {image_uid}"
    );
    openshell_ocsf_validate::validate_event(record)
        .map_err(|reason| Error::msg(format!("does not conform to the OCSF schema: {reason}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_records_reads_marked_lines_only() {
        let stderr = "2026 INFO OCSF NET:OPEN [MED] DENIED\n\
                      2026 INFO OCSF-JSON {\"class_uid\":4001}\n";
        let records = json_records(stderr).unwrap();
        assert_eq!(records, vec![serde_json::json!({"class_uid": 4001})]);
    }

    #[test]
    fn json_records_rejects_escapes() {
        assert!(json_records("x OCSF-JSON \x1b[1m{}\n").is_err());
    }
}
