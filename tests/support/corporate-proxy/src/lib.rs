// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! The environment's corporate proxy, for suites that check sandbox egress
//! through it.
//!
//! The environment runs one proxy and configures the gateway's driver to send
//! sandbox egress through it. The proxy serves TLS, requires Basic auth and
//! intercepts the TLS in every tunnel, all with one CA of its own. The
//! gateway's `no_proxy` sends one destination port, the bypass port, direct.
//! The environment publishes:
//!
//! | Variable | Meaning |
//! |---|---|
//! | `OPENSHELL_TEST_CORPORATE_PROXY_URL` | The proxy URL the gateway uses, e.g. `https://host.openshell.internal:3128` |
//! | `OPENSHELL_TEST_CORPORATE_PROXY_CA_CERT` | The path of the proxy's CA certificate, in PEM |
//! | `OPENSHELL_TEST_CORPORATE_PROXY_BYPASS_LISTEN` | The port a test listens on for a destination that the gateway's `no_proxy` sends direct |
//! | `OPENSHELL_TEST_CORPORATE_PROXY_LOG` | The path of the proxy's log, readable by the tests |
//!
//! Under `openshell-test-runner`, the tmachine `<base>-corporate-proxy`
//! environments do that (`tests/tmachine/ansible/playbooks/corporate-proxy.yaml`).
//! A missing variable fails the test; it never skips it.
//!
//! The log has one JSON line per CONNECT and lasts as long as the
//! environment, so a test takes a [`LogCursor`] before its sandbox starts
//! and reads only what came after it, for the ports it started servers on:
//!
//! ```ignore
//! let proxy = CorporateProxy::from_env()?;
//! let cursor = proxy.log_cursor()?;
//! // ... run a sandbox that reaches a server on `port` ...
//! let connects = proxy.connects_to(&cursor, port)?;
//! ```
//!
//! Tests that bind the bypass port can't run at the same time.

use std::fmt;
use std::io::{Read as _, Seek as _, SeekFrom};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use testkit::{Error, Result};

pub const URL_ENV: &str = "OPENSHELL_TEST_CORPORATE_PROXY_URL";
pub const CA_CERT_ENV: &str = "OPENSHELL_TEST_CORPORATE_PROXY_CA_CERT";
pub const BYPASS_LISTEN_ENV: &str = "OPENSHELL_TEST_CORPORATE_PROXY_BYPASS_LISTEN";
pub const LOG_ENV: &str = "OPENSHELL_TEST_CORPORATE_PROXY_LOG";

/// How to reach the environment's corporate proxy and read its log.
#[derive(Clone, Debug)]
pub struct CorporateProxy {
    url: String,
    ca_cert: PathBuf,
    bypass_port: u16,
    log: PathBuf,
}

/// A point in the proxy's log. [`CorporateProxy::connects_since`] reads the
/// CONNECTs logged after it.
#[derive(Clone, Copy, Debug)]
pub struct LogCursor(u64);

/// One CONNECT the proxy received.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct Connect {
    /// The CONNECT target, `host:port`. The supervisor sends a validated IP
    /// unless the gateway sets `proxy_connect_by_hostname`.
    pub target: String,
    pub auth: Auth,
    pub result: Outcome,
    /// Why the CONNECT failed, for failure messages.
    #[serde(default)]
    pub error: Option<String>,
}

/// Whether the CONNECT carried the proxy's credentials.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Auth {
    Ok,
    Missing,
    Wrong,
}

/// What the proxy did with the CONNECT.
#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Answered 407, because the credentials were missing or wrong.
    Rejected,
    /// Answered 502, because the target refused or timed out.
    DialFailed,
    /// The client rejected the proxy's re-signed certificate, or dropped the
    /// tunnel's TLS handshake.
    ClientTlsFailed,
    /// The target's TLS handshake failed.
    UpstreamTlsFailed,
    /// The proxy terminated the tunnel's TLS and relayed it to the target.
    Intercepted,
}

impl Connect {
    /// The CONNECT target's host, without IPv6 brackets.
    pub fn host(&self) -> &str {
        self.target
            .rsplit_once(':')
            .map_or(self.target.as_str(), |(host, _)| host)
            .trim_start_matches('[')
            .trim_end_matches(']')
    }

    /// The CONNECT target's port.
    pub fn port(&self) -> Option<u16> {
        self.target.rsplit_once(':')?.1.parse().ok()
    }
}

impl fmt::Display for Connect {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "CONNECT {} auth={:?} result={:?}",
            self.target, self.auth, self.result
        )?;
        if let Some(error) = &self.error {
            write!(f, " error={error}")?;
        }
        Ok(())
    }
}

impl CorporateProxy {
    /// Read `OPENSHELL_TEST_CORPORATE_PROXY_*`. Fails naming the first
    /// missing variable.
    pub fn from_env() -> Result<Self> {
        Self::from_vars(|name| std::env::var(name).ok())
    }

    fn from_vars(var: impl Fn(&str) -> Option<String>) -> Result<Self> {
        let required = |name: &str| {
            var(name)
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty())
                .ok_or_else(|| {
                    Error::msg(format!(
                        "{name} is not set; this suite needs a corporate proxy (see the corporate-proxy-support crate docs)"
                    ))
                })
        };
        let url = required(URL_ENV)?;
        let ca_cert = required(CA_CERT_ENV)?.into();
        let bypass_port = required(BYPASS_LISTEN_ENV)?;
        let bypass_port = bypass_port.parse().map_err(|error| {
            Error::msg(format!(
                "{BYPASS_LISTEN_ENV} is {bypass_port:?}, not a port: {error}"
            ))
        })?;
        let log = required(LOG_ENV)?.into();
        Ok(Self {
            url,
            ca_cert,
            bypass_port,
            log,
        })
    }

    /// The proxy URL the gateway uses.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// The path of the proxy's CA certificate, in PEM.
    pub fn ca_cert(&self) -> &Path {
        &self.ca_cert
    }

    /// The destination port the gateway's `no_proxy` sends direct.
    pub fn bypass_port(&self) -> u16 {
        self.bypass_port
    }

    /// The end of the log now.
    pub fn log_cursor(&self) -> Result<LogCursor> {
        let metadata = std::fs::metadata(&self.log)
            .map_err(|error| Error::msg(format!("read {}: {error}", self.log.display())))?;
        Ok(LogCursor(metadata.len()))
    }

    /// The CONNECTs logged after `cursor`, oldest first. A line the proxy is
    /// still writing is left out.
    pub fn connects_since(&self, cursor: &LogCursor) -> Result<Vec<Connect>> {
        let read =
            |error: std::io::Error| Error::msg(format!("read {}: {error}", self.log.display()));
        let mut file = std::fs::File::open(&self.log).map_err(read)?;
        let len = file.metadata().map_err(read)?.len();
        testkit::ensure!(
            len >= cursor.0,
            "{} is {len} bytes, shorter than the cursor at {}; was it truncated?",
            self.log.display(),
            cursor.0
        );
        file.seek(SeekFrom::Start(cursor.0)).map_err(read)?;
        let mut text = String::new();
        file.read_to_string(&mut text).map_err(read)?;
        parse(&text).map_err(|error| Error::msg(format!("{}: {error}", self.log.display())))
    }

    /// The CONNECTs to `port` logged after `cursor`.
    pub fn connects_to(&self, cursor: &LogCursor, port: u16) -> Result<Vec<Connect>> {
        Ok(self
            .connects_since(cursor)?
            .into_iter()
            .filter(|connect| connect.port() == Some(port))
            .collect())
    }
}

/// Parse the complete lines of `text`.
fn parse(text: &str) -> std::result::Result<Vec<Connect>, String> {
    let complete = text.rfind('\n').map_or("", |end| &text[..end]);
    complete
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            serde_json::from_str(line).map_err(|error| format!("bad log line {line:?}: {error}"))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::Write as _;

    use super::*;

    fn vars(pairs: &[(&str, &str)]) -> impl Fn(&str) -> Option<String> {
        let map: HashMap<String, String> = pairs
            .iter()
            .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
            .collect();
        move |name| map.get(name).cloned()
    }

    const ALL: &[(&str, &str)] = &[
        (URL_ENV, "https://host.openshell.internal:3128"),
        (CA_CERT_ENV, "/etc/ca.pem"),
        (BYPASS_LISTEN_ENV, "39443"),
        (LOG_ENV, "/var/log/proxy.jsonl"),
    ];

    #[test]
    fn reads_every_variable() {
        let proxy = CorporateProxy::from_vars(vars(ALL)).unwrap();
        assert_eq!(proxy.url(), "https://host.openshell.internal:3128");
        assert_eq!(proxy.ca_cert(), Path::new("/etc/ca.pem"));
        assert_eq!(proxy.bypass_port(), 39443);
    }

    #[test]
    fn missing_or_empty_variables_fail_naming_them() {
        for name in [URL_ENV, CA_CERT_ENV, BYPASS_LISTEN_ENV, LOG_ENV] {
            let without: Vec<_> = ALL
                .iter()
                .copied()
                .filter(|(key, _)| *key != name)
                .collect();
            let error = CorporateProxy::from_vars(vars(&without)).unwrap_err();
            assert!(error.to_string().contains(name), "{error}");

            let mut empty = without.clone();
            empty.push((name, " "));
            let error = CorporateProxy::from_vars(vars(&empty)).unwrap_err();
            assert!(error.to_string().contains(name), "{error}");
        }
    }

    #[test]
    fn bad_bypass_port_fails() {
        let mut pairs = ALL.to_vec();
        pairs.retain(|(key, _)| *key != BYPASS_LISTEN_ENV);
        pairs.push((BYPASS_LISTEN_ENV, "70000"));
        let error = CorporateProxy::from_vars(vars(&pairs)).unwrap_err();
        assert!(error.to_string().contains("not a port"), "{error}");
    }

    #[test]
    fn connect_target_parts() {
        let connect = |target: &str| Connect {
            target: target.into(),
            auth: Auth::Ok,
            result: Outcome::Intercepted,
            error: None,
        };
        assert_eq!(connect("10.0.2.15:443").host(), "10.0.2.15");
        assert_eq!(connect("10.0.2.15:443").port(), Some(443));
        assert_eq!(connect("[fd00::1]:8443").host(), "fd00::1");
        assert_eq!(connect("[fd00::1]:8443").port(), Some(8443));
        assert_eq!(connect("nonsense").port(), None);
    }

    #[test]
    fn reads_only_complete_lines_after_the_cursor() {
        let mut log = tempfile::NamedTempFile::new().unwrap();
        writeln!(
            log,
            r#"{{"time": 1.0, "target": "10.0.0.1:1", "auth": "missing", "result": "rejected"}}"#
        )
        .unwrap();
        let proxy = CorporateProxy {
            log: log.path().to_owned(),
            ..CorporateProxy::from_vars(vars(ALL)).unwrap()
        };
        let cursor = proxy.log_cursor().unwrap();
        writeln!(
            log,
            r#"{{"time": 2.0, "target": "10.0.0.1:443", "auth": "ok", "result": "intercepted"}}"#
        )
        .unwrap();
        writeln!(
            log,
            r#"{{"time": 3.0, "target": "10.0.0.1:444", "auth": "ok", "result": "dial_failed", "error": "refused"}}"#
        )
        .unwrap();
        write!(log, r#"{{"time": 4.0, "target": "10.0"#).unwrap();
        log.flush().unwrap();

        let connects = proxy.connects_since(&cursor).unwrap();
        assert_eq!(
            connects,
            [
                Connect {
                    target: "10.0.0.1:443".into(),
                    auth: Auth::Ok,
                    result: Outcome::Intercepted,
                    error: None,
                },
                Connect {
                    target: "10.0.0.1:444".into(),
                    auth: Auth::Ok,
                    result: Outcome::DialFailed,
                    error: Some("refused".into()),
                },
            ]
        );
        assert_eq!(proxy.connects_to(&cursor, 443).unwrap(), connects[..1]);
    }

    #[test]
    fn bad_lines_fail() {
        let error = parse("not json\n").unwrap_err();
        assert!(error.contains("not json"), "{error}");
    }
}
