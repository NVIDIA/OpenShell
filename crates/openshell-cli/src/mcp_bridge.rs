// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! `openshell mcp serve`: a local MCP server over stdio that forwards each
//! message to the gateway's `/mcp` with the CLI's login (RFC 0021).
//!
//! Stdout carries MCP messages only, one JSON-RPC message per line; the
//! client reads every line as one. Everything else goes to stderr.

use openshell_bootstrap::oidc_token::{load_oidc_token, store_oidc_token};
use openshell_sdk::{OpenShellClient, Refresh, RefreshError, RefreshedToken};
use serde_json::{Value, json};
use std::future::Future;
use std::sync::Arc;
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncWrite, AsyncWriteExt};

/// What the gateway answered to one forwarded message.
pub struct Sent {
    pub status: u16,
    pub body: Vec<u8>,
}

/// Read MCP messages from `input` and answer each on `output`, one per line.
///
/// Each message is sent on its own task, so a long `wait` never holds up a
/// `ping`; a whole reply line is written under one lock. Returns when `input`
/// closes and every call in flight has answered.
pub async fn serve<R, W, S, F>(input: R, output: W, send: S) -> std::io::Result<()>
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin + Send + 'static,
    S: Fn(Vec<u8>) -> F + Clone + Send + 'static,
    F: Future<Output = Result<Sent, String>> + Send,
{
    let output = Arc::new(tokio::sync::Mutex::new(output));
    let mut input = input;
    let mut raw = Vec::new();
    let mut calls = tokio::task::JoinSet::new();
    loop {
        raw.clear();
        if input.read_until(b'\n', &mut raw).await? == 0 {
            break;
        }
        // A line that is not UTF-8 cannot be JSON: answer it as a parse
        // error, as for any other bad line, and keep reading.
        let line = String::from_utf8(raw.clone()).map_or_else(
            |_| "\u{fffd}".to_string(),
            |line| line.trim_end_matches(['\r', '\n']).to_string(),
        );
        if line.trim().is_empty() {
            continue;
        }
        let output = Arc::clone(&output);
        let send = send.clone();
        calls.spawn(async move {
            let Some(reply) = reply_to(&line, send).await else {
                return;
            };
            let mut output = output.lock().await;
            // A client that went away cannot be told anything.
            let _ = output.write_all(format!("{reply}\n").as_bytes()).await;
            let _ = output.flush().await;
        });
    }
    while calls.join_next().await.is_some() {}
    Ok(())
}

/// The reply line for one message, or none for a notification the gateway
/// accepted.
async fn reply_to<S, F>(line: &str, send: S) -> Option<String>
where
    S: Fn(Vec<u8>) -> F,
    F: Future<Output = Result<Sent, String>>,
{
    let Ok(message) = serde_json::from_str::<Value>(line) else {
        return Some(rpc_error(&Value::Null, -32700, "parse error"));
    };
    let id = message.get("id").cloned();
    let error = |message: String| id.as_ref().map(|id| rpc_error(id, -32000, &message));
    match send(line.as_bytes().to_vec()).await {
        // Re-encode the reply so it is one line whatever the gateway sent.
        Ok(Sent { status: 200, body }) => serde_json::from_slice::<Value>(&body).map_or_else(
            |_| error("the gateway sent a reply that is not JSON".to_string()),
            |reply| Some(reply.to_string()),
        ),
        Ok(Sent { status: 202, .. }) => None,
        Ok(Sent { status, body }) => {
            let text = String::from_utf8_lossy(&body);
            let hint = match status {
                401 => "; run `openshell gateway login`",
                _ => "",
            };
            error(format!(
                "the gateway refused the call (HTTP {status}): {}{hint}",
                text.trim()
            ))
        }
        Err(message) => error(message),
    }
}

fn rpc_error(id: &Value, code: i64, message: &str) -> String {
    json!({"jsonrpc": "2.0", "id": id, "error": {"code": code, "message": message}}).to_string()
}

/// The gateway client, built on first use.
///
/// A built client is kept, and its login is refreshed by the client itself.
/// A failed build is not kept: that call answers with the fresh error and the
/// next call tries again, so a bridge started before `openshell gateway login`
/// works once the user logs in. Concurrent first calls share one attempt.
pub struct LazyClient<C, M> {
    client: tokio::sync::OnceCell<C>,
    build: M,
}

impl<C, M, F> LazyClient<C, M>
where
    C: Send + Sync,
    M: Fn() -> F + Sync,
    F: Future<Output = Result<C, String>> + Send,
{
    pub fn new(build: M) -> Self {
        Self {
            client: tokio::sync::OnceCell::new(),
            build,
        }
    }

    pub async fn get(&self) -> Result<&C, String> {
        self.client.get_or_try_init(|| (self.build)()).await
    }
}

/// Forward one message with `client`, or explain why there is no client.
pub async fn send_with(
    client: Result<&OpenShellClient, String>,
    body: &[u8],
    workspace: &str,
) -> Result<Sent, String> {
    let client = client?;
    let reply = client
        .post_mcp(body, workspace)
        .await
        .map_err(|error| format!("gateway unreachable: {error}"))?;
    Ok(Sent {
        status: reply.status.as_u16(),
        body: reply.body,
    })
}

/// Refreshes the gateway's stored OIDC login, as the CLI does at start-up,
/// for a bridge that outlives one access token.
pub struct StoredOidcRefresher {
    pub gateway_name: String,
    pub audience: Option<String>,
    pub scopes: Option<String>,
    pub insecure: bool,
}

#[async_trait::async_trait]
impl Refresh for StoredOidcRefresher {
    async fn refresh(&self) -> Result<RefreshedToken, RefreshError> {
        let bundle = load_oidc_token(&self.gateway_name).ok_or_else(|| {
            RefreshError::Terminal(format!(
                "no stored login; run `openshell gateway login {}`",
                self.gateway_name
            ))
        })?;
        let refreshed = crate::oidc_auth::oidc_renew_token(
            &bundle,
            self.audience.as_deref(),
            self.scopes.as_deref(),
            self.insecure,
        )
        .await
        .map_err(|error| RefreshError::Transient(error.to_string()))?;
        if let Err(error) = store_oidc_token(&self.gateway_name, &refreshed) {
            tracing::warn!("could not store the refreshed login: {error}");
        }
        let token = RefreshedToken::new(refreshed.access_token);
        Ok(match refreshed.expires_at {
            Some(expires_at) => token.with_expires_at(expires_at),
            None => token,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Run the bridge over `input` with a gateway that answers by `answer`,
    /// and return its stdout lines.
    async fn bridge_lines(input: &str, answer: fn(&Value) -> Result<Sent, String>) -> Vec<String> {
        let (writer, mut reader) = tokio::io::duplex(1 << 20);
        let send =
            move |body: Vec<u8>| async move { answer(&serde_json::from_slice(&body).unwrap()) };
        serve(input.as_bytes(), writer, send).await.unwrap();
        let mut out = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut reader, &mut out)
            .await
            .unwrap();
        out.lines().map(str::to_string).collect()
    }

    fn gateway(message: &Value) -> Result<Sent, String> {
        let reply = |status, body: Value| {
            Ok(Sent {
                status,
                body: body.to_string().into_bytes(),
            })
        };
        match message["method"].as_str().unwrap_or_default() {
            // Pretty-printed, to check the bridge sends it as one line.
            "ping" => Ok(Sent {
                status: 200,
                body: serde_json::to_vec_pretty(
                    &json!({"jsonrpc": "2.0", "id": message["id"], "result": {}}),
                )
                .unwrap(),
            }),
            "notifications/initialized" => reply(202, Value::Null),
            "forbidden" => Ok(Sent {
                status: 403,
                body: b"requests with an Origin header are refused".to_vec(),
            }),
            "expired" => Ok(Sent {
                status: 401,
                body: Vec::new(),
            }),
            _ => Err("gateway unreachable: connection refused".to_string()),
        }
    }

    #[tokio::test]
    async fn stdout_carries_one_json_rpc_message_per_line_and_nothing_else() {
        let input = [
            r#"{"jsonrpc":"2.0","id":1,"method":"ping"}"#,
            r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
            "",
            r#"{"jsonrpc":"2.0","id":2,"method":"forbidden"}"#,
            r#"{"jsonrpc":"2.0","id":"three","method":"expired"}"#,
            r#"{"jsonrpc":"2.0","id":4,"method":"down"}"#,
            "not json",
        ]
        .join("\n");
        let lines = bridge_lines(&input, gateway).await;

        // Five replies: the notification and the blank line get none.
        assert_eq!(lines.len(), 5, "{lines:?}");
        let mut by_id = std::collections::HashMap::new();
        for line in &lines {
            let message: Value = serde_json::from_str(line).unwrap_or_else(|_| panic!("{line}"));
            assert_eq!(message["jsonrpc"], "2.0", "{line}");
            by_id.insert(message["id"].to_string(), message);
        }
        assert_eq!(by_id["1"]["result"], json!({}));
        assert!(
            by_id["2"]["error"]["message"]
                .as_str()
                .unwrap()
                .contains("HTTP 403")
        );
        assert!(
            by_id["\"three\""]["error"]["message"]
                .as_str()
                .unwrap()
                .contains("openshell gateway login")
        );
        assert!(
            by_id["4"]["error"]["message"]
                .as_str()
                .unwrap()
                .contains("unreachable")
        );
        assert_eq!(by_id["null"]["error"]["code"], -32700);
    }

    #[tokio::test]
    async fn a_login_after_the_bridge_started_works_without_a_restart() {
        use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

        let logged_in = Arc::new(AtomicBool::new(false));
        let builds = Arc::new(AtomicUsize::new(0));
        let client = Arc::new(LazyClient::new({
            let (logged_in, builds) = (Arc::clone(&logged_in), Arc::clone(&builds));
            move || {
                let (logged_in, builds) = (Arc::clone(&logged_in), Arc::clone(&builds));
                async move {
                    let attempt = builds.fetch_add(1, Ordering::SeqCst) + 1;
                    // A slow connect, so concurrent first calls overlap.
                    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                    if logged_in.load(Ordering::SeqCst) {
                        Ok("client")
                    } else {
                        Err(format!("attempt {attempt}: run `openshell gateway login`"))
                    }
                }
            }
        }));
        let send = move |body: Vec<u8>| {
            let client = Arc::clone(&client);
            async move {
                client.get().await?;
                let message: Value = serde_json::from_slice(&body).unwrap();
                Ok(Sent {
                    status: 200,
                    body: json!({"jsonrpc": "2.0", "id": message["id"], "result": {}})
                        .to_string()
                        .into_bytes(),
                })
            }
        };
        let (mut stdin, input) = tokio::io::duplex(1 << 16);
        let (output, stdout) = tokio::io::duplex(1 << 16);
        let bridge = tokio::spawn(serve(tokio::io::BufReader::new(input), output, send));
        let mut stdout = tokio::io::BufReader::new(stdout).lines();
        let ping = |id: usize| format!("{{\"jsonrpc\":\"2.0\",\"id\":{id},\"method\":\"ping\"}}\n");

        stdin.write_all(ping(1).as_bytes()).await.unwrap();
        let first: Value =
            serde_json::from_str(&stdout.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(
            first["error"]["message"], "attempt 1: run `openshell gateway login`",
            "the call gets the error from its own attempt"
        );

        logged_in.store(true, Ordering::SeqCst);
        for id in 2..=6 {
            stdin.write_all(ping(id).as_bytes()).await.unwrap();
        }
        for _ in 2..=6 {
            let reply: Value =
                serde_json::from_str(&stdout.next_line().await.unwrap().unwrap()).unwrap();
            assert_eq!(reply["result"], json!({}), "{reply}");
        }
        assert_eq!(
            builds.load(Ordering::SeqCst),
            2,
            "one failed build, then one build shared by every later call"
        );

        drop(stdin);
        bridge.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn a_line_that_is_not_utf8_is_a_parse_error_and_the_bridge_keeps_reading() {
        let (writer, mut reader) = tokio::io::duplex(1 << 20);
        let mut input = b"\xff\xfe not utf-8\n".to_vec();
        input.extend_from_slice(b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"ping\"}\r\n");
        let send = |body: Vec<u8>| async move { gateway(&serde_json::from_slice(&body).unwrap()) };

        serve(&input[..], writer, send).await.unwrap();

        let mut out = String::new();
        tokio::io::AsyncReadExt::read_to_string(&mut reader, &mut out)
            .await
            .unwrap();
        let replies: Vec<Value> = out
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect();
        assert_eq!(replies.len(), 2, "{out}");
        let parse_error = replies.iter().find(|reply| reply["id"].is_null()).unwrap();
        assert_eq!(parse_error["error"]["code"], -32700);
        assert_eq!(parse_error["error"]["message"], "parse error");
        let ping = replies.iter().find(|reply| reply["id"] == 1).unwrap();
        assert_eq!(ping["result"], json!({}));
    }

    #[tokio::test]
    async fn a_slow_call_does_not_hold_up_the_others() {
        let (writer, mut reader) = tokio::io::duplex(1 << 20);
        let send = |body: Vec<u8>| async move {
            let message: Value = serde_json::from_slice(&body).unwrap();
            if message["method"] == "slow" {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
            }
            Ok(Sent {
                status: 200,
                body: json!({"jsonrpc": "2.0", "id": message["id"], "result": {}})
                    .to_string()
                    .into_bytes(),
            })
        };
        let input = "{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"slow\"}\n\
                     {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"ping\"}\n";
        tokio::spawn(serve(input.as_bytes(), writer, send));

        let mut first = String::new();
        let mut reader = tokio::io::BufReader::new(&mut reader);
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            reader.read_line(&mut first),
        )
        .await
        .expect("the ping is answered before the slow call ends")
        .unwrap();
        assert_eq!(serde_json::from_str::<Value>(&first).unwrap()["id"], 2);
    }
}
