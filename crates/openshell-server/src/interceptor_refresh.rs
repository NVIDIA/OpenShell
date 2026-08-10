// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use metrics::counter;
use openshell_core::proto::gateway_interceptor::v1::DescribeRequest;
use openshell_core::proto::gateway_interceptor::v1::gateway_interceptor_client::GatewayInterceptorClient;
use tokio::sync::mpsc;
use tonic::transport::Channel;
use tracing::{debug, info, warn};

const RECONNECT_PROBE_INTERVAL: Duration = Duration::from_secs(2);
const RECONNECT_BACKOFF_MAX: Duration = Duration::from_secs(30);
const DESCRIBE_TIMEOUT: Duration = Duration::from_secs(5);

pub fn spawn_interceptor_refresh_worker(state: Arc<crate::ServerState>, poll_interval: Duration) {
    let Some(ref interceptors) = state.gateway_interceptors else {
        return;
    };

    let clients = interceptors.interceptor_clients();
    if clients.is_empty() {
        return;
    }

    info!(
        poll_interval_secs = poll_interval.as_secs(),
        interceptors = clients.len(),
        "gateway interceptor refresh worker started (reconnect + poll)"
    );

    let (tx, mut rx) = mpsc::channel::<String>(16);

    for (name, client) in clients {
        let tx = tx.clone();
        tokio::spawn(watch_interceptor_connection(name, client, tx));
    }

    let state = state.clone();
    tokio::spawn(async move {
        let mut poll_ticker = tokio::time::interval(poll_interval);
        poll_ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        poll_ticker.tick().await;

        loop {
            let trigger = tokio::select! {
                _ = poll_ticker.tick() => "poll",
                name = rx.recv() => {
                    if let Some(name) = name {
                        info!(
                            interceptor = %name,
                            "interceptor reconnected, triggering manifest refresh"
                        );
                    } else {
                        break;
                    }
                    "reconnect"
                }
            };

            let Some(ref interceptors) = state.gateway_interceptors else {
                continue;
            };

            match interceptors.refresh().await {
                Ok(structural_change) => {
                    counter!(
                        "openshell_gateway_interceptor_refresh_total",
                        "trigger" => trigger,
                        "result" => "success"
                    )
                    .increment(1);
                    if structural_change {
                        info!(
                            trigger,
                            "gateway interceptor manifest refreshed with structural changes"
                        );
                    } else {
                        debug!(trigger, "gateway interceptor manifest refreshed");
                    }
                }
                Err(err) => {
                    counter!(
                        "openshell_gateway_interceptor_refresh_total",
                        "trigger" => trigger,
                        "result" => "error"
                    )
                    .increment(1);
                    warn!(
                        trigger,
                        error = %err,
                        "gateway interceptor manifest refresh failed; keeping previous plan"
                    );
                }
            }
        }
    });
}

async fn watch_interceptor_connection(
    name: String,
    mut client: GatewayInterceptorClient<Channel>,
    tx: mpsc::Sender<String>,
) {
    let mut connected = true;
    let mut backoff = RECONNECT_PROBE_INTERVAL;

    loop {
        let sleep_duration = if connected {
            backoff = RECONNECT_PROBE_INTERVAL;
            RECONNECT_BACKOFF_MAX
        } else {
            backoff
        };
        tokio::time::sleep(sleep_duration).await;

        let result = tokio::time::timeout(
            DESCRIBE_TIMEOUT,
            client.describe(tonic::Request::new(DescribeRequest {})),
        )
        .await;

        if let Ok(Ok(_)) = result {
            if !connected {
                connected = true;
                backoff = RECONNECT_PROBE_INTERVAL;
                let _ = tx.send(name.clone()).await;
            }
        } else {
            if connected {
                warn!(interceptor = %name, "interceptor connection lost");
                connected = false;
            }
            backoff = (backoff * 2).min(RECONNECT_BACKOFF_MAX);
        }
    }
}
