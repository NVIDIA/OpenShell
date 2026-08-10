// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

use std::sync::Arc;
use std::time::Duration;

use metrics::counter;
use tracing::{debug, info, warn};

pub fn spawn_interceptor_refresh_worker(state: Arc<crate::ServerState>, interval: Duration) {
    info!(
        interval_seconds = interval.as_secs(),
        "gateway interceptor refresh worker started"
    );
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        ticker.tick().await;
        loop {
            ticker.tick().await;
            let Some(ref interceptors) = state.gateway_interceptors else {
                continue;
            };
            match interceptors.refresh().await {
                Ok(true) => {
                    counter!("openshell_gateway_interceptor_refresh_total", "result" => "success")
                        .increment(1);
                    info!("gateway interceptor manifest refreshed with new bindings");
                }
                Ok(false) => {
                    counter!("openshell_gateway_interceptor_refresh_total", "result" => "unchanged")
                        .increment(1);
                    debug!("gateway interceptor manifest unchanged");
                }
                Err(err) => {
                    counter!("openshell_gateway_interceptor_refresh_total", "result" => "error")
                        .increment(1);
                    warn!(
                        error = %err,
                        "gateway interceptor manifest refresh failed; keeping previous plan"
                    );
                }
            }
        }
    });
}
