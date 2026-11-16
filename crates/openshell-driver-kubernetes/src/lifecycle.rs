// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Per-sandbox serialization shared by lifecycle RPCs and driver reconciliation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, Weak};
use tokio::sync::Mutex as AsyncMutex;

#[derive(Debug, Default)]
pub struct LifecycleGates {
    gates: Mutex<HashMap<String, Weak<AsyncMutex<()>>>>,
}

impl LifecycleGates {
    pub fn gate_for(&self, sandbox_id: &str) -> Arc<AsyncMutex<()>> {
        let mut gates = self.gates.lock().expect("lifecycle gate registry poisoned");
        gates.retain(|_, gate| gate.strong_count() > 0);
        if let Some(gate) = gates.get(sandbox_id).and_then(Weak::upgrade) {
            return gate;
        }
        let gate = Arc::new(AsyncMutex::new(()));
        gates.insert(sandbox_id.to_string(), Arc::downgrade(&gate));
        gate
    }
}
