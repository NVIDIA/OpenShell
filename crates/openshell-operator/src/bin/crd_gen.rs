// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

//! Utility to generate the SandboxRuntime CRD YAML for Helm chart deployment.

use kube::CustomResourceExt;
use openshell_operator::crd::SandboxRuntime;

fn main() {
    print!(
        "{}",
        serde_yml::to_string(&SandboxRuntime::crd()).unwrap()
    );
}
