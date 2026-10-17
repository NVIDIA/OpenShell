// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Cedar version of fs-empty.yaml: no filesystem paths and no network access.
//
// The MXC driver maps YAML filesystem policies only, so run-mxc-e2e.ps1 keeps
// using fs-empty.yaml; this file records the Cedar form. A Cedar policy has
// no include_workdir, and a policy without filesystem permits grants no
// paths. On Linux, the supervisor still adds its baseline runtime paths to a
// Cedar policy, while a YAML policy with no paths and no network policies
// gets no Landlock ruleset.
//
// Cedar denies by default, so the policy has no statements.
