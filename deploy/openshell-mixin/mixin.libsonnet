// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
(import 'config.libsonnet') +
(import 'dashboards.libsonnet') +
(import 'defaults.libsonnet') +
{
  // Stable extension points; no unreviewed alert thresholds or recording rules.
  prometheusAlerts: { groups: [] },
  prometheusRules: { groups: [] },
}
