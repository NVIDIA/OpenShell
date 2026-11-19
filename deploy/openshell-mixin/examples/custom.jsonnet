// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
// From the repository root: MIXIN=examples/custom.jsonnet mise run monitoring:generate
(import '../mixin.libsonnet') + {
  _config+:: {
    openshell+: {
      metricsMatchers: [{ name: 'job', operator: '=~', value: 'gateway|openshell-gateway' }],
      metricsClusterLabel: 'kubernetes_cluster',
      namespaceRegex: 'openshell.*|team-sandboxes',
      tracesEnabled: false,
      datasourceRegex+: { metrics: '^production-metrics$', logs: '^production-logs$' },
    },
  },
}
