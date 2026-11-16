// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

local g = import 'github.com/grafana/grafonnet/gen/grafonnet-latest/main.libsonnet';
(import '../mixin.libsonnet') + {
  _config+:: {
    openshell+: {
      uidPrefix: 'team-',
      refresh: '1m',
      timezone: 'utc',
      tracesEnabled: false,
      tags: ['openshell', 'production'],
      dashboardUids+: { 'openshell-operational-logs.json': 'operations' },
      dashboardOverrides+: {
        'openshell-operational-health.json': { title: 'Production OpenShell health' },
      },
    },
  },
  grafanaDashboards+: {
    'openshell-operational-health.json'+: {
      panels: [
        if p.id == 2 then p {
          fieldConfig+: {
            defaults+: {
              thresholds: {
                mode: 'absolute',
                steps: [
                  { color: 'green', value: null },
                  { color: 'yellow', value: 0.1 },
                  { color: 'red', value: 0.5 },
                ],
              },
            },
          },
        } else p
        for p in super.panels
      ] + [
        g.panel.text.new('Runbook') +
        g.panel.text.panelOptions.withGridPos(h=3, w=24, x=0, y=62) + {
          id: 100,
          options: { mode: 'markdown', content: 'Investigate database readiness and RPC failures before restarting gateways.' },
        },
      ],
    },
  },
}
