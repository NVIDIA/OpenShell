// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
{
  _config+:: {
    openshell+: {
      metricsMatchers: [{ name: 'job', operator: '=', value: 'openshell-gateway' }],
      uidPrefix: '',
      dashboardUids: {},
      tags: ['openshell'],
      ocsfTags: ['ocsf'],
      refresh: '30s',
      timezone: 'browser',
      // Optional per-dashboard field overrides, keyed by exported JSON filename.
      dashboardOverrides: {},
      metricsClusterLabel: 'cluster',
      metricsInstanceLabel: 'instance',
      logsClusterLabel: 'k8s_cluster_name',
      logsNamespaceLabel: 'k8s_namespace_name',
      namespaceRegex: 'openshell.*',
      tracesEnabled: true,
      tracesClusterAttribute: 'resource.k8s.cluster.name',
      tracesService: 'openshell-gateway',
      // Match datasource names. Empty means all datasources of that type.
      datasourceRegex: { metrics: '', logs: '', traces: '' },
    },
  },
}
