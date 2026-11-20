// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

local queries = import '../queries.libsonnet';
local g = import 'github.com/grafana/grafonnet/gen/grafonnet-latest/main.libsonnet';
{
  local c = self._config.openshell,
  local q = queries.new(c),
  grafanaDashboards+:: {
    'openshell-operational-health.json':
      g.dashboard.new('OpenShell / Operational health')
      + {
        id: null,
        description: 'Gateway readiness, request rates and latency, supervisor sessions, routing, relay capacity, and mutation locks from OpenShell metrics. Select a Prometheus datasource, cluster, and gateway target. Optional gateway trace search uses Tempo and the selected cluster. Missing observations do not establish health; latency panels show means unless labeled p95.',
        schemaVersion: 40,
        version: 1,
        editable: true,
        time: {
          from: 'now-1h',
          to: 'now',
        },
        timepicker: {},
        annotations: {
          list: [],
        },
        links: [
          {
            type: 'dashboards',
            title: 'OpenShell dashboards',
            tags: [
              'openshell',
            ],
            asDropdown: true,
            includeVars: true,
            keepTime: true,
            targetBlank: false,
          },
        ],
        fiscalYearStartMonth: 0,
      }
      + g.dashboard.withVariables([v for v in [
        g.dashboard.variable.datasource.new('metrics', 'prometheus') + {
          label: 'Metrics source',
          refresh: 1,
          options: [],
          hide: 0,
          regex: c.datasourceRegex.metrics,
        },
        g.dashboard.variable.datasource.new('traces', 'tempo') + {
          label: 'Trace source',
          regex: c.datasourceRegex.traces,
          refresh: 1,
          hide: 0,
          options: [],
        },
        g.dashboard.variable.query.new('cluster', {
          query: ('label_values(openshell_server_readiness_database_healthy{' + q.metricsSelector + '}, ' + q.metricsClusterLabel + ')'),
          refId: 'clusterVariableQuery',
        }) + {
          label: 'Cluster',
          datasource: {
            type: 'prometheus',
            uid: '${metrics}',
          },
          definition: ('label_values(openshell_server_readiness_database_healthy{' + q.metricsSelector + '}, ' + q.metricsClusterLabel + ')'),
          refresh: 1,
          sort: 1,
          multi: true,
          includeAll: true,
          allValue: '.*',
          current: {
            text: 'All',
            value: '$__all',
          },
          options: [],
        },
        g.dashboard.variable.query.new('instance', {
          query: ('label_values(openshell_server_readiness_database_healthy{' + q.metricsClusterScope + '}, ' + q.metricsInstanceLabel + ')'),
          refId: 'instanceVariableQuery',
        }) + {
          label: 'Gateway target',
          datasource: {
            type: 'prometheus',
            uid: '${metrics}',
          },
          definition: ('label_values(openshell_server_readiness_database_healthy{' + q.metricsClusterScope + '}, ' + q.metricsInstanceLabel + ')'),
          refresh: 1,
          sort: 1,
          multi: true,
          includeAll: true,
          allValue: '.*',
          current: {
            text: 'All',
            value: '$__all',
          },
          options: [],
        },
      ] if c.tracesEnabled || v.name != 'traces'])
      + g.dashboard.withPanels([
        (g.panel.text.new('Read this dashboard') + { datasource:: null }
         + g.panel.text.panelOptions.withGridPos(h=5, w=24, x=0, y=0)
         + {
           id: 1,
           options: {
             mode: 'markdown',
             content: '**OpenShell operational health**  \nOpenShell-emitted health metrics: database readiness, completed RPC/HTTP throughput and latency, routed attempt outcomes, supervisor sessions, relay pressure, and mutation locks. **No observations is not a healthy zero.** RPC counts represent completed requests; streaming calls contribute when they end. Routed retries count as separate attempts. No collector, backend, scrape-generated availability, or Kubernetes metrics are included. The tracing section searches gateway spans in the selected datasource and cluster; click a trace ID to inspect it. Gateway target filters apply only to metrics.',
           },
         }),
        (g.panel.stat.new('Mean database probe latency')
         + g.panel.stat.panelOptions.withGridPos(h=4, w=4, x=0, y=5)
         + g.panel.stat.panelOptions.withDescription('Mean database probe duration across selected gateway replicas, weighted by probe count. No completed probes means no observations.')
         + g.panel.stat.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.stat.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('sum(rate(openshell_server_readiness_database_probe_duration_seconds_sum{' + q.metricsScope + '}[$__rate_interval])) / (sum(rate(openshell_server_readiness_database_probe_duration_seconds_count{' + q.metricsScope + '}[$__rate_interval])) > 0)')) + {
             refId: 'A',
             legendFormat: '',
             range: false,
             instant: true,
             editorMode: 'code',
           },
         ])
         + {
           id: 2,
           fieldConfig: {
             defaults: {
               unit: 's',
               noValue: 'No observations',
               color: {
                 mode: 'thresholds',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'blue',
                     value: null,
                   },
                 ],
               },
               mappings: [
                 {
                   type: 'special',
                   options: {
                     match: 'null',
                     result: {
                       text: 'No observations',
                       color: 'gray',
                     },
                   },
                 },
               ],
             },
             overrides: [],
           },
           options: {
             reduceOptions: {
               calcs: [
                 'lastNotNull',
               ],
               fields: '',
               values: false,
             },
             orientation: 'auto',
             textMode: 'auto',
             colorMode: 'value',
             graphMode: 'none',
             justifyMode: 'auto',
           },
         }),
        (g.panel.stat.new('Database ready')
         + g.panel.stat.panelOptions.withGridPos(h=4, w=4, x=4, y=5)
         + g.panel.stat.panelOptions.withDescription('Minimum database readiness across selected targets. Does not represent Kubernetes Deployment/StatefulSet readiness.')
         + g.panel.stat.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.stat.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('min(openshell_server_readiness_database_healthy{' + q.metricsScope + '})')) + {
             refId: 'A',
             legendFormat: '',
             range: false,
             instant: true,
             editorMode: 'code',
           },
         ])
         + {
           id: 3,
           fieldConfig: {
             defaults: {
               unit: 'short',
               noValue: 'No observations',
               color: {
                 mode: 'thresholds',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'red',
                     value: null,
                   },
                   {
                     color: 'green',
                     value: 1,
                   },
                 ],
               },
               mappings: [
                 {
                   type: 'value',
                   options: {
                     '0': {
                       text: 'NOT READY',
                       color: 'red',
                     },
                     '1': {
                       text: 'READY',
                       color: 'green',
                     },
                   },
                 },
                 {
                   type: 'special',
                   options: {
                     match: 'null',
                     result: {
                       text: 'NO DATA',
                       color: 'gray',
                     },
                   },
                 },
               ],
             },
             overrides: [],
           },
           options: {
             reduceOptions: {
               calcs: [
                 'lastNotNull',
               ],
               fields: '',
               values: false,
             },
             orientation: 'auto',
             textMode: 'auto',
             colorMode: 'value',
             graphMode: 'none',
             justifyMode: 'auto',
           },
         }),
        (g.panel.stat.new('Supervisor sessions')
         + g.panel.stat.panelOptions.withGridPos(h=4, w=4, x=8, y=5)
         + g.panel.stat.panelOptions.withDescription('Active supervisor control sessions on selected gateway replicas. This is not a count of sandboxes or users. Zero can be legitimate.')
         + g.panel.stat.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.stat.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('sum(openshell_server_supervisor_sessions{' + q.metricsScope + '})')) + {
             refId: 'A',
             legendFormat: '',
             range: false,
             instant: true,
             editorMode: 'code',
           },
         ])
         + {
           id: 4,
           fieldConfig: {
             defaults: {
               unit: 'short',
               noValue: 'No observations',
               color: {
                 mode: 'thresholds',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'blue',
                     value: null,
                   },
                 ],
               },
             },
             overrides: [],
           },
           options: {
             reduceOptions: {
               calcs: [
                 'lastNotNull',
               ],
               fields: '',
               values: false,
             },
             orientation: 'auto',
             textMode: 'auto',
             colorMode: 'value',
             graphMode: 'none',
             justifyMode: 'auto',
           },
         }),
        (g.panel.stat.new('Completed RPCs / sec')
         + g.panel.stat.panelOptions.withGridPos(h=4, w=4, x=12, y=5)
         + g.panel.stat.panelOptions.withDescription('Completed RPCs per second, including internal and supervisor calls. Streaming calls are counted when they end.')
         + g.panel.stat.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.stat.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('sum(rate(openshell_server_grpc_requests_total{' + q.metricsScope + '}[$__rate_interval]))')) + {
             refId: 'A',
             legendFormat: '',
             range: false,
             instant: true,
             editorMode: 'code',
           },
         ])
         + {
           id: 5,
           fieldConfig: {
             defaults: {
               unit: 'reqps',
               noValue: 'No observations',
               color: {
                 mode: 'thresholds',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'blue',
                     value: null,
                   },
                 ],
               },
             },
             overrides: [],
           },
           options: {
             reduceOptions: {
               calcs: [
                 'lastNotNull',
               ],
               fields: '',
               values: false,
             },
             orientation: 'auto',
             textMode: 'auto',
             colorMode: 'value',
             graphMode: 'none',
             justifyMode: 'auto',
           },
         }),
        (g.panel.stat.new('Service-side failure ratio')
         + g.panel.stat.panelOptions.withGridPos(h=4, w=4, x=16, y=5)
         + g.panel.stat.panelOptions.withDescription('Fraction of completed RPCs with codes 2,4,8,10,12,13,14,15. Expected caller/authentication errors are excluded. Thresholds are provisional, not SLOs.')
         + g.panel.stat.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.stat.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('(sum(rate(openshell_server_grpc_requests_total{' + q.metricsScope + ',code=~"2|4|8|10|12|13|14|15"}[$__rate_interval])) or (0 * sum(rate(openshell_server_grpc_requests_total{' + q.metricsScope + '}[$__rate_interval])))) / clamp_min(sum(rate(openshell_server_grpc_requests_total{' + q.metricsScope + '}[$__rate_interval])), 0.000001)')) + {
             refId: 'A',
             legendFormat: '',
             range: false,
             instant: true,
             editorMode: 'code',
           },
         ])
         + {
           id: 6,
           fieldConfig: {
             defaults: {
               unit: 'percentunit',
               noValue: 'No observations',
               color: {
                 mode: 'thresholds',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                   {
                     color: 'yellow',
                     value: 0.01,
                   },
                   {
                     color: 'red',
                     value: 0.05,
                   },
                 ],
               },
             },
             overrides: [],
           },
           options: {
             reduceOptions: {
               calcs: [
                 'lastNotNull',
               ],
               fields: '',
               values: false,
             },
             orientation: 'auto',
             textMode: 'auto',
             colorMode: 'value',
             graphMode: 'none',
             justifyMode: 'auto',
           },
         }),
        (g.panel.stat.new('Relay capacity used')
         + g.panel.stat.panelOptions.withGridPos(h=4, w=4, x=20, y=5)
         + g.panel.stat.panelOptions.withDescription('Highest pending-relay occupancy across selected replicas. Thresholds of 70% and 90% are provisional.')
         + g.panel.stat.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.stat.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('max(openshell_server_relay_pending{' + q.metricsScope + '} / clamp_min(openshell_server_relay_pending_capacity{' + q.metricsScope + '}, 1))')) + {
             refId: 'A',
             legendFormat: '',
             range: false,
             instant: true,
             editorMode: 'code',
           },
         ])
         + {
           id: 7,
           fieldConfig: {
             defaults: {
               unit: 'percentunit',
               noValue: 'No observations',
               color: {
                 mode: 'thresholds',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                   {
                     color: 'yellow',
                     value: 0.7,
                   },
                   {
                     color: 'red',
                     value: 0.9,
                   },
                 ],
               },
             },
             overrides: [],
           },
           options: {
             reduceOptions: {
               calcs: [
                 'lastNotNull',
               ],
               fields: '',
               values: false,
             },
             orientation: 'auto',
             textMode: 'auto',
             colorMode: 'value',
             graphMode: 'none',
             justifyMode: 'auto',
           },
         }),
        (g.panel.row.new('Traffic, latency and readiness') + {
           id: 8,
           collapsed: false,
           gridPos: {
             x: 0,
             y: 9,
             w: 24,
             h: 1,
           },
           panels: [],
         }),
        (g.panel.timeSeries.new('Completed RPCs by method')
         + g.panel.timeSeries.panelOptions.withGridPos(h=7, w=12, x=0, y=10)
         + g.panel.timeSeries.panelOptions.withDescription('Completed RPCs per second, grouped by method across selected gateway replicas. Streaming calls are counted when they end.')
         + g.panel.timeSeries.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('sum by (method) (rate(openshell_server_grpc_requests_total{' + q.metricsScope + '}[$__rate_interval]))')) + {
             refId: 'A',
             legendFormat: '{{method}}',
             range: true,
             instant: false,
             editorMode: 'code',
           },
         ])
         + {
           id: 9,
           fieldConfig: {
             defaults: {
               unit: 'reqps',
               noValue: 'No observations',
               color: {
                 mode: 'palette-classic',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                 ],
               },
               custom: {
                 drawStyle: 'line',
                 lineInterpolation: 'linear',
                 lineWidth: 1,
                 fillOpacity: 8,
                 showPoints: 'never',
                 spanNulls: false,
                 axisPlacement: 'auto',
               },
             },
             overrides: [],
           },
           options: {
             tooltip: {
               mode: 'multi',
               sort: 'desc',
             },
             legend: {
               displayMode: 'list',
               placement: 'bottom',
               showLegend: true,
               calcs: [],
             },
           },
         }),
        (g.panel.timeSeries.new('Mean completed RPC latency by method')
         + g.panel.timeSeries.panelOptions.withGridPos(h=7, w=12, x=12, y=10)
         + g.panel.timeSeries.panelOptions.withDescription('Mean duration of completed RPCs by method, calculated from summed durations and counts across selected replicas. Streaming durations include the full session lifetime. This is a mean, not p95 or p99; no completed calls means no observations.')
         + g.panel.timeSeries.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('sum by (method) (rate(openshell_server_grpc_request_duration_seconds_sum{' + q.metricsScope + '}[$__rate_interval])) / (sum by (method) (rate(openshell_server_grpc_request_duration_seconds_count{' + q.metricsScope + '}[$__rate_interval])) > 0)')) + {
             refId: 'A',
             legendFormat: '{{method}}',
             range: true,
             instant: false,
             editorMode: 'code',
           },
         ])
         + {
           id: 10,
           fieldConfig: {
             defaults: {
               unit: 's',
               noValue: 'No observations',
               color: {
                 mode: 'palette-classic',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                 ],
               },
               custom: {
                 drawStyle: 'line',
                 lineInterpolation: 'linear',
                 lineWidth: 1,
                 fillOpacity: 8,
                 showPoints: 'never',
                 spanNulls: false,
                 axisPlacement: 'auto',
               },
             },
             overrides: [],
           },
           options: {
             tooltip: {
               mode: 'multi',
               sort: 'desc',
             },
             legend: {
               displayMode: 'list',
               placement: 'bottom',
               showLegend: true,
               calcs: [],
             },
           },
         }),
        (g.panel.timeSeries.new('Non-OK RPC outcomes')
         + g.panel.timeSeries.panelOptions.withGridPos(h=7, w=12, x=0, y=17)
         + g.panel.timeSeries.panelOptions.withDescription('Includes caller and auth errors as well as service failures. Codes: 1 cancelled, 2 unknown, 3 invalid argument, 4 deadline, 5 not found, 6 exists, 7 denied, 8 exhausted, 9 precondition, 10 aborted, 11 range, 12 unimplemented, 13 internal, 14 unavailable, 15 data loss, 16 unauthenticated.')
         + g.panel.timeSeries.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('sum by (method, code) (rate(openshell_server_grpc_requests_total{' + q.metricsScope + ',code!="0"}[$__rate_interval]))')) + {
             refId: 'A',
             legendFormat: '{{method}} · code {{code}}',
             range: true,
             instant: false,
             editorMode: 'code',
           },
         ])
         + {
           id: 11,
           fieldConfig: {
             defaults: {
               unit: 'reqps',
               noValue: 'No observations',
               color: {
                 mode: 'palette-classic',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                 ],
               },
               custom: {
                 drawStyle: 'line',
                 lineInterpolation: 'linear',
                 lineWidth: 1,
                 fillOpacity: 8,
                 showPoints: 'never',
                 spanNulls: false,
                 axisPlacement: 'auto',
               },
             },
             overrides: [],
           },
           options: {
             tooltip: {
               mode: 'multi',
               sort: 'desc',
             },
             legend: {
               displayMode: 'list',
               placement: 'bottom',
               showLegend: true,
               calcs: [],
             },
           },
         }),
        (g.panel.timeSeries.new('Database readiness and supervisor sessions')
         + g.panel.timeSeries.panelOptions.withGridPos(h=7, w=12, x=12, y=17)
         + g.panel.timeSeries.panelOptions.withDescription('Gateway-reported state. Sessions are not sandbox inventory; database readiness is not pod readiness.')
         + g.panel.timeSeries.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('min(openshell_server_readiness_database_healthy{' + q.metricsScope + '})')) + {
             refId: 'A',
             legendFormat: 'Database ready (0/1)',
             range: true,
             instant: false,
             editorMode: 'code',
           },
           g.query.prometheus.new('${metrics}', ('sum(openshell_server_supervisor_sessions{' + q.metricsScope + '})')) + {
             refId: 'B',
             legendFormat: 'Supervisor sessions',
             range: true,
             instant: false,
             editorMode: 'code',
           },
         ])
         + {
           id: 12,
           fieldConfig: {
             defaults: {
               unit: 'short',
               noValue: 'No observations',
               color: {
                 mode: 'palette-classic',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                 ],
               },
               custom: {
                 drawStyle: 'line',
                 lineInterpolation: 'linear',
                 lineWidth: 1,
                 fillOpacity: 8,
                 showPoints: 'never',
                 spanNulls: false,
                 axisPlacement: 'auto',
               },
             },
             overrides: [],
           },
           options: {
             tooltip: {
               mode: 'multi',
               sort: 'desc',
             },
             legend: {
               displayMode: 'list',
               placement: 'bottom',
               showLegend: true,
               calcs: [],
             },
           },
         }),
        (g.panel.row.new('HTTP traffic, latency and outcomes') + {
           id: 21,
           collapsed: false,
           panels: [],
           gridPos: {
             x: 0,
             y: 24,
             w: 24,
             h: 1,
           },
         }),
        (g.panel.timeSeries.new('HTTP requests by path')
         + g.panel.timeSeries.panelOptions.withGridPos(h=7, w=12, x=0, y=25)
         + g.panel.timeSeries.panelOptions.withDescription("HTTP requests per second, grouped by the gateway's path label. gRPC traffic is shown separately. An unknown path cannot be attributed to a specific endpoint. Missing series appear as No observations.")
         + g.panel.timeSeries.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('sum by (path) (rate(openshell_server_http_requests_total{' + q.metricsScope + '}[$__rate_interval]))')) + {
             refId: 'A',
             legendFormat: '{{path}}',
             range: true,
             instant: false,
             editorMode: 'code',
           },
         ])
         + {
           id: 22,
           fieldConfig: {
             defaults: {
               unit: 'reqps',
               noValue: 'No observations',
               color: {
                 mode: 'palette-classic',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                 ],
               },
               custom: {
                 drawStyle: 'line',
                 lineInterpolation: 'linear',
                 lineWidth: 1,
                 fillOpacity: 8,
                 showPoints: 'never',
                 spanNulls: false,
                 axisPlacement: 'auto',
               },
             },
             overrides: [],
           },
           options: {
             tooltip: {
               mode: 'multi',
               sort: 'desc',
             },
             legend: {
               displayMode: 'list',
               placement: 'bottom',
               showLegend: true,
               calcs: [],
             },
           },
         }),
        (g.panel.timeSeries.new('Mean HTTP latency by path and status')
         + g.panel.timeSeries.panelOptions.withGridPos(h=7, w=12, x=12, y=25)
         + g.panel.timeSeries.panelOptions.withDescription('Mean HTTP request duration by path and response status, calculated from summed durations and counts across selected replicas. This is a mean, not p95 or p99; no new duration observations means no mean is available.')
         + g.panel.timeSeries.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('sum by (path, status) (rate(openshell_server_http_request_duration_seconds_sum{' + q.metricsScope + '}[$__rate_interval])) / (sum by (path, status) (rate(openshell_server_http_request_duration_seconds_count{' + q.metricsScope + '}[$__rate_interval])) > 0)')) + {
             refId: 'A',
             legendFormat: '{{path}} · HTTP {{status}}',
             range: true,
             instant: false,
             editorMode: 'code',
           },
         ])
         + {
           id: 23,
           fieldConfig: {
             defaults: {
               unit: 's',
               noValue: 'No observations',
               color: {
                 mode: 'palette-classic',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                 ],
               },
               custom: {
                 drawStyle: 'line',
                 lineInterpolation: 'linear',
                 lineWidth: 1,
                 fillOpacity: 8,
                 showPoints: 'never',
                 spanNulls: false,
                 axisPlacement: 'auto',
               },
             },
             overrides: [],
           },
           options: {
             tooltip: {
               mode: 'multi',
               sort: 'desc',
             },
             legend: {
               displayMode: 'list',
               placement: 'bottom',
               showLegend: true,
               calcs: [],
             },
           },
         }),
        (g.panel.timeSeries.new('HTTP client and server errors')
         + g.panel.timeSeries.panelOptions.withGridPos(h=7, w=24, x=0, y=32)
         + g.panel.timeSeries.panelOptions.withDescription('4xx caller/authentication responses and 5xx server responses are shown separately. Expected denials, bad requests and not-found responses are not automatically platform availability failures. Redirects are not classified as errors.')
         + g.panel.timeSeries.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('sum by (path, status) (rate(openshell_server_http_requests_total{' + q.metricsScope + ',status=~"4.."}[$__rate_interval]))')) + {
             refId: 'A',
             legendFormat: 'Client/auth · {{path}} · HTTP {{status}}',
             range: true,
             instant: false,
             editorMode: 'code',
           },
           g.query.prometheus.new('${metrics}', ('sum by (path, status) (rate(openshell_server_http_requests_total{' + q.metricsScope + ',status=~"5.."}[$__rate_interval]))')) + {
             refId: 'B',
             legendFormat: 'Server · {{path}} · HTTP {{status}}',
             range: true,
             instant: false,
             editorMode: 'code',
           },
         ])
         + {
           id: 24,
           fieldConfig: {
             defaults: {
               unit: 'reqps',
               noValue: 'No observations',
               color: {
                 mode: 'palette-classic',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                 ],
               },
               custom: {
                 drawStyle: 'line',
                 lineInterpolation: 'linear',
                 lineWidth: 1,
                 fillOpacity: 8,
                 showPoints: 'never',
                 spanNulls: false,
                 axisPlacement: 'auto',
               },
             },
             overrides: [],
           },
           options: {
             tooltip: {
               mode: 'multi',
               sort: 'desc',
             },
             legend: {
               displayMode: 'list',
               placement: 'bottom',
               showLegend: true,
               calcs: [],
             },
           },
         }),
        (g.panel.row.new('Local and peer routing attempts') + {
           id: 25,
           collapsed: false,
           panels: [],
           gridPos: {
             x: 0,
             y: 39,
             w: 24,
             h: 1,
           },
         }),
        (g.panel.timeSeries.new('Routed attempts by operation and route')
         + g.panel.timeSeries.panelOptions.withGridPos(h=7, w=12, x=0, y=40)
         + g.panel.timeSeries.panelOptions.withDescription('Local relay setup and outbound peer attempts completed or cancelled by each replica. Each retry counts separately: attempts are not unique logical requests or end-to-end sandbox operations.')
         + g.panel.timeSeries.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('sum by (operation, route, relay_kind) (rate(openshell_server_routed_request_attempts_total{' + q.metricsScope + '}[$__rate_interval]))')) + {
             refId: 'A',
             legendFormat: '{{operation}} · {{route}} · {{relay_kind}}',
             range: true,
             instant: false,
             editorMode: 'code',
           },
         ])
         + {
           id: 26,
           fieldConfig: {
             defaults: {
               unit: 'reqps',
               noValue: 'No observations',
               color: {
                 mode: 'palette-classic',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                 ],
               },
               custom: {
                 drawStyle: 'line',
                 lineInterpolation: 'linear',
                 lineWidth: 1,
                 fillOpacity: 8,
                 showPoints: 'never',
                 spanNulls: false,
                 axisPlacement: 'auto',
               },
             },
             overrides: [],
           },
           options: {
             tooltip: {
               mode: 'multi',
               sort: 'desc',
             },
             legend: {
               displayMode: 'list',
               placement: 'bottom',
               showLegend: true,
               calcs: [],
             },
           },
         }),
        (g.panel.timeSeries.new('Routed attempt outcomes')
         + g.panel.timeSeries.panelOptions.withGridPos(h=7, w=12, x=12, y=40)
         + g.panel.timeSeries.panelOptions.withDescription('Local and peer routing attempts grouped by outcome and gRPC status. Cancellations and caller errors are included. Each retry counts separately, so a failed attempt may be followed by a successful retry.')
         + g.panel.timeSeries.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('sum by (operation, route, outcome, grpc_code) (rate(openshell_server_routed_request_attempts_total{' + q.metricsScope + '}[$__rate_interval]))')) + {
             refId: 'A',
             legendFormat: '{{operation}} · {{route}} · {{outcome}} · {{grpc_code}}',
             range: true,
             instant: false,
             editorMode: 'code',
           },
         ])
         + {
           id: 27,
           fieldConfig: {
             defaults: {
               unit: 'reqps',
               noValue: 'No observations',
               color: {
                 mode: 'palette-classic',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                 ],
               },
               custom: {
                 drawStyle: 'line',
                 lineInterpolation: 'linear',
                 lineWidth: 1,
                 fillOpacity: 8,
                 showPoints: 'never',
                 spanNulls: false,
                 axisPlacement: 'auto',
               },
             },
             overrides: [],
           },
           options: {
             tooltip: {
               mode: 'multi',
               sort: 'desc',
             },
             legend: {
               displayMode: 'list',
               placement: 'bottom',
               showLegend: true,
               calcs: [],
             },
           },
         }),
        (g.panel.row.new('Relay and mutation pressure') + {
           id: 13,
           collapsed: false,
           gridPos: {
             x: 0,
             y: 47,
             w: 24,
             h: 1,
           },
           panels: [],
         }),
        (g.panel.timeSeries.new('Pending relay channels and capacity')
         + g.panel.timeSeries.panelOptions.withGridPos(h=7, w=12, x=0, y=48)
         + g.panel.timeSeries.panelOptions.withDescription('Channels waiting for supervisor callback; summed across selected replicas.')
         + g.panel.timeSeries.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('sum(openshell_server_relay_pending{' + q.metricsScope + '})')) + {
             refId: 'A',
             legendFormat: 'Pending',
             range: true,
             instant: false,
             editorMode: 'code',
           },
           g.query.prometheus.new('${metrics}', ('sum(openshell_server_relay_pending_capacity{' + q.metricsScope + '})')) + {
             refId: 'B',
             legendFormat: 'Capacity',
             range: true,
             instant: false,
             editorMode: 'code',
           },
         ])
         + {
           id: 14,
           fieldConfig: {
             defaults: {
               unit: 'short',
               noValue: 'No observations',
               color: {
                 mode: 'palette-classic',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                 ],
               },
               custom: {
                 drawStyle: 'line',
                 lineInterpolation: 'linear',
                 lineWidth: 1,
                 fillOpacity: 8,
                 showPoints: 'never',
                 spanNulls: false,
                 axisPlacement: 'auto',
               },
             },
             overrides: [],
           },
           options: {
             tooltip: {
               mode: 'multi',
               sort: 'desc',
             },
             legend: {
               displayMode: 'list',
               placement: 'bottom',
               showLegend: true,
               calcs: [],
             },
           },
         }),
        (g.panel.timeSeries.new('Relay expirations and rejections')
         + g.panel.timeSeries.panelOptions.withGridPos(h=7, w=12, x=12, y=48)
         + g.panel.timeSeries.panelOptions.withDescription('Relay expirations and rejections per second across selected gateway replicas. Rejections are grouped by reason. These counts describe relay setup failures, not unique failed sandbox operations.')
         + g.panel.timeSeries.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('sum(rate(openshell_server_relay_expired_total{' + q.metricsScope + '}[$__rate_interval]))')) + {
             refId: 'A',
             legendFormat: 'Expired',
             range: true,
             instant: false,
             editorMode: 'code',
           },
           g.query.prometheus.new('${metrics}', ('sum by (reason) (rate(openshell_server_relay_rejected_total{' + q.metricsScope + '}[$__rate_interval]))')) + {
             refId: 'B',
             legendFormat: 'Rejected · {{reason}}',
             range: true,
             instant: false,
             editorMode: 'code',
           },
         ])
         + {
           id: 15,
           fieldConfig: {
             defaults: {
               unit: 'ops',
               noValue: 'No observations',
               color: {
                 mode: 'palette-classic',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                 ],
               },
               custom: {
                 drawStyle: 'line',
                 lineInterpolation: 'linear',
                 lineWidth: 1,
                 fillOpacity: 8,
                 showPoints: 'never',
                 spanNulls: false,
                 axisPlacement: 'auto',
               },
             },
             overrides: [],
           },
           options: {
             tooltip: {
               mode: 'multi',
               sort: 'desc',
             },
             legend: {
               displayMode: 'list',
               placement: 'bottom',
               showLegend: true,
               calcs: [],
             },
           },
         }),
        (g.panel.timeSeries.new('Mutation lock wait p95')
         + g.panel.timeSeries.panelOptions.withGridPos(h=7, w=8, x=0, y=55)
         + g.panel.timeSeries.panelOptions.withDescription('95th percentile of mutation lock wait time, calculated from histogram buckets across selected replicas. No lock observations in the rate window means no observations.')
         + g.panel.timeSeries.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('histogram_quantile(0.95, sum by (le, scope) (rate(openshell_server_mutation_lock_wait_seconds_bucket{' + q.metricsScope + '}[$__rate_interval])))')) + {
             refId: 'A',
             legendFormat: '{{scope}}',
             range: true,
             instant: false,
             editorMode: 'code',
           },
         ])
         + {
           id: 16,
           fieldConfig: {
             defaults: {
               unit: 's',
               noValue: 'No observations',
               color: {
                 mode: 'palette-classic',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                 ],
               },
               custom: {
                 drawStyle: 'line',
                 lineInterpolation: 'linear',
                 lineWidth: 1,
                 fillOpacity: 8,
                 showPoints: 'never',
                 spanNulls: false,
                 axisPlacement: 'auto',
               },
             },
             overrides: [],
           },
           options: {
             tooltip: {
               mode: 'multi',
               sort: 'desc',
             },
             legend: {
               displayMode: 'list',
               placement: 'bottom',
               showLegend: true,
               calcs: [],
             },
           },
         }),
        (g.panel.timeSeries.new('Mutation lock hold p95')
         + g.panel.timeSeries.panelOptions.withGridPos(h=7, w=8, x=8, y=55)
         + g.panel.timeSeries.panelOptions.withDescription('95th percentile of mutation lock hold time, calculated from histogram buckets across selected replicas. Includes locks released after cancellation.')
         + g.panel.timeSeries.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('histogram_quantile(0.95, sum by (le, scope) (rate(openshell_server_mutation_lock_hold_seconds_bucket{' + q.metricsScope + '}[$__rate_interval])))')) + {
             refId: 'A',
             legendFormat: '{{scope}}',
             range: true,
             instant: false,
             editorMode: 'code',
           },
         ])
         + {
           id: 17,
           fieldConfig: {
             defaults: {
               unit: 's',
               noValue: 'No observations',
               color: {
                 mode: 'palette-classic',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                 ],
               },
               custom: {
                 drawStyle: 'line',
                 lineInterpolation: 'linear',
                 lineWidth: 1,
                 fillOpacity: 8,
                 showPoints: 'never',
                 spanNulls: false,
                 axisPlacement: 'auto',
               },
             },
             overrides: [],
           },
           options: {
             tooltip: {
               mode: 'multi',
               sort: 'desc',
             },
             legend: {
               displayMode: 'list',
               placement: 'bottom',
               showLegend: true,
               calcs: [],
             },
           },
         }),
        (g.panel.timeSeries.new('Mutation failures and deadline-scan skips')
         + g.panel.timeSeries.panelOptions.withGridPos(h=7, w=8, x=16, y=55)
         + g.panel.timeSeries.panelOptions.withDescription('A skipped scan indicates busy mutation locks; it is not itself a sandbox provisioning timeout.')
         + g.panel.timeSeries.queryOptions.withDatasource('prometheus', '${metrics}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.prometheus.new('${metrics}', ('sum by (scope) (rate(openshell_server_mutation_lock_errors_total{' + q.metricsScope + '}[$__rate_interval]))')) + {
             refId: 'A',
             legendFormat: 'Lock error · {{scope}}',
             range: true,
             instant: false,
             editorMode: 'code',
           },
           g.query.prometheus.new('${metrics}', ('sum by (scope) (rate(openshell_server_mutation_lock_timeouts_total{' + q.metricsScope + '}[$__rate_interval]))')) + {
             refId: 'B',
             legendFormat: 'Lock timeout · {{scope}}',
             range: true,
             instant: false,
             editorMode: 'code',
           },
           g.query.prometheus.new('${metrics}', ('sum by (scope) (rate(openshell_server_provisioning_deadline_skips_total{' + q.metricsScope + '}[$__rate_interval]))')) + {
             refId: 'C',
             legendFormat: 'Deadline scan skipped · {{scope}}',
             range: true,
             instant: false,
             editorMode: 'code',
           },
         ])
         + {
           id: 18,
           fieldConfig: {
             defaults: {
               unit: 'ops',
               noValue: 'No observations',
               color: {
                 mode: 'palette-classic',
               },
               thresholds: {
                 mode: 'absolute',
                 steps: [
                   {
                     color: 'green',
                     value: null,
                   },
                 ],
               },
               custom: {
                 drawStyle: 'line',
                 lineInterpolation: 'linear',
                 lineWidth: 1,
                 fillOpacity: 8,
                 showPoints: 'never',
                 spanNulls: false,
                 axisPlacement: 'auto',
               },
             },
             overrides: [],
           },
           options: {
             tooltip: {
               mode: 'multi',
               sort: 'desc',
             },
             legend: {
               displayMode: 'list',
               placement: 'bottom',
               showLegend: true,
               calcs: [],
             },
           },
         }),
      ] + (if c.tracesEnabled then [
             (g.panel.row.new('Gateway tracing') + {
                id: 19,
                collapsed: false,
                gridPos: {
                  x: 0,
                  y: 62,
                  w: 24,
                  h: 1,
                },
                panels: [],
              }),
             (g.panel.table.new('OpenShell gateway traces')
              + g.panel.table.panelOptions.withGridPos(h=10, w=24, x=0, y=63)
              + g.panel.table.panelOptions.withDescription('Up to 20 matching gateway traces in the selected datasource, cluster, and dashboard time range. Click a trace ID to inspect its spans in Explore. Gateway target is a metric scrape address and does not filter traces. Missing results do not indicate gateway health.')
              + g.panel.table.queryOptions.withDatasource('tempo', '${traces}')
              + g.panel.table.queryOptions.withTargets([
                g.query.tempo.withQuery(('{resource.service.name = ' + q.tracesService + ' && ' + q.tracesClusterAttribute + ' =~ "${cluster:regex}"}')) + {
                  refId: 'A',
                  queryType: 'traceql',
                  tableType: 'traces',
                  limit: 20,
                },
              ])
              + {
                id: 20,
                transformations: [
                  {
                    id: 'organize',
                    options: {
                      excludeByName: {
                        nested: true,
                      },
                      indexByName: {
                        startTime: 0,
                        traceService: 1,
                        traceName: 2,
                        traceDuration: 3,
                        traceID: 4,
                      },
                    },
                  },
                ],
                fieldConfig: {
                  defaults: {},
                  overrides: [],
                },
                options: {
                  showHeader: true,
                  cellHeight: 'sm',
                  sortBy: [
                    {
                      displayName: 'Start time',
                      desc: true,
                    },
                  ],
                },
              }),
           ] else []), setPanelIDs=false),
  },
}
