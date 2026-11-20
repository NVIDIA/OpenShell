// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

local queries = import '../queries.libsonnet';
local g = import 'github.com/grafana/grafonnet/gen/grafonnet-latest/main.libsonnet';
{
  local c = self._config.openshell,
  local q = queries.new(c),
  grafanaDashboards+:: {
    'openshell-operational-logs.json':
      g.dashboard.new('OpenShell / Operational logs')
      + {
        id: null,
        description: 'Gateway, supervisor, and workload pod logs from Loki. Select a datasource and cluster, then filter by component, pod, stream, or message. Open the OCSF logs dashboard for structured security and audit events.',
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
      }
      + g.dashboard.withVariables([
        g.dashboard.variable.datasource.new('logs', 'loki') + {
          label: 'Logs source',
          regex: c.datasourceRegex.logs,
          refresh: 1,
          hide: 0,
          options: [],
        },
        g.dashboard.variable.query.new('cluster', {
          type: 1,
          label: q.logsClusterLabel,
          stream: ('{' + q.logsNamespaceLabel + '=~' + q.namespaceRegex + '}'),
          refId: 'clusterVariableQuery',
        }) + {
          label: 'Cluster',
          datasource: {
            type: 'loki',
            uid: '${logs}',
          },
          definition: ('label_values({' + q.logsNamespaceLabel + '=~' + q.namespaceRegex + '}, ' + q.logsClusterLabel + ')'),
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
        g.dashboard.variable.custom.new('component', [
          'openshell-gateway',
          'supervisor',
          'agent',
          'gateway',
        ]) + {
          label: 'Component',
          query: 'openshell-gateway,supervisor,agent,gateway',
          multi: true,
          includeAll: true,
          allValue: '.*',
          current: {
            text: 'All',
            value: '$__all',
          },
          options: [
            {
              text: 'openshell-gateway',
              value: 'openshell-gateway',
              selected: false,
            },
            {
              text: 'supervisor',
              value: 'supervisor',
              selected: false,
            },
            {
              text: 'agent',
              value: 'agent',
              selected: false,
            },
            {
              selected: false,
              text: 'gateway',
              value: 'gateway',
            },
          ],
        },
        g.dashboard.variable.textbox.new('pod', '.*') + {
          label: 'Pod name (regex)',
          current: {
            text: '.*',
            value: '.*',
          },
          options: [
            {
              text: '.*',
              value: '.*',
              selected: true,
            },
          ],
        },
        g.dashboard.variable.custom.new('stream', [
          'stdout',
          'stderr',
        ]) + {
          label: 'Stream',
          query: 'stdout,stderr',
          multi: true,
          includeAll: true,
          allValue: '.*',
          current: {
            text: 'All',
            value: '$__all',
          },
          options: [
            {
              text: 'stdout',
              value: 'stdout',
              selected: false,
            },
            {
              text: 'stderr',
              value: 'stderr',
              selected: false,
            },
          ],
        },
        g.dashboard.variable.textbox.new('search', '') + {
          label: 'Message search (regex)',
          current: {
            text: '',
            value: '',
          },
          options: [
            {
              text: '',
              value: '',
              selected: true,
            },
          ],
        },
      ])
      + g.dashboard.withPanels([
        (g.panel.text.new('Operational diagnostics') + { datasource:: null }
         + g.panel.text.panelOptions.withGridPos(h=3, w=24, x=0, y=0)
         + {
           id: 1,
           options: {
             mode: 'markdown',
             content: 'Components: **openshell-gateway** (gateway), **supervisor** (sandbox supervisor), **agent** (sandbox main-process stdout/stderr). Expand a line for pod/container metadata. OCSF JSON and shorthand console events are excluded; open **OCSF logs** in the OpenShell dashboards menu for audit events.\n\nSelect the Loki datasource and cluster to inspect. Regex text filters default to `.*`; do not include backticks. Separate exec/PTY output may not appear in pod logs. Log volume and stderr are not health or error classifications.',
           },
         }),
        (g.panel.stat.new('Log lines in selected range')
         + g.panel.stat.panelOptions.withGridPos(h=5, w=6, x=0, y=3)
         + g.panel.stat.queryOptions.withDatasource('loki', '${logs}')
         + g.panel.stat.queryOptions.withTargets([
           g.query.loki.new('${logs}', ('sum(count_over_time({' + q.logsScope + ',service_name=~"openshell-gateway|supervisor|agent"} | service_name=~"${component:regex}" | log_kind!="ocsf" !~ ` OCSF(-JSON)? ` | k8s_pod_name=~`${pod:raw}` | log_iostream=~"${stream:regex}" |~ `${search:raw}` [$__range]))')) + {
             refId: 'A',
             queryType: 'instant',
             editorMode: 'code',
             legendFormat: '',
           },
         ])
         + {
           id: 2,
           fieldConfig: {
             defaults: {
               color: {
                 mode: 'palette-classic',
               },
               unit: 'short',
               noValue: 'No observations',
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
             colorMode: 'none',
             graphMode: 'none',
             textMode: 'auto',
             orientation: 'auto',
           },
         }),
        (g.panel.timeSeries.new('Log rate by component')
         + g.panel.timeSeries.panelOptions.withGridPos(h=5, w=18, x=6, y=3)
         + g.panel.timeSeries.queryOptions.withDatasource('loki', '${logs}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.loki.new('${logs}', ('sum by (service_name) (rate({' + q.logsScope + ',service_name=~"openshell-gateway|supervisor|agent"} | service_name=~"${component:regex}" | log_kind!="ocsf" !~ ` OCSF(-JSON)? ` | k8s_pod_name=~`${pod:raw}` | log_iostream=~"${stream:regex}" |~ `${search:raw}` [$__auto]))')) + {
             refId: 'A',
             queryType: 'range',
             editorMode: 'code',
             legendFormat: '{{service_name}}',
           },
         ])
         + {
           id: 3,
           fieldConfig: {
             defaults: {
               color: {
                 mode: 'palette-classic',
               },
               unit: 'ops',
               noValue: 'No observations',
               custom: {
                 drawStyle: 'line',
                 lineWidth: 1,
                 fillOpacity: 10,
                 showPoints: 'never',
                 spanNulls: false,
               },
             },
             overrides: [],
           },
           options: {
             legend: {
               displayMode: 'list',
               placement: 'bottom',
             },
             tooltip: {
               mode: 'multi',
               sort: 'desc',
             },
           },
         }),
        (g.panel.logs.new('Operational pod logs')
         + g.panel.logs.panelOptions.withGridPos(h=18, w=24, x=0, y=8)
         + g.panel.logs.panelOptions.withDescription('Up to 1,000 matching operational log lines, newest first. Expand a line for pod, component, and stream metadata. OCSF JSON and shorthand console records are excluded. Separate exec or terminal output may not appear in pod logs.')
         + g.panel.logs.queryOptions.withDatasource('loki', '${logs}')
         + g.panel.logs.queryOptions.withTargets([
           g.query.loki.new('${logs}', ('{' + q.logsScope + ',service_name=~"openshell-gateway|supervisor|agent"} | service_name=~"${component:regex}" | log_kind!="ocsf" !~ ` OCSF(-JSON)? ` | k8s_pod_name=~`${pod:raw}` | log_iostream=~"${stream:regex}" |~ `${search:raw}`')) + {
             refId: 'A',
             queryType: 'range',
             editorMode: 'code',
             legendFormat: '',
             maxLines: 1000,
           },
         ])
         + {
           id: 4,
           fieldConfig: {
             defaults: {
               color: {
                 mode: 'palette-classic',
               },
               unit: 'short',
               noValue: 'No observations',
             },
             overrides: [],
           },
           options: {
             showTime: true,
             showLabels: false,
             showCommonLabels: false,
             wrapLogMessage: true,
             prettifyLogMessage: true,
             enableLogDetails: true,
             sortOrder: 'Descending',
             dedupStrategy: 'none',
           },
         }),
      ], setPanelIDs=false),
  },
}
