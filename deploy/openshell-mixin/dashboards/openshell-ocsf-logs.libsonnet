// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

local queries = import '../queries.libsonnet';
local g = import 'github.com/grafana/grafonnet/gen/grafonnet-latest/main.libsonnet';
{
  local c = self._config.openshell,
  local q = queries.new(c),
  grafanaDashboards+:: {
    'openshell-ocsf-logs.json':
      g.dashboard.new('OpenShell / OCSF logs')
      + {
        id: null,
        description: 'Structured gateway and supervisor security and audit events from Loki. Select a datasource and cluster, then filter by sandbox, event class, or severity. Expand an event to inspect its complete OCSF JSON and metadata. Missing events do not establish health.',
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
        g.dashboard.variable.textbox.new('sandbox', '.*') + {
          label: 'Sandbox name (regex)',
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
        g.dashboard.variable.textbox.new('sandbox_id', '.*') + {
          label: 'Sandbox ID (regex)',
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
        g.dashboard.variable.textbox.new('class_uid', '.*') + {
          label: 'OCSF class UID (regex)',
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
        g.dashboard.variable.custom.new('severity', [
          '0',
          '1',
          '2',
          '3',
          '4',
          '5',
          '6',
          '99',
        ]) + {
          label: 'OCSF severity ID',
          query: '0,1,2,3,4,5,6,99',
          multi: true,
          includeAll: true,
          allValue: '.*',
          current: {
            text: 'All',
            value: '$__all',
          },
          options: [
            {
              text: '0',
              value: '0',
              selected: false,
            },
            {
              text: '1',
              value: '1',
              selected: false,
            },
            {
              text: '2',
              value: '2',
              selected: false,
            },
            {
              text: '3',
              value: '3',
              selected: false,
            },
            {
              text: '4',
              value: '4',
              selected: false,
            },
            {
              text: '5',
              value: '5',
              selected: false,
            },
            {
              text: '6',
              value: '6',
              selected: false,
            },
            {
              text: '99',
              value: '99',
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
        (g.panel.text.new('Structured audit events') + { datasource:: null }
         + g.panel.text.panelOptions.withGridPos(h=3, w=24, x=0, y=0)
         + {
           id: 1,
           options: {
             mode: 'markdown',
             content: 'View complete OCSF JSON events; expand a log line for sandbox and Kubernetes metadata. Class IDs are preserved as emitted (including legacy class `0`). Severity IDs: 0 unknown, 1 informational, 2 low, 3 medium, 4 high, 5 critical, 6 fatal, 99 other.\n\nSelect the Loki datasource and cluster to inspect. Regex text filters default to `.*`; do not include backticks. Counts cover the selected time range and filters; absent events do not establish health.',
           },
         }),
        (g.panel.stat.new('OCSF events in selected range')
         + g.panel.stat.panelOptions.withGridPos(h=5, w=6, x=0, y=3)
         + g.panel.stat.queryOptions.withDatasource('loki', '${logs}')
         + g.panel.stat.queryOptions.withTargets([
           g.query.loki.new('${logs}', ('sum(count_over_time({' + q.logsScope + '} | log_kind="ocsf" | sandbox_name=~`${sandbox:raw}` | sandbox_id=~`${sandbox_id:raw}` | ocsf_class_uid=~`${class_uid:raw}` | ocsf_severity_id=~"${severity:regex}" |~ `${search:raw}` [$__range]))')) + {
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
        (g.panel.barGauge.new('Events by severity ID')
         + g.panel.barGauge.panelOptions.withGridPos(h=5, w=18, x=6, y=3)
         + g.panel.barGauge.queryOptions.withDatasource('loki', '${logs}')
         + g.panel.barGauge.queryOptions.withTargets([
           g.query.loki.new('${logs}', ('sum by (ocsf_severity_id) (count_over_time({' + q.logsScope + '} | log_kind="ocsf" | sandbox_name=~`${sandbox:raw}` | sandbox_id=~`${sandbox_id:raw}` | ocsf_class_uid=~`${class_uid:raw}` | ocsf_severity_id=~"${severity:regex}" |~ `${search:raw}` [$__range]))')) + {
             refId: 'A',
             queryType: 'instant',
             editorMode: 'code',
             legendFormat: 'Severity {{ocsf_severity_id}}',
           },
         ])
         + {
           id: 3,
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
             orientation: 'horizontal',
             displayMode: 'basic',
             reduceOptions: {
               calcs: [
                 'lastNotNull',
               ],
               fields: '',
               values: false,
             },
             showUnfilled: true,
           },
         }),
        (g.panel.timeSeries.new('Event rate by OCSF class UID')
         + g.panel.timeSeries.panelOptions.withGridPos(h=7, w=24, x=0, y=8)
         + g.panel.timeSeries.queryOptions.withDatasource('loki', '${logs}')
         + g.panel.timeSeries.queryOptions.withTargets([
           g.query.loki.new('${logs}', ('sum by (ocsf_class_uid) (rate({' + q.logsScope + '} | log_kind="ocsf" | sandbox_name=~`${sandbox:raw}` | sandbox_id=~`${sandbox_id:raw}` | ocsf_class_uid=~`${class_uid:raw}` | ocsf_severity_id=~"${severity:regex}" |~ `${search:raw}` [$__auto]))')) + {
             refId: 'A',
             queryType: 'range',
             editorMode: 'code',
             legendFormat: 'Class {{ocsf_class_uid}}',
           },
         ])
         + {
           id: 4,
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
        (g.panel.logs.new('OCSF event JSON')
         + g.panel.logs.panelOptions.withGridPos(h=15, w=24, x=0, y=15)
         + g.panel.logs.panelOptions.withDescription('Up to 1,000 matching structured OCSF events, newest first. Full JSON is retained; expand a line to inspect metadata. Sandbox fields describe the audited sandbox, not a scrape target.')
         + g.panel.logs.queryOptions.withDatasource('loki', '${logs}')
         + g.panel.logs.queryOptions.withTargets([
           g.query.loki.new('${logs}', ('{' + q.logsScope + '} | log_kind="ocsf" | sandbox_name=~`${sandbox:raw}` | sandbox_id=~`${sandbox_id:raw}` | ocsf_class_uid=~`${class_uid:raw}` | ocsf_severity_id=~"${severity:regex}" |~ `${search:raw}`')) + {
             refId: 'A',
             queryType: 'range',
             editorMode: 'code',
             legendFormat: '',
             maxLines: 1000,
           },
         ])
         + {
           id: 5,
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
