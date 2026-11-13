// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

local g = import 'github.com/grafana/grafonnet/gen/grafonnet-latest/main.libsonnet';
{
  local c = self._config.openshell,
  local dashboards = super.grafanaDashboards,
  grafanaDashboards::: {
    [name]:
      local stem = std.strReplace(name, '.json', '');
      local uid = c.uidPrefix + std.get(c.dashboardUids, name, stem);
      assert std.length(uid) > 0 && std.length(uid) <= 40 : 'Dashboard UIDs must contain 1–40 characters';
      dashboards[name] +
      g.dashboard.withUid(uid) +
      g.dashboard.withTags(c.tags + (if name == 'openshell-ocsf-logs.json' then c.ocsfTags else [])) +
      g.dashboard.withRefresh(c.refresh) +
      g.dashboard.withTimezone(c.timezone) +
      g.dashboard.withLinks([
        if link.type == 'dashboards' && link.title == 'OpenShell dashboards'
        then link { tags: c.tags }
        else link
        for link in dashboards[name].links
      ]) +
      std.get(c.dashboardOverrides, name, {})
    for name in std.objectFields(dashboards)
  },
}
