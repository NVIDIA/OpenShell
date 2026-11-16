// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

local labelStart = std.stringChars('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_');
local labelRest = labelStart + std.stringChars('0123456789');
local identifier(value, dotted=false) =
  assert std.isString(value) && std.length(value) > 0 : 'Label/attribute names must be nonempty strings';
  assert std.all([
    std.length(part) > 0 && std.member(labelStart, part[0]) &&
    std.all([std.member(labelRest, c) for c in std.stringChars(part)])
    for part in (if dotted then std.split(value, '.') else [value])
  ]) :
         'Invalid label/attribute name: ' + value;
  value;
local quoted(value) =
  assert std.isString(value) : 'Matcher values must be strings';
  std.manifestJsonEx(value, '');
local matcher(m) =
  assert std.isObject(m) && std.objectFields(m) == ['name', 'operator', 'value'] :
         'Metric matchers require exactly name, operator, and value';
  assert std.member(['=', '!=', '=~', '!~'], m.operator) : 'Invalid metric matcher operator';
  identifier(m.name) + m.operator + quoted(m.value);
{
  new(c): {
    metricsClusterLabel: identifier(c.metricsClusterLabel),
    metricsInstanceLabel: identifier(c.metricsInstanceLabel),
    logsClusterLabel: identifier(c.logsClusterLabel),
    logsNamespaceLabel: identifier(c.logsNamespaceLabel),
    tracesClusterAttribute: identifier(c.tracesClusterAttribute, dotted=true),
    tracesService: quoted(c.tracesService),
    namespaceRegex: quoted(c.namespaceRegex),
    metricsSelector:
      assert std.isArray(c.metricsMatchers) && std.length(c.metricsMatchers) > 0 :
             'metricsMatchers must be a nonempty array';
      std.join(',', [matcher(m) for m in c.metricsMatchers]),
    metricsClusterScope: self.metricsSelector + ',' + self.metricsClusterLabel + '=~"${cluster:regex}"',
    metricsScope: self.metricsClusterScope + ',' + self.metricsInstanceLabel + '=~"${instance:regex}"',
    logsScope: self.logsClusterLabel + '=~"${cluster:regex}",' + self.logsNamespaceLabel + '=~' + self.namespaceRegex,
  },
}
