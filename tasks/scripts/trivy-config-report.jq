# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

# Inputs are raw, repository-relative Trivy config reports. Consolidation is
# presentation only: the gate continues comparing unmodified reports per profile.
if length == 0 or any(.[];
  .SchemaVersion != 2
  or (.ArtifactName | type) != "string"
  or (.ArtifactType | type) != "string"
  or (.TrivyProfile | type) != "string"
  or (.Results != null and (.Results | type) != "array")
) then error("invalid Trivy configuration reports") else . end
| .[0] as $template
| [
    .[] as $report
    | $report.Results[]?
    | (.Misconfigurations[]?.TrivyProfile) = $report.TrivyProfile
  ] as $results
| $template
| .ArtifactName = "deployment configuration (all profiles)"
| del(.TrivyProfile)
| .Results = (
    $results
    | group_by([.Target, .Class, .Type])
    | map(
        . as $targets
        | .[0]
        | .Misconfigurations = (
            [$targets[] | .Misconfigurations[]?]
            | group_by([
                .ID, .Namespace, .Severity, .Message,
                .CauseMetadata.Provider, .CauseMetadata.Service,
                .CauseMetadata.Resource
              ])
            | map(
                . as $findings
                | .[0]
                | .Message += ("\nProfiles: " + ($findings | map(.TrivyProfile) | unique | join(", ")))
                | del(.TrivyProfile)
              )
          )
        | .MisconfSummary = {
            Successes: 0,
            Failures: (.Misconfigurations | length),
            Exceptions: 0
          }
      )
  )
