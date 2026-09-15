// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
)

// --- Network Policy types ---

// NetworkPolicyRule defines a named network policy rule containing endpoints and binaries.
type NetworkPolicyRule = types.NetworkPolicyRule

// PolicyNetworkEndpoint describes a full network endpoint in a sandbox network policy rule.
type PolicyNetworkEndpoint = types.PolicyNetworkEndpoint

// NetworkTLSMode controls TLS handling for a policy endpoint.
type NetworkTLSMode = types.NetworkTLSMode

// NetworkEnforcementMode controls endpoint L7 enforcement behavior.
type NetworkEnforcementMode = types.NetworkEnforcementMode

// NetworkAccessPreset selects a predefined endpoint access policy.
type NetworkAccessPreset = types.NetworkAccessPreset

const (
	// NetworkTLSModeUnspecified uses automatic TLS handling.
	NetworkTLSModeUnspecified = types.NetworkTLSModeUnspecified
	// NetworkTLSModeSkip disables TLS inspection.
	NetworkTLSModeSkip = types.NetworkTLSModeSkip
	// NetworkTLSModeTerminate is retained for wire compatibility.
	NetworkTLSModeTerminate = types.NetworkTLSModeTerminate
	// NetworkTLSModePassthrough is retained for wire compatibility.
	NetworkTLSModePassthrough = types.NetworkTLSModePassthrough

	// NetworkEnforcementModeUnspecified uses the documented audit default.
	NetworkEnforcementModeUnspecified = types.NetworkEnforcementModeUnspecified
	// NetworkEnforcementModeEnforce blocks policy violations.
	NetworkEnforcementModeEnforce = types.NetworkEnforcementModeEnforce
	// NetworkEnforcementModeAudit logs policy violations without blocking them.
	NetworkEnforcementModeAudit = types.NetworkEnforcementModeAudit

	// NetworkAccessPresetUnspecified selects no access preset.
	NetworkAccessPresetUnspecified = types.NetworkAccessPresetUnspecified
	// NetworkAccessPresetReadOnly permits read operations.
	NetworkAccessPresetReadOnly = types.NetworkAccessPresetReadOnly
	// NetworkAccessPresetReadWrite permits read and write operations.
	NetworkAccessPresetReadWrite = types.NetworkAccessPresetReadWrite
	// NetworkAccessPresetFull permits every operation supported by the protocol.
	NetworkAccessPresetFull = types.NetworkAccessPresetFull
)

// PolicyNetworkBinary identifies a binary subject to network policy enforcement.
type PolicyNetworkBinary = types.PolicyNetworkBinary

// L7Rule wraps an L7 allow rule.
type L7Rule = types.L7Rule

// L7Allow specifies layer-7 allow criteria for HTTP/GraphQL traffic.
type L7Allow = types.L7Allow

// L7DenyRule specifies layer-7 deny criteria for HTTP/GraphQL traffic.
type L7DenyRule = types.L7DenyRule

// L7QueryMatcher matches query parameters by glob pattern or exact values.
type L7QueryMatcher = types.L7QueryMatcher

// GraphqlOperation describes a GraphQL operation for persisted-query validation.
type GraphqlOperation = types.GraphqlOperation

// --- MergeOperation types ---

// PolicyMergeOperation represents a single atomic policy mutation.
type PolicyMergeOperation = types.PolicyMergeOperation

// AddNetworkRule adds a named network policy rule with a full rule definition.
type AddNetworkRule = types.AddNetworkRule

// RemoveNetworkEndpoint removes a specific endpoint from a named rule.
type RemoveNetworkEndpoint = types.RemoveNetworkEndpoint

// RemoveNetworkRule removes an entire named rule from the policy.
type RemoveNetworkRule = types.RemoveNetworkRule

// AddDenyRules appends layer-7 deny rules to a specific endpoint.
type AddDenyRules = types.AddDenyRules

// AddAllowRules appends layer-7 allow rules to a specific endpoint.
type AddAllowRules = types.AddAllowRules

// RemoveNetworkBinary removes a binary from a named rule.
type RemoveNetworkBinary = types.RemoveNetworkBinary
