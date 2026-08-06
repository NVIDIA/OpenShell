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
