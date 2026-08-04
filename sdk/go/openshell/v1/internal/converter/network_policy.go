// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	sbv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
)

// --- NetworkPolicyRule ---

// NetworkPolicyRuleFromProto converts a proto NetworkPolicyRule to an SDK NetworkPolicyRule.
func NetworkPolicyRuleFromProto(r *sbv1.NetworkPolicyRule) *types.NetworkPolicyRule {
	if r == nil {
		return nil
	}
	result := &types.NetworkPolicyRule{
		Name: r.GetName(),
	}
	if eps := r.GetEndpoints(); len(eps) > 0 {
		result.Endpoints = make([]types.PolicyNetworkEndpoint, len(eps))
		for i, ep := range eps {
			if ep != nil {
				result.Endpoints[i] = policyNetworkEndpointFromProto(ep)
			}
		}
	}
	if bins := r.GetBinaries(); len(bins) > 0 {
		result.Binaries = make([]types.PolicyNetworkBinary, len(bins))
		for i, b := range bins {
			if b != nil {
				result.Binaries[i] = types.PolicyNetworkBinary{Path: b.GetPath()}
			}
		}
	}
	return result
}

// NetworkPolicyRuleToProto converts an SDK NetworkPolicyRule to a proto NetworkPolicyRule.
func NetworkPolicyRuleToProto(r *types.NetworkPolicyRule) *sbv1.NetworkPolicyRule {
	if r == nil {
		return nil
	}
	result := &sbv1.NetworkPolicyRule{
		Name: r.Name,
	}
	if len(r.Endpoints) > 0 {
		result.Endpoints = make([]*sbv1.NetworkEndpoint, len(r.Endpoints))
		for i := range r.Endpoints {
			result.Endpoints[i] = policyNetworkEndpointToProto(&r.Endpoints[i])
		}
	}
	if len(r.Binaries) > 0 {
		result.Binaries = make([]*sbv1.NetworkBinary, len(r.Binaries))
		for i := range r.Binaries {
			result.Binaries[i] = &sbv1.NetworkBinary{Path: r.Binaries[i].Path}
		}
	}
	return result
}

// --- PolicyNetworkEndpoint ---

func policyNetworkEndpointFromProto(ep *sbv1.NetworkEndpoint) types.PolicyNetworkEndpoint {
	result := types.PolicyNetworkEndpoint{
		Host:                         ep.GetHost(),
		Port:                         ep.GetPort(),
		Protocol:                     ep.GetProtocol(),
		TLS:                          ep.GetTls(),
		Enforcement:                  ep.GetEnforcement(),
		Access:                       ep.GetAccess(),
		AllowEncodedSlash:            ep.GetAllowEncodedSlash(),
		PersistedQueries:             ep.GetPersistedQueries(),
		GraphqlMaxBodyBytes:          ep.GetGraphqlMaxBodyBytes(),
		Path:                         ep.GetPath(),
		WebsocketCredentialRewrite:   ep.GetWebsocketCredentialRewrite(),
		RequestBodyCredentialRewrite: ep.GetRequestBodyCredentialRewrite(),
		AdvisorProposed:              ep.GetAdvisorProposed(),
		CredentialSigning:            ep.GetCredentialSigning(),
		SigningService:               ep.GetSigningService(),
		SigningRegion:                ep.GetSigningRegion(),
		JsonRpcMaxBodyBytes:          ep.GetJsonRpcMaxBodyBytes(),
	}
	if mcp := ep.GetMcp(); mcp != nil {
		result.Mcp = mcpOptionsFromProto(mcp)
	}
	if ports := ep.GetPorts(); len(ports) > 0 {
		result.Ports = make([]uint32, len(ports))
		copy(result.Ports, ports)
	}
	if ips := ep.GetAllowedIps(); len(ips) > 0 {
		result.AllowedIPs = CopyStringSlice(ips)
	}
	if rules := ep.GetRules(); len(rules) > 0 {
		result.Rules = make([]types.L7Rule, len(rules))
		for i, r := range rules {
			if r != nil {
				result.Rules[i] = l7RuleFromProto(r)
			}
		}
	}
	if deny := ep.GetDenyRules(); len(deny) > 0 {
		result.DenyRules = make([]types.L7DenyRule, len(deny))
		for i, r := range deny {
			if r != nil {
				result.DenyRules[i] = l7DenyRuleFromProto(r)
			}
		}
	}
	if gql := ep.GetGraphqlPersistedQueries(); len(gql) > 0 {
		result.GraphqlPersistedQueries = make(map[string]types.GraphqlOperation, len(gql))
		for k, v := range gql {
			if v != nil {
				result.GraphqlPersistedQueries[k] = graphqlOperationFromProto(v)
			}
		}
	}
	return result
}

func policyNetworkEndpointToProto(ep *types.PolicyNetworkEndpoint) *sbv1.NetworkEndpoint {
	result := &sbv1.NetworkEndpoint{
		Host:                         ep.Host,
		Port:                         ep.Port,
		Protocol:                     ep.Protocol,
		Tls:                          ep.TLS,
		Enforcement:                  ep.Enforcement,
		Access:                       ep.Access,
		AllowEncodedSlash:            ep.AllowEncodedSlash,
		PersistedQueries:             ep.PersistedQueries,
		GraphqlMaxBodyBytes:          ep.GraphqlMaxBodyBytes,
		Path:                         ep.Path,
		WebsocketCredentialRewrite:   ep.WebsocketCredentialRewrite,
		RequestBodyCredentialRewrite: ep.RequestBodyCredentialRewrite,
		AdvisorProposed:              ep.AdvisorProposed,
		CredentialSigning:            ep.CredentialSigning,
		SigningService:               ep.SigningService,
		SigningRegion:                ep.SigningRegion,
		JsonRpcMaxBodyBytes:          ep.JsonRpcMaxBodyBytes,
	}
	if ep.Mcp != nil {
		result.Mcp = mcpOptionsToProto(ep.Mcp)
	}
	if len(ep.Ports) > 0 {
		result.Ports = make([]uint32, len(ep.Ports))
		copy(result.Ports, ep.Ports)
	}
	if len(ep.AllowedIPs) > 0 {
		result.AllowedIps = CopyStringSlice(ep.AllowedIPs)
	}
	if len(ep.Rules) > 0 {
		result.Rules = make([]*sbv1.L7Rule, len(ep.Rules))
		for i := range ep.Rules {
			result.Rules[i] = l7RuleToProto(&ep.Rules[i])
		}
	}
	if len(ep.DenyRules) > 0 {
		result.DenyRules = make([]*sbv1.L7DenyRule, len(ep.DenyRules))
		for i := range ep.DenyRules {
			result.DenyRules[i] = l7DenyRuleToProto(&ep.DenyRules[i])
		}
	}
	if len(ep.GraphqlPersistedQueries) > 0 {
		result.GraphqlPersistedQueries = make(map[string]*sbv1.GraphqlOperation, len(ep.GraphqlPersistedQueries))
		for k, v := range ep.GraphqlPersistedQueries {
			result.GraphqlPersistedQueries[k] = graphqlOperationToProto(&v)
		}
	}
	return result
}

// --- L7Rule ---

func l7RuleFromProto(r *sbv1.L7Rule) types.L7Rule {
	result := types.L7Rule{}
	if a := r.GetAllow(); a != nil {
		result.Allow = &types.L7Allow{
			Method:        a.GetMethod(),
			Path:          a.GetPath(),
			Command:       a.GetCommand(),
			OperationType: a.GetOperationType(),
			OperationName: a.GetOperationName(),
			Fields:        CopyStringSlice(a.GetFields()),
		}
		if q := a.GetQuery(); len(q) > 0 {
			result.Allow.Query = l7QueryMapFromProto(q)
		}
		if p := a.GetParams(); len(p) > 0 {
			result.Allow.Params = l7QueryMapFromProto(p)
		}
	}
	return result
}

func l7RuleToProto(r *types.L7Rule) *sbv1.L7Rule {
	result := &sbv1.L7Rule{}
	if r.Allow != nil {
		result.Allow = &sbv1.L7Allow{
			Method:        r.Allow.Method,
			Path:          r.Allow.Path,
			Command:       r.Allow.Command,
			OperationType: r.Allow.OperationType,
			OperationName: r.Allow.OperationName,
			Fields:        CopyStringSlice(r.Allow.Fields),
		}
		if len(r.Allow.Query) > 0 {
			result.Allow.Query = l7QueryMapToProto(r.Allow.Query)
		}
		if len(r.Allow.Params) > 0 {
			result.Allow.Params = l7QueryMapToProto(r.Allow.Params)
		}
	}
	return result
}

// --- L7DenyRule ---

func l7DenyRuleFromProto(r *sbv1.L7DenyRule) types.L7DenyRule {
	result := types.L7DenyRule{
		Method:        r.GetMethod(),
		Path:          r.GetPath(),
		Command:       r.GetCommand(),
		OperationType: r.GetOperationType(),
		OperationName: r.GetOperationName(),
		Fields:        CopyStringSlice(r.GetFields()),
		Query:         l7QueryMapFromProtoDeny(r.GetQuery()),
	}
	if p := r.GetParams(); len(p) > 0 {
		result.Params = l7QueryMapFromProto(p)
	}
	return result
}

func l7DenyRuleToProto(r *types.L7DenyRule) *sbv1.L7DenyRule {
	result := &sbv1.L7DenyRule{
		Method:        r.Method,
		Path:          r.Path,
		Command:       r.Command,
		OperationType: r.OperationType,
		OperationName: r.OperationName,
		Fields:        CopyStringSlice(r.Fields),
	}
	if len(r.Query) > 0 {
		result.Query = l7QueryMapToProtoDeny(r.Query)
	}
	if len(r.Params) > 0 {
		result.Params = l7QueryMapToProto(r.Params)
	}
	return result
}

// --- L7QueryMatcher helpers ---

func l7QueryMapFromProto(m map[string]*sbv1.L7QueryMatcher) map[string]types.L7QueryMatcher {
	if len(m) == 0 {
		return nil
	}
	result := make(map[string]types.L7QueryMatcher, len(m))
	for k, v := range m {
		if v != nil {
			result[k] = types.L7QueryMatcher{
				Glob: v.GetGlob(),
				Any:  CopyStringSlice(v.GetAny()),
			}
		}
	}
	return result
}

func l7QueryMapToProto(m map[string]types.L7QueryMatcher) map[string]*sbv1.L7QueryMatcher {
	if len(m) == 0 {
		return nil
	}
	result := make(map[string]*sbv1.L7QueryMatcher, len(m))
	for k, v := range m {
		result[k] = &sbv1.L7QueryMatcher{
			Glob: v.Glob,
			Any:  CopyStringSlice(v.Any),
		}
	}
	return result
}

// L7DenyRule uses the same L7QueryMatcher proto type but on a different message.
func l7QueryMapFromProtoDeny(m map[string]*sbv1.L7QueryMatcher) map[string]types.L7QueryMatcher {
	return l7QueryMapFromProto(m)
}

func l7QueryMapToProtoDeny(m map[string]types.L7QueryMatcher) map[string]*sbv1.L7QueryMatcher {
	return l7QueryMapToProto(m)
}

// --- GraphqlOperation ---

func graphqlOperationFromProto(op *sbv1.GraphqlOperation) types.GraphqlOperation {
	return types.GraphqlOperation{
		OperationType: op.GetOperationType(),
		OperationName: op.GetOperationName(),
		Fields:        CopyStringSlice(op.GetFields()),
	}
}

func graphqlOperationToProto(op *types.GraphqlOperation) *sbv1.GraphqlOperation {
	return &sbv1.GraphqlOperation{
		OperationType: op.OperationType,
		OperationName: op.OperationName,
		Fields:        CopyStringSlice(op.Fields),
	}
}

// --- McpOptions ---

func mcpOptionsFromProto(m *sbv1.McpOptions) *types.McpOptions {
	if m == nil {
		return nil
	}
	return &types.McpOptions{
		StrictToolNames:         m.StrictToolNames,
		AllowAllKnownMcpMethods: m.AllowAllKnownMcpMethods,
	}
}

func mcpOptionsToProto(m *types.McpOptions) *sbv1.McpOptions {
	if m == nil {
		return nil
	}
	return &sbv1.McpOptions{
		StrictToolNames:         m.StrictToolNames,
		AllowAllKnownMcpMethods: m.AllowAllKnownMcpMethods,
	}
}
