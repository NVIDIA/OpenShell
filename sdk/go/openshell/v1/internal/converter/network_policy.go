// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	policyv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/policyv1"
)

// --- NetworkPolicyRule ---

// NetworkPolicyRuleFromProto converts a proto NetworkPolicyRule to an SDK NetworkPolicyRule.
func NetworkPolicyRuleFromProto(r *policyv1.NetworkPolicyRule) *types.NetworkPolicyRule {
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
func NetworkPolicyRuleToProto(r *types.NetworkPolicyRule) *policyv1.NetworkPolicyRule {
	if r == nil {
		return nil
	}
	result := &policyv1.NetworkPolicyRule{
		Name: r.Name,
	}
	if len(r.Endpoints) > 0 {
		result.Endpoints = make([]*policyv1.NetworkEndpoint, len(r.Endpoints))
		for i := range r.Endpoints {
			result.Endpoints[i] = policyNetworkEndpointToProto(&r.Endpoints[i])
		}
	}
	if len(r.Binaries) > 0 {
		result.Binaries = make([]*policyv1.NetworkBinary, len(r.Binaries))
		for i := range r.Binaries {
			result.Binaries[i] = &policyv1.NetworkBinary{Path: r.Binaries[i].Path}
		}
	}
	return result
}

// --- PolicyNetworkEndpoint ---

func policyNetworkEndpointFromProto(ep *policyv1.NetworkEndpoint) types.PolicyNetworkEndpoint {
	result := types.PolicyNetworkEndpoint{
		Host:                         ep.GetHost(),
		Protocol:                     ep.GetProtocol(),
		TLS:                          types.NetworkTLSMode(ep.GetTls()),
		Enforcement:                  types.NetworkEnforcementMode(ep.GetEnforcement()),
		Access:                       types.NetworkAccessPreset(ep.GetAccess()),
		AllowEncodedSlash:            ep.GetAllowEncodedSlash(),
		PersistedQueries:             ep.GetPersistedQueries(),
		GraphqlMaxBodyBytes:          ep.GetGraphqlMaxBodyBytes(),
		Path:                         ep.GetPath(),
		WebsocketCredentialRewrite:   ep.GetWebsocketCredentialRewrite(),
		RequestBodyCredentialRewrite: ep.GetRequestBodyCredentialRewrite(),
		AllowUninspectedCredentials:  ep.GetAllowUninspectedCredentials(),
		CredentialSigning:            ep.GetCredentialSigning(),
		SigningService:               ep.GetSigningService(),
		SigningRegion:                ep.GetSigningRegion(),
	}
	if jsonRPC := ep.GetJsonRpc(); jsonRPC != nil {
		result.JSONRPCMaxBodyBytes = jsonRPC.GetMaxBodyBytes()
	}
	if binding := ep.GetCredentialBinding(); binding != nil {
		result.CredentialBinding = &types.NetworkCredentialBinding{
			Provider: binding.GetProvider(),
		}
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
	result.Mcp = mcpOptionsFromProto(ep.GetMcp())
	return result
}

func policyNetworkEndpointToProto(ep *types.PolicyNetworkEndpoint) *policyv1.NetworkEndpoint {
	result := &policyv1.NetworkEndpoint{
		Host:                         ep.Host,
		Protocol:                     ep.Protocol,
		Tls:                          string(ep.TLS),
		Enforcement:                  string(ep.Enforcement),
		Access:                       string(ep.Access),
		AllowEncodedSlash:            ep.AllowEncodedSlash,
		PersistedQueries:             ep.PersistedQueries,
		GraphqlMaxBodyBytes:          ep.GraphqlMaxBodyBytes,
		Path:                         ep.Path,
		WebsocketCredentialRewrite:   ep.WebsocketCredentialRewrite,
		RequestBodyCredentialRewrite: ep.RequestBodyCredentialRewrite,
		AllowUninspectedCredentials:  ep.AllowUninspectedCredentials,
		CredentialSigning:            ep.CredentialSigning,
		SigningService:               ep.SigningService,
		SigningRegion:                ep.SigningRegion,
	}
	if ep.JSONRPCMaxBodyBytes != 0 {
		result.JsonRpc = &policyv1.JsonRpcConfig{MaxBodyBytes: ep.JSONRPCMaxBodyBytes}
	}
	if ep.CredentialBinding != nil {
		result.CredentialBinding = &policyv1.NetworkCredentialBinding{
			Provider: ep.CredentialBinding.Provider,
		}
	}
	if len(ep.Ports) > 0 {
		result.Ports = make([]uint32, len(ep.Ports))
		copy(result.Ports, ep.Ports)
	}
	if len(ep.AllowedIPs) > 0 {
		result.AllowedIps = CopyStringSlice(ep.AllowedIPs)
	}
	if len(ep.Rules) > 0 {
		result.Rules = make([]*policyv1.L7Rule, len(ep.Rules))
		for i := range ep.Rules {
			result.Rules[i] = l7RuleToProto(&ep.Rules[i])
		}
	}
	if len(ep.DenyRules) > 0 {
		result.DenyRules = make([]*policyv1.L7DenyRule, len(ep.DenyRules))
		for i := range ep.DenyRules {
			result.DenyRules[i] = l7DenyRuleToProto(&ep.DenyRules[i])
		}
	}
	if len(ep.GraphqlPersistedQueries) > 0 {
		result.GraphqlPersistedQueries = make(map[string]*policyv1.GraphqlOperation, len(ep.GraphqlPersistedQueries))
		for k, v := range ep.GraphqlPersistedQueries {
			result.GraphqlPersistedQueries[k] = graphqlOperationToProto(&v)
		}
	}
	result.Mcp = mcpOptionsToProto(ep.Mcp)
	return result
}

// --- McpOptions ---

// mcpOptionsFromProto performs a transport conversion only. It leaves an empty
// version list empty because checked policy and server ingress own default
// materialization and validation.
func mcpOptionsFromProto(m *policyv1.McpConfig) *types.McpOptions {
	if m == nil {
		return nil
	}
	return &types.McpOptions{
		MaxBodyBytes:            m.GetMaxBodyBytes(),
		StrictToolNames:         CopyBoolPtr(m.StrictToolNames),
		AllowAllKnownMcpMethods: CopyBoolPtr(m.AllowAllKnownMcpMethods),
		Versions:                CopyStringSlice(m.GetVersions()),
	}
}

func mcpOptionsToProto(m *types.McpOptions) *policyv1.McpConfig {
	if m == nil {
		return nil
	}
	return &policyv1.McpConfig{
		MaxBodyBytes:            m.MaxBodyBytes,
		StrictToolNames:         CopyBoolPtr(m.StrictToolNames),
		AllowAllKnownMcpMethods: CopyBoolPtr(m.AllowAllKnownMcpMethods),
		Versions:                CopyStringSlice(m.Versions),
	}
}

// --- L7Rule ---

func l7RuleFromProto(r *policyv1.L7Rule) types.L7Rule {
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
			result.Allow.Params = l7ParameterMapFromProto(p)
		}
		if tool := a.GetTool(); tool != nil {
			converted := matcherFromProto(tool)
			result.Allow.Tool = &converted
		}
	}
	return result
}

func l7RuleToProto(r *types.L7Rule) *policyv1.L7Rule {
	result := &policyv1.L7Rule{}
	if r.Allow != nil {
		result.Allow = &policyv1.L7Allow{
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
			result.Allow.Params = l7ParameterMapToProto(r.Allow.Params)
		}
		if r.Allow.Tool != nil {
			result.Allow.Tool = matcherToProto(*r.Allow.Tool)
		}
	}
	return result
}

// --- L7DenyRule ---

func l7DenyRuleFromProto(r *policyv1.L7DenyRule) types.L7DenyRule {
	result := types.L7DenyRule{
		Method:        r.GetMethod(),
		Path:          r.GetPath(),
		Command:       r.GetCommand(),
		OperationType: r.GetOperationType(),
		OperationName: r.GetOperationName(),
		Fields:        CopyStringSlice(r.GetFields()),
		Query:         l7QueryMapFromProto(r.GetQuery()),
		Params:        l7ParameterMapFromProto(r.GetParams()),
	}
	if tool := r.GetTool(); tool != nil {
		converted := matcherFromProto(tool)
		result.Tool = &converted
	}
	return result
}

func l7DenyRuleToProto(r *types.L7DenyRule) *policyv1.L7DenyRule {
	result := &policyv1.L7DenyRule{
		Method:        r.Method,
		Path:          r.Path,
		Command:       r.Command,
		OperationType: r.OperationType,
		OperationName: r.OperationName,
		Fields:        CopyStringSlice(r.Fields),
	}
	if len(r.Query) > 0 {
		result.Query = l7QueryMapToProto(r.Query)
	}
	if len(r.Params) > 0 {
		result.Params = l7ParameterMapToProto(r.Params)
	}
	if r.Tool != nil {
		result.Tool = matcherToProto(*r.Tool)
	}
	return result
}

// --- L7QueryMatcher helpers ---

func l7QueryMapFromProto(m map[string]*policyv1.Matcher) map[string]types.L7QueryMatcher {
	if len(m) == 0 {
		return nil
	}
	result := make(map[string]types.L7QueryMatcher, len(m))
	for k, v := range m {
		if v != nil {
			result[k] = matcherFromProto(v)
		}
	}
	return result
}

func l7QueryMapToProto(m map[string]types.L7QueryMatcher) map[string]*policyv1.Matcher {
	if len(m) == 0 {
		return nil
	}
	result := make(map[string]*policyv1.Matcher, len(m))
	for k, v := range m {
		result[k] = matcherToProto(v)
	}
	return result
}

func matcherFromProto(m *policyv1.Matcher) types.L7QueryMatcher {
	result := types.L7QueryMatcher{Glob: m.GetGlob()}
	if anyMatcher := m.GetAny(); anyMatcher != nil {
		result.Any = CopyStringSlice(anyMatcher.GetValues())
	}
	return result
}

func matcherToProto(m types.L7QueryMatcher) *policyv1.Matcher {
	if len(m.Any) > 0 {
		return &policyv1.Matcher{Kind: &policyv1.Matcher_Any{Any: &policyv1.AnyMatcher{
			Values: CopyStringSlice(m.Any),
		}}}
	}
	return &policyv1.Matcher{Kind: &policyv1.Matcher_Glob{Glob: m.Glob}}
}

func l7ParameterMapFromProto(m map[string]*policyv1.ParameterMatcher) map[string]types.ParameterMatcher {
	if len(m) == 0 {
		return nil
	}
	result := make(map[string]types.ParameterMatcher, len(m))
	for key, value := range m {
		if matcher := value.GetMatcher(); matcher != nil {
			converted := matcherFromProto(matcher)
			result[key] = types.ParameterMatcher{Matcher: &converted}
		} else if object := value.GetObject(); object != nil {
			result[key] = types.ParameterMatcher{Object: l7ParameterMapFromProto(object.GetFields())}
		}
	}
	return result
}

func l7ParameterMapToProto(m map[string]types.ParameterMatcher) map[string]*policyv1.ParameterMatcher {
	if len(m) == 0 {
		return nil
	}
	result := make(map[string]*policyv1.ParameterMatcher, len(m))
	for key, value := range m {
		if value.Matcher != nil {
			result[key] = &policyv1.ParameterMatcher{Kind: &policyv1.ParameterMatcher_Matcher{
				Matcher: matcherToProto(*value.Matcher),
			}}
		} else {
			result[key] = &policyv1.ParameterMatcher{Kind: &policyv1.ParameterMatcher_Object{
				Object: &policyv1.ParameterObject{Fields: l7ParameterMapToProto(value.Object)},
			}}
		}
	}
	return result
}

// --- GraphqlOperation ---

func graphqlOperationFromProto(op *policyv1.GraphqlOperation) types.GraphqlOperation {
	return types.GraphqlOperation{
		OperationType: op.GetOperationType(),
		OperationName: op.GetOperationName(),
		Fields:        CopyStringSlice(op.GetFields()),
	}
}

func graphqlOperationToProto(op *types.GraphqlOperation) *policyv1.GraphqlOperation {
	return &policyv1.GraphqlOperation{
		OperationType: op.OperationType,
		OperationName: op.OperationName,
		Fields:        CopyStringSlice(op.Fields),
	}
}
