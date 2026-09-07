// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	sbv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- NetworkPolicyRule round-trip ---

func TestNetworkPolicyRuleFromProto(t *testing.T) {
	proto := &sbv1.NetworkPolicyRule{
		Name: "web-api",
		Endpoints: []*sbv1.NetworkEndpoint{
			{
				Host:                         "api.example.com",
				Port:                         443,
				Protocol:                     "rest",
				Tls:                          "strict",
				Enforcement:                  "enforce",
				Access:                       "allow",
				Ports:                        []uint32{80, 443},
				AllowedIps:                   []string{"10.0.0.1", "10.0.0.2"},
				AllowEncodedSlash:            true,
				PersistedQueries:             "allow",
				GraphqlMaxBodyBytes:          1024,
				Path:                         "/api/v1",
				WebsocketCredentialRewrite:   true,
				RequestBodyCredentialRewrite: false,
				AllowUninspectedCredentials:  true,
				ProviderCredentialed:         true,
				AdvisorProposed:              true,
				CredentialSigning:            "sigv4",
				SigningService:               "bedrock",
				SigningRegion:                "us-west-2",
				JsonRpcMaxBodyBytes:          65536,
				Mcp: &sbv1.McpOptions{
					StrictToolNames:         boolPtr(true),
					AllowAllKnownMcpMethods: boolPtr(false),
				},
				Rules: []*sbv1.L7Rule{
					{
						Allow: &sbv1.L7Allow{
							Method:  "GET",
							Path:    "/users",
							Command: "list",
							Query: map[string]*sbv1.L7QueryMatcher{
								"page": {Glob: "[0-9]*", Any: []string{"1", "2"}},
							},
							OperationType: "query",
							OperationName: "GetUsers",
							Fields:        []string{"id", "name"},
							Params: map[string]*sbv1.L7QueryMatcher{
								"name": {Glob: "my-tool-*"},
							},
						},
					},
				},
				DenyRules: []*sbv1.L7DenyRule{
					{
						Method:        "DELETE",
						Path:          "/admin",
						Command:       "rm",
						OperationType: "mutation",
						OperationName: "DeleteAll",
						Fields:        []string{"*"},
						Query: map[string]*sbv1.L7QueryMatcher{
							"force": {Glob: "true"},
						},
						Params: map[string]*sbv1.L7QueryMatcher{
							"tool": {Glob: "deny-*"},
						},
					},
				},
				GraphqlPersistedQueries: map[string]*sbv1.GraphqlOperation{
					"abc123": {
						OperationType: "query",
						OperationName: "GetUser",
						Fields:        []string{"id", "email"},
					},
				},
			},
		},
		Binaries: []*sbv1.NetworkBinary{
			{Path: "/usr/bin/curl"},
		},
	}

	rule := NetworkPolicyRuleFromProto(proto)

	require.NotNil(t, rule)
	assert.Equal(t, "web-api", rule.Name)
	require.Len(t, rule.Endpoints, 1)
	ep := rule.Endpoints[0]
	assert.Equal(t, "api.example.com", ep.Host)
	assert.Equal(t, uint32(443), ep.Port)
	assert.Equal(t, "rest", ep.Protocol)
	assert.Equal(t, "strict", ep.TLS)
	assert.Equal(t, "enforce", ep.Enforcement)
	assert.Equal(t, "allow", ep.Access)
	assert.Equal(t, []uint32{80, 443}, ep.Ports)
	assert.Equal(t, []string{"10.0.0.1", "10.0.0.2"}, ep.AllowedIPs)
	assert.True(t, ep.AllowEncodedSlash)
	assert.Equal(t, "allow", ep.PersistedQueries)
	assert.Equal(t, uint32(1024), ep.GraphqlMaxBodyBytes)
	assert.Equal(t, "/api/v1", ep.Path)
	assert.True(t, ep.WebsocketCredentialRewrite)
	assert.False(t, ep.RequestBodyCredentialRewrite)
	assert.True(t, ep.AllowUninspectedCredentials)
	assert.True(t, ep.ProviderCredentialed)
	assert.True(t, ep.AdvisorProposed)
	assert.Equal(t, "sigv4", ep.CredentialSigning)
	assert.Equal(t, "bedrock", ep.SigningService)
	assert.Equal(t, "us-west-2", ep.SigningRegion)
	assert.Equal(t, uint32(65536), ep.JSONRPCMaxBodyBytes)

	// MCP options
	require.NotNil(t, ep.Mcp)
	require.NotNil(t, ep.Mcp.StrictToolNames)
	assert.True(t, *ep.Mcp.StrictToolNames)
	require.NotNil(t, ep.Mcp.AllowAllKnownMcpMethods)
	assert.False(t, *ep.Mcp.AllowAllKnownMcpMethods)

	// L7 rules
	require.Len(t, ep.Rules, 1)
	allow := ep.Rules[0].Allow
	require.NotNil(t, allow)
	assert.Equal(t, "GET", allow.Method)
	assert.Equal(t, "/users", allow.Path)
	assert.Equal(t, "list", allow.Command)
	assert.Equal(t, "query", allow.OperationType)
	assert.Equal(t, "GetUsers", allow.OperationName)
	assert.Equal(t, []string{"id", "name"}, allow.Fields)
	require.Contains(t, allow.Query, "page")
	assert.Equal(t, "[0-9]*", allow.Query["page"].Glob)
	assert.Equal(t, []string{"1", "2"}, allow.Query["page"].Any)
	require.Contains(t, allow.Params, "name")
	assert.Equal(t, "my-tool-*", allow.Params["name"].Glob)

	// Deny rules
	require.Len(t, ep.DenyRules, 1)
	deny := ep.DenyRules[0]
	assert.Equal(t, "DELETE", deny.Method)
	assert.Equal(t, "/admin", deny.Path)
	assert.Equal(t, "rm", deny.Command)
	assert.Equal(t, "mutation", deny.OperationType)
	assert.Equal(t, "DeleteAll", deny.OperationName)
	assert.Equal(t, []string{"*"}, deny.Fields)
	require.Contains(t, deny.Query, "force")
	assert.Equal(t, "true", deny.Query["force"].Glob)
	require.Contains(t, deny.Params, "tool")
	assert.Equal(t, "deny-*", deny.Params["tool"].Glob)

	// GraphQL persisted queries
	require.Contains(t, ep.GraphqlPersistedQueries, "abc123")
	gql := ep.GraphqlPersistedQueries["abc123"]
	assert.Equal(t, "query", gql.OperationType)
	assert.Equal(t, "GetUser", gql.OperationName)
	assert.Equal(t, []string{"id", "email"}, gql.Fields)

	// Binaries
	require.Len(t, rule.Binaries, 1)
	assert.Equal(t, "/usr/bin/curl", rule.Binaries[0].Path)
}

func TestNetworkPolicyRuleFromProto_Nil(t *testing.T) {
	assert.Nil(t, NetworkPolicyRuleFromProto(nil))
}

func TestNetworkPolicyRuleRoundTrip(t *testing.T) {
	original := &v1.NetworkPolicyRule{
		Name: "graphql-api",
		Endpoints: []v1.PolicyNetworkEndpoint{
			{
				Host:                         "gql.example.com",
				Port:                         8080,
				Protocol:                     "graphql",
				TLS:                          "permissive",
				Enforcement:                  "audit",
				Access:                       "allow",
				Ports:                        []uint32{8080, 8443},
				AllowedIPs:                   []string{"192.168.1.0/24"},
				AllowEncodedSlash:            false,
				PersistedQueries:             "enforce",
				GraphqlMaxBodyBytes:          2048,
				Path:                         "/graphql",
				WebsocketCredentialRewrite:   false,
				RequestBodyCredentialRewrite: true,
				AllowUninspectedCredentials:  true,
				ProviderCredentialed:         true,
				AdvisorProposed:              false,
				CredentialSigning:            "sigv4",
				SigningService:               "bedrock",
				SigningRegion:                "us-east-1",
				JSONRPCMaxBodyBytes:          32768,
				Mcp: &v1.McpOptions{
					StrictToolNames:         boolPtr(true),
					AllowAllKnownMcpMethods: boolPtr(false),
				},
				Rules: []v1.L7Rule{
					{
						Allow: &v1.L7Allow{
							Method:        "POST",
							Path:          "/graphql",
							OperationType: "query",
							OperationName: "ListItems",
							Fields:        []string{"id"},
							Query: map[string]v1.L7QueryMatcher{
								"limit": {Glob: "[0-9]+"},
							},
							Params: map[string]v1.L7QueryMatcher{
								"tool": {Glob: "allowed-*"},
							},
						},
					},
				},
				DenyRules: []v1.L7DenyRule{
					{
						Method:        "POST",
						Path:          "/graphql",
						OperationType: "mutation",
						OperationName: "DropDB",
						Params: map[string]v1.L7QueryMatcher{
							"tool": {Glob: "denied-*"},
						},
					},
				},
				GraphqlPersistedQueries: map[string]v1.GraphqlOperation{
					"hash1": {
						OperationType: "query",
						OperationName: "Safe",
						Fields:        []string{"f1"},
					},
				},
			},
		},
		Binaries: []v1.PolicyNetworkBinary{
			{Path: "/usr/bin/wget"},
		},
	}

	proto := NetworkPolicyRuleToProto(original)
	require.NotNil(t, proto)

	roundTrip := NetworkPolicyRuleFromProto(proto)
	require.NotNil(t, roundTrip)

	assert.Equal(t, original.Name, roundTrip.Name)
	require.Len(t, roundTrip.Endpoints, 1)
	assert.Equal(t, original.Endpoints[0].Host, roundTrip.Endpoints[0].Host)
	assert.Equal(t, original.Endpoints[0].Port, roundTrip.Endpoints[0].Port)
	assert.Equal(t, original.Endpoints[0].Protocol, roundTrip.Endpoints[0].Protocol)
	assert.Equal(t, original.Endpoints[0].TLS, roundTrip.Endpoints[0].TLS)
	assert.Equal(t, original.Endpoints[0].Enforcement, roundTrip.Endpoints[0].Enforcement)
	assert.Equal(t, original.Endpoints[0].Access, roundTrip.Endpoints[0].Access)
	assert.Equal(t, original.Endpoints[0].Ports, roundTrip.Endpoints[0].Ports)
	assert.Equal(t, original.Endpoints[0].AllowedIPs, roundTrip.Endpoints[0].AllowedIPs)
	assert.Equal(t, original.Endpoints[0].AllowEncodedSlash, roundTrip.Endpoints[0].AllowEncodedSlash)
	assert.Equal(t, original.Endpoints[0].GraphqlMaxBodyBytes, roundTrip.Endpoints[0].GraphqlMaxBodyBytes)
	assert.Equal(t, original.Endpoints[0].AllowUninspectedCredentials, roundTrip.Endpoints[0].AllowUninspectedCredentials)
	assert.Equal(t, original.Endpoints[0].ProviderCredentialed, roundTrip.Endpoints[0].ProviderCredentialed)
	assert.Equal(t, original.Endpoints[0].AdvisorProposed, roundTrip.Endpoints[0].AdvisorProposed)
	assert.Equal(t, original.Endpoints[0].CredentialSigning, roundTrip.Endpoints[0].CredentialSigning)
	assert.Equal(t, original.Endpoints[0].SigningService, roundTrip.Endpoints[0].SigningService)
	assert.Equal(t, original.Endpoints[0].SigningRegion, roundTrip.Endpoints[0].SigningRegion)
	assert.Equal(t, original.Endpoints[0].JSONRPCMaxBodyBytes, roundTrip.Endpoints[0].JSONRPCMaxBodyBytes)

	// MCP round-trip
	require.NotNil(t, roundTrip.Endpoints[0].Mcp)
	assert.Equal(t, original.Endpoints[0].Mcp.StrictToolNames, roundTrip.Endpoints[0].Mcp.StrictToolNames)
	assert.Equal(t, original.Endpoints[0].Mcp.AllowAllKnownMcpMethods, roundTrip.Endpoints[0].Mcp.AllowAllKnownMcpMethods)

	// L7 rules round-trip
	require.Len(t, roundTrip.Endpoints[0].Rules, 1)
	assert.Equal(t, original.Endpoints[0].Rules[0].Allow.Method, roundTrip.Endpoints[0].Rules[0].Allow.Method)
	assert.Equal(t, original.Endpoints[0].Rules[0].Allow.OperationName, roundTrip.Endpoints[0].Rules[0].Allow.OperationName)
	assert.Equal(t, original.Endpoints[0].Rules[0].Allow.Query["limit"].Glob, roundTrip.Endpoints[0].Rules[0].Allow.Query["limit"].Glob)
	assert.Equal(t, original.Endpoints[0].Rules[0].Allow.Params["tool"].Glob, roundTrip.Endpoints[0].Rules[0].Allow.Params["tool"].Glob)

	// Deny rules round-trip
	require.Len(t, roundTrip.Endpoints[0].DenyRules, 1)
	assert.Equal(t, original.Endpoints[0].DenyRules[0].OperationName, roundTrip.Endpoints[0].DenyRules[0].OperationName)
	assert.Equal(t, original.Endpoints[0].DenyRules[0].Params["tool"].Glob, roundTrip.Endpoints[0].DenyRules[0].Params["tool"].Glob)

	// GraphQL persisted queries round-trip
	require.Contains(t, roundTrip.Endpoints[0].GraphqlPersistedQueries, "hash1")

	// Binaries round-trip
	require.Len(t, roundTrip.Binaries, 1)
	assert.Equal(t, original.Binaries[0].Path, roundTrip.Binaries[0].Path)
}

func TestNetworkPolicyRuleToProto_Nil(t *testing.T) {
	assert.Nil(t, NetworkPolicyRuleToProto(nil))
}

func TestNetworkPolicyRuleDeepCopy(t *testing.T) {
	proto := &sbv1.NetworkPolicyRule{
		Name: "test",
		Endpoints: []*sbv1.NetworkEndpoint{
			{
				AllowedIps: []string{"1.2.3.4"},
				Ports:      []uint32{80},
				Rules: []*sbv1.L7Rule{
					{Allow: &sbv1.L7Allow{Fields: []string{"f1"}}},
				},
			},
		},
	}

	rule := NetworkPolicyRuleFromProto(proto)

	// Mutate proto source
	proto.Endpoints[0].AllowedIps[0] = "changed"
	proto.Endpoints[0].Ports[0] = 9999
	proto.Endpoints[0].Rules[0].Allow.Fields[0] = "changed"

	// SDK type should be unaffected
	assert.Equal(t, "1.2.3.4", rule.Endpoints[0].AllowedIPs[0])
	assert.Equal(t, uint32(80), rule.Endpoints[0].Ports[0])
	assert.Equal(t, "f1", rule.Endpoints[0].Rules[0].Allow.Fields[0])

	// MCP deep copy
	mcpProto := &sbv1.NetworkPolicyRule{
		Name: "mcp-test",
		Endpoints: []*sbv1.NetworkEndpoint{
			{
				Mcp: &sbv1.McpOptions{
					StrictToolNames: boolPtr(true),
				},
			},
		},
	}
	mcpRule := NetworkPolicyRuleFromProto(mcpProto)
	*mcpProto.Endpoints[0].Mcp.StrictToolNames = false
	require.NotNil(t, mcpRule.Endpoints[0].Mcp.StrictToolNames)
	assert.True(t, *mcpRule.Endpoints[0].Mcp.StrictToolNames)
}

func TestL7RuleFromProto_NilAllow(t *testing.T) {
	proto := &sbv1.L7Rule{Allow: nil}
	result := l7RuleFromProto(proto)
	assert.Nil(t, result.Allow)
}

func boolPtr(v bool) *bool { return &v }
