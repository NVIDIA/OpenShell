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
				Host:     "api.example.com",
				Port:     443,
				Protocol: "rest",
				Tls:      "strict",
				Enforcement: "enforce",
				Access:   "allow",
				Ports:    []uint32{80, 443},
				AllowedIps: []string{"10.0.0.1", "10.0.0.2"},
				AllowEncodedSlash: true,
				PersistedQueries:  "allow",
				GraphqlMaxBodyBytes: 1024,
				Path:              "/api/v1",
				WebsocketCredentialRewrite:  true,
				RequestBodyCredentialRewrite: false,
				AdvisorProposed:             true,
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
	assert.True(t, ep.AdvisorProposed)

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
				Host:     "gql.example.com",
				Port:     8080,
				Protocol: "graphql",
				TLS:      "permissive",
				Enforcement: "audit",
				Access:   "allow",
				Ports:    []uint32{8080, 8443},
				AllowedIPs: []string{"192.168.1.0/24"},
				AllowEncodedSlash: false,
				PersistedQueries:  "enforce",
				GraphqlMaxBodyBytes: 2048,
				Path:              "/graphql",
				WebsocketCredentialRewrite:  false,
				RequestBodyCredentialRewrite: true,
				AdvisorProposed:             false,
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
						},
					},
				},
				DenyRules: []v1.L7DenyRule{
					{
						Method:        "POST",
						Path:          "/graphql",
						OperationType: "mutation",
						OperationName: "DropDB",
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
	assert.Equal(t, original.Endpoints[0].AdvisorProposed, roundTrip.Endpoints[0].AdvisorProposed)

	// L7 rules round-trip
	require.Len(t, roundTrip.Endpoints[0].Rules, 1)
	assert.Equal(t, original.Endpoints[0].Rules[0].Allow.Method, roundTrip.Endpoints[0].Rules[0].Allow.Method)
	assert.Equal(t, original.Endpoints[0].Rules[0].Allow.OperationName, roundTrip.Endpoints[0].Rules[0].Allow.OperationName)
	assert.Equal(t, original.Endpoints[0].Rules[0].Allow.Query["limit"].Glob, roundTrip.Endpoints[0].Rules[0].Allow.Query["limit"].Glob)

	// Deny rules round-trip
	require.Len(t, roundTrip.Endpoints[0].DenyRules, 1)
	assert.Equal(t, original.Endpoints[0].DenyRules[0].OperationName, roundTrip.Endpoints[0].DenyRules[0].OperationName)

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
}

func TestL7RuleFromProto_NilAllow(t *testing.T) {
	proto := &sbv1.L7Rule{Allow: nil}
	result := l7RuleFromProto(proto)
	assert.Nil(t, result.Allow)
}
