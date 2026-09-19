// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package types

// NetworkPolicyRule defines a named network policy rule containing endpoints and binaries.
type NetworkPolicyRule struct {
	// Name is the map key for this rule in the sandbox policy.
	Name string
	// Endpoints lists the network endpoints governed by this rule.
	Endpoints []PolicyNetworkEndpoint
	// Binaries lists the binaries governed by this rule.
	Binaries []PolicyNetworkBinary
}

// NetworkTLSMode controls TLS handling for a policy endpoint.
type NetworkTLSMode string

const (
	// NetworkTLSModeUnspecified uses automatic TLS handling.
	NetworkTLSModeUnspecified NetworkTLSMode = ""
	// NetworkTLSModeSkip disables TLS inspection.
	NetworkTLSModeSkip NetworkTLSMode = "skip"
	// NetworkTLSModeTerminate is retained for wire compatibility; prefer unspecified.
	NetworkTLSModeTerminate NetworkTLSMode = "terminate"
	// NetworkTLSModePassthrough is retained for wire compatibility; prefer unspecified.
	NetworkTLSModePassthrough NetworkTLSMode = "passthrough"
)

// NetworkEnforcementMode controls whether an endpoint audits or enforces L7 rules.
type NetworkEnforcementMode string

const (
	// NetworkEnforcementModeUnspecified uses the documented audit default.
	NetworkEnforcementModeUnspecified NetworkEnforcementMode = ""
	// NetworkEnforcementModeEnforce blocks policy violations.
	NetworkEnforcementModeEnforce NetworkEnforcementMode = "enforce"
	// NetworkEnforcementModeAudit logs policy violations without blocking them.
	NetworkEnforcementModeAudit NetworkEnforcementMode = "audit"
)

// NetworkAccessPreset selects a predefined endpoint access policy.
type NetworkAccessPreset string

const (
	// NetworkAccessPresetUnspecified selects no access preset.
	NetworkAccessPresetUnspecified NetworkAccessPreset = ""
	// NetworkAccessPresetReadOnly permits read operations.
	NetworkAccessPresetReadOnly NetworkAccessPreset = "read-only"
	// NetworkAccessPresetReadWrite permits read and write operations.
	NetworkAccessPresetReadWrite NetworkAccessPreset = "read-write"
	// NetworkAccessPresetFull permits every operation supported by the protocol.
	NetworkAccessPresetFull NetworkAccessPreset = "full"
)

// PolicyNetworkEndpoint describes a full network endpoint with its access controls
// as used in sandbox network policy rules. This is distinct from [NetworkEndpoint]
// which is the simplified profile-level endpoint (Host, Ports, Protocol only).
type PolicyNetworkEndpoint struct {
	Host                         string
	Ports                        []uint32
	Protocol                     string
	TLS                          NetworkTLSMode
	Enforcement                  NetworkEnforcementMode
	Access                       NetworkAccessPreset
	Rules                        []L7Rule
	AllowedIPs                   []string
	DenyRules                    []L7DenyRule
	AllowEncodedSlash            bool
	PersistedQueries             string
	GraphqlPersistedQueries      map[string]GraphqlOperation
	GraphqlMaxBodyBytes          uint32
	Path                         string
	WebsocketCredentialRewrite   bool
	RequestBodyCredentialRewrite bool
	// AllowUninspectedCredentials explicitly permits credential-bearing traffic
	// on paths OpenShell cannot inspect or rewrite.
	AllowUninspectedCredentials bool
	CredentialSigning           string
	SigningService              string
	SigningRegion               string
	JSONRPCMaxBodyBytes         uint32
	Mcp                         *McpOptions
	CredentialBinding           *NetworkCredentialBinding
}

// NetworkCredentialBinding binds an endpoint to static credentials from an attached provider.
type NetworkCredentialBinding struct {
	Provider string
}

// PolicyNetworkBinary identifies a binary subject to network policy enforcement.
// This is distinct from [NetworkBinary] which is the simplified profile-level binary.
type PolicyNetworkBinary struct {
	// Path is the filesystem path to the binary.
	Path string
}

// L7Rule wraps an L7 allow rule.
type L7Rule struct {
	// Allow holds the layer-7 allow criteria.
	Allow *L7Allow
}

// L7Allow specifies layer-7 allow criteria for HTTP/GraphQL traffic.
type L7Allow struct {
	Method        string
	Path          string
	Command       string
	Query         map[string]L7QueryMatcher
	OperationType string
	OperationName string
	Fields        []string
	Tool          *L7QueryMatcher
	Params        map[string]ParameterMatcher
}

// L7DenyRule specifies layer-7 deny criteria for HTTP/GraphQL traffic.
type L7DenyRule struct {
	Method        string
	Path          string
	Command       string
	Query         map[string]L7QueryMatcher
	OperationType string
	OperationName string
	Fields        []string
	Tool          *L7QueryMatcher
	Params        map[string]ParameterMatcher
}

// L7QueryMatcher matches query parameters by glob pattern or exact values.
type L7QueryMatcher struct {
	Glob string
	Any  []string
}

// ParameterMatcher recursively matches either a scalar value or an object.
// Exactly one of Matcher or Object should be set.
type ParameterMatcher struct {
	Matcher *L7QueryMatcher
	Object  map[string]ParameterMatcher
}

// McpOptions configures MCP-specific policy controls on a network endpoint.
type McpOptions struct {
	MaxBodyBytes            uint32
	StrictToolNames         *bool
	AllowAllKnownMcpMethods *bool
	// Versions lists the exact MCP protocol revisions accepted by the endpoint.
	// An empty list represents omission at the protobuf transport boundary; the
	// checked policy or server ingress materializes the pinned default
	// "2025-11-25" before storing canonical state. Nonempty lists remain exact
	// allowlists.
	Versions []string
}

// GraphqlOperation describes a GraphQL operation for persisted-query validation.
type GraphqlOperation struct {
	OperationType string
	OperationName string
	Fields        []string
}

// --- MergeOperation types ---

// PolicyMergeOperation represents a single atomic policy mutation.
// Exactly one of the pointer fields must be non-nil, modelling the proto oneof.
type PolicyMergeOperation struct {
	// AddRule adds a new named network policy rule.
	AddRule *AddNetworkRule
	// RemoveEndpoint removes a single endpoint from a rule.
	RemoveEndpoint *RemoveNetworkEndpoint
	// RemoveRule removes an entire named rule.
	RemoveRule *RemoveNetworkRule
	// AddDenyRules appends deny rules to an endpoint.
	AddDenyRules *AddDenyRules
	// AddAllowRules appends allow rules to an endpoint.
	AddAllowRules *AddAllowRules
	// RemoveBinary removes a binary from a rule.
	RemoveBinary *RemoveNetworkBinary
}

// AddNetworkRule adds a named network policy rule with a full rule definition.
type AddNetworkRule struct {
	// RuleName is the name key for the rule.
	RuleName string
	// Rule is the full network policy rule to add.
	Rule NetworkPolicyRule
}

// RemoveNetworkEndpoint removes a specific endpoint from a named rule.
type RemoveNetworkEndpoint struct {
	// RuleName is the name of the rule containing the endpoint.
	RuleName string
	// Host is the endpoint host to remove.
	Host string
	// Port is the endpoint port to remove.
	Port uint32
}

// RemoveNetworkRule removes an entire named rule from the policy.
type RemoveNetworkRule struct {
	// RuleName is the name of the rule to remove.
	RuleName string
}

// L7RuleTarget identifies an endpoint and declares its complete affected scope.
// The gateway requires the ports and binary scope to match the stored endpoint
// and rule before appending any layer-7 rules.
type L7RuleTarget struct {
	// RuleName names the base-policy rule containing the endpoint.
	RuleName string
	// Host is the endpoint host, matched case-insensitively.
	Host string
	// Ports lists every port affected by the append, not only a lookup port.
	Ports []uint32
	// Path selects the endpoint path, distinct from an appended request path.
	// Nil requires a unique endpoint; a pointer to "" selects an unscoped endpoint.
	Path *string
	// Binaries lists every binary governed by the containing rule.
	// Exactly one of a nonempty Binaries list or AnyBinary=true is required.
	Binaries []PolicyNetworkBinary
	// AnyBinary explicitly acknowledges a rule with unrestricted binary scope.
	AnyBinary bool
}

// AddDenyRules appends layer-7 deny rules to a specific endpoint.
type AddDenyRules struct {
	// Target is required and declares the full scope affected by the append.
	Target *L7RuleTarget
	// DenyRules are the deny rules to append.
	DenyRules []L7DenyRule
}

// AddAllowRules appends layer-7 allow rules to a specific endpoint.
type AddAllowRules struct {
	// Target is required and declares the full scope affected by the append.
	Target *L7RuleTarget
	// Rules are the allow rules to append.
	Rules []L7Rule
}

// RemoveNetworkBinary removes a binary from a named rule.
type RemoveNetworkBinary struct {
	// RuleName is the name of the rule containing the binary.
	RuleName string
	// BinaryPath is the filesystem path of the binary to remove.
	BinaryPath string
}
