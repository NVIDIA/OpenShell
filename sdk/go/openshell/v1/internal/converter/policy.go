// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"fmt"
	"strings"

	"buf.build/go/protovalidate"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	policyv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/policyv1"
	sbv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"google.golang.org/protobuf/types/known/structpb"
)

// --- PolicyLoadStatus enum mapping ---

// PolicyLoadStatusFromProto converts a proto PolicyStatus to an SDK PolicyLoadStatus.
func PolicyLoadStatusFromProto(s pb.PolicyStatus) types.PolicyLoadStatus {
	switch s {
	case pb.PolicyStatus_POLICY_STATUS_PENDING:
		return types.PolicyLoadStatusPending
	case pb.PolicyStatus_POLICY_STATUS_LOADED:
		return types.PolicyLoadStatusLoaded
	case pb.PolicyStatus_POLICY_STATUS_FAILED:
		return types.PolicyLoadStatusFailed
	case pb.PolicyStatus_POLICY_STATUS_SUPERSEDED:
		return types.PolicyLoadStatusSuperseded
	default:
		return types.PolicyLoadStatusUnspecified
	}
}

// PolicyLoadStatusToProto converts an SDK PolicyLoadStatus to a proto PolicyStatus.
func PolicyLoadStatusToProto(s types.PolicyLoadStatus) pb.PolicyStatus {
	switch s {
	case types.PolicyLoadStatusPending:
		return pb.PolicyStatus_POLICY_STATUS_PENDING
	case types.PolicyLoadStatusLoaded:
		return pb.PolicyStatus_POLICY_STATUS_LOADED
	case types.PolicyLoadStatusFailed:
		return pb.PolicyStatus_POLICY_STATUS_FAILED
	case types.PolicyLoadStatusSuperseded:
		return pb.PolicyStatus_POLICY_STATUS_SUPERSEDED
	default:
		return pb.PolicyStatus_POLICY_STATUS_UNSPECIFIED
	}
}

// --- PolicyChunk ---

// PolicyChunkFromProto converts a proto PolicyChunk to an SDK PolicyChunk.
func PolicyChunkFromProto(c *pb.PolicyChunk) *types.PolicyChunk {
	if c == nil {
		return nil
	}
	return &types.PolicyChunk{
		ID:                           c.GetId(),
		Status:                       c.GetStatus(),
		RuleName:                     c.GetRuleName(),
		ProposedRule:                 NetworkPolicyRuleFromProto(c.GetProposedRule()),
		Rationale:                    c.GetRationale(),
		SecurityNotes:                c.GetSecurityNotes(),
		Confidence:                   c.GetConfidence(),
		DenialSummaryIDs:             CopyStringSlice(c.GetDenialSummaryIds()),
		CreatedAt:                    TimeFromProto(c.GetCreatedTime()),
		DecidedAt:                    TimeFromProto(c.GetDecidedTime()),
		Stage:                        c.GetStage(),
		SupersedesChunkID:            c.GetSupersedesChunkId(),
		HitCount:                     c.GetHitCount(),
		FirstSeen:                    TimeFromProto(c.GetFirstSeenTime()),
		LastSeen:                     TimeFromProto(c.GetLastSeenTime()),
		Binary:                       c.GetBinary(),
		ValidationResult:             c.GetValidationResult(),
		RejectionReason:              c.GetRejectionReason(),
		ApplicationError:             c.GetApplicationError(),
		ReviewToken:                  c.GetReviewToken(),
		CurrentEffectivePolicyHash:   c.GetCurrentEffectivePolicyHash(),
		CandidateEffectivePolicyHash: c.GetCandidateEffectivePolicyHash(),
		CurrentEffectivePolicy:       PolicyDocumentFromProto(c.GetCurrentEffectivePolicy()),
		CandidateEffectivePolicy:     PolicyDocumentFromProto(c.GetCandidateEffectivePolicy()),
	}
}

// --- DraftPolicy ---

// DraftPolicyFromProto converts a proto GetDraftPolicyResponse to an SDK DraftPolicy.
func DraftPolicyFromProto(r *pb.GetDraftPolicyResponse) *types.DraftPolicy {
	if r == nil {
		return nil
	}
	result := &types.DraftPolicy{
		RollingSummary: r.GetRollingSummary(),
		DraftVersion:   r.GetDraftVersion(),
		LastAnalyzedAt: TimeFromProto(r.GetLastAnalyzedTime()),
	}
	if chunks := r.GetChunks(); len(chunks) > 0 {
		result.Chunks = make([]types.PolicyChunk, 0, len(chunks))
		for _, c := range chunks {
			if converted := PolicyChunkFromProto(c); converted != nil {
				result.Chunks = append(result.Chunks, *converted)
			}
		}
	}
	return result
}

// --- PolicyDocument ---

// PolicyDocumentFromProto converts a proto PolicyDocument to an SDK PolicyDocument.
// Returns nil for nil input. All slice and map fields are deep-copied.
func PolicyDocumentFromProto(p *policyv1.PolicyDocument) *types.PolicyDocument {
	if p == nil {
		return nil
	}
	result := &types.PolicyDocument{
		Version:    p.GetVersion(),
		Filesystem: filesystemPolicyFromProto(p.GetFilesystemPolicy()),
		Landlock:   landlockPolicyFromProto(p.GetLandlock()),
		Process:    processPolicyFromProto(p.GetProcess()),
	}
	if np := p.GetNetworkPolicies(); np != nil {
		result.NetworkPolicies = make(map[string]types.NetworkPolicyRule, len(np))
		for k, v := range np {
			if converted := NetworkPolicyRuleFromProto(v); converted != nil {
				result.NetworkPolicies[k] = *converted
			}
		}
	}
	if mw := p.GetNetworkMiddlewares(); mw != nil {
		result.NetworkMiddlewares = make(map[string]types.NetworkMiddlewareConfig, len(mw))
		for k, v := range mw {
			if v != nil {
				result.NetworkMiddlewares[k] = middlewareConfigFromProto(v)
			}
		}
	}
	return result
}

// PolicyDocumentFromInternalProto projects the supervisor's internal policy
// response onto the authored policy contract. The schemas deliberately are
// not wire-compatible: the internal message uses enums and normalized matcher
// fields, and it carries runtime-only authority that must not cross this SDK
// boundary.
func PolicyDocumentFromInternalProto(p *sbv1.SandboxPolicy) *types.PolicyDocument {
	if p == nil {
		return nil
	}
	return PolicyDocumentFromProto(publicPolicyFromInternalProto(p))
}

func publicPolicyFromInternalProto(p *sbv1.SandboxPolicy) *policyv1.PolicyDocument {
	result := &policyv1.PolicyDocument{Version: p.GetVersion()}
	if filesystem := p.GetFilesystem(); filesystem != nil {
		result.FilesystemPolicy = &policyv1.FilesystemPolicy{
			IncludeWorkdir: filesystem.GetIncludeWorkdir(),
			ReadOnly:       CopyStringSlice(filesystem.GetReadOnly()),
			ReadWrite:      CopyStringSlice(filesystem.GetReadWrite()),
		}
	}
	if landlock := p.GetLandlock(); landlock != nil {
		result.Landlock = &policyv1.LandlockPolicy{Compatibility: landlock.GetCompatibility()}
	}
	if process := p.GetProcess(); process != nil {
		result.Process = &policyv1.ProcessPolicy{
			RunAsUser:  process.GetRunAsUser(),
			RunAsGroup: process.GetRunAsGroup(),
		}
	}
	if policies := p.GetNetworkPolicies(); policies != nil {
		result.NetworkPolicies = make(map[string]*policyv1.NetworkPolicyRule, len(policies))
		for name, rule := range policies {
			if rule != nil {
				result.NetworkPolicies[name] = publicNetworkRuleFromInternalProto(rule)
			}
		}
	}
	if middlewares := p.GetNetworkMiddlewares(); middlewares != nil {
		result.NetworkMiddlewares = make(map[string]*policyv1.NetworkMiddleware, len(middlewares))
		for name, middleware := range middlewares {
			if middleware == nil {
				continue
			}
			converted := &policyv1.NetworkMiddleware{
				Name:       middleware.GetName(),
				Middleware: middleware.GetMiddleware(),
				Config:     middleware.GetConfig(),
				OnError:    middleware.GetOnError(),
				Order:      middleware.GetOrder(),
			}
			if endpoints := middleware.GetEndpoints(); endpoints != nil {
				converted.Endpoints = &policyv1.MiddlewareEndpointSelector{
					Include: CopyStringSlice(endpoints.GetInclude()),
					Exclude: CopyStringSlice(endpoints.GetExclude()),
				}
			}
			result.NetworkMiddlewares[name] = converted
		}
	}
	return result
}

func publicNetworkRuleFromInternalProto(rule *sbv1.NetworkPolicyRule) *policyv1.NetworkPolicyRule {
	result := &policyv1.NetworkPolicyRule{Name: rule.GetName()}
	if endpoints := rule.GetEndpoints(); len(endpoints) > 0 {
		result.Endpoints = make([]*policyv1.NetworkEndpoint, 0, len(endpoints))
		for _, endpoint := range endpoints {
			if endpoint != nil {
				result.Endpoints = append(result.Endpoints, publicNetworkEndpointFromInternalProto(endpoint))
			}
		}
	}
	if binaries := rule.GetBinaries(); len(binaries) > 0 {
		result.Binaries = make([]*policyv1.NetworkBinary, 0, len(binaries))
		for _, binary := range binaries {
			if binary != nil {
				result.Binaries = append(result.Binaries, &policyv1.NetworkBinary{Path: binary.GetPath()})
			}
		}
	}
	return result
}

func publicNetworkEndpointFromInternalProto(endpoint *sbv1.NetworkEndpoint) *policyv1.NetworkEndpoint {
	protocol := endpoint.GetProtocol()
	result := &policyv1.NetworkEndpoint{
		Host:                         endpoint.GetHost(),
		Protocol:                     protocol,
		Tls:                          publicTLSMode(endpoint.GetTls()),
		Enforcement:                  publicEnforcementMode(endpoint.GetEnforcement()),
		Access:                       publicAccessPreset(endpoint.GetAccess()),
		AllowedIps:                   CopyStringSlice(endpoint.GetAllowedIps()),
		AllowEncodedSlash:            endpoint.GetAllowEncodedSlash(),
		PersistedQueries:             endpoint.GetPersistedQueries(),
		GraphqlMaxBodyBytes:          endpoint.GetGraphqlMaxBodyBytes(),
		Path:                         endpoint.GetPath(),
		WebsocketCredentialRewrite:   endpoint.GetWebsocketCredentialRewrite(),
		RequestBodyCredentialRewrite: endpoint.GetRequestBodyCredentialRewrite(),
		AllowUninspectedCredentials:  endpoint.GetAllowUninspectedCredentials(),
		CredentialSigning:            endpoint.GetCredentialSigning(),
		SigningService:               endpoint.GetSigningService(),
		SigningRegion:                endpoint.GetSigningRegion(),
	}
	if ports := endpoint.GetPorts(); len(ports) > 0 {
		result.Ports = stableUnique(ports)
	} else if port := endpoint.GetPort(); port != 0 {
		// Older internal records may still use the legacy scalar port. The
		// authored contract has only the canonical list representation.
		result.Ports = []uint32{port}
	}
	if binding := endpoint.GetCredentialBinding(); binding != nil {
		result.CredentialBinding = &policyv1.NetworkCredentialBinding{Provider: binding.GetProvider()}
	}
	if operations := endpoint.GetGraphqlPersistedQueries(); len(operations) > 0 {
		result.GraphqlPersistedQueries = make(map[string]*policyv1.GraphqlOperation, len(operations))
		for name, operation := range operations {
			if operation != nil {
				result.GraphqlPersistedQueries[name] = &policyv1.GraphqlOperation{
					OperationType: operation.GetOperationType(),
					OperationName: operation.GetOperationName(),
					Fields:        CopyStringSlice(operation.GetFields()),
				}
			}
		}
	}
	if rules := endpoint.GetRules(); len(rules) > 0 {
		result.Rules = make([]*policyv1.L7Rule, 0, len(rules))
		for _, rule := range rules {
			if rule != nil {
				result.Rules = append(result.Rules, publicL7RuleFromInternalProto(protocol, endpoint.GetMcp(), rule))
			}
		}
	}
	if rules := endpoint.GetDenyRules(); len(rules) > 0 {
		result.DenyRules = make([]*policyv1.L7DenyRule, 0, len(rules))
		for _, rule := range rules {
			if rule != nil {
				result.DenyRules = append(result.DenyRules, publicL7DenyRuleFromInternalProto(protocol, endpoint.GetMcp(), rule))
			}
		}
	}
	if strings.EqualFold(protocol, "mcp") {
		if options := endpoint.GetMcp(); options != nil || endpoint.GetJsonRpcMaxBodyBytes() != 0 {
			result.Mcp = &policyv1.McpConfig{MaxBodyBytes: endpoint.GetJsonRpcMaxBodyBytes()}
			if options != nil {
				result.Mcp.Versions = CopyStringSlice(options.GetVersions())
				result.Mcp.StrictToolNames = CopyBoolPtr(options.StrictToolNames)
				result.Mcp.AllowAllKnownMcpMethods = CopyBoolPtr(options.AllowAllKnownMcpMethods)
			}
		}
	} else if endpoint.GetJsonRpcMaxBodyBytes() != 0 {
		result.JsonRpc = &policyv1.JsonRpcConfig{MaxBodyBytes: endpoint.GetJsonRpcMaxBodyBytes()}
	}
	return result
}

func publicL7RuleFromInternalProto(protocol string, options *sbv1.McpOptions, rule *sbv1.L7Rule) *policyv1.L7Rule {
	result := &policyv1.L7Rule{}
	if allow := rule.GetAllow(); allow != nil {
		tool, params := publicParamsFromInternalProto(protocol, allow.GetParams())
		result.Allow = &policyv1.L7Allow{
			Method:        publicMCPMethod(protocol, options, allow.GetMethod(), tool != nil),
			Path:          allow.GetPath(),
			Command:       allow.GetCommand(),
			Query:         publicMatcherMapFromInternalProto(allow.GetQuery()),
			OperationType: allow.GetOperationType(),
			OperationName: allow.GetOperationName(),
			Fields:        CopyStringSlice(allow.GetFields()),
			Tool:          tool,
			Params:        params,
		}
	}
	return result
}

func publicL7DenyRuleFromInternalProto(protocol string, options *sbv1.McpOptions, rule *sbv1.L7DenyRule) *policyv1.L7DenyRule {
	tool, params := publicParamsFromInternalProto(protocol, rule.GetParams())
	return &policyv1.L7DenyRule{
		Method:        publicMCPMethod(protocol, options, rule.GetMethod(), tool != nil),
		Path:          rule.GetPath(),
		Command:       rule.GetCommand(),
		Query:         publicMatcherMapFromInternalProto(rule.GetQuery()),
		OperationType: rule.GetOperationType(),
		OperationName: rule.GetOperationName(),
		Fields:        CopyStringSlice(rule.GetFields()),
		Tool:          tool,
		Params:        params,
	}
}

func publicMCPMethod(protocol string, options *sbv1.McpOptions, method string, hasTool bool) string {
	if !strings.EqualFold(protocol, "mcp") {
		return method
	}
	if !hasTool && method == "*" {
		return ""
	}
	if hasTool && method == "tools/call" && options != nil && options.GetAllowAllKnownMcpMethods() {
		return ""
	}
	return method
}

func publicParamsFromInternalProto(protocol string, params map[string]*sbv1.L7QueryMatcher) (*policyv1.Matcher, map[string]*policyv1.ParameterMatcher) {
	if len(params) == 0 {
		return nil, nil
	}
	remaining := params
	var tool *policyv1.Matcher
	if strings.EqualFold(protocol, "mcp") {
		remaining = make(map[string]*sbv1.L7QueryMatcher, len(params))
		for name, matcher := range params {
			if name == "name" {
				tool = publicMatcherFromInternalProto(matcher)
			} else {
				remaining[name] = matcher
			}
		}
		if nested, ok := publicNestedParamsFromInternalProto(remaining); ok {
			return tool, nested
		}
	}
	return tool, publicFlatParamsFromInternalProto(remaining)
}

func publicNestedParamsFromInternalProto(params map[string]*sbv1.L7QueryMatcher) (map[string]*policyv1.ParameterMatcher, bool) {
	if len(params) == 0 {
		return nil, true
	}
	result := make(map[string]*policyv1.ParameterMatcher, len(params))
	for name, matcher := range params {
		parts := strings.Split(name, ".")
		if len(parts) == 0 {
			return nil, false
		}
		current := result
		for index, part := range parts {
			if part == "" {
				return nil, false
			}
			last := index == len(parts)-1
			existing, found := current[part]
			if last {
				if found {
					return nil, false
				}
				current[part] = &policyv1.ParameterMatcher{Kind: &policyv1.ParameterMatcher_Matcher{
					Matcher: publicMatcherFromInternalProto(matcher),
				}}
				continue
			}
			if !found {
				existing = &policyv1.ParameterMatcher{Kind: &policyv1.ParameterMatcher_Object{
					Object: &policyv1.ParameterObject{Fields: make(map[string]*policyv1.ParameterMatcher)},
				}}
				current[part] = existing
			}
			object := existing.GetObject()
			if object == nil {
				return nil, false
			}
			current = object.Fields
		}
	}
	return result, true
}

func publicFlatParamsFromInternalProto(params map[string]*sbv1.L7QueryMatcher) map[string]*policyv1.ParameterMatcher {
	if len(params) == 0 {
		return nil
	}
	result := make(map[string]*policyv1.ParameterMatcher, len(params))
	for name, matcher := range params {
		result[name] = &policyv1.ParameterMatcher{Kind: &policyv1.ParameterMatcher_Matcher{
			Matcher: publicMatcherFromInternalProto(matcher),
		}}
	}
	return result
}

func publicMatcherMapFromInternalProto(matchers map[string]*sbv1.L7QueryMatcher) map[string]*policyv1.Matcher {
	if len(matchers) == 0 {
		return nil
	}
	result := make(map[string]*policyv1.Matcher, len(matchers))
	for name, matcher := range matchers {
		result[name] = publicMatcherFromInternalProto(matcher)
	}
	return result
}

func publicMatcherFromInternalProto(matcher *sbv1.L7QueryMatcher) *policyv1.Matcher {
	if matcher != nil && len(matcher.GetAny()) > 0 {
		return &policyv1.Matcher{Kind: &policyv1.Matcher_Any{Any: &policyv1.AnyMatcher{
			Values: stableUnique(matcher.GetAny()),
		}}}
	}
	glob := ""
	if matcher != nil {
		glob = matcher.GetGlob()
	}
	return &policyv1.Matcher{Kind: &policyv1.Matcher_Glob{Glob: glob}}
}

// stableUnique canonicalizes legacy runtime lists for public fields whose
// protobuf contract requires unique values. Retaining the first occurrence
// keeps the projection deterministic without changing caller-visible order.
func stableUnique[T comparable](values []T) []T {
	result := make([]T, 0, len(values))
	seen := make(map[T]struct{}, len(values))
	for _, value := range values {
		if _, found := seen[value]; found {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}

func publicTLSMode(mode sbv1.NetworkTlsMode) string {
	// Numeric cases keep the explicit projection compatible with deprecated
	// internal enum values without making new SDK code depend on their names.
	switch int32(mode) {
	case 1:
		return "skip"
	case 2:
		return "terminate"
	case 3:
		return "passthrough"
	default:
		return ""
	}
}

func publicEnforcementMode(mode sbv1.NetworkEnforcementMode) string {
	switch mode {
	case sbv1.NetworkEnforcementMode_NETWORK_ENFORCEMENT_MODE_ENFORCE:
		return "enforce"
	case sbv1.NetworkEnforcementMode_NETWORK_ENFORCEMENT_MODE_AUDIT:
		return "audit"
	default:
		return ""
	}
}

func publicAccessPreset(preset sbv1.NetworkAccessPreset) string {
	switch preset {
	case sbv1.NetworkAccessPreset_NETWORK_ACCESS_PRESET_READ_ONLY:
		return "read-only"
	case sbv1.NetworkAccessPreset_NETWORK_ACCESS_PRESET_READ_WRITE:
		return "read-write"
	case sbv1.NetworkAccessPreset_NETWORK_ACCESS_PRESET_FULL:
		return "full"
	default:
		return ""
	}
}

// PolicyDocumentToProto converts an SDK PolicyDocument to a proto PolicyDocument.
// Returns nil for nil input. All slice and map fields are deep-copied.
func PolicyDocumentToProto(p *types.PolicyDocument) *policyv1.PolicyDocument {
	if p == nil {
		return nil
	}
	result := &policyv1.PolicyDocument{
		Version:          p.Version,
		FilesystemPolicy: filesystemPolicyToProto(p.Filesystem),
		Landlock:         landlockPolicyToProto(p.Landlock),
		Process:          processPolicyToProto(p.Process),
	}
	if p.NetworkPolicies != nil {
		result.NetworkPolicies = make(map[string]*policyv1.NetworkPolicyRule, len(p.NetworkPolicies))
		for k, v := range p.NetworkPolicies {
			result.NetworkPolicies[k] = NetworkPolicyRuleToProto(&v)
		}
	}
	if p.NetworkMiddlewares != nil {
		result.NetworkMiddlewares = make(map[string]*policyv1.NetworkMiddleware, len(p.NetworkMiddlewares))
		for k, v := range p.NetworkMiddlewares {
			result.NetworkMiddlewares[k] = middlewareConfigToProto(&v)
		}
	}
	return result
}

// PolicyDocumentToProtoChecked converts middleware configuration without
// silently discarding values unsupported by protobuf Struct.
func PolicyDocumentToProtoChecked(p *types.PolicyDocument) (*policyv1.PolicyDocument, error) {
	result := PolicyDocumentToProto(p)
	if p == nil {
		return result, nil
	}
	for name, middleware := range p.NetworkMiddlewares {
		if middleware.Config == nil {
			continue
		}
		config, err := structpb.NewStruct(middleware.Config)
		if err != nil {
			return nil, fmt.Errorf("network middleware %q config: %w", name, err)
		}
		result.NetworkMiddlewares[name].Config = config
	}
	if err := protovalidate.Validate(result); err != nil {
		return nil, fmt.Errorf("policy document validation: %w", err)
	}
	return result, nil
}

func middlewareConfigFromProto(m *policyv1.NetworkMiddleware) types.NetworkMiddlewareConfig {
	result := types.NetworkMiddlewareConfig{
		Name:       m.GetName(),
		Middleware: m.GetMiddleware(),
		OnError:    m.GetOnError(),
		Order:      m.GetOrder(),
	}
	if c := m.GetConfig(); c != nil {
		result.Config = c.AsMap()
	}
	if ep := m.GetEndpoints(); ep != nil {
		result.Endpoints = &types.MiddlewareEndpointSelector{
			Include: CopyStringSlice(ep.GetInclude()),
			Exclude: CopyStringSlice(ep.GetExclude()),
		}
	}
	return result
}

func middlewareConfigToProto(m *types.NetworkMiddlewareConfig) *policyv1.NetworkMiddleware {
	result := &policyv1.NetworkMiddleware{
		Name:       m.Name,
		Middleware: m.Middleware,
		OnError:    m.OnError,
		Order:      m.Order,
	}
	if m.Config != nil {
		// Non-JSON-compatible values (e.g., chan, func) are silently dropped.
		// Round-trip data from structpb.AsMap is always re-serializable.
		s, err := structpb.NewStruct(m.Config)
		if err == nil {
			result.Config = s
		}
	}
	if m.Endpoints != nil {
		result.Endpoints = &policyv1.MiddlewareEndpointSelector{
			Include: CopyStringSlice(m.Endpoints.Include),
			Exclude: CopyStringSlice(m.Endpoints.Exclude),
		}
	}
	return result
}

func filesystemPolicyFromProto(f *policyv1.FilesystemPolicy) *types.FilesystemPolicy {
	if f == nil {
		return nil
	}
	return &types.FilesystemPolicy{
		IncludeWorkdir: f.GetIncludeWorkdir(),
		ReadOnly:       CopyStringSlice(f.GetReadOnly()),
		ReadWrite:      CopyStringSlice(f.GetReadWrite()),
	}
}

func filesystemPolicyToProto(f *types.FilesystemPolicy) *policyv1.FilesystemPolicy {
	if f == nil {
		return nil
	}
	return &policyv1.FilesystemPolicy{
		IncludeWorkdir: f.IncludeWorkdir,
		ReadOnly:       CopyStringSlice(f.ReadOnly),
		ReadWrite:      CopyStringSlice(f.ReadWrite),
	}
}

func landlockPolicyFromProto(l *policyv1.LandlockPolicy) *types.LandlockPolicy {
	if l == nil {
		return nil
	}
	return &types.LandlockPolicy{
		Compatibility: l.GetCompatibility(),
	}
}

func landlockPolicyToProto(l *types.LandlockPolicy) *policyv1.LandlockPolicy {
	if l == nil {
		return nil
	}
	return &policyv1.LandlockPolicy{
		Compatibility: l.Compatibility,
	}
}

func processPolicyFromProto(p *policyv1.ProcessPolicy) *types.ProcessPolicy {
	if p == nil {
		return nil
	}
	return &types.ProcessPolicy{
		RunAsUser:  p.GetRunAsUser(),
		RunAsGroup: p.GetRunAsGroup(),
	}
}

func processPolicyToProto(p *types.ProcessPolicy) *policyv1.ProcessPolicy {
	if p == nil {
		return nil
	}
	return &policyv1.ProcessPolicy{
		RunAsUser:  p.RunAsUser,
		RunAsGroup: p.RunAsGroup,
	}
}

// --- SandboxPolicyRevision ---

// SandboxPolicyRevisionFromProto converts a proto SandboxPolicyRevision to an SDK SandboxPolicyRevision.
func SandboxPolicyRevisionFromProto(r *pb.SandboxPolicyRevision) *types.SandboxPolicyRevision {
	if r == nil {
		return nil
	}
	return &types.SandboxPolicyRevision{
		Version:    r.GetVersion(),
		PolicyHash: r.GetPolicyHash(),
		Status:     PolicyLoadStatusFromProto(r.GetStatus()),
		LoadError:  r.GetLoadError(),
		CreatedAt:  TimeFromProto(r.GetCreatedTime()),
		LoadedAt:   TimeFromProto(r.GetLoadedTime()),
		Policy:     PolicyDocumentFromProto(r.GetPolicy()),
		Provenance: CopyStringMap(r.GetProvenance()),
	}
}

// --- PolicyStatusResult ---

// PolicyStatusResultFromProto converts a proto GetSandboxPolicyStatusResponse to an SDK PolicyStatusResult.
func PolicyStatusResultFromProto(r *pb.GetSandboxPolicyStatusResponse) *types.PolicyStatusResult {
	if r == nil {
		return nil
	}
	result := &types.PolicyStatusResult{
		ActiveVersion: r.GetActiveVersion(),
	}
	if rev := SandboxPolicyRevisionFromProto(r.GetRevision()); rev != nil {
		result.Revision = *rev
	}
	return result
}

// --- ApproveResult ---

// ApproveResultFromProto converts a proto ApproveDraftChunkResponse to an SDK ApproveResult.
func ApproveResultFromProto(r *pb.ApproveDraftChunkResponse) *types.ApproveResult {
	if r == nil {
		return nil
	}
	return &types.ApproveResult{
		PolicyVersion: r.GetPolicyVersion(),
		PolicyHash:    r.GetPolicyHash(),
	}
}

// --- ApproveAllResult ---

// ApproveAllResultFromProto converts a proto ApproveAllDraftChunksResponse to an SDK ApproveAllResult.
func ApproveAllResultFromProto(r *pb.ApproveAllDraftChunksResponse) *types.ApproveAllResult {
	if r == nil {
		return nil
	}
	return &types.ApproveAllResult{
		PolicyVersion:  r.GetPolicyVersion(),
		PolicyHash:     r.GetPolicyHash(),
		ChunksApproved: r.GetChunksApproved(),
		ChunksSkipped:  r.GetChunksSkipped(),
	}
}

// --- UndoResult ---

// UndoResultFromProto converts a proto UndoDraftChunkResponse to an SDK UndoResult.
func UndoResultFromProto(r *pb.UndoDraftChunkResponse) *types.UndoResult {
	if r == nil {
		return nil
	}
	return &types.UndoResult{
		PolicyVersion: r.GetPolicyVersion(),
		PolicyHash:    r.GetPolicyHash(),
	}
}

// --- ClearResult ---

// ClearResultFromProto converts a proto ClearDraftChunksResponse to an SDK ClearResult.
func ClearResultFromProto(r *pb.ClearDraftChunksResponse) *types.ClearResult {
	if r == nil {
		return nil
	}
	return &types.ClearResult{
		ChunksCleared: r.GetChunksCleared(),
	}
}

// --- DraftHistoryEntry ---

// DraftHistoryEntryFromProto converts a proto DraftHistoryEntry to an SDK DraftHistoryEntry.
func DraftHistoryEntryFromProto(e *pb.DraftHistoryEntry) *types.DraftHistoryEntry {
	if e == nil {
		return nil
	}
	return &types.DraftHistoryEntry{
		Timestamp:   TimeFromProto(e.GetEventTime()),
		EventType:   e.GetEventType(),
		Description: e.GetDescription(),
		ChunkID:     e.GetChunkId(),
	}
}
