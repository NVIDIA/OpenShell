// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sbv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
)

// --- ProfileCategory enum mapping ---

// ProfileCategoryFromProto converts a proto ProviderProfileCategory to an SDK ProfileCategory.
func ProfileCategoryFromProto(c pb.ProviderProfileCategory) types.ProfileCategory {
	switch c {
	case pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_OTHER:
		return types.ProfileCategoryOther
	case pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_INFERENCE:
		return types.ProfileCategoryInference
	case pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_AGENT:
		return types.ProfileCategoryAgent
	case pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_SOURCE_CONTROL:
		return types.ProfileCategorySourceControl
	case pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_MESSAGING:
		return types.ProfileCategoryMessaging
	case pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_DATA:
		return types.ProfileCategoryData
	case pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_KNOWLEDGE:
		return types.ProfileCategoryKnowledge
	default:
		return types.ProfileCategory("")
	}
}

// ProfileCategoryToProto converts an SDK ProfileCategory to a proto ProviderProfileCategory.
func ProfileCategoryToProto(c types.ProfileCategory) pb.ProviderProfileCategory {
	switch c {
	case types.ProfileCategoryOther:
		return pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_OTHER
	case types.ProfileCategoryInference:
		return pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_INFERENCE
	case types.ProfileCategoryAgent:
		return pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_AGENT
	case types.ProfileCategorySourceControl:
		return pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_SOURCE_CONTROL
	case types.ProfileCategoryMessaging:
		return pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_MESSAGING
	case types.ProfileCategoryData:
		return pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_DATA
	case types.ProfileCategoryKnowledge:
		return pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_KNOWLEDGE
	default:
		return pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_UNSPECIFIED
	}
}

// --- NetworkEndpoint ---

// NetworkEndpointFromProto converts a proto NetworkEndpoint to an SDK NetworkEndpoint.
// Only Host, Port, and Protocol are mapped; additional proto fields are ignored.
func NetworkEndpointFromProto(ep *sbv1.NetworkEndpoint) *types.NetworkEndpoint {
	if ep == nil {
		return nil
	}
	return &types.NetworkEndpoint{
		Host:     ep.GetHost(),
		Port:     ep.GetPort(),
		Protocol: ep.GetProtocol(),
	}
}

// NetworkEndpointToProto converts an SDK NetworkEndpoint to a proto NetworkEndpoint.
func NetworkEndpointToProto(ep *types.NetworkEndpoint) *sbv1.NetworkEndpoint {
	if ep == nil {
		return nil
	}
	return &sbv1.NetworkEndpoint{
		Host:     ep.Host,
		Port:     ep.Port,
		Protocol: ep.Protocol,
	}
}

// --- NetworkBinary ---

// NetworkBinaryFromProto converts a proto NetworkBinary to an SDK NetworkBinary.
func NetworkBinaryFromProto(b *sbv1.NetworkBinary) *types.NetworkBinary {
	if b == nil {
		return nil
	}
	return &types.NetworkBinary{
		Path: b.GetPath(),
	}
}

// NetworkBinaryToProto converts an SDK NetworkBinary to a proto NetworkBinary.
func NetworkBinaryToProto(b *types.NetworkBinary) *sbv1.NetworkBinary {
	if b == nil {
		return nil
	}
	return &sbv1.NetworkBinary{
		Path: b.Path,
	}
}

// --- ProfileCredential ---

// ProfileCredentialFromProto converts a proto ProviderProfileCredential to an SDK ProfileCredential.
// The SDK maps 4 fields from the 10-field proto: Name, Description, Required, and Secret.
// Secret is derived from whether the proto has a Refresh configuration.
func ProfileCredentialFromProto(c *pb.ProviderProfileCredential) *types.ProfileCredential {
	if c == nil {
		return nil
	}
	return &types.ProfileCredential{
		Name:        c.GetName(),
		Description: c.GetDescription(),
		Required:    c.GetRequired(),
		Secret:      c.GetRefresh() != nil,
	}
}

// ProfileCredentialToProto converts an SDK ProfileCredential to a proto ProviderProfileCredential.
// Only Name, Description, and Required are mapped. Secret is not round-trippable
// because it is derived from the Refresh field in the proto.
func ProfileCredentialToProto(c *types.ProfileCredential) *pb.ProviderProfileCredential {
	if c == nil {
		return nil
	}
	return &pb.ProviderProfileCredential{
		Name:        c.Name,
		Description: c.Description,
		Required:    c.Required,
	}
}

// --- ProfileDiagnostic ---

// ProfileDiagnosticFromProto converts a proto ProviderProfileDiagnostic to an SDK ProfileDiagnostic.
func ProfileDiagnosticFromProto(d *pb.ProviderProfileDiagnostic) *types.ProfileDiagnostic {
	if d == nil {
		return nil
	}
	return &types.ProfileDiagnostic{
		Source:    d.GetSource(),
		ProfileID: d.GetProfileId(),
		Field:    d.GetField(),
		Message:  d.GetMessage(),
		Severity: d.GetSeverity(),
	}
}

// --- ProviderProfile ---

// ProviderProfileFromProto converts a proto ProviderProfile to an SDK ProviderProfile.
func ProviderProfileFromProto(p *pb.ProviderProfile) *types.ProviderProfile {
	if p == nil {
		return nil
	}

	result := &types.ProviderProfile{
		ID:               p.GetId(),
		DisplayName:      p.GetDisplayName(),
		Description:      p.GetDescription(),
		Category:         ProfileCategoryFromProto(p.GetCategory()),
		InferenceCapable: p.GetInferenceCapable(),
		ResourceVersion:  p.GetResourceVersion(),
	}

	// Credentials
	if creds := p.GetCredentials(); len(creds) > 0 {
		result.Credentials = make([]types.ProfileCredential, 0, len(creds))
		for _, c := range creds {
			if converted := ProfileCredentialFromProto(c); converted != nil {
				result.Credentials = append(result.Credentials, *converted)
			}
		}
	}

	// Endpoints
	if eps := p.GetEndpoints(); len(eps) > 0 {
		result.Endpoints = make([]types.NetworkEndpoint, 0, len(eps))
		for _, ep := range eps {
			if converted := NetworkEndpointFromProto(ep); converted != nil {
				result.Endpoints = append(result.Endpoints, *converted)
			}
		}
	}

	// Binaries
	if bins := p.GetBinaries(); len(bins) > 0 {
		result.Binaries = make([]types.NetworkBinary, 0, len(bins))
		for _, b := range bins {
			if converted := NetworkBinaryFromProto(b); converted != nil {
				result.Binaries = append(result.Binaries, *converted)
			}
		}
	}

	// Discovery
	if d := p.GetDiscovery(); d != nil {
		result.Discovery = types.ProfileDiscovery{
			Credentials: CopyStringSlice(d.GetCredentials()),
		}
	}

	return result
}

// ProviderProfileToProto converts an SDK ProviderProfile to a proto ProviderProfile.
func ProviderProfileToProto(p *types.ProviderProfile) *pb.ProviderProfile {
	if p == nil {
		return nil
	}

	result := &pb.ProviderProfile{
		Id:               p.ID,
		DisplayName:      p.DisplayName,
		Description:      p.Description,
		Category:         ProfileCategoryToProto(p.Category),
		InferenceCapable: p.InferenceCapable,
		ResourceVersion:  p.ResourceVersion,
	}

	// Credentials
	if len(p.Credentials) > 0 {
		result.Credentials = make([]*pb.ProviderProfileCredential, len(p.Credentials))
		for i := range p.Credentials {
			result.Credentials[i] = ProfileCredentialToProto(&p.Credentials[i])
		}
	}

	// Endpoints
	if len(p.Endpoints) > 0 {
		result.Endpoints = make([]*sbv1.NetworkEndpoint, len(p.Endpoints))
		for i := range p.Endpoints {
			result.Endpoints[i] = NetworkEndpointToProto(&p.Endpoints[i])
		}
	}

	// Binaries
	if len(p.Binaries) > 0 {
		result.Binaries = make([]*sbv1.NetworkBinary, len(p.Binaries))
		for i := range p.Binaries {
			result.Binaries[i] = NetworkBinaryToProto(&p.Binaries[i])
		}
	}

	// Discovery
	if len(p.Discovery.Credentials) > 0 {
		result.Discovery = &pb.ProviderProfileDiscovery{
			Credentials: CopyStringSlice(p.Discovery.Credentials),
		}
	}

	return result
}

// --- ProfileImportItem ---

// ProfileImportItemToProto converts an SDK ProfileImportItem to a proto ProviderProfileImportItem.
func ProfileImportItemToProto(item *types.ProfileImportItem) *pb.ProviderProfileImportItem {
	if item == nil {
		return nil
	}
	return &pb.ProviderProfileImportItem{
		Profile: ProviderProfileToProto(&item.Profile),
		Source:  item.Source,
	}
}

// ProfileImportItemFromProto converts a proto ProviderProfileImportItem to an SDK ProfileImportItem.
func ProfileImportItemFromProto(item *pb.ProviderProfileImportItem) *types.ProfileImportItem {
	if item == nil {
		return nil
	}

	result := &types.ProfileImportItem{
		Source: item.GetSource(),
	}

	if p := ProviderProfileFromProto(item.GetProfile()); p != nil {
		result.Profile = *p
	}

	return result
}
