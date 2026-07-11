// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sbv1 "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// --- ProfileCategory ---

func TestProfileCategoryFromProto(t *testing.T) {
	tests := []struct {
		proto pb.ProviderProfileCategory
		want  v1.ProfileCategory
	}{
		{pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_OTHER, v1.ProfileCategoryOther},
		{pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_INFERENCE, v1.ProfileCategoryInference},
		{pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_AGENT, v1.ProfileCategoryAgent},
		{pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_SOURCE_CONTROL, v1.ProfileCategorySourceControl},
		{pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_MESSAGING, v1.ProfileCategoryMessaging},
		{pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_DATA, v1.ProfileCategoryData},
		{pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_KNOWLEDGE, v1.ProfileCategoryKnowledge},
		{pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_UNSPECIFIED, v1.ProfileCategory("")},
	}
	for _, tt := range tests {
		t.Run(tt.proto.String(), func(t *testing.T) {
			assert.Equal(t, tt.want, ProfileCategoryFromProto(tt.proto))
		})
	}
}

func TestProfileCategoryToProto(t *testing.T) {
	tests := []struct {
		sdk  v1.ProfileCategory
		want pb.ProviderProfileCategory
	}{
		{v1.ProfileCategoryOther, pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_OTHER},
		{v1.ProfileCategoryInference, pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_INFERENCE},
		{v1.ProfileCategoryAgent, pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_AGENT},
		{v1.ProfileCategorySourceControl, pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_SOURCE_CONTROL},
		{v1.ProfileCategoryMessaging, pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_MESSAGING},
		{v1.ProfileCategoryData, pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_DATA},
		{v1.ProfileCategoryKnowledge, pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_KNOWLEDGE},
		{v1.ProfileCategory(""), pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_UNSPECIFIED},
		{v1.ProfileCategory("Unknown"), pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_UNSPECIFIED},
	}
	for _, tt := range tests {
		t.Run(string(tt.sdk), func(t *testing.T) {
			assert.Equal(t, tt.want, ProfileCategoryToProto(tt.sdk))
		})
	}
}

// --- NetworkEndpoint ---

func TestNetworkEndpointFromProto(t *testing.T) {
	proto := &sbv1.NetworkEndpoint{
		Host:     "api.example.com",
		Port:     443,
		Protocol: "rest",
	}

	ep := NetworkEndpointFromProto(proto)

	require.NotNil(t, ep)
	assert.Equal(t, "api.example.com", ep.Host)
	assert.Equal(t, uint32(443), ep.Port)
	assert.Equal(t, "rest", ep.Protocol)
}

func TestNetworkEndpointFromProto_Nil(t *testing.T) {
	ep := NetworkEndpointFromProto(nil)
	assert.Nil(t, ep)
}

func TestNetworkEndpointToProto(t *testing.T) {
	ep := &v1.NetworkEndpoint{
		Host:     "api.example.com",
		Port:     443,
		Protocol: "rest",
	}

	proto := NetworkEndpointToProto(ep)

	require.NotNil(t, proto)
	assert.Equal(t, "api.example.com", proto.Host)
	assert.Equal(t, uint32(443), proto.Port)
	assert.Equal(t, "rest", proto.Protocol)
}

func TestNetworkEndpointToProto_Nil(t *testing.T) {
	proto := NetworkEndpointToProto(nil)
	assert.Nil(t, proto)
}

// --- NetworkBinary ---

func TestNetworkBinaryFromProto(t *testing.T) {
	proto := &sbv1.NetworkBinary{
		Path: "/usr/local/bin/tool",
	}

	bin := NetworkBinaryFromProto(proto)

	require.NotNil(t, bin)
	assert.Equal(t, "/usr/local/bin/tool", bin.Path)
}

func TestNetworkBinaryFromProto_Nil(t *testing.T) {
	bin := NetworkBinaryFromProto(nil)
	assert.Nil(t, bin)
}

func TestNetworkBinaryToProto(t *testing.T) {
	bin := &v1.NetworkBinary{
		Path: "/usr/local/bin/tool",
	}

	proto := NetworkBinaryToProto(bin)

	require.NotNil(t, proto)
	assert.Equal(t, "/usr/local/bin/tool", proto.Path)
}

func TestNetworkBinaryToProto_Nil(t *testing.T) {
	proto := NetworkBinaryToProto(nil)
	assert.Nil(t, proto)
}

// --- ProfileCredential ---

func TestProfileCredentialFromProto(t *testing.T) {
	proto := &pb.ProviderProfileCredential{
		Name:        "API_KEY",
		Description: "API key for auth",
		Required:    true,
		Refresh: &pb.ProviderCredentialRefresh{
			Strategy: pb.ProviderCredentialRefreshStrategy_PROVIDER_CREDENTIAL_REFRESH_STRATEGY_OAUTH2_REFRESH_TOKEN,
		},
	}

	cred := ProfileCredentialFromProto(proto)

	require.NotNil(t, cred)
	assert.Equal(t, "API_KEY", cred.Name)
	assert.Equal(t, "API key for auth", cred.Description)
	assert.True(t, cred.Required)
	assert.True(t, cred.Secret, "credential with refresh config is secret")
}

func TestProfileCredentialFromProto_NotSecret(t *testing.T) {
	proto := &pb.ProviderProfileCredential{
		Name:     "ENDPOINT_URL",
		Required: false,
	}

	cred := ProfileCredentialFromProto(proto)

	require.NotNil(t, cred)
	assert.Equal(t, "ENDPOINT_URL", cred.Name)
	assert.False(t, cred.Required)
	assert.False(t, cred.Secret, "credential without refresh config is not secret")
}

func TestProfileCredentialFromProto_Nil(t *testing.T) {
	cred := ProfileCredentialFromProto(nil)
	assert.Nil(t, cred)
}

// --- ProfileDiagnostic ---

func TestProfileDiagnosticFromProto(t *testing.T) {
	proto := &pb.ProviderProfileDiagnostic{
		Source:    "import",
		ProfileId: "prof-1",
		Field:    "credentials",
		Message:  "missing required field",
		Severity: "error",
	}

	diag := ProfileDiagnosticFromProto(proto)

	require.NotNil(t, diag)
	assert.Equal(t, "import", diag.Source)
	assert.Equal(t, "prof-1", diag.ProfileID)
	assert.Equal(t, "credentials", diag.Field)
	assert.Equal(t, "missing required field", diag.Message)
	assert.Equal(t, "error", diag.Severity)
}

func TestProfileDiagnosticFromProto_Nil(t *testing.T) {
	diag := ProfileDiagnosticFromProto(nil)
	assert.Nil(t, diag)
}

// --- ProviderProfile ---

func TestProviderProfileFromProto(t *testing.T) {
	proto := &pb.ProviderProfile{
		Id:          "prof-1",
		DisplayName: "Claude Provider",
		Description: "Anthropic Claude",
		Category:    pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_INFERENCE,
		Credentials: []*pb.ProviderProfileCredential{
			{Name: "API_KEY", Description: "key", Required: true},
		},
		Endpoints: []*sbv1.NetworkEndpoint{
			{Host: "api.anthropic.com", Port: 443, Protocol: "rest"},
		},
		Binaries: []*sbv1.NetworkBinary{
			{Path: "/usr/bin/claude"},
		},
		InferenceCapable: true,
		Discovery: &pb.ProviderProfileDiscovery{
			Credentials: []string{"API_KEY"},
		},
		ResourceVersion: 7,
	}

	profile := ProviderProfileFromProto(proto)

	require.NotNil(t, profile)
	assert.Equal(t, "prof-1", profile.ID)
	assert.Equal(t, "Claude Provider", profile.DisplayName)
	assert.Equal(t, "Anthropic Claude", profile.Description)
	assert.Equal(t, v1.ProfileCategoryInference, profile.Category)
	assert.True(t, profile.InferenceCapable)
	assert.Equal(t, uint64(7), profile.ResourceVersion)

	require.Len(t, profile.Credentials, 1)
	assert.Equal(t, "API_KEY", profile.Credentials[0].Name)
	assert.True(t, profile.Credentials[0].Required)

	require.Len(t, profile.Endpoints, 1)
	assert.Equal(t, "api.anthropic.com", profile.Endpoints[0].Host)
	assert.Equal(t, uint32(443), profile.Endpoints[0].Port)

	require.Len(t, profile.Binaries, 1)
	assert.Equal(t, "/usr/bin/claude", profile.Binaries[0].Path)

	assert.Equal(t, []string{"API_KEY"}, profile.Discovery.Credentials)
}

func TestProviderProfileFromProto_NilDiscovery(t *testing.T) {
	proto := &pb.ProviderProfile{
		Id: "prof-2",
	}

	profile := ProviderProfileFromProto(proto)

	require.NotNil(t, profile)
	assert.Nil(t, profile.Discovery.Credentials)
}

func TestProviderProfileFromProto_Nil(t *testing.T) {
	profile := ProviderProfileFromProto(nil)
	assert.Nil(t, profile)
}

func TestProviderProfileToProto(t *testing.T) {
	profile := &v1.ProviderProfile{
		ID:          "prof-1",
		DisplayName: "Claude Provider",
		Description: "Anthropic Claude",
		Category:    v1.ProfileCategoryInference,
		Credentials: []v1.ProfileCredential{
			{Name: "API_KEY", Description: "key", Required: true, Secret: true},
		},
		Endpoints: []v1.NetworkEndpoint{
			{Host: "api.anthropic.com", Port: 443, Protocol: "rest"},
		},
		Binaries: []v1.NetworkBinary{
			{Path: "/usr/bin/claude"},
		},
		InferenceCapable: true,
		Discovery: v1.ProfileDiscovery{
			Credentials: []string{"API_KEY"},
		},
		ResourceVersion: 7,
	}

	proto := ProviderProfileToProto(profile)

	require.NotNil(t, proto)
	assert.Equal(t, "prof-1", proto.Id)
	assert.Equal(t, "Claude Provider", proto.DisplayName)
	assert.Equal(t, "Anthropic Claude", proto.Description)
	assert.Equal(t, pb.ProviderProfileCategory_PROVIDER_PROFILE_CATEGORY_INFERENCE, proto.Category)
	assert.True(t, proto.InferenceCapable)
	assert.Equal(t, uint64(7), proto.ResourceVersion)

	require.Len(t, proto.Credentials, 1)
	assert.Equal(t, "API_KEY", proto.Credentials[0].Name)

	require.Len(t, proto.Endpoints, 1)
	assert.Equal(t, "api.anthropic.com", proto.Endpoints[0].Host)

	require.Len(t, proto.Binaries, 1)
	assert.Equal(t, "/usr/bin/claude", proto.Binaries[0].Path)

	require.NotNil(t, proto.Discovery)
	assert.Equal(t, []string{"API_KEY"}, proto.Discovery.Credentials)
}

func TestProviderProfileToProto_Nil(t *testing.T) {
	proto := ProviderProfileToProto(nil)
	assert.Nil(t, proto)
}

// --- ProfileImportItem ---

func TestProfileImportItemToProto(t *testing.T) {
	item := &v1.ProfileImportItem{
		Profile: v1.ProviderProfile{
			ID:          "prof-1",
			DisplayName: "Test",
			Category:    v1.ProfileCategoryOther,
		},
		Source: "file:///profiles/test.yaml",
	}

	proto := ProfileImportItemToProto(item)

	require.NotNil(t, proto)
	assert.Equal(t, "file:///profiles/test.yaml", proto.Source)
	require.NotNil(t, proto.Profile)
	assert.Equal(t, "prof-1", proto.Profile.Id)
	assert.Equal(t, "Test", proto.Profile.DisplayName)
}

func TestProfileImportItemToProto_Nil(t *testing.T) {
	proto := ProfileImportItemToProto(nil)
	assert.Nil(t, proto)
}

func TestProfileImportItemFromProto(t *testing.T) {
	proto := &pb.ProviderProfileImportItem{
		Profile: &pb.ProviderProfile{
			Id:          "prof-1",
			DisplayName: "Test",
		},
		Source: "file:///profiles/test.yaml",
	}

	item := ProfileImportItemFromProto(proto)

	require.NotNil(t, item)
	assert.Equal(t, "file:///profiles/test.yaml", item.Source)
	assert.Equal(t, "prof-1", item.Profile.ID)
}

func TestProfileImportItemFromProto_Nil(t *testing.T) {
	item := ProfileImportItemFromProto(nil)
	assert.Nil(t, item)
}

// --- ProviderProfile round-trip ---

func TestProviderProfileRoundTrip(t *testing.T) {
	original := &v1.ProviderProfile{
		ID:          "prof-rt",
		DisplayName: "Round Trip",
		Description: "Testing round trip",
		Category:    v1.ProfileCategoryAgent,
		Credentials: []v1.ProfileCredential{
			{Name: "TOKEN", Description: "auth token", Required: true, Secret: false},
		},
		Endpoints: []v1.NetworkEndpoint{
			{Host: "agent.example.com", Port: 8080, Protocol: "websocket"},
		},
		Binaries: []v1.NetworkBinary{
			{Path: "/bin/agent"},
		},
		InferenceCapable: false,
		Discovery: v1.ProfileDiscovery{
			Credentials: []string{"TOKEN"},
		},
		ResourceVersion: 42,
	}

	proto := ProviderProfileToProto(original)
	back := ProviderProfileFromProto(proto)

	require.NotNil(t, back)
	assert.Equal(t, original.ID, back.ID)
	assert.Equal(t, original.DisplayName, back.DisplayName)
	assert.Equal(t, original.Description, back.Description)
	assert.Equal(t, original.Category, back.Category)
	assert.Equal(t, original.InferenceCapable, back.InferenceCapable)
	assert.Equal(t, original.ResourceVersion, back.ResourceVersion)

	require.Len(t, back.Credentials, 1)
	assert.Equal(t, original.Credentials[0].Name, back.Credentials[0].Name)
	assert.Equal(t, original.Credentials[0].Required, back.Credentials[0].Required)

	require.Len(t, back.Endpoints, 1)
	assert.Equal(t, original.Endpoints[0].Host, back.Endpoints[0].Host)
	assert.Equal(t, original.Endpoints[0].Port, back.Endpoints[0].Port)

	require.Len(t, back.Binaries, 1)
	assert.Equal(t, original.Binaries[0].Path, back.Binaries[0].Path)

	assert.Equal(t, original.Discovery.Credentials, back.Discovery.Credentials)
}
