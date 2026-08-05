// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderFromProto_Nil(t *testing.T) {
	assert.Nil(t, ProviderFromProto(nil))
}

func TestProviderFromProto_Full(t *testing.T) {
	proto := &dm.Provider{
		Metadata: &dm.ObjectMeta{
			Id:              "prov-1",
			Name:            "claude-provider",
			CreatedAtMs:     1700000000000,
			Labels:          map[string]string{"env": "prod"},
			Annotations:     map[string]string{"note": "test"},
			ResourceVersion: 42,
			Workspace:       "default",
		},
		Type:             "claude",
		Credentials:      map[string]string{"api_key": "secret"},
		Config:           map[string]string{"base_url": "https://api.example.com"},
		ProfileWorkspace: "shared",
		CredentialExpiresAtMs: map[string]int64{
			"api_key": 1700003600000,
		},
		CredentialHandles: map[string]*dm.CredentialHandle{
			"api_key": {
				Driver:   "vault",
				Handle:   "secret/data/claude",
				Metadata: map[string]string{"version": "3"},
			},
		},
	}

	result := ProviderFromProto(proto)

	require.NotNil(t, result)
	assert.Equal(t, "prov-1", result.ID)
	assert.Equal(t, "claude-provider", result.Name)
	assert.Equal(t, "claude", result.Type)
	assert.Equal(t, uint64(42), result.ResourceVersion)
	assert.Equal(t, "default", result.Workspace)
	assert.Equal(t, map[string]string{"env": "prod"}, result.Labels)
	assert.Equal(t, map[string]string{"note": "test"}, result.Annotations)
	assert.Equal(t, map[string]string{"base_url": "https://api.example.com"}, result.Spec.Config)
	assert.Equal(t, "shared", result.Spec.ProfileWorkspace)

	require.Len(t, result.Spec.CredentialExpiresAt, 1)
	assert.False(t, result.Spec.CredentialExpiresAt["api_key"].IsZero())

	require.Len(t, result.Spec.CredentialHandles, 1)
	h := result.Spec.CredentialHandles["api_key"]
	assert.Equal(t, "vault", h.Driver)
	assert.Equal(t, "secret/data/claude", h.Handle)
	assert.Equal(t, map[string]string{"version": "3"}, h.Metadata)
}

func TestProviderFromProto_NilMetadata(t *testing.T) {
	proto := &dm.Provider{
		Type:   "openai",
		Config: map[string]string{"key": "val"},
	}

	result := ProviderFromProto(proto)

	require.NotNil(t, result)
	assert.Equal(t, "", result.ID)
	assert.Equal(t, "", result.Name)
	assert.Equal(t, "openai", result.Type)
	assert.Equal(t, map[string]string{"key": "val"}, result.Spec.Config)
}

func TestProviderFromProto_EmptyHandles(t *testing.T) {
	proto := &dm.Provider{
		Type:              "test",
		CredentialHandles: map[string]*dm.CredentialHandle{},
	}

	result := ProviderFromProto(proto)

	require.NotNil(t, result)
	assert.Nil(t, result.Spec.CredentialHandles)
}

func TestProviderToProto_Nil(t *testing.T) {
	assert.Nil(t, ProviderToProto(nil))
}

func TestProviderToProto_Full(t *testing.T) {
	expires := time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)
	provider := &types.Provider{
		ID:              "prov-1",
		Name:            "test-provider",
		Type:            "claude",
		Labels:          map[string]string{"env": "dev"},
		Annotations:     map[string]string{"note": "x"},
		ResourceVersion: 7,
		Workspace:       "ws-1",
		Spec: types.ProviderSpec{
			Credentials:         map[string]string{"token": "abc"},
			Config:              map[string]string{"url": "https://example.com"},
			ProfileWorkspace:    "global",
			CredentialExpiresAt: map[string]time.Time{"token": expires},
			CredentialHandles: map[string]types.CredentialHandle{
				"token": {
					Driver:   "k8s-secrets",
					Handle:   "ns/secret-name",
					Metadata: map[string]string{"k": "v"},
				},
			},
		},
	}

	result := ProviderToProto(provider)

	require.NotNil(t, result)
	assert.Equal(t, "prov-1", result.Metadata.Id)
	assert.Equal(t, "test-provider", result.Metadata.Name)
	assert.Equal(t, "claude", result.Type)
	assert.Equal(t, "global", result.ProfileWorkspace)
	assert.Equal(t, map[string]string{"token": "abc"}, result.Credentials)
	assert.Equal(t, map[string]string{"url": "https://example.com"}, result.Config)

	require.Len(t, result.CredentialExpiresAtMs, 1)
	assert.Greater(t, result.CredentialExpiresAtMs["token"], int64(0))

	require.Len(t, result.CredentialHandles, 1)
	h := result.CredentialHandles["token"]
	assert.Equal(t, "k8s-secrets", h.Driver)
	assert.Equal(t, "ns/secret-name", h.Handle)
	assert.Equal(t, map[string]string{"k": "v"}, h.Metadata)
}

func TestProviderRoundTrip(t *testing.T) {
	original := &types.Provider{
		ID:              "rt-1",
		Name:            "roundtrip",
		Type:            "gitlab",
		ResourceVersion: 3,
		Workspace:       "default",
		Labels:          map[string]string{"team": "infra"},
		Spec: types.ProviderSpec{
			Config:           map[string]string{"url": "https://gitlab.com"},
			ProfileWorkspace: "shared",
			CredentialHandles: map[string]types.CredentialHandle{
				"pat": {Driver: "vault", Handle: "secret/gitlab", Metadata: map[string]string{"ver": "1"}},
			},
		},
	}

	proto := ProviderToProto(original)
	back := ProviderFromProto(proto)

	assert.Equal(t, original.ID, back.ID)
	assert.Equal(t, original.Name, back.Name)
	assert.Equal(t, original.Type, back.Type)
	assert.Equal(t, original.Workspace, back.Workspace)
	assert.Equal(t, original.Labels, back.Labels)
	assert.Equal(t, original.Spec.Config, back.Spec.Config)
	assert.Equal(t, original.Spec.ProfileWorkspace, back.Spec.ProfileWorkspace)
	assert.Equal(t, original.Spec.CredentialHandles, back.Spec.CredentialHandles)
}
