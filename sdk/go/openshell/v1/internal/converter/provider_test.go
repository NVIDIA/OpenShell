// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"
	"time"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestProviderFromProto(t *testing.T) {
	proto := &dm.Provider{
		Metadata: &dm.ObjectMeta{
			Id:              "prov-1",
			Name:            "my-claude",
			CreatedAtMs:     1700000000000,
			Labels:          map[string]string{"env": "prod"},
			ResourceVersion: 5,
		},
		Type:        "claude",
		Credentials: map[string]string{"API_KEY": "secret"},
		Config:      map[string]string{"region": "us-east-1"},
		CredentialExpiresAtMs: map[string]int64{
			"API_KEY": 1700100000000,
		},
	}

	p := ProviderFromProto(proto)

	require.NotNil(t, p)
	assert.Equal(t, "prov-1", p.ID)
	assert.Equal(t, "my-claude", p.Name)
	assert.Equal(t, "claude", p.Type)
	assert.Equal(t, time.UnixMilli(1700000000000).UTC(), p.CreatedAt)
	assert.Equal(t, map[string]string{"env": "prod"}, p.Labels)
	assert.Equal(t, uint64(5), p.ResourceVersion)
	assert.Nil(t, p.Spec.Credentials, "credentials are write-only")
	assert.Equal(t, map[string]string{"region": "us-east-1"}, p.Spec.Config)
	assert.Equal(t, time.UnixMilli(1700100000000).UTC(), p.Spec.CredentialExpiresAt["API_KEY"])
}

func TestProviderFromProto_NilMetadata(t *testing.T) {
	proto := &dm.Provider{
		Type: "gitlab",
	}

	p := ProviderFromProto(proto)

	require.NotNil(t, p)
	assert.Empty(t, p.ID)
	assert.Empty(t, p.Name)
	assert.Equal(t, "gitlab", p.Type)
	assert.True(t, p.CreatedAt.IsZero())
}

func TestProviderFromProto_Nil(t *testing.T) {
	p := ProviderFromProto(nil)
	assert.Nil(t, p)
}

func TestProviderToProto(t *testing.T) {
	p := &v1.Provider{
		ID:              "prov-1",
		Name:            "my-claude",
		Type:            "claude",
		CreatedAt:       time.UnixMilli(1700000000000).UTC(),
		Labels:          map[string]string{"env": "prod"},
		ResourceVersion: 5,
		Spec: v1.ProviderSpec{
			Credentials: map[string]string{"API_KEY": "secret"},
			Config:      map[string]string{"region": "us-east-1"},
			CredentialExpiresAt: map[string]time.Time{
				"API_KEY": time.UnixMilli(1700100000000).UTC(),
			},
		},
	}

	proto := ProviderToProto(p)

	require.NotNil(t, proto)
	require.NotNil(t, proto.Metadata)
	assert.Equal(t, "prov-1", proto.Metadata.Id)
	assert.Equal(t, "my-claude", proto.Metadata.Name)
	assert.Equal(t, int64(1700000000000), proto.Metadata.CreatedAtMs)
	assert.Equal(t, map[string]string{"env": "prod"}, proto.Metadata.Labels)
	assert.Equal(t, uint64(5), proto.Metadata.ResourceVersion)
	assert.Equal(t, "claude", proto.Type)
	assert.Equal(t, map[string]string{"API_KEY": "secret"}, proto.Credentials)
	assert.Equal(t, map[string]string{"region": "us-east-1"}, proto.Config)
	assert.Equal(t, int64(1700100000000), proto.CredentialExpiresAtMs["API_KEY"])
}

func TestProviderToProto_Nil(t *testing.T) {
	proto := ProviderToProto(nil)
	assert.Nil(t, proto)
}

func TestProviderRoundTrip(t *testing.T) {
	original := &v1.Provider{
		ID:              "prov-rt",
		Name:            "round-trip",
		Type:            "github",
		CreatedAt:       time.UnixMilli(1700000000000).UTC(),
		Labels:          map[string]string{"team": "infra"},
		ResourceVersion: 42,
		Spec: v1.ProviderSpec{
			Credentials: map[string]string{"TOKEN": "abc123"},
			Config:      map[string]string{"org": "myorg"},
			CredentialExpiresAt: map[string]time.Time{
				"TOKEN": time.UnixMilli(1700200000000).UTC(),
			},
		},
	}

	proto := ProviderToProto(original)
	back := ProviderFromProto(proto)

	assert.Equal(t, original.ID, back.ID)
	assert.Equal(t, original.Name, back.Name)
	assert.Equal(t, original.Type, back.Type)
	assert.Equal(t, original.CreatedAt, back.CreatedAt)
	assert.Equal(t, original.Labels, back.Labels)
	assert.Equal(t, original.ResourceVersion, back.ResourceVersion)
	assert.Nil(t, back.Spec.Credentials, "credentials are write-only and should not be returned")
	assert.Equal(t, original.Spec.Config, back.Spec.Config)
	assert.Equal(t, original.Spec.CredentialExpiresAt, back.Spec.CredentialExpiresAt)
}
