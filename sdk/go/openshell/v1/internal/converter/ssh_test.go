// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSSHSessionFromProto(t *testing.T) {
	resp := &pb.CreateSshSessionResponse{
		SandboxId:          "sb-123",
		Token:              "tok-secret",
		GatewayHost:        "gw.example.com",
		GatewayPort:        2222,
		GatewayScheme:      "https",
		HostKeyFingerprint: "SHA256:abc123",
		ExpiresAtMs:        1700000000000,
	}

	session := SSHSessionFromProto(resp)

	require.NotNil(t, session)
	assert.Equal(t, "sb-123", session.SandboxID)
	assert.Equal(t, "tok-secret", session.Token)
	assert.Equal(t, "gw.example.com", session.GatewayHost)
	assert.Equal(t, uint32(2222), session.GatewayPort)
	assert.Equal(t, "https", session.GatewayScheme)
	assert.Equal(t, "SHA256:abc123", session.HostKeyFingerprint)
	assert.Equal(t, int64(1700000000000), session.ExpiresAtMs)
}

func TestSSHSessionFromProto_MinimalFields(t *testing.T) {
	resp := &pb.CreateSshSessionResponse{
		SandboxId:   "sb-min",
		Token:       "tok-min",
		GatewayHost: "localhost",
		GatewayPort: 22,
	}

	session := SSHSessionFromProto(resp)

	require.NotNil(t, session)
	assert.Equal(t, "sb-min", session.SandboxID)
	assert.Equal(t, "tok-min", session.Token)
	assert.Equal(t, "localhost", session.GatewayHost)
	assert.Equal(t, uint32(22), session.GatewayPort)
	assert.Empty(t, session.GatewayScheme)
	assert.Empty(t, session.HostKeyFingerprint)
	assert.Zero(t, session.ExpiresAtMs)
}

func TestSSHSessionFromProto_Nil(t *testing.T) {
	session := SSHSessionFromProto(nil)
	assert.Nil(t, session)
}

func TestSSHSessionToProto(t *testing.T) {
	session := &v1.SSHSession{
		SandboxID:          "sb-123",
		Token:              "tok-secret",
		GatewayHost:        "gw.example.com",
		GatewayPort:        2222,
		GatewayScheme:      "https",
		HostKeyFingerprint: "SHA256:abc123",
		ExpiresAtMs:        1700000000000,
	}

	resp := SSHSessionToProto(session)

	require.NotNil(t, resp)
	assert.Equal(t, "sb-123", resp.SandboxId)
	assert.Equal(t, "tok-secret", resp.Token)
	assert.Equal(t, "gw.example.com", resp.GatewayHost)
	assert.Equal(t, uint32(2222), resp.GatewayPort)
	assert.Equal(t, "https", resp.GatewayScheme)
	assert.Equal(t, "SHA256:abc123", resp.HostKeyFingerprint)
	assert.Equal(t, int64(1700000000000), resp.ExpiresAtMs)
}

func TestSSHSessionToProto_Nil(t *testing.T) {
	resp := SSHSessionToProto(nil)
	assert.Nil(t, resp)
}

func TestSSHSessionRoundTrip(t *testing.T) {
	original := &v1.SSHSession{
		SandboxID:          "sb-rt",
		Token:              "tok-rt",
		GatewayHost:        "rt.example.com",
		GatewayPort:        443,
		GatewayScheme:      "https",
		HostKeyFingerprint: "SHA256:roundtrip",
		ExpiresAtMs:        1800000000000,
	}

	proto := SSHSessionToProto(original)
	back := SSHSessionFromProto(proto)

	require.NotNil(t, back)
	assert.Equal(t, original.SandboxID, back.SandboxID)
	assert.Equal(t, original.Token, back.Token)
	assert.Equal(t, original.GatewayHost, back.GatewayHost)
	assert.Equal(t, original.GatewayPort, back.GatewayPort)
	assert.Equal(t, original.GatewayScheme, back.GatewayScheme)
	assert.Equal(t, original.HostKeyFingerprint, back.HostKeyFingerprint)
	assert.Equal(t, original.ExpiresAtMs, back.ExpiresAtMs)
}
