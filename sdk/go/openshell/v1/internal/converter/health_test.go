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

func TestGatewayInfoFromProto(t *testing.T) {
	proto := &pb.GetGatewayInfoResponse{
		Status:         pb.ServiceStatus_SERVICE_STATUS_HEALTHY,
		GatewayVersion: "1.5.0",
		ComputeDrivers: []*pb.ComputeDriverInfo{
			{
				Name: "k8s",
				Capabilities: &pb.ComputeDriverCapabilities{
					DriverName:    "kubernetes",
					DriverVersion: "2.1.0",
				},
			},
			{
				Name: "docker",
				Capabilities: &pb.ComputeDriverCapabilities{
					DriverName:    "docker-engine",
					DriverVersion: "24.0.0",
				},
			},
		},
	}

	info := GatewayInfoFromProto(proto)

	require.NotNil(t, info)
	assert.Equal(t, v1.ServiceStatusHealthy, info.Status)
	assert.Equal(t, "1.5.0", info.Version)
	require.Len(t, info.ComputeDrivers, 2)
	assert.Equal(t, "k8s", info.ComputeDrivers[0].Name)
	assert.Equal(t, "kubernetes", info.ComputeDrivers[0].DriverName)
	assert.Equal(t, "2.1.0", info.ComputeDrivers[0].DriverVersion)
	assert.Equal(t, "docker", info.ComputeDrivers[1].Name)
	assert.Equal(t, "docker-engine", info.ComputeDrivers[1].DriverName)
}

func TestGatewayInfoFromProto_NoDrivers(t *testing.T) {
	proto := &pb.GetGatewayInfoResponse{
		Status:         pb.ServiceStatus_SERVICE_STATUS_DEGRADED,
		GatewayVersion: "1.0.0",
	}

	info := GatewayInfoFromProto(proto)

	require.NotNil(t, info)
	assert.Equal(t, v1.ServiceStatusDegraded, info.Status)
	assert.Empty(t, info.ComputeDrivers)
}

func TestGatewayInfoFromProto_Nil(t *testing.T) {
	info := GatewayInfoFromProto(nil)
	assert.Nil(t, info)
}

func TestGatewayInfoFromProto_DeepCopy(t *testing.T) {
	proto := &pb.GetGatewayInfoResponse{
		Status:         pb.ServiceStatus_SERVICE_STATUS_HEALTHY,
		GatewayVersion: "1.0.0",
		ComputeDrivers: []*pb.ComputeDriverInfo{
			{Name: "k8s", Capabilities: &pb.ComputeDriverCapabilities{DriverName: "kubernetes"}},
		},
	}

	info := GatewayInfoFromProto(proto)
	proto.ComputeDrivers[0].Name = "mutated"

	assert.Equal(t, "k8s", info.ComputeDrivers[0].Name)
}

func TestServiceStatusFromProto(t *testing.T) {
	tests := []struct {
		proto    pb.ServiceStatus
		expected v1.ServiceStatus
	}{
		{pb.ServiceStatus_SERVICE_STATUS_HEALTHY, v1.ServiceStatusHealthy},
		{pb.ServiceStatus_SERVICE_STATUS_DEGRADED, v1.ServiceStatusDegraded},
		{pb.ServiceStatus_SERVICE_STATUS_UNHEALTHY, v1.ServiceStatusUnhealthy},
		{pb.ServiceStatus_SERVICE_STATUS_UNSPECIFIED, v1.ServiceStatusUnknown},
		{pb.ServiceStatus(99), v1.ServiceStatusUnknown},
	}

	for _, tt := range tests {
		assert.Equal(t, tt.expected, ServiceStatusFromProto(tt.proto))
	}
}

func TestComputeDriverInfoFromProto_NilCapabilities(t *testing.T) {
	proto := &pb.ComputeDriverInfo{
		Name: "bare-metal",
	}

	info := ComputeDriverInfoFromProto(proto)

	assert.Equal(t, "bare-metal", info.Name)
	assert.Empty(t, info.DriverName)
	assert.Empty(t, info.DriverVersion)
}

func TestCurrentUserFromProto(t *testing.T) {
	proto := &pb.GetCurrentUserResponse{
		Subject:          "user-123",
		DisplayName:      "Test User",
		Roles:            []string{"admin", "viewer"},
		Scopes:           []string{"read", "write"},
		IdentityProvider: "oidc-provider",
	}

	user := CurrentUserFromProto(proto)

	require.NotNil(t, user)
	assert.Equal(t, "user-123", user.Subject)
	assert.Equal(t, "Test User", user.DisplayName)
	assert.Equal(t, []string{"admin", "viewer"}, user.Roles)
	assert.Equal(t, []string{"read", "write"}, user.Scopes)
	assert.Equal(t, "oidc-provider", user.IdentityProvider)
}

func TestCurrentUserFromProto_DeepCopy(t *testing.T) {
	roles := []string{"admin"}
	proto := &pb.GetCurrentUserResponse{
		Subject: "user-1",
		Roles:   roles,
	}

	user := CurrentUserFromProto(proto)
	roles[0] = "mutated"

	assert.Equal(t, "admin", user.Roles[0])
}

func TestCurrentUserFromProto_Nil(t *testing.T) {
	user := CurrentUserFromProto(nil)
	assert.Nil(t, user)
}

func TestCurrentUserFromProto_EmptyFields(t *testing.T) {
	proto := &pb.GetCurrentUserResponse{
		Subject: "minimal-user",
	}

	user := CurrentUserFromProto(proto)

	require.NotNil(t, user)
	assert.Equal(t, "minimal-user", user.Subject)
	assert.Empty(t, user.DisplayName)
	assert.Nil(t, user.Roles)
	assert.Nil(t, user.Scopes)
	assert.Empty(t, user.IdentityProvider)
}
