// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// GatewayInfoFromProto converts a proto GetGatewayInfoResponse to an SDK GatewayInfo.
func GatewayInfoFromProto(resp *pb.GetGatewayInfoResponse) *types.GatewayInfo {
	if resp == nil {
		return nil
	}

	drivers := make([]types.ComputeDriverInfo, 0, len(resp.GetComputeDrivers()))
	for _, d := range resp.GetComputeDrivers() {
		drivers = append(drivers, ComputeDriverInfoFromProto(d))
	}

	return &types.GatewayInfo{
		Status:         ServiceStatusFromProto(resp.GetStatus()),
		Version:        resp.GetGatewayVersion(),
		ComputeDrivers: drivers,
	}
}

// ServiceStatusFromProto converts a proto ServiceStatus to an SDK ServiceStatus.
func ServiceStatusFromProto(status pb.ServiceStatus) types.ServiceStatus {
	switch status {
	case pb.ServiceStatus_SERVICE_STATUS_HEALTHY:
		return types.ServiceStatusHealthy
	case pb.ServiceStatus_SERVICE_STATUS_DEGRADED:
		return types.ServiceStatusDegraded
	case pb.ServiceStatus_SERVICE_STATUS_UNHEALTHY:
		return types.ServiceStatusUnhealthy
	default:
		return types.ServiceStatusUnknown
	}
}

// ComputeDriverInfoFromProto converts a proto ComputeDriverInfo to an SDK ComputeDriverInfo.
func ComputeDriverInfoFromProto(d *pb.ComputeDriverInfo) types.ComputeDriverInfo {
	result := types.ComputeDriverInfo{
		Name: d.GetName(),
	}
	if caps := d.GetCapabilities(); caps != nil {
		result.DriverName = caps.GetDriverName()
		result.DriverVersion = caps.GetDriverVersion()
	}
	return result
}

// CurrentUserFromProto converts a proto GetCurrentUserResponse to an SDK CurrentUser.
func CurrentUserFromProto(resp *pb.GetCurrentUserResponse) *types.CurrentUser {
	if resp == nil {
		return nil
	}

	return &types.CurrentUser{
		Subject:          resp.GetSubject(),
		DisplayName:      resp.GetDisplayName(),
		Roles:            CopyStringSlice(resp.GetRoles()),
		Scopes:           CopyStringSlice(resp.GetScopes()),
		IdentityProvider: resp.GetIdentityProvider(),
	}
}
