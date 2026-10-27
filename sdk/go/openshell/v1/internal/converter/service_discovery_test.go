// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestDiscoverySnapshotCopiesAndRejectsIncompleteViews(t *testing.T) {
	wire := &pb.ServiceRouteSnapshot{Revision: "revision", Routes: []*pb.DiscoveredServiceRoute{{
		Workspace: "default", Sandbox: "demo", Hostname: "demo.example.com", InstallationVersion: "owner-1",
		Endpoint: &pb.ServiceRouteEndpoint{Host: "10.0.0.1", Port: 9443}, ExpiresAt: timestamppb.New(time.Now()),
	}}}
	snapshot, err := ServiceRouteSnapshotFromProto(wire, "default")
	require.NoError(t, err)
	snapshot.Routes[0].Endpoint.Host = "changed"
	require.Equal(t, "10.0.0.1", wire.Routes[0].Endpoint.Host)
	wire.Routes[0].Hostname = "different.example.com"
	require.Equal(t, "demo.example.com", snapshot.Routes[0].Hostname)
	_, err = ServiceRouteSnapshotFromProto(wire, "other")
	require.Error(t, err)
	wire.Routes[0].ExpiresAt = nil
	_, err = ServiceRouteSnapshotFromProto(wire, "default")
	require.Error(t, err)
	_, err = ServiceRouteSnapshotFromProto(nil, "default")
	require.Error(t, err)
}

func TestDiscoveryConverterRejectsRoutesOutsideSelectedSet(t *testing.T) {
	view := &pb.ServiceRouteSnapshot{Revision: "r", Routes: []*pb.DiscoveredServiceRoute{{Workspace: "outside", Hostname: "outside.example.com", InstallationVersion: "v", Endpoint: &pb.ServiceRouteEndpoint{Host: "10.0.0.1", Port: 9443}, ExpiresAt: timestamppb.Now()}}}
	_, err := ServiceRouteSnapshotForScopeFromProto(view, types.ServiceRouteScope{Workspaces: []string{"team-a", "team-b"}})
	require.Error(t, err)
	result, err := ServiceRouteSnapshotForScopeFromProto(view, types.ServiceRouteScope{AllWorkspaces: true})
	require.NoError(t, err)
	result.Routes[0].Workspace = "changed"
	require.Equal(t, "outside", view.Routes[0].Workspace)
}
