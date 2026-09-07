// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// ServiceEndpointFromProto converts a proto ServiceEndpointResponse to an SDK ServiceEndpoint.
// The response flattens the nested Endpoint and top-level URL into a single SDK type.
func ServiceEndpointFromProto(resp *pb.ServiceEndpointResponse) *types.ServiceEndpoint {
	if resp == nil {
		return nil
	}

	result := &types.ServiceEndpoint{
		URL: resp.GetUrl(),
	}

	if ep := resp.GetEndpoint(); ep != nil {
		result.SandboxID = ep.GetSandboxId()
		result.SandboxName = ep.GetSandboxName()
		result.ServiceName = ep.GetServiceName()
		result.TargetPort = ep.GetTargetPort()
		result.Domain = ep.GetDomain()

		if m := ep.GetMetadata(); m != nil {
			result.ID = m.GetId()
			result.Workspace = m.GetWorkspace()
		}
	}

	return result
}

// ServiceEndpointToProto converts an SDK ServiceEndpoint to a proto ServiceEndpointResponse.
func ServiceEndpointToProto(se *types.ServiceEndpoint) *pb.ServiceEndpointResponse {
	if se == nil {
		return nil
	}

	return &pb.ServiceEndpointResponse{
		Endpoint: &pb.ServiceEndpoint{
			Metadata: &dm.ObjectMeta{
				Id:        se.ID,
				Workspace: se.Workspace,
			},
			SandboxId:   se.SandboxID,
			SandboxName: se.SandboxName,
			ServiceName: se.ServiceName,
			TargetPort:  se.TargetPort,
			Domain:      se.Domain,
		},
		Url: se.URL,
	}
}
