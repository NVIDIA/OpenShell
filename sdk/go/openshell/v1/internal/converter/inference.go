// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/inferencev1"
)

// InferenceRouteConfigToProto converts an SDK InferenceRouteConfig plus
// workspace into a proto SetInferenceRouteRequest.
func InferenceRouteConfigToProto(workspace string, cfg *types.InferenceRouteConfig) *pb.SetInferenceRouteRequest {
	if cfg == nil {
		return &pb.SetInferenceRouteRequest{Workspace: workspace}
	}
	return &pb.SetInferenceRouteRequest{
		ProviderName: cfg.ProviderName,
		ModelId:      cfg.ModelID,
		RouteName:    cfg.RouteName,
		NoVerify:     cfg.NoVerify,
		TimeoutSecs:  cfg.TimeoutSecs,
		Workspace:    workspace,
	}
}

// InferenceRouteFromSetResponse converts a proto SetInferenceRouteResponse
// to an SDK InferenceRoute.
func InferenceRouteFromSetResponse(resp *pb.SetInferenceRouteResponse) *types.InferenceRoute {
	if resp == nil {
		return nil
	}
	return &types.InferenceRoute{
		ProviderName:        resp.GetProviderName(),
		ModelID:             resp.GetModelId(),
		Version:             resp.GetVersion(),
		RouteName:           resp.GetRouteName(),
		TimeoutSecs:         resp.GetTimeoutSecs(),
		Workspace:           resp.GetWorkspace(),
		ValidationPerformed: resp.GetValidationPerformed(),
		ValidatedEndpoints:  validatedEndpointsFromProto(resp.GetValidatedEndpoints()),
	}
}

// InferenceRouteFromGetResponse converts a proto GetInferenceRouteResponse
// to an SDK InferenceRoute.
func InferenceRouteFromGetResponse(resp *pb.GetInferenceRouteResponse) *types.InferenceRoute {
	if resp == nil {
		return nil
	}
	return &types.InferenceRoute{
		ProviderName: resp.GetProviderName(),
		ModelID:      resp.GetModelId(),
		Version:      resp.GetVersion(),
		RouteName:    resp.GetRouteName(),
		TimeoutSecs:  resp.GetTimeoutSecs(),
		Workspace:    resp.GetWorkspace(),
	}
}

// validatedEndpointsFromProto converts a slice of proto ValidatedEndpoint
// to SDK ValidatedEndpoint values. Returns nil for nil or empty input.
func validatedEndpointsFromProto(eps []*pb.ValidatedEndpoint) []types.ValidatedEndpoint {
	if len(eps) == 0 {
		return nil
	}
	result := make([]types.ValidatedEndpoint, len(eps))
	for i, ep := range eps {
		result[i] = types.ValidatedEndpoint{
			URL:      ep.GetUrl(),
			Protocol: ep.GetProtocol(),
		}
	}
	return result
}
