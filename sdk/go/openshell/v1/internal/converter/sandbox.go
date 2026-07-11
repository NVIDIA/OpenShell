// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// SandboxFromProto converts a proto Sandbox to an SDK Sandbox.
func SandboxFromProto(s *pb.Sandbox) *types.Sandbox {
	if s == nil {
		return nil
	}

	result := &types.Sandbox{}

	if m := s.GetMetadata(); m != nil {
		result.ID = m.GetId()
		result.Name = m.GetName()
		result.CreatedAt = TimeFromMillis(m.GetCreatedAtMs())
		result.Labels = CopyStringMap(m.GetLabels())
		result.ResourceVersion = m.GetResourceVersion()
	}

	if spec := s.GetSpec(); spec != nil {
		result.Spec = sandboxSpecFromProto(spec)
	}

	if status := s.GetStatus(); status != nil {
		result.Status = sandboxStatusFromProto(status)
	} else {
		result.Status.Phase = types.SandboxUnknown
	}

	return result
}

func sandboxSpecFromProto(spec *pb.SandboxSpec) types.SandboxSpec {
	result := types.SandboxSpec{
		LogLevel:    spec.GetLogLevel(),
		Environment: CopyStringMap(spec.GetEnvironment()),
		Providers:   CopyStringSlice(spec.GetProviders()),
		Policy:      SandboxPolicyFromProto(spec.GetPolicy()),
	}

	if tmpl := spec.GetTemplate(); tmpl != nil {
		result.Template = &types.SandboxTemplate{
			Image:            tmpl.GetImage(),
			RuntimeClassName: tmpl.GetRuntimeClassName(),
			AgentSocket:      tmpl.GetAgentSocket(),
			Labels:           CopyStringMap(tmpl.GetLabels()),
			Annotations:      CopyStringMap(tmpl.GetAnnotations()),
			Environment:      CopyStringMap(tmpl.GetEnvironment()),
			UserNamespaces:   CopyBoolPtr(tmpl.UserNamespaces),
		}
	}

	if rr := spec.GetResourceRequirements(); rr != nil {
		if gpu := rr.GetGpu(); gpu != nil && gpu.Count != nil {
			result.GPUCount = gpu.Count
		}
	}

	return result
}

func sandboxStatusFromProto(status *pb.SandboxStatus) types.SandboxStatus {
	result := types.SandboxStatus{
		SandboxName:          status.GetSandboxName(),
		AgentPod:             status.GetAgentPod(),
		AgentFd:              status.GetAgentFd(),
		SandboxFd:            status.GetSandboxFd(),
		Phase:                SandboxPhaseFromProto(status.GetPhase()),
		CurrentPolicyVersion: status.GetCurrentPolicyVersion(),
	}

	for _, c := range status.GetConditions() {
		result.Conditions = append(result.Conditions, types.SandboxCondition{
			Type:               c.GetType(),
			Status:             c.GetStatus(),
			Reason:             c.GetReason(),
			Message:            c.GetMessage(),
			LastTransitionTime: c.GetLastTransitionTime(),
		})
	}

	return result
}

// SandboxPhaseFromProto converts a proto SandboxPhase to an SDK SandboxPhase.
func SandboxPhaseFromProto(phase pb.SandboxPhase) types.SandboxPhase {
	switch phase {
	case pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING:
		return types.SandboxProvisioning
	case pb.SandboxPhase_SANDBOX_PHASE_READY:
		return types.SandboxReady
	case pb.SandboxPhase_SANDBOX_PHASE_ERROR:
		return types.SandboxError
	case pb.SandboxPhase_SANDBOX_PHASE_DELETING:
		return types.SandboxDeleting
	case pb.SandboxPhase_SANDBOX_PHASE_UNKNOWN:
		return types.SandboxUnknown
	default:
		return types.SandboxUnknown
	}
}

// SandboxPhaseToProto converts an SDK SandboxPhase to a proto SandboxPhase.
func SandboxPhaseToProto(phase types.SandboxPhase) pb.SandboxPhase {
	switch phase {
	case types.SandboxProvisioning:
		return pb.SandboxPhase_SANDBOX_PHASE_PROVISIONING
	case types.SandboxReady:
		return pb.SandboxPhase_SANDBOX_PHASE_READY
	case types.SandboxError:
		return pb.SandboxPhase_SANDBOX_PHASE_ERROR
	case types.SandboxDeleting:
		return pb.SandboxPhase_SANDBOX_PHASE_DELETING
	case types.SandboxUnknown:
		return pb.SandboxPhase_SANDBOX_PHASE_UNKNOWN
	default:
		return pb.SandboxPhase_SANDBOX_PHASE_UNKNOWN
	}
}

// SandboxToProto converts an SDK Sandbox to a proto Sandbox.
func SandboxToProto(s *types.Sandbox) *pb.Sandbox {
	if s == nil {
		return nil
	}

	return &pb.Sandbox{
		Metadata: &dm.ObjectMeta{
			Id:              s.ID,
			Name:            s.Name,
			CreatedAtMs:     MillisFromTime(s.CreatedAt),
			Labels:          CopyStringMap(s.Labels),
			ResourceVersion: s.ResourceVersion,
		},
		Spec: SandboxSpecToProto(&s.Spec),
	}
}

// SandboxSpecToProto converts an SDK SandboxSpec to a proto SandboxSpec.
func SandboxSpecToProto(spec *types.SandboxSpec) *pb.SandboxSpec {
	if spec == nil {
		return nil
	}

	result := &pb.SandboxSpec{
		LogLevel:    spec.LogLevel,
		Environment: CopyStringMap(spec.Environment),
		Providers:   CopyStringSlice(spec.Providers),
		Policy:      SandboxPolicyToProto(spec.Policy),
	}

	if spec.Template != nil {
		result.Template = &pb.SandboxTemplate{
			Image:            spec.Template.Image,
			RuntimeClassName: spec.Template.RuntimeClassName,
			AgentSocket:      spec.Template.AgentSocket,
			Labels:           CopyStringMap(spec.Template.Labels),
			Annotations:      CopyStringMap(spec.Template.Annotations),
			Environment:      CopyStringMap(spec.Template.Environment),
			UserNamespaces:   CopyBoolPtr(spec.Template.UserNamespaces),
		}
	}

	if spec.GPUCount != nil {
		result.ResourceRequirements = &pb.ResourceRequirements{
			Gpu: &pb.GpuResourceRequirements{
				Count: spec.GPUCount,
			},
		}
	}

	return result
}
