// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"fmt"
	"time"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/structpb"
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
		result.Annotations = CopyStringMap(m.GetAnnotations())
		result.ResourceVersion = m.GetResourceVersion()
		result.Workspace = m.GetWorkspace()
		result.DeletionTimestamp = TimeFromMillisPtr(m.GetDeletionTimestampMs())
	}
	if provenance := s.GetCreatedFromTemplate(); provenance != nil {
		result.CreatedFromTemplate = &types.SandboxTemplateProvenance{
			Name:            provenance.GetName(),
			ResourceVersion: provenance.GetResourceVersion(),
		}
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
		Workload:     sandboxWorkloadFromProto(spec.GetWorkload()),
		DriverConfig: structToMap(spec.GetDriverConfig()),
		Providers:    CopyStringSlice(spec.GetProviders()),
		Policy:       SandboxPolicyFromProto(spec.GetPolicy()),
	}

	return result
}

func sandboxWorkloadFromProto(workload *pb.SandboxWorkloadConfig) *types.SandboxWorkloadConfig {
	if workload == nil {
		return nil
	}
	return &types.SandboxWorkloadConfig{
		Image:       workload.GetImage(),
		Environment: CopyStringMap(workload.GetEnvironment()),
		Resources:   sandboxResourcesFromProto(workload.GetResources()),
	}
}

func sandboxResourcesFromProto(resources *pb.SandboxResources) *types.SandboxResources {
	if resources == nil {
		return nil
	}
	return &types.SandboxResources{
		CPU:      resources.GetCpu(),
		Memory:   resources.GetMemory(),
		GPUCount: resources.GpuCount,
	}
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
	case pb.SandboxPhase_SANDBOX_PHASE_STOPPING:
		return types.SandboxStopping
	case pb.SandboxPhase_SANDBOX_PHASE_STOPPED:
		return types.SandboxStopped
	case pb.SandboxPhase_SANDBOX_PHASE_STARTING:
		return types.SandboxStarting
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
	case types.SandboxStopping:
		return pb.SandboxPhase_SANDBOX_PHASE_STOPPING
	case types.SandboxStopped:
		return pb.SandboxPhase_SANDBOX_PHASE_STOPPED
	case types.SandboxStarting:
		return pb.SandboxPhase_SANDBOX_PHASE_STARTING
	default:
		return pb.SandboxPhase_SANDBOX_PHASE_UNKNOWN
	}
}

// SandboxToProto converts an SDK Sandbox to a proto Sandbox.
func SandboxToProto(s *types.Sandbox) (*pb.Sandbox, error) {
	if s == nil {
		return nil, nil
	}
	spec, err := SandboxSpecToProto(&s.Spec)
	if err != nil {
		return nil, err
	}

	return &pb.Sandbox{
		Metadata: &dm.ObjectMeta{
			Id:                  s.ID,
			Name:                s.Name,
			CreatedAtMs:         MillisFromTime(s.CreatedAt),
			Labels:              CopyStringMap(s.Labels),
			Annotations:         CopyStringMap(s.Annotations),
			ResourceVersion:     s.ResourceVersion,
			Workspace:           s.Workspace,
			DeletionTimestampMs: MillisFromTimePtr(s.DeletionTimestamp),
		},
		CreatedFromTemplate: sandboxTemplateProvenanceToProto(s.CreatedFromTemplate),
		Spec:                spec,
	}, nil
}

// SandboxSpecToProto converts an SDK SandboxSpec to a proto SandboxSpec.
func SandboxSpecToProto(spec *types.SandboxSpec) (*pb.SandboxSpec, error) {
	if spec == nil {
		return nil, nil
	}

	driverConfig, err := mapToStruct(spec.DriverConfig)
	if err != nil {
		return nil, fmt.Errorf("convert driver config: %w", err)
	}
	policy, err := SandboxPolicyToProtoChecked(spec.Policy)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	result := &pb.SandboxSpec{
		Workload:     sandboxWorkloadToProto(spec.Workload),
		DriverConfig: driverConfig,
		Providers:    CopyStringSlice(spec.Providers),
		Policy:       policy,
	}

	return result, nil
}

// SandboxSpecToProtoChecked converts an SDK SandboxSpec and reports values
// that protobuf Struct cannot represent instead of silently dropping them.
func SandboxSpecToProtoChecked(spec *types.SandboxSpec) (*pb.SandboxSpec, error) {
	return SandboxSpecToProto(spec)
}

func sandboxWorkloadToProto(workload *types.SandboxWorkloadConfig) *pb.SandboxWorkloadConfig {
	if workload == nil {
		return nil
	}
	return &pb.SandboxWorkloadConfig{
		Image:       workload.Image,
		Environment: CopyStringMap(workload.Environment),
		Resources:   sandboxResourcesToProto(workload.Resources),
	}
}

func sandboxResourcesToProto(resources *types.SandboxResources) *pb.SandboxResources {
	if resources == nil {
		return nil
	}
	return &pb.SandboxResources{
		Cpu:      resources.CPU,
		Memory:   resources.Memory,
		GpuCount: resources.GPUCount,
	}
}

func sandboxTemplateProvenanceToProto(provenance *types.SandboxTemplateProvenance) *pb.SandboxTemplateProvenance {
	if provenance == nil {
		return nil
	}
	return &pb.SandboxTemplateProvenance{
		Name:            provenance.Name,
		ResourceVersion: provenance.ResourceVersion,
	}
}

// SandboxTemplateFromProto converts a proto SandboxTemplate to an SDK SandboxTemplate.
func SandboxTemplateFromProto(template *pb.SandboxTemplate) *types.SandboxTemplate {
	if template == nil {
		return nil
	}
	result := &types.SandboxTemplate{}
	if m := template.GetMetadata(); m != nil {
		result.ID = m.GetId()
		result.Name = m.GetName()
		result.CreatedAt = TimeFromMillis(m.GetCreatedAtMs())
		result.Labels = CopyStringMap(m.GetLabels())
		result.Annotations = CopyStringMap(m.GetAnnotations())
		result.ResourceVersion = m.GetResourceVersion()
		result.Workspace = m.GetWorkspace()
		result.DeletionTimestamp = TimeFromMillisPtr(m.GetDeletionTimestampMs())
	}
	result.Spec = sandboxTemplateSpecFromProto(template.GetSpec())
	return result
}

func sandboxTemplateSpecFromProto(spec *pb.SandboxTemplateSpec) types.SandboxTemplateSpec {
	if spec == nil {
		return types.SandboxTemplateSpec{}
	}
	return types.SandboxTemplateSpec{
		Workload:            sandboxWorkloadFromProto(spec.GetWorkload()),
		DriverConfig:        structToMap(spec.GetDriverConfig()),
		DesiredServiceLevel: sandboxServiceLevelFromProto(spec.GetDesiredServiceLevel()),
	}
}

func sandboxServiceLevelFromProto(serviceLevel *pb.SandboxServiceLevel) *types.SandboxServiceLevel {
	if serviceLevel == nil {
		return nil
	}
	return &types.SandboxServiceLevel{
		Startup: sandboxStartupFromProto(serviceLevel.GetStartup()),
	}
}

func sandboxStartupFromProto(startup *pb.SandboxStartup) *types.SandboxStartup {
	if startup == nil {
		return nil
	}
	return &types.SandboxStartup{
		ReadyWithin: durationFromProto(startup.GetReadyWithin()),
		MaxBurst:    startup.GetMaxBurst(),
	}
}

// SandboxTemplateToProto converts an SDK SandboxTemplate to a proto SandboxTemplate.
func SandboxTemplateToProto(template *types.SandboxTemplate) (*pb.SandboxTemplate, error) {
	if template == nil {
		return nil, nil
	}
	spec, err := sandboxTemplateSpecToProto(&template.Spec)
	if err != nil {
		return nil, err
	}
	return &pb.SandboxTemplate{
		Metadata: &dm.ObjectMeta{
			Id:                  template.ID,
			Name:                template.Name,
			CreatedAtMs:         MillisFromTime(template.CreatedAt),
			Labels:              CopyStringMap(template.Labels),
			Annotations:         CopyStringMap(template.Annotations),
			ResourceVersion:     template.ResourceVersion,
			Workspace:           template.Workspace,
			DeletionTimestampMs: MillisFromTimePtr(template.DeletionTimestamp),
		},
		Spec: spec,
	}, nil
}

func sandboxTemplateSpecToProto(spec *types.SandboxTemplateSpec) (*pb.SandboxTemplateSpec, error) {
	if spec == nil {
		return nil, nil
	}
	driverConfig, err := mapToStruct(spec.DriverConfig)
	if err != nil {
		return nil, fmt.Errorf("convert template driver config: %w", err)
	}
	return &pb.SandboxTemplateSpec{
		Workload:            sandboxWorkloadToProto(spec.Workload),
		DriverConfig:        driverConfig,
		DesiredServiceLevel: sandboxServiceLevelToProto(spec.DesiredServiceLevel),
	}, nil
}

func sandboxServiceLevelToProto(serviceLevel *types.SandboxServiceLevel) *pb.SandboxServiceLevel {
	if serviceLevel == nil {
		return nil
	}
	return &pb.SandboxServiceLevel{
		Startup: sandboxStartupToProto(serviceLevel.Startup),
	}
}

func sandboxStartupToProto(startup *types.SandboxStartup) *pb.SandboxStartup {
	if startup == nil {
		return nil
	}
	return &pb.SandboxStartup{
		ReadyWithin: durationToProto(startup.ReadyWithin),
		MaxBurst:    startup.MaxBurst,
	}
}

func durationFromProto(duration *durationpb.Duration) time.Duration {
	if duration == nil {
		return 0
	}
	return duration.AsDuration()
}

func durationToProto(duration time.Duration) *durationpb.Duration {
	if duration == 0 {
		return nil
	}
	return durationpb.New(duration)
}

func structToMap(s *structpb.Struct) map[string]any {
	if s == nil {
		return nil
	}
	return s.AsMap()
}

func mapToStruct(m map[string]any) (*structpb.Struct, error) {
	if m == nil {
		return nil, nil
	}
	return structpb.NewStruct(m)
}
