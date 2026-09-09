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

	if provenance := s.GetCreatedFromWorkloadTemplate(); provenance != nil {
		result.CreatedFromWorkloadTemplate = &types.SandboxWorkloadTemplateProvenance{
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
		LogLevel:    spec.GetLogLevel(),
		Environment: CopyStringMap(spec.GetEnvironment()),
		Providers:   CopyStringSlice(spec.GetProviders()),
		Policy:      SandboxPolicyFromProto(spec.GetPolicy()),
	}

	if tmpl := spec.GetTemplate(); tmpl != nil {
		t := &types.SandboxTemplate{
			Image:            tmpl.GetImage(),
			RuntimeClassName: tmpl.GetRuntimeClassName(),
			AgentSocket:      tmpl.GetAgentSocket(),
			Labels:           CopyStringMap(tmpl.GetLabels()),
			Annotations:      CopyStringMap(tmpl.GetAnnotations()),
			Environment:      CopyStringMap(tmpl.GetEnvironment()),
			UserNamespaces:   CopyBoolPtr(tmpl.UserNamespaces),
		}
		if res := tmpl.GetResources(); res != nil {
			t.Resources = res.AsMap()
		}
		if dc := tmpl.GetDriverConfig(); dc != nil {
			t.DriverConfig = dc.AsMap()
		}
		result.Template = t
	}

	if rr := spec.GetResourceRequirements(); rr != nil {
		if gpu := rr.GetGpu(); gpu != nil {
			result.GPU = true
			if gpu.Count != nil {
				result.GPUCount = gpu.Count
			}
		}
	}
	result.Command = CopyStringSlice(spec.GetCommand())
	result.TTY = spec.GetTty()

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
	result.ExitCode = CopyInt32Ptr(status.ExitCode)

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
	case pb.SandboxPhase_SANDBOX_PHASE_COMPLETED:
		return types.SandboxCompleted
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
	case types.SandboxCompleted:
		return pb.SandboxPhase_SANDBOX_PHASE_COMPLETED
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
			Id:                  s.ID,
			Name:                s.Name,
			CreatedAtMs:         MillisFromTime(s.CreatedAt),
			Labels:              CopyStringMap(s.Labels),
			Annotations:         CopyStringMap(s.Annotations),
			ResourceVersion:     s.ResourceVersion,
			Workspace:           s.Workspace,
			DeletionTimestampMs: MillisFromTimePtr(s.DeletionTimestamp),
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
		tmpl := &pb.SandboxTemplate{
			Image:            spec.Template.Image,
			RuntimeClassName: spec.Template.RuntimeClassName,
			AgentSocket:      spec.Template.AgentSocket,
			Labels:           CopyStringMap(spec.Template.Labels),
			Annotations:      CopyStringMap(spec.Template.Annotations),
			Environment:      CopyStringMap(spec.Template.Environment),
			UserNamespaces:   CopyBoolPtr(spec.Template.UserNamespaces),
		}
		if spec.Template.Resources != nil {
			// Non-JSON-compatible values (e.g., chan, func) are silently dropped.
			// Round-trip data from structpb.AsMap is always re-serializable.
			s, err := structpb.NewStruct(spec.Template.Resources)
			if err == nil {
				tmpl.Resources = s
			}
		}
		if spec.Template.DriverConfig != nil {
			s, err := structpb.NewStruct(spec.Template.DriverConfig)
			if err == nil {
				tmpl.DriverConfig = s
			}
		}
		result.Template = tmpl
	}

	if spec.GPU || spec.GPUCount != nil {
		result.ResourceRequirements = &pb.ResourceRequirements{
			Gpu: &pb.GpuResourceRequirements{
				Count: spec.GPUCount,
			},
		}
	}

	result.Command = CopyStringSlice(spec.Command)
	result.Tty = spec.TTY

	return result
}

// SandboxSpecToProtoChecked converts an SDK SandboxSpec and reports values
// that protobuf Struct cannot represent instead of silently dropping them.
func SandboxSpecToProtoChecked(spec *types.SandboxSpec) (*pb.SandboxSpec, error) {
	result := SandboxSpecToProto(spec)
	if spec == nil {
		return result, nil
	}
	policy, err := SandboxPolicyToProtoChecked(spec.Policy)
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	result.Policy = policy
	if spec.Template == nil {
		return result, nil
	}
	if spec.Template.Resources != nil {
		resources, err := structpb.NewStruct(spec.Template.Resources)
		if err != nil {
			return nil, fmt.Errorf("template resources: %w", err)
		}
		result.Template.Resources = resources
	}
	if spec.Template.DriverConfig != nil {
		driverConfig, err := structpb.NewStruct(spec.Template.DriverConfig)
		if err != nil {
			return nil, fmt.Errorf("template driver config: %w", err)
		}
		result.Template.DriverConfig = driverConfig
	}
	return result, nil
}

// SandboxWorkloadTemplateFromProto converts a reusable template proto to an SDK template.
func SandboxWorkloadTemplateFromProto(t *pb.SandboxWorkloadTemplate) *types.SandboxWorkloadTemplate {
	if t == nil {
		return nil
	}

	result := &types.SandboxWorkloadTemplate{}
	if m := t.GetMetadata(); m != nil {
		result.ID = m.GetId()
		result.Name = m.GetName()
		result.CreatedAt = TimeFromMillis(m.GetCreatedAtMs())
		result.Labels = CopyStringMap(m.GetLabels())
		result.Annotations = CopyStringMap(m.GetAnnotations())
		result.ResourceVersion = m.GetResourceVersion()
		result.Workspace = m.GetWorkspace()
		result.DeletionTimestamp = TimeFromMillisPtr(m.GetDeletionTimestampMs())
	}
	if spec := t.GetSpec(); spec != nil {
		result.Spec = SandboxWorkloadTemplateSpecFromProto(spec)
	}
	return result
}

// SandboxWorkloadTemplateSpecFromProto converts a reusable template spec proto.
func SandboxWorkloadTemplateSpecFromProto(spec *pb.SandboxWorkloadTemplateSpec) types.SandboxWorkloadTemplateSpec {
	result := types.SandboxWorkloadTemplateSpec{}
	if spec == nil {
		return result
	}
	result.Workload = SandboxWorkloadConfigFromProto(spec.GetWorkload())
	result.DesiredServiceLevel = SandboxServiceLevelFromProto(spec.GetDesiredServiceLevel())
	if dc := spec.GetDriverConfig(); dc != nil {
		result.DriverConfig = dc.AsMap()
	}
	return result
}

// SandboxWorkloadConfigFromProto converts a portable workload proto.
func SandboxWorkloadConfigFromProto(workload *pb.SandboxWorkloadConfig) *types.SandboxWorkloadConfig {
	if workload == nil {
		return nil
	}
	return &types.SandboxWorkloadConfig{
		Image:       workload.GetImage(),
		Environment: CopyStringMap(workload.GetEnvironment()),
		Resources:   SandboxResourcesFromProto(workload.GetResources()),
	}
}

// SandboxResourcesFromProto converts portable resource requirements.
func SandboxResourcesFromProto(resources *pb.SandboxResources) *types.SandboxResources {
	if resources == nil {
		return nil
	}
	return &types.SandboxResources{
		CPU:    resources.GetCpu(),
		Memory: resources.GetMemory(),
		GPU:    sandboxResourceGpuFromProto(resources),
	}
}

// SandboxServiceLevelFromProto converts template service-level hints.
func SandboxServiceLevelFromProto(level *pb.SandboxServiceLevel) *types.SandboxServiceLevel {
	if level == nil {
		return nil
	}
	return &types.SandboxServiceLevel{
		Startup: SandboxStartupFromProto(level.GetStartup()),
	}
}

// SandboxStartupFromProto converts startup service-level hints.
func SandboxStartupFromProto(startup *pb.SandboxStartup) *types.SandboxStartup {
	if startup == nil {
		return nil
	}
	return &types.SandboxStartup{
		ReadyWithin: durationFromProto(startup.GetReadyWithin()),
		MaxBurst:    startup.GetMaxBurst(),
	}
}

// SandboxWorkloadTemplateToProto converts an SDK reusable template to proto.
func SandboxWorkloadTemplateToProto(t *types.SandboxWorkloadTemplate) *pb.SandboxWorkloadTemplate {
	if t == nil {
		return nil
	}
	return &pb.SandboxWorkloadTemplate{
		Metadata: &dm.ObjectMeta{
			Id:                  t.ID,
			Name:                t.Name,
			CreatedAtMs:         MillisFromTime(t.CreatedAt),
			Labels:              CopyStringMap(t.Labels),
			Annotations:         CopyStringMap(t.Annotations),
			ResourceVersion:     t.ResourceVersion,
			Workspace:           t.Workspace,
			DeletionTimestampMs: MillisFromTimePtr(t.DeletionTimestamp),
		},
		Spec: SandboxWorkloadTemplateSpecToProto(&t.Spec),
	}
}

// SandboxWorkloadTemplateSpecToProto converts an SDK reusable template spec to proto.
func SandboxWorkloadTemplateSpecToProto(spec *types.SandboxWorkloadTemplateSpec) *pb.SandboxWorkloadTemplateSpec {
	if spec == nil {
		return nil
	}
	result := &pb.SandboxWorkloadTemplateSpec{
		Workload:            SandboxWorkloadConfigToProto(spec.Workload),
		DesiredServiceLevel: SandboxServiceLevelToProto(spec.DesiredServiceLevel),
	}
	if spec.DriverConfig != nil {
		if driverConfig, err := structpb.NewStruct(spec.DriverConfig); err == nil {
			result.DriverConfig = driverConfig
		}
	}
	return result
}

// SandboxWorkloadConfigToProto converts an SDK portable workload to proto.
func SandboxWorkloadConfigToProto(workload *types.SandboxWorkloadConfig) *pb.SandboxWorkloadConfig {
	if workload == nil {
		return nil
	}
	return &pb.SandboxWorkloadConfig{
		Image:       workload.Image,
		Environment: CopyStringMap(workload.Environment),
		Resources:   SandboxResourcesToProto(workload.Resources),
	}
}

// SandboxResourcesToProto converts portable resource requirements.
func SandboxResourcesToProto(resources *types.SandboxResources) *pb.SandboxResources {
	if resources == nil {
		return nil
	}
	return &pb.SandboxResources{
		Cpu:    resources.CPU,
		Memory: resources.Memory,
		Gpu:    sandboxResourceGpuToProto(resources),
	}
}

func sandboxResourceGpuToProto(resources *types.SandboxResources) *pb.GpuResourceRequirements {
	if resources == nil || resources.GPU == nil {
		return nil
	}
	return &pb.GpuResourceRequirements{Count: CopyUint32Ptr(resources.GPU.Count)}
}

func sandboxResourceGpuFromProto(resources *pb.SandboxResources) *types.SandboxGPURequirements {
	if resources == nil || resources.GetGpu() == nil {
		return nil
	}
	return &types.SandboxGPURequirements{Count: CopyUint32Ptr(resources.GetGpu().Count)}
}

// SandboxServiceLevelToProto converts template service-level hints.
func SandboxServiceLevelToProto(level *types.SandboxServiceLevel) *pb.SandboxServiceLevel {
	if level == nil {
		return nil
	}
	return &pb.SandboxServiceLevel{
		Startup: SandboxStartupToProto(level.Startup),
	}
}

// SandboxStartupToProto converts startup service-level hints.
func SandboxStartupToProto(startup *types.SandboxStartup) *pb.SandboxStartup {
	if startup == nil {
		return nil
	}
	return &pb.SandboxStartup{
		ReadyWithin: durationToProto(startup.ReadyWithin),
		MaxBurst:    startup.MaxBurst,
	}
}

// SandboxWorkloadTemplateToProtoChecked converts an SDK reusable template and
// reports driver config values that protobuf Struct cannot represent.
func SandboxWorkloadTemplateToProtoChecked(t *types.SandboxWorkloadTemplate) (*pb.SandboxWorkloadTemplate, error) {
	result := SandboxWorkloadTemplateToProto(t)
	if t == nil {
		return result, nil
	}
	if t.Spec.DriverConfig != nil {
		driverConfig, err := structpb.NewStruct(t.Spec.DriverConfig)
		if err != nil {
			return nil, fmt.Errorf("driver config: %w", err)
		}
		result.Spec.DriverConfig = driverConfig
	}
	return result, nil
}

// CopyUint32Ptr returns a copy of a *uint32 pointer.
func CopyUint32Ptr(p *uint32) *uint32 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

func durationFromProto(d *durationpb.Duration) time.Duration {
	if d == nil {
		return 0
	}
	return d.AsDuration()
}

func durationToProto(d time.Duration) *durationpb.Duration {
	if d == 0 {
		return nil
	}
	return durationpb.New(d)
}
