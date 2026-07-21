// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxpb "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// These tests use protobuf reflection to detect proto fields that the
// converter layer does not handle.  When buf generates new fields from an
// updated .proto, the field name appears in the proto descriptor but not in
// the "handled" set below.
//
// Unhandled fields are reported via t.Log (non-breaking) so that proto
// contributors are not forced to fix SDK converters in the same PR.
// A separate CI workflow (planned) will create a GitHub issue when
// converter drift lands on main.
//
// This closes the silent-drift gap described in the PR #2271 review: Go
// compiles happily when a converter ignores a new proto field, so without
// this detection the SDK quietly loses the ability to express that field.

func TestConverterCoversAllProtoFields_SandboxSpec(t *testing.T) {
	handled := fieldSet{
		"log_level":             true,
		"environment":           true,
		"template":              true,
		"policy":                true,
		"providers":             true,
		"resource_requirements": true,
	}

	assertAllFieldsCovered(t, (&pb.SandboxSpec{}).ProtoReflect().Descriptor(), handled, nil)
}

func TestConverterCoversAllProtoFields_SandboxTemplate(t *testing.T) {
	handled := fieldSet{
		"image":              true,
		"runtime_class_name": true,
		"agent_socket":       true,
		"labels":             true,
		"annotations":        true,
		"environment":        true,
		"resources":          true,
		"user_namespaces":    true,
		"driver_config":      true,
	}

	assertAllFieldsCovered(t, (&pb.SandboxTemplate{}).ProtoReflect().Descriptor(), handled, nil)
}

func TestConverterCoversAllProtoFields_SandboxStatus(t *testing.T) {
	handled := fieldSet{
		"sandbox_name":           true,
		"agent_pod":              true,
		"agent_fd":               true,
		"sandbox_fd":             true,
		"phase":                  true,
		"conditions":             true,
		"current_policy_version": true,
	}

	assertAllFieldsCovered(t, (&pb.SandboxStatus{}).ProtoReflect().Descriptor(), handled, nil)
}

func TestConverterCoversAllProtoFields_SandboxCondition(t *testing.T) {
	handled := fieldSet{
		"type":                 true,
		"status":               true,
		"reason":               true,
		"message":              true,
		"last_transition_time": true,
	}

	assertAllFieldsCovered(t, (&pb.SandboxCondition{}).ProtoReflect().Descriptor(), handled, nil)
}

func TestConverterCoversAllProtoFields_SandboxPolicy(t *testing.T) {
	handled := fieldSet{
		"version":          true,
		"filesystem":       true,
		"network_policies": true,
		"process":          true,
		"landlock":         true,
	}

	skipped := fieldSet{
		// Middleware support is not yet exposed in the SDK domain model.
		// Tracked for a later PR in the Go SDK series.
		"network_middlewares": true,
	}

	assertAllFieldsCovered(t, (&sandboxpb.SandboxPolicy{}).ProtoReflect().Descriptor(), handled, skipped)
}

// fieldSet tracks proto field names that the converter handles.
type fieldSet map[string]bool

// assertAllFieldsCovered logs warnings for proto fields not present in
// either handled or skipped.  It does not fail the test so that proto
// changes can merge without simultaneously fixing SDK converters.
// Stale entries in the handled set (fields removed from the proto) DO
// fail, since they indicate the converter references something that no
// longer exists.
func assertAllFieldsCovered(
	t *testing.T,
	desc protoreflect.MessageDescriptor,
	handled fieldSet,
	skipped fieldSet,
) {
	t.Helper()

	fields := desc.Fields()
	for i := 0; i < fields.Len(); i++ {
		name := string(fields.Get(i).Name())
		if handled[name] || skipped[name] {
			continue
		}
		t.Logf(
			"WARNING: proto %s field %q is not handled by the converter and not explicitly skipped. "+
				"Add converter support in the appropriate FromProto/ToProto function, "+
				"or add it to the skipped set with a justification.",
			desc.FullName(), name,
		)
	}

	for name := range handled {
		found := false
		for i := 0; i < fields.Len(); i++ {
			if string(fields.Get(i).Name()) == name {
				found = true
				break
			}
		}
		if !found {
			t.Errorf(
				"handled field %q is listed for proto %s but does not exist in the descriptor. "+
					"The proto field may have been removed or renamed.",
				name, desc.FullName(),
			)
		}
	}
}
