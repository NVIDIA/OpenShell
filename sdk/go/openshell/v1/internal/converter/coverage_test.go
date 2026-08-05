// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"

	dm "github.com/NVIDIA/OpenShell/sdk/go/proto/datamodelv1"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	sandboxpb "github.com/NVIDIA/OpenShell/sdk/go/proto/sandboxv1"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// These tests use protobuf reflection to detect proto fields that the
// converter layer does not handle. When buf generates new fields from an
// updated .proto, the field name appears in the proto descriptor but not in
// the "handled" set below.
//
// Unhandled fields FAIL the test so that proto drift is caught immediately.
// If a field is intentionally deferred, add it to the "skipped" set with a
// justification comment.

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
		// Tracked in GitHub issue #36 for Drop D.
		"network_middlewares": true,
	}

	assertAllFieldsCovered(t, (&sandboxpb.SandboxPolicy{}).ProtoReflect().Descriptor(), handled, skipped)
}

func TestConverterCoversAllProtoFields_NetworkEndpoint(t *testing.T) {
	handled := fieldSet{
		"host":                            true,
		"port":                            true,
		"ports":                           true,
		"protocol":                        true,
		"tls":                             true,
		"enforcement":                     true,
		"access":                          true,
		"rules":                           true,
		"allowed_ips":                     true,
		"deny_rules":                      true,
		"allow_encoded_slash":             true,
		"persisted_queries":               true,
		"graphql_persisted_queries":       true,
		"graphql_max_body_bytes":          true,
		"path":                            true,
		"websocket_credential_rewrite":    true,
		"request_body_credential_rewrite": true,
		"advisor_proposed":                true,
		"credential_signing":              true,
		"signing_service":                 true,
		"signing_region":                  true,
		"json_rpc_max_body_bytes":         true,
		"mcp":                             true,
	}

	assertAllFieldsCovered(t, (&sandboxpb.NetworkEndpoint{}).ProtoReflect().Descriptor(), handled, nil)
}

func TestConverterCoversAllProtoFields_L7Allow(t *testing.T) {
	handled := fieldSet{
		"method":         true,
		"path":           true,
		"command":        true,
		"query":          true,
		"operation_type": true,
		"operation_name": true,
		"fields":         true,
		"params":         true,
	}

	assertAllFieldsCovered(t, (&sandboxpb.L7Allow{}).ProtoReflect().Descriptor(), handled, nil)
}

func TestConverterCoversAllProtoFields_L7DenyRule(t *testing.T) {
	handled := fieldSet{
		"method":         true,
		"path":           true,
		"command":        true,
		"query":          true,
		"operation_type": true,
		"operation_name": true,
		"fields":         true,
		"params":         true,
	}

	assertAllFieldsCovered(t, (&sandboxpb.L7DenyRule{}).ProtoReflect().Descriptor(), handled, nil)
}

func TestConverterCoversAllProtoFields_Provider(t *testing.T) {
	handled := fieldSet{
		"metadata":                 true,
		"type":                     true,
		"credentials":              true,
		"config":                   true,
		"credential_expires_at_ms": true,
		"profile_workspace":        true,
		"credential_handles":       true,
	}

	assertAllFieldsCovered(t, (&dm.Provider{}).ProtoReflect().Descriptor(), handled, nil)
}

func TestConverterCoversAllProtoFields_CredentialHandle(t *testing.T) {
	handled := fieldSet{
		"driver":   true,
		"handle":   true,
		"metadata": true,
	}

	assertAllFieldsCovered(t, (&dm.CredentialHandle{}).ProtoReflect().Descriptor(), handled, nil)
}

func TestConverterCoversAllProtoFields_McpOptions(t *testing.T) {
	handled := fieldSet{
		"strict_tool_names":           true,
		"allow_all_known_mcp_methods": true,
	}

	assertAllFieldsCovered(t, (&sandboxpb.McpOptions{}).ProtoReflect().Descriptor(), handled, nil)
}

// fieldSet tracks proto field names that the converter handles.
type fieldSet map[string]bool

// assertAllFieldsCovered fails the test for proto fields not present in
// either handled or skipped. Stale entries in the handled set (fields
// removed from the proto) also fail.
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
		t.Errorf(
			"proto %s field %q is not handled by the converter and not explicitly skipped. "+
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
