// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// FrozenPolicyStateFromProto copies the accepted policy independently of sandbox status.
func FrozenPolicyStateFromProto(state *pb.FrozenSandboxPolicyState) *types.FrozenPolicyState {
	if state == nil {
		return nil
	}
	result := &types.FrozenPolicyState{Requested: state.GetRequested()}
	if frozen := state.GetPolicy(); frozen != nil {
		result.Policy = &types.FrozenSandboxPolicy{
			Policy:  SandboxPolicyFromProto(frozen.GetPolicy()),
			Version: frozen.GetVersion(), PolicyHash: frozen.GetPolicyHash(),
			FrozenAt:            TimeFromProto(frozen.GetFrozenTime()),
			PolicySource:        PolicySourceFromProto(frozen.GetPolicySource()),
			GlobalPolicyVersion: frozen.GetGlobalPolicyVersion(),
		}
	}
	return result
}
