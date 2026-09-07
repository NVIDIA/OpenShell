// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
)

// SSHSessionFromProto converts a CreateSshSessionResponse to an SSHSession.
func SSHSessionFromProto(resp *pb.CreateSshSessionResponse) *v1.SSHSession {
	if resp == nil {
		return nil
	}
	return &v1.SSHSession{
		SandboxID:          resp.GetSandboxId(),
		Token:              resp.GetToken(),
		GatewayHost:        resp.GetGatewayHost(),
		GatewayPort:        resp.GetGatewayPort(),
		GatewayScheme:      resp.GetGatewayScheme(),
		HostKeyFingerprint: resp.GetHostKeyFingerprint(),
		ExpiresAtMs:        resp.GetExpiresAtMs(),
	}
}

// SSHSessionToProto converts an SSHSession to a CreateSshSessionResponse.
// This is primarily used for round-trip testing and fake implementations.
func SSHSessionToProto(session *v1.SSHSession) *pb.CreateSshSessionResponse {
	if session == nil {
		return nil
	}
	return &pb.CreateSshSessionResponse{
		SandboxId:          session.SandboxID,
		Token:              session.Token,
		GatewayHost:        session.GatewayHost,
		GatewayPort:        session.GatewayPort,
		GatewayScheme:      session.GatewayScheme,
		HostKeyFingerprint: session.HostKeyFingerprint,
		ExpiresAtMs:        session.ExpiresAtMs,
	}
}
