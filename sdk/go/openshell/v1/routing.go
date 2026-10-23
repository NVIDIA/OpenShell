// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"io"
	"strings"

	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Metadata that lets an edge proxy send a sandbox's long-lived calls straight
// to the gateway replica holding its supervisor session.
const (
	ownerReplicaHeader = "x-openshell-owner"
	ownerRequestHeader = "x-openshell-want-owner"
	routeReplicaHeader = "x-openshell-replica"
)

// ownerGetter is implemented by the gateway-backed sandbox client.
type ownerGetter interface {
	getWithOwner(ctx context.Context, workspace, name string) (*Sandbox, string, error)
}

// sandboxOwner checks that the sandbox exists and returns the replica that
// owns its supervisor session, or "" when the gateway reports none.
func sandboxOwner(ctx context.Context, sandboxes SandboxInterface, workspace, name string) (string, error) {
	if g, ok := sandboxes.(ownerGetter); ok {
		_, owner, err := g.getWithOwner(ctx, workspace, name)
		return owner, err
	}
	_, err := sandboxes.Get(ctx, workspace, name)
	return "", err
}

// openRouted opens a stream tagged with the owner replica. It opens once more
// untagged when the proxy reports that the owner's route has no ready endpoints.
// A stale owner is safe: any replica relays the call to the real owner.
func openRouted[S grpc.ClientStream](ctx context.Context, owner string, open func(context.Context) (S, error)) (S, error) {
	if owner == "" {
		return open(ctx)
	}
	stream, err := open(metadata.AppendToOutgoingContext(ctx, routeReplicaHeader, owner))
	if err == nil {
		// Header blocks until the proxy answers; nil metadata means the stream
		// ended without headers, and RecvMsg then returns its status.
		var md metadata.MD
		if md, err = stream.Header(); err == nil && md == nil {
			err = stream.RecvMsg(nil)
		}
	}
	if retryUnrouted(err) {
		return open(ctx)
	}
	return stream, err
}

// openForward opens a ForwardTcp stream routed to owner and sends its init frame.
func openForward(ctx context.Context, client pb.OpenShellClient, owner string, init *pb.TcpForwardFrame) (grpc.BidiStreamingClient[pb.TcpForwardFrame, pb.TcpForwardFrame], error) {
	return openRouted(ctx, owner, func(ctx context.Context) (grpc.BidiStreamingClient[pb.TcpForwardFrame, pb.TcpForwardFrame], error) {
		s, err := client.ForwardTcp(ctx)
		if err != nil {
			return nil, err
		}
		// io.EOF means the stream already ended; its status comes from Recv.
		if err := s.Send(init); err != nil && err != io.EOF {
			return s, err
		}
		return s, nil
	})
}

// retryUnrouted matches what Envoy Gateway answers for a replica route with no
// ready endpoints: UNAVAILABLE with no message. Gateway errors always carry one.
func retryUnrouted(err error) bool {
	s, ok := status.FromError(err)
	if !ok || s.Code() != codes.Unavailable {
		return false
	}
	msg := s.Message()
	return msg == "" || strings.Contains(msg, "no healthy upstream") || strings.Contains(msg, "connection failure")
}
