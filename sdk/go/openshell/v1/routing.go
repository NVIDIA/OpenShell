// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"io"
	"strings"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

// Metadata that lets an edge proxy send a sandbox's long-lived calls straight
// to the gateway replica holding its supervisor session. The headers and the
// retry rule are documented in docs/kubernetes/ingress.mdx.
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
// With an owner, it returns only after the gateway answers, as the CLI does.
func openRouted[S grpc.ClientStream](ctx context.Context, owner string, open func(context.Context) (S, error)) (S, error) {
	if owner == "" {
		return open(ctx)
	}
	stream, err := answered(open(metadata.AppendToOutgoingContext(ctx, routeReplicaHeader, owner)))
	if retryUnrouted(err) {
		return answered(open(ctx))
	}
	return stream, err
}

// answered waits for the response headers. Nil metadata means the stream ended
// without headers, and RecvMsg then returns its status.
func answered[S grpc.ClientStream](stream S, err error) (S, error) {
	if err == nil {
		var md metadata.MD
		if md, err = stream.Header(); err == nil && md == nil {
			err = stream.RecvMsg(nil)
		}
	}
	return stream, err
}

// openBidiRouted is openRouted for a bidi stream whose first frame is sent on open.
func openBidiRouted[I, O any](ctx context.Context, owner string, first *I, open func(context.Context, ...grpc.CallOption) (grpc.BidiStreamingClient[I, O], error)) (grpc.BidiStreamingClient[I, O], error) {
	return openRouted(ctx, owner, func(ctx context.Context) (grpc.BidiStreamingClient[I, O], error) {
		s, err := open(ctx)
		if err != nil {
			return nil, err
		}
		// io.EOF means the stream already ended; answered reports its status.
		if err := s.Send(first); err == io.EOF {
			return answered(s, nil)
		} else if err != nil {
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
