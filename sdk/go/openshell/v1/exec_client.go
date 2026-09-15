// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"io"
	"sync"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/converter"
	pb "github.com/NVIDIA/OpenShell/sdk/go/proto/openshellv1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/status"
)

type execClient struct {
	client    pb.OpenShellClient
	sandboxes SandboxInterface
}

func newExecClient(conn grpc.ClientConnInterface, sandboxes SandboxInterface) *execClient {
	return &execClient{client: pb.NewOpenShellClient(conn), sandboxes: sandboxes}
}

func (e *execClient) Run(ctx context.Context, workspace, sandboxName string, command []string, opts ...ExecOptions) (*ExecResult, error) {
	if sandboxName == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	if _, err := e.sandboxes.Get(ctx, workspace, sandboxName); err != nil {
		return nil, err
	}
	var opt *ExecOptions
	if len(opts) > 0 {
		opt = &opts[0]
	}
	req := converter.ExecRequestToProto(sandboxName, command, opt)
	req.WorkspaceScope = namedWorkspaceScope(workspace)

	stream, err := e.client.ExecSandbox(ctx, req)
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}

	var events []*pb.ExecSandboxEvent
	for {
		ev, recvErr := stream.Recv()
		if recvErr == io.EOF {
			break
		}
		if recvErr != nil {
			return nil, converter.FromGRPCError(recvErr)
		}
		events = append(events, ev)
	}

	return converter.ExecResultFromEvents(events)
}

func (e *execClient) Stream(ctx context.Context, workspace, sandboxName string, command []string, opts ...ExecOptions) (ExecStream, error) {
	if sandboxName == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	if _, err := e.sandboxes.Get(ctx, workspace, sandboxName); err != nil {
		return nil, err
	}
	var opt *ExecOptions
	if len(opts) > 0 {
		opt = &opts[0]
	}
	req := converter.ExecRequestToProto(sandboxName, command, opt)
	req.WorkspaceScope = namedWorkspaceScope(workspace)

	streamCtx, cancel := context.WithCancel(ctx)
	stream, err := e.client.ExecSandbox(streamCtx, req)
	if err != nil {
		cancel()
		return nil, converter.FromGRPCError(err)
	}

	return &execStream{stream: stream, cancel: cancel}, nil
}

func (e *execClient) Interactive(ctx context.Context, workspace, sandboxName string, command []string, cols, rows uint32, opts ...ExecOptions) (InteractiveSession, error) {
	if sandboxName == "" {
		return nil, &StatusError{Code: ErrorInvalidArgument, Message: "sandbox name must not be empty"}
	}
	if _, err := e.sandboxes.Get(ctx, workspace, sandboxName); err != nil {
		return nil, err
	}
	var opt *ExecOptions
	if len(opts) > 0 {
		opt = &opts[0]
	}

	streamCtx, cancel := context.WithCancel(ctx)
	stream, err := e.client.ExecSandboxInteractive(streamCtx)
	if err != nil {
		cancel()
		return nil, converter.FromGRPCError(err)
	}

	startReq := converter.ExecInteractiveRequestToProto(sandboxName, command, cols, rows, opt)
	startReq.WorkspaceScope = namedWorkspaceScope(workspace)
	if sendErr := stream.Send(&pb.ExecSandboxInput{
		Payload: &pb.ExecSandboxInput_Start{Start: startReq},
	}); sendErr != nil {
		cancel()
		return nil, converter.FromGRPCError(sendErr)
	}

	return newInteractiveSession(streamCtx, cancel, stream), nil
}

// execStream wraps a server-streaming RPC into the ExecStream interface.
type execStream struct {
	stream   grpc.ServerStreamingClient[pb.ExecSandboxEvent]
	cancel   context.CancelFunc
	exitCode int
	exited   bool
	hasExit  bool
}

func (s *execStream) Next() (*ExecChunk, error) {
	if s.exited {
		return nil, io.EOF
	}

	ev, err := s.stream.Recv()
	if err == io.EOF {
		return nil, io.EOF
	}
	if err != nil {
		return nil, converter.FromGRPCError(err)
	}

	chunk, code, convErr := converter.ExecChunkFromEvent(ev)
	if convErr != nil {
		return nil, convErr
	}
	if chunk != nil {
		return chunk, nil
	}
	// nil chunk with no error means exit event
	s.exitCode = code
	s.exited = true
	s.hasExit = true
	return nil, io.EOF
}

func (s *execStream) ExitCode() (int, error) {
	if !s.exited {
		for {
			_, err := s.Next()
			if err == io.EOF {
				break
			}
			if err != nil {
				return -1, err
			}
		}
	}
	if !s.hasExit {
		return -1, &StatusError{Code: ErrorInternal, Message: "stream ended without exit event"}
	}
	return s.exitCode, nil
}

func (s *execStream) Close() error {
	if s.cancel != nil {
		s.cancel()
	}
	return nil
}

// interactiveSession wraps a bidirectional streaming RPC into the InteractiveSession interface.
// A background goroutine owns the Recv loop and routes events to dataCh (for Read)
// and publishes the final exit/status through done, preventing concurrent Recv calls.
type interactiveSession struct {
	stream        grpc.BidiStreamingClient[pb.ExecSandboxInput, pb.ExecSandboxEvent]
	cancel        context.CancelFunc
	sendMu        sync.Mutex
	inputClosed   bool
	inputCloseErr error
	closeOnce     sync.Once
	closeErr      error
	dataCh        chan []byte
	done          chan struct{}
	errOnce       sync.Once
	err           error
	buf           []byte

	exitCode    int
	hasExitCode bool
}

func newInteractiveSession(ctx context.Context, cancel context.CancelFunc, stream grpc.BidiStreamingClient[pb.ExecSandboxInput, pb.ExecSandboxEvent]) *interactiveSession {
	s := &interactiveSession{
		stream: stream,
		cancel: cancel,
		dataCh: make(chan []byte, 64),
		done:   make(chan struct{}),
	}
	go s.readLoop(ctx)
	return s
}

func (s *interactiveSession) setErr(err error) {
	s.errOnce.Do(func() { s.err = err })
}

func (s *interactiveSession) readLoop(ctx context.Context) {
	defer s.cancel()
	defer close(s.dataCh)
	defer close(s.done)
	for {
		ev, err := s.stream.Recv()
		if err != nil {
			if err != io.EOF {
				s.setErr(converter.FromGRPCError(err))
			} else if ctx.Err() != nil {
				s.setErr(converter.FromGRPCError(status.FromContextError(ctx.Err()).Err()))
			} else if !s.hasExitCode {
				s.setErr(&StatusError{Code: ErrorInternal, Message: "stream ended without exit event"})
			}
			return
		}

		if s.hasExitCode {
			s.setErr(&StatusError{Code: ErrorInternal, Message: "received event after exit"})
			return
		}
		chunk, code, convErr := converter.ExecChunkFromEvent(ev)
		if convErr != nil {
			s.setErr(convErr)
			return
		}
		// nil chunk with no error means exit event
		if chunk == nil {
			s.exitCode = code
			s.hasExitCode = true
			continue
		}
		select {
		case s.dataCh <- chunk.Data:
		case <-ctx.Done():
			s.setErr(converter.FromGRPCError(status.FromContextError(ctx.Err()).Err()))
			return
		}
	}
}

func (s *interactiveSession) Read(p []byte) (int, error) {
	if len(s.buf) > 0 {
		n := copy(p, s.buf)
		s.buf = s.buf[n:]
		return n, nil
	}

	data, ok := <-s.dataCh
	if !ok {
		if s.err != nil {
			return 0, s.err
		}
		return 0, io.EOF
	}
	n := copy(p, data)
	if n < len(data) {
		s.buf = append(s.buf, data[n:]...)
	}
	return n, nil
}

func (s *interactiveSession) Write(p []byte) (int, error) {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.inputClosed {
		return 0, io.ErrClosedPipe
	}
	err := s.stream.Send(&pb.ExecSandboxInput{
		Payload: &pb.ExecSandboxInput_Stdin{Stdin: p},
	})
	if err != nil {
		return 0, converter.FromGRPCError(err)
	}
	return len(p), nil
}

func (s *interactiveSession) Resize(cols, rows uint32) error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if s.inputClosed {
		return io.ErrClosedPipe
	}
	err := s.stream.Send(&pb.ExecSandboxInput{
		Payload: &pb.ExecSandboxInput_Resize{
			Resize: &pb.ExecSandboxWindowResize{
				Cols: cols,
				Rows: rows,
			},
		},
	})
	if err != nil {
		return converter.FromGRPCError(err)
	}
	return nil
}

func (s *interactiveSession) ExitCode() (int, error) {
	<-s.done
	if s.hasExitCode {
		return s.exitCode, s.err
	}
	return -1, s.err
}

func (s *interactiveSession) CloseWrite() error {
	s.sendMu.Lock()
	defer s.sendMu.Unlock()
	if !s.inputClosed {
		s.inputClosed = true
		s.inputCloseErr = s.stream.CloseSend()
	}
	return s.inputCloseErr
}

func (s *interactiveSession) Cancel() error {
	s.closeOnce.Do(func() {
		// Cancel before taking sendMu so a blocked Write can release it.
		s.cancel()
		s.closeErr = s.CloseWrite()
		<-s.done
	})
	return s.closeErr
}

func (s *interactiveSession) Close() error {
	return s.Cancel()
}
