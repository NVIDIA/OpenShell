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
	sb, err := e.sandboxes.Get(ctx, workspace, sandboxName)
	if err != nil {
		return nil, err
	}

	var opt *ExecOptions
	if len(opts) > 0 {
		opt = &opts[0]
	}
	req := converter.ExecRequestToProto(sb.ID, command, opt)

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
	sb, err := e.sandboxes.Get(ctx, workspace, sandboxName)
	if err != nil {
		return nil, err
	}

	var opt *ExecOptions
	if len(opts) > 0 {
		opt = &opts[0]
	}
	req := converter.ExecRequestToProto(sb.ID, command, opt)

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
	sb, err := e.sandboxes.Get(ctx, workspace, sandboxName)
	if err != nil {
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

	startReq := converter.ExecInteractiveRequestToProto(sb.ID, command, cols, rows, opt)
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
// and exitCh (for ExitCode), preventing concurrent Recv calls on the stream.
type interactiveSession struct {
	stream  grpc.BidiStreamingClient[pb.ExecSandboxInput, pb.ExecSandboxEvent]
	cancel  context.CancelFunc
	sendMu  sync.Mutex
	dataCh  chan []byte
	exitCh  chan int
	done    chan struct{}
	errOnce sync.Once
	err     error
	buf     []byte

	exitMu      sync.Mutex
	exitCode    int
	hasExitCode bool
}

func newInteractiveSession(ctx context.Context, cancel context.CancelFunc, stream grpc.BidiStreamingClient[pb.ExecSandboxInput, pb.ExecSandboxEvent]) *interactiveSession {
	s := &interactiveSession{
		stream: stream,
		cancel: cancel,
		dataCh: make(chan []byte, 64),
		exitCh: make(chan int, 1),
		done:   make(chan struct{}),
	}
	go s.readLoop(ctx)
	return s
}

func (s *interactiveSession) setErr(err error) {
	s.errOnce.Do(func() { s.err = err })
}

func (s *interactiveSession) readLoop(ctx context.Context) {
	defer close(s.dataCh)
	defer close(s.done)
	for {
		ev, err := s.stream.Recv()
		if err != nil {
			if err != io.EOF {
				s.setErr(converter.FromGRPCError(err))
			}
			return
		}

		chunk, code, convErr := converter.ExecChunkFromEvent(ev)
		if convErr != nil {
			s.setErr(convErr)
			return
		}
		// nil chunk with no error means exit event
		if chunk == nil {
			select {
			case s.exitCh <- code:
			default:
			}
			return
		}
		select {
		case s.dataCh <- chunk.Data:
		case <-ctx.Done():
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
	s.exitMu.Lock()
	if s.hasExitCode {
		code := s.exitCode
		s.exitMu.Unlock()
		return code, nil
	}
	s.exitMu.Unlock()

	select {
	case code := <-s.exitCh:
		s.exitMu.Lock()
		s.exitCode = code
		s.hasExitCode = true
		s.exitMu.Unlock()
		return code, nil
	case <-s.done:
		select {
		case code := <-s.exitCh:
			s.exitMu.Lock()
			s.exitCode = code
			s.hasExitCode = true
			s.exitMu.Unlock()
			return code, nil
		default:
			if s.err != nil {
				return -1, s.err
			}
			return -1, &StatusError{Code: ErrorInternal, Message: "stream ended without exit event"}
		}
	}
}

func (s *interactiveSession) Close() error {
	s.cancel()
	err := s.stream.CloseSend()
	<-s.done
	return err
}
