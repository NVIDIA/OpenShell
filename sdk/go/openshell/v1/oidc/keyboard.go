// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"reflect"
	"strings"
)

type readResult struct {
	code string
	err  error
}

// keyboardFlow implements the keyboard fallback for the authorization
// code flow. It displays the authorization URL to the user and reads
// the pasted authorization code from the provided reader.
//
// Parameters:
//   - ctx: context for cancellation/timeout
//   - authURL: the full authorization URL to display
//   - input: reader for user input (typically os.Stdin)
//   - output: writer for prompts/instructions (typically os.Stderr)
//
// Returns the authorization code or an error.
func keyboardFlow(ctx context.Context, authURL string, input io.Reader, output io.Writer) (string, error) {
	// Display instructions and URL.
	_, _ = fmt.Fprintf(output, "\nOpen the following URL in your browser to authenticate:\n\n  %s\n\n", authURL)
	_, _ = fmt.Fprint(output, "Paste the authorization code here and press Enter: ")

	// Read code with context cancellation support.
	result, err := keyboardInput.read(ctx, input)
	if err != nil {
		return "", err
	}
	if result.err != nil {
		return "", result.err
	}
	if result.code == "" {
		return "", fmt.Errorf("%w: empty authorization code", ErrAuthCode)
	}
	return result.code, nil
}

type inputRequest struct {
	input   io.Reader
	result  chan readResult
	abandon chan struct{}
}

type inputDispatcher struct {
	requests chan inputRequest
}

var keyboardInput = newInputDispatcher()

func newInputDispatcher() *inputDispatcher {
	d := &inputDispatcher{requests: make(chan inputRequest)}
	go d.run()
	return d
}

func (d *inputDispatcher) read(ctx context.Context, input io.Reader) (readResult, error) {
	if err := ctx.Err(); err != nil {
		return readResult{}, fmt.Errorf("%w: %v", ErrTimeout, err)
	}
	request := inputRequest{
		input:   input,
		result:  make(chan readResult),
		abandon: make(chan struct{}),
	}
	defer close(request.abandon)

	select {
	case d.requests <- request:
	case <-ctx.Done():
		return readResult{}, fmt.Errorf("%w: %v", ErrTimeout, ctx.Err())
	}
	select {
	case result := <-request.result:
		return result, nil
	case <-ctx.Done():
		return readResult{}, fmt.Errorf("%w: %v", ErrTimeout, ctx.Err())
	}
}

func (d *inputDispatcher) run() {
	var (
		scanner       *bufio.Scanner
		scannerInput  io.Reader
		pendingResult *readResult
		pendingInput  io.Reader
	)
	for request := range d.requests {
		if pendingResult != nil && sameReader(pendingInput, request.input) {
			res := *pendingResult
			pendingResult = nil
			pendingInput = nil
			select {
			case request.result <- res:
			case <-request.abandon:
				pendingResult = &res
				pendingInput = request.input
			}
			continue
		}
		pendingResult = nil
		pendingInput = nil

		if scanner == nil || !sameReader(scannerInput, request.input) {
			scanner = bufio.NewScanner(request.input)
			scannerInput = request.input
		}

		var res readResult
		scanned := scanner.Scan()
		if scanned {
			res = readResult{code: strings.TrimSpace(scanner.Text())}
		} else {
			if err := scanner.Err(); err != nil {
				res = readResult{err: fmt.Errorf("%w: failed to read authorization code: %v", ErrAuthCode, err)}
			} else {
				res = readResult{err: fmt.Errorf("%w: no authorization code received (EOF)", ErrAuthCode)}
			}
			scanner = nil
			scannerInput = nil
		}

		select {
		case request.result <- res:
		case <-request.abandon:
			if scanned {
				pendingResult = &res
				pendingInput = request.input
			}
		}
	}
}

func sameReader(a, b io.Reader) bool {
	if a == nil || b == nil {
		return false
	}
	ta := reflect.TypeOf(a)
	tb := reflect.TypeOf(b)
	if ta != tb || !ta.Comparable() {
		return false
	}
	return a == b
}

