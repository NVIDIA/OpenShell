// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
)

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
	type readResult struct {
		code string
		err  error
	}
	ch := make(chan readResult, 1)

	go func() {
		scanner := bufio.NewScanner(input)
		if scanner.Scan() {
			ch <- readResult{code: strings.TrimSpace(scanner.Text())}
		} else {
			err := scanner.Err()
			if err == nil {
				// EOF without reading a line.
				ch <- readResult{err: fmt.Errorf("%w: no authorization code received (EOF)", ErrAuthCode)}
			} else {
				ch <- readResult{err: fmt.Errorf("%w: failed to read authorization code: %v", ErrAuthCode, err)}
			}
		}
	}()

	select {
	case <-ctx.Done():
		return "", fmt.Errorf("%w: %v", ErrTimeout, ctx.Err())
	case result := <-ch:
		if result.err != nil {
			return "", result.err
		}
		if result.code == "" {
			return "", fmt.Errorf("%w: empty authorization code", ErrAuthCode)
		}
		return result.code, nil
	}
}
