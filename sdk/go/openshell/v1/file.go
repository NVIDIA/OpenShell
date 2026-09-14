// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package v1

import (
	"context"
	"errors"
)

// ErrTransportNotAvailable indicates that this SDK build has no file-transfer
// transport. Callers can detect it with errors.Is.
var ErrTransportNotAvailable = errors.New("openshell: file transport not available")

// FileInterface defines file transfer operations on sandboxes.
// Methods accept a sandbox name and resolve it to an ID internally.
type FileInterface interface {
	Upload(ctx context.Context, workspace, sandboxName string, localPath string, remotePath string) error
	Download(ctx context.Context, workspace, sandboxName string, remotePath string, localPath string) error
}
