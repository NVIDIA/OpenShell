// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/internal/oidctoken"
)

// writeToken persists an OIDC token bundle to disk as oidc_token.json in
// the given directory, in the CLI's format. The file is written with 0600
// permissions (owner-only) to protect credentials.
func writeToken(dir string, b oidctoken.Bundle) error {
	data, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("%w: failed to marshal token: %v", ErrTokenPersist, err)
	}

	path := filepath.Join(dir, oidctoken.FileName)
	tmp, err := os.CreateTemp(dir, ".oidc-token-*")
	if err != nil {
		return fmt.Errorf("%w: failed to create temporary token file: %v", ErrTokenPersist, err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: failed to secure temporary token file: %v", ErrTokenPersist, err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: failed to write %s: %v", ErrTokenPersist, path, err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("%w: failed to sync %s: %v", ErrTokenPersist, path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("%w: failed to close %s: %v", ErrTokenPersist, path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("%w: failed to replace %s: %v", ErrTokenPersist, path, err)
	}

	return nil
}

// readToken reads an existing oidc_token.json from the given
// directory. It returns:
//   - (bundle, nil) if the file exists and parses
//   - (nil, nil) if the file does not exist
//   - (nil, error) if the file exists but cannot be read or parsed
func readToken(dir string) (*oidctoken.Bundle, error) {
	path := filepath.Join(dir, oidctoken.FileName)

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: cannot read %s: %v", ErrTokenPersist, path, err)
	}

	var bundle oidctoken.Bundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return nil, fmt.Errorf("%w: invalid JSON in %s: %v", ErrTokenPersist, oidctoken.FileName, err)
	}

	return &bundle, nil
}
