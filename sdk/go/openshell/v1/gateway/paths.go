// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

const (
	// appName is the application directory name used in XDG paths.
	appName = "openshell"

	// gatewaySubdir is the subdirectory within the app config holding
	// per-gateway directories.
	gatewaySubdir = "gateways"

	// activeGatewayFile is the filename that stores the active gateway name.
	activeGatewayFile = "active_gateway"

	// systemConfigBase is the system-wide config directory.
	systemConfigBase = "/etc/openshell"

	// systemGatewayDirEnv overrides the system-wide config root. Keep this in
	// sync with the Rust CLI so SDK discovery sees the same gateway set.
	systemGatewayDirEnv = "OPENSHELL_SYSTEM_GATEWAY_DIR"
)

// userConfigDir returns the user-specific configuration directory for
// OpenShell, following XDG Base Directory specification:
//
//	$XDG_CONFIG_HOME/openshell    (if XDG_CONFIG_HOME is set)
//	~/.config/openshell           (fallback)
func userConfigDir() (string, error) {
	if xdg := os.Getenv("XDG_CONFIG_HOME"); xdg != "" {
		if !filepath.IsAbs(xdg) {
			return "", fmt.Errorf("XDG_CONFIG_HOME must be an absolute path, got %q", xdg)
		}
		return filepath.Join(xdg, appName), nil
	}

	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("cannot determine home directory: %w", err)
	}

	return filepath.Join(home, ".config", appName), nil
}

// systemGatewayDir returns the system-wide gateway config directory.
func systemGatewayDir() string {
	return filepath.Join(systemConfigDir(), gatewaySubdir)
}

// systemConfigDir returns the system-wide configuration root. Empty and
// relative overrides are ignored to match the CLI's fail-safe behavior.
func systemConfigDir() string {
	if dir := os.Getenv(systemGatewayDirEnv); dir != "" && filepath.IsAbs(dir) {
		return dir
	}
	return systemConfigBase
}

// resolveGatewayDir searches for a gateway directory by name, checking the
// user directory first, then the system directory. Returns the absolute
// directory path, the config source, or ErrGatewayNotFound.
func resolveGatewayDir(name string) (string, ConfigSource, error) {
	if err := validateGatewayName(name); err != nil {
		return "", "", err
	}

	// Check user config dir first.
	userBase, err := userConfigDir()
	if err == nil {
		userDir := filepath.Join(userBase, gatewaySubdir, name)
		if info, statErr := os.Stat(userDir); statErr == nil && info.IsDir() {
			return userDir, SourceUser, nil
		}
	}

	// Check system config dir.
	sysDir := filepath.Join(systemGatewayDir(), name)
	if info, statErr := os.Stat(sysDir); statErr == nil && info.IsDir() {
		return sysDir, SourceSystem, nil
	}

	return "", "", fmt.Errorf("%w: %q", ErrGatewayNotFound, name)
}

// validateGatewayName accepts portable, single-component gateway names.
// Host-derived FQDN and IPv4 names may contain dots. Windows device names,
// reserved filename characters, and ambiguous dot components are rejected
// on every platform to keep SDK behavior consistent.
func validateGatewayName(name string) error {
	if name == "" {
		return fmt.Errorf("%w: name must not be empty", ErrInvalidGatewayName)
	}
	if name == "." || name == ".." {
		return fmt.Errorf("%w: invalid path component", ErrInvalidGatewayName)
	}
	if strings.ContainsAny(name, `/\`) {
		return fmt.Errorf("%w: name must not contain path separators", ErrInvalidGatewayName)
	}
	if strings.ContainsRune(name, '\x00') {
		return fmt.Errorf("%w: name must not contain NUL", ErrInvalidGatewayName)
	}
	if strings.HasPrefix(name, ".") || strings.HasSuffix(name, ".") || strings.Contains(name, "..") {
		return fmt.Errorf("%w: invalid dot placement", ErrInvalidGatewayName)
	}

	// This ASCII-only grammar excludes Windows reserved filename characters
	// (including colons in raw IPv6 addresses), spaces, and control characters.
	for _, r := range name {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') ||
			(r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			continue
		}
		return fmt.Errorf("%w: non-portable character %q", ErrInvalidGatewayName, r)
	}

	// Windows treats device names as reserved even with an extension:
	// e.g. CON.txt and COM1.example.com refer to device names.
	stem, _, _ := strings.Cut(name, ".")
	stem = strings.ToUpper(stem)
	switch stem {
	case "CON", "PRN", "AUX", "NUL":
		return fmt.Errorf("%w: reserved Windows device name", ErrInvalidGatewayName)
	}
	// Reject COM0/LPT0 conservatively too, for Windows portability.
	if len(stem) == 4 && (strings.HasPrefix(stem, "COM") || strings.HasPrefix(stem, "LPT")) &&
		stem[3] >= '0' && stem[3] <= '9' {
		return fmt.Errorf("%w: reserved Windows device name", ErrInvalidGatewayName)
	}
	return nil
}

// resolveActiveGateway reads the active_gateway file from the user
// config directory and returns the validated gateway name. Returns
// ErrNoActiveGateway if the file is missing or empty.
func resolveActiveGateway() (string, error) {
	userBase, err := userConfigDir()
	if err != nil {
		return "", fmt.Errorf("%w: cannot determine config directory: %v", ErrNoActiveGateway, err)
	}

	path := filepath.Join(userBase, activeGatewayFile)
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%w", ErrNoActiveGateway)
	}

	name := strings.TrimSpace(string(data))
	if name == "" {
		return "", fmt.Errorf("%w: active_gateway file is empty", ErrNoActiveGateway)
	}

	if err := validateGatewayName(name); err != nil {
		return "", fmt.Errorf("%w: active_gateway contains invalid name %q: %v", ErrNoActiveGateway, name, err)
	}

	return name, nil
}

// listGatewayDirs returns a list of gateway directories found under the
// given base path. Each entry is just the directory name (gateway name).
func listGatewayDirs(base string) ([]string, error) {
	gatewaysDir := filepath.Join(base, gatewaySubdir)
	entries, err := os.ReadDir(gatewaysDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() && validateGatewayName(e.Name()) == nil {
			names = append(names, e.Name())
		}
	}
	return names, nil
}
