// SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

// Package main implements a cgo shared library that lets the openshell-vm
// compute driver (Rust) delegate OCI registry image resolution/pull and
// layer unpacking to containerd's Go client libraries instead of a
// hand-rolled registry client and tar merge routine.
//
// This binary is never run directly. It is built with
// `go build -buildmode=c-shared` and dynamically loaded by
// crates/openshell-driver-vm/src/containerd_shim.rs via libloading, the
// same way the driver loads libkrun. Every exported function returns NULL
// on success or a heap-allocated C string describing the error; callers
// must free non-NULL results with ContainerdFreeString.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"fmt"
	"time"
	"unsafe"
)

// requestTimeout bounds a single pull/resolve call. Sandbox image pulls can
// legitimately take a while on a slow link, so this is generous rather than
// tight; the Rust caller runs it in a blocking task and has its own
// higher-level timeouts via the gRPC request lifecycle.
const requestTimeout = 30 * time.Minute

func main() {} // required by -buildmode=c-shared, never executed.

//export ContainerdFreeString
func ContainerdFreeString(s *C.char) {
	if s != nil {
		C.free(unsafe.Pointer(s))
	}
}

// ContainerdResolveDigest resolves imageRef against its registry and writes
// the resolved manifest/index digest (e.g. "sha256:...") to *outDigest
// without downloading any layer content. Used to cheaply check the driver's
// on-disk image cache before committing to a full pull.
//
//export ContainerdResolveDigest
func ContainerdResolveDigest(cImageRef, cPlatformOS, cPlatformArch *C.char, outDigest **C.char) *C.char {
	if outDigest == nil {
		return errString("outDigest must not be null")
	}
	*outDigest = nil

	imageRef := C.GoString(cImageRef)
	platformOS := C.GoString(cPlatformOS)
	platformArch := C.GoString(cPlatformArch)

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	digest, err := resolveDigest(ctx, imageRef, platformOS, platformArch)
	if err != nil {
		return errString(err.Error())
	}
	*outDigest = C.CString(digest)
	return nil
}

// ContainerdPullImage resolves imageRef, downloads its manifest/config/layer
// blobs for the requested platform, and writes them out as a standard OCI
// Image Layout (oci-layout, index.json, blobs/sha256/*) rooted at
// destLayoutDir. The index.json manifest entry carries the
// "org.opencontainers.image.ref.name" annotation used by the guest-side
// `umoci raw unpack --image <dir>:<ref>` step, so callers must keep this in
// sync with ociLayoutRefName below and the guest init script.
//
//export ContainerdPullImage
func ContainerdPullImage(cImageRef, cDestLayoutDir, cPlatformOS, cPlatformArch *C.char) *C.char {
	imageRef := C.GoString(cImageRef)
	destLayoutDir := C.GoString(cDestLayoutDir)
	platformOS := C.GoString(cPlatformOS)
	platformArch := C.GoString(cPlatformArch)

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	if err := pullImage(ctx, imageRef, destLayoutDir, platformOS, platformArch); err != nil {
		return errString(err.Error())
	}
	return nil
}

// ContainerdUnpackLayout applies every layer of the single-manifest OCI
// Image Layout at layoutDir onto destRootfsDir, in order, using containerd's
// archive.Apply (correct OCI whiteout/opaque-directory semantics, xattrs,
// and device/fifo entries). destRootfsDir is created if missing; existing
// contents are merged into (not replaced by) the unpack, matching the
// semantics of applying layers onto an already-prepared base directory.
//
//export ContainerdUnpackLayout
func ContainerdUnpackLayout(cLayoutDir, cDestRootfsDir *C.char) *C.char {
	layoutDir := C.GoString(cLayoutDir)
	destRootfsDir := C.GoString(cDestRootfsDir)

	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()

	if err := unpackLayout(ctx, layoutDir, destRootfsDir); err != nil {
		return errString(err.Error())
	}
	return nil
}

func errString(msg string) *C.char {
	return C.CString(msg)
}

// wrapf is a small helper to keep error construction terse in the pull/unpack
// implementation files.
func wrapf(err error, format string, args ...any) error {
	return fmt.Errorf(format+": %w", append(args, err)...)
}
