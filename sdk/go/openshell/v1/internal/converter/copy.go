// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

// CopyStringMap returns a shallow copy of a string-to-string map.
// Returns nil for nil input.
func CopyStringMap(m map[string]string) map[string]string {
	if m == nil {
		return nil
	}
	c := make(map[string]string, len(m))
	for k, v := range m {
		c[k] = v
	}
	return c
}

// CopyBoolPtr returns a copy of a *bool pointer.
// Returns nil for nil input.
func CopyBoolPtr(p *bool) *bool {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// CopyInt32Ptr returns a copy of an *int32 pointer.
func CopyInt32Ptr(p *int32) *int32 {
	if p == nil {
		return nil
	}
	v := *p
	return &v
}

// CopyStringSlice returns a copy of a string slice.
// Returns nil for nil input.
func CopyStringSlice(s []string) []string {
	if s == nil {
		return nil
	}
	c := make([]string, len(s))
	copy(c, s)
	return c
}

// CopyByteSlice returns a copy of a byte slice.
// Returns nil for nil input.
func CopyByteSlice(b []byte) []byte {
	if b == nil {
		return nil
	}
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

func boolCount(flags ...bool) int {
	n := 0
	for _, f := range flags {
		if f {
			n++
		}
	}
	return n
}
