// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import "time"

// TimeFromMillis converts a millisecond epoch timestamp to time.Time.
// A zero value returns the zero time.
func TimeFromMillis(ms int64) time.Time {
	if ms == 0 {
		return time.Time{}
	}
	return time.UnixMilli(ms).UTC()
}

// MillisFromTime converts a time.Time to a millisecond epoch timestamp.
// A zero time returns 0.
func MillisFromTime(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

// TimeFromMillisPtr converts a millisecond epoch timestamp to a *time.Time.
// A zero value returns nil (the resource is not being deleted).
func TimeFromMillisPtr(ms int64) *time.Time {
	if ms == 0 {
		return nil
	}
	t := time.UnixMilli(ms).UTC()
	return &t
}

// MillisFromTimePtr converts a *time.Time to a millisecond epoch timestamp.
// A nil pointer returns 0.
func MillisFromTimePtr(t *time.Time) int64 {
	if t == nil {
		return 0
	}
	return t.UnixMilli()
}
