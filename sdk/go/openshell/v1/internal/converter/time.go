// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"time"

	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// TimeFromProto converts a valid protobuf timestamp to UTC time.
func TimeFromProto(value *timestamppb.Timestamp) time.Time {
	if value == nil || value.CheckValid() != nil {
		return time.Time{}
	}
	return value.AsTime().UTC()
}

// TimePtrFromProto converts a valid protobuf timestamp to a UTC time pointer.
func TimePtrFromProto(value *timestamppb.Timestamp) *time.Time {
	converted := TimeFromProto(value)
	if converted.IsZero() {
		return nil
	}
	return &converted
}

// TimestampFromTime converts a non-zero time to a protobuf timestamp.
func TimestampFromTime(value time.Time) *timestamppb.Timestamp {
	if value.IsZero() {
		return nil
	}
	return timestamppb.New(value)
}

// TimestampFromTimePtr converts a non-nil time pointer to a protobuf timestamp.
func TimestampFromTimePtr(value *time.Time) *timestamppb.Timestamp {
	if value == nil {
		return nil
	}
	return TimestampFromTime(*value)
}

// MillisFromProto converts a valid protobuf timestamp to Unix milliseconds.
func MillisFromProto(value *timestamppb.Timestamp) int64 {
	converted := TimeFromProto(value)
	if converted.IsZero() {
		return 0
	}
	return converted.UnixMilli()
}

// TimestampFromMillis converts non-zero Unix milliseconds to a protobuf timestamp.
func TimestampFromMillis(value int64) *timestamppb.Timestamp {
	if value == 0 {
		return nil
	}
	return timestamppb.New(time.UnixMilli(value))
}

// TimestampStringFromProto formats a valid protobuf timestamp as RFC 3339.
func TimestampStringFromProto(value *timestamppb.Timestamp) string {
	converted := TimeFromProto(value)
	if converted.IsZero() {
		return ""
	}
	return converted.Format(time.RFC3339Nano)
}

// DurationSecondsFromProto converts a valid non-negative protobuf duration to seconds.
func DurationSecondsFromProto(value *durationpb.Duration) uint64 {
	if value == nil || value.CheckValid() != nil || value.AsDuration() < 0 {
		return 0
	}
	return uint64(value.AsDuration() / time.Second)
}

// DurationFromSeconds converts non-zero seconds to a protobuf duration.
func DurationFromSeconds(value uint64) *durationpb.Duration {
	if value == 0 || value > uint64((time.Duration(1<<63-1))/time.Second) {
		return nil
	}
	return durationpb.New(time.Duration(value) * time.Second)
}

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
