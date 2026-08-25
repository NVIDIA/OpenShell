// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package converter

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestTimeFromMillis(t *testing.T) {
	ms := int64(1719475200000) // 2024-06-27T12:00:00Z
	tm := TimeFromMillis(ms)
	assert.Equal(t, 2024, tm.Year())
	assert.Equal(t, time.June, tm.Month())
	assert.Equal(t, 27, tm.Day())
}

func TestTimeFromMillis_Zero(t *testing.T) {
	tm := TimeFromMillis(0)
	assert.True(t, tm.IsZero())
}

func TestMillisFromTime(t *testing.T) {
	tm := time.Date(2024, time.June, 27, 12, 0, 0, 0, time.UTC)
	ms := MillisFromTime(tm)
	assert.Equal(t, int64(1719489600000), ms)
}

func TestMillisFromTime_Zero(t *testing.T) {
	ms := MillisFromTime(time.Time{})
	assert.Equal(t, int64(0), ms)
}

func TestRoundTrip(t *testing.T) {
	original := time.Date(2025, time.March, 15, 10, 30, 0, 0, time.UTC)
	ms := MillisFromTime(original)
	restored := TimeFromMillis(ms)
	assert.Equal(t, original.Unix(), restored.Unix())
}

func TestTimeFromMillisPtr_NonZero(t *testing.T) {
	ms := int64(1719475200000)
	tp := TimeFromMillisPtr(ms)
	assert.NotNil(t, tp)
	assert.Equal(t, 2024, tp.Year())
}

func TestTimeFromMillisPtr_Zero(t *testing.T) {
	tp := TimeFromMillisPtr(0)
	assert.Nil(t, tp)
}

func TestMillisFromTimePtr_NonNil(t *testing.T) {
	tm := time.Date(2024, time.June, 27, 12, 0, 0, 0, time.UTC)
	ms := MillisFromTimePtr(&tm)
	assert.Equal(t, int64(1719489600000), ms)
}

func TestMillisFromTimePtr_Nil(t *testing.T) {
	ms := MillisFromTimePtr(nil)
	assert.Equal(t, int64(0), ms)
}

func TestPtrRoundTrip(t *testing.T) {
	original := time.Date(2025, time.March, 15, 10, 30, 0, 0, time.UTC)
	ms := MillisFromTimePtr(&original)
	restored := TimeFromMillisPtr(ms)
	assert.NotNil(t, restored)
	assert.Equal(t, original.Unix(), restored.Unix())
}
