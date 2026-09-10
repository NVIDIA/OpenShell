// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0

package options

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// testConfig is a plain config struct for testing Apply.
type testConfig struct {
	a int
	b string
}

// testOption is a named option type, mirroring the SDK's pattern.
type testOption func(*testConfig)

func TestApply_EmptySlice(t *testing.T) {
	var cfg testConfig
	Apply(&cfg, []testOption{})
	assert.Equal(t, testConfig{}, cfg)
}

func TestApply_NilSlice(t *testing.T) {
	var cfg testConfig
	Apply[testConfig, testOption](&cfg, nil)
	assert.Equal(t, testConfig{}, cfg)
}

func TestApply_AllNil(t *testing.T) {
	var cfg testConfig
	Apply(&cfg, []testOption{nil, nil, nil})
	assert.Equal(t, testConfig{}, cfg)
}

func TestApply_NilFirst(t *testing.T) {
	var cfg testConfig
	Apply(&cfg, []testOption{
		nil,
		func(c *testConfig) { c.a = 1 },
	})
	assert.Equal(t, 1, cfg.a)
}

func TestApply_NilMiddle(t *testing.T) {
	var cfg testConfig
	Apply(&cfg, []testOption{
		func(c *testConfig) { c.a = 1 },
		nil,
		func(c *testConfig) { c.b = "two" },
	})
	assert.Equal(t, 1, cfg.a)
	assert.Equal(t, "two", cfg.b)
}

func TestApply_NilLast(t *testing.T) {
	var cfg testConfig
	Apply(&cfg, []testOption{
		func(c *testConfig) { c.a = 1 },
		nil,
	})
	assert.Equal(t, 1, cfg.a)
}

func TestApply_OrderPreserved(t *testing.T) {
	var cfg testConfig
	Apply(&cfg, []testOption{
		func(c *testConfig) { c.a = 1 },
		func(c *testConfig) { c.a = 2 },
		func(c *testConfig) { c.a = 3 },
	})
	// The last option wins because options apply in order.
	assert.Equal(t, 3, cfg.a)
}

// liveObject simulates the fake.Client pattern where options mutate a live
// object rather than a plain config struct.
type liveObject struct {
	name  string
	count int
}

type liveOption func(*liveObject)

func TestApply_LiveObjectTarget(t *testing.T) {
	obj := &liveObject{name: "initial", count: 0}
	Apply(obj, []liveOption{
		nil,
		func(o *liveObject) { o.name = "updated" },
		nil,
		func(o *liveObject) { o.count = 42 },
	})
	assert.Equal(t, "updated", obj.name)
	assert.Equal(t, 42, obj.count)
}
