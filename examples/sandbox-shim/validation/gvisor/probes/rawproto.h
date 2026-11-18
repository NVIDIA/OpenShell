// SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
// SPDX-License-Identifier: Apache-2.0
//
// Spike-only wire structs between the guest tracer (probes/rawevent.c) and
// the host SecCheck collector (host/collector.c). Both ends run on the same
// machine and architecture, so the structs are sent as native bytes.
#pragma once
#include <stdint.h>

#define RAW_SYSNO_GETTID 178  // arm64
#define RAW_MESSAGE_SYSCALL_RAW 6

#define RAW_QUERY_MAGIC 0x31515647u  // "GVQ1"
#define RAW_REPLY_MAGIC 0x31525647u  // "GVR1"

enum { RAW_FOUND = 0, RAW_TIMEOUT = 1 };

// Test hooks. A production adapter has none of these.
#define RAW_HOOK_DROP 1u  // discard the matching event, as if it were lost

struct raw_query {
  uint32_t magic, seq;
  int32_t tid;
  uint32_t flags;
  uint64_t nonce[2];
  uint32_t timeout_ms, delay_ms;
};

struct raw_reply {
  uint32_t magic, seq;
  int32_t status, tid;
  uint64_t fd;
  int64_t start_ns;
  uint32_t dropped, other_events_same_tid;
};
