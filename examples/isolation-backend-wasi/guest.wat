;; SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
;; SPDX-License-Identifier: Apache-2.0

;; Handwritten WASIp1 guest: no compiler SDK or platform-specific binary needed.
(module
  (import "wasi_snapshot_preview1" "path_open"
    (func $open (param i32 i32 i32 i32 i32 i64 i64 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_read"
    (func $read (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_write"
    (func $write (param i32 i32 i32 i32) (result i32)))
  (import "wasi_snapshot_preview1" "fd_close" (func $close (param i32) (result i32)))
  (memory (export "memory") 1)
  (data (i32.const 128) "allowed.txt")
  (data (i32.const 160) "../secret.txt")
  (data (i32.const 192) "escape")
  (data (i32.const 224) "new.txt")
  (data (i32.const 256) "escape denied\n")
  (data (i32.const 288) "symlink denied\n")
  (data (i32.const 320) "write denied\n")

  (func $assert_zero (param $errno i32)
    local.get $errno if unreachable end)
  (func $assert_denied (param $errno i32)
    local.get $errno i32.eqz if unreachable end)
  (func $print (param $pointer i32) (param $length i32)
    i32.const 0 local.get $pointer i32.store
    i32.const 4 local.get $length i32.store
    i32.const 1 i32.const 0 i32.const 1 i32.const 8 call $write call $assert_zero)

  (func (export "_start") (local $fd i32)
    ;; Preopen fd 3. Read rights = FD_READ (2); returned fd stored at offset 16.
    i32.const 3 i32.const 0 i32.const 128 i32.const 11 i32.const 0
    i64.const 2 i64.const 0 i32.const 0 i32.const 16 call $open call $assert_zero
    i32.const 16 i32.load local.set $fd
    i32.const 0 i32.const 1024 i32.store
    i32.const 4 i32.const 128 i32.store
    local.get $fd i32.const 0 i32.const 1 i32.const 8 call $read call $assert_zero
    i32.const 1024 i32.const 8 i32.load call $print
    local.get $fd call $close call $assert_zero

    ;; Traversal beyond the preopen must fail.
    i32.const 3 i32.const 0 i32.const 160 i32.const 13 i32.const 0
    i64.const 2 i64.const 0 i32.const 0 i32.const 16 call $open call $assert_denied
    i32.const 256 i32.const 14 call $print

    ;; Follow a symlink that points at a real file outside the granted directory.
    i32.const 3 i32.const 1 i32.const 192 i32.const 6 i32.const 0
    i64.const 2 i64.const 0 i32.const 0 i32.const 16 call $open call $assert_denied
    i32.const 288 i32.const 15 call $print

    ;; O_CREAT (1), FD_WRITE (64) against a read-only preopen must fail.
    i32.const 3 i32.const 0 i32.const 224 i32.const 7 i32.const 1
    i64.const 64 i64.const 0 i32.const 0 i32.const 16 call $open call $assert_denied
    i32.const 320 i32.const 13 call $print))
