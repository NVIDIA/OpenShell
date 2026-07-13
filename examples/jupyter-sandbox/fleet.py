# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""A small, generic abstraction for managing a fleet of context managers."""

from __future__ import annotations

import sys
from collections.abc import Callable, Iterator, Sequence
from contextlib import AbstractContextManager, ExitStack
from typing import Generic, TypeVar, overload

T = TypeVar("T")
MemberFactory = Callable[[int], AbstractContextManager[T]]


class Fleet(Sequence[T], AbstractContextManager["Fleet[T]"], Generic[T]):
    """Create and clean up a fixed number of context-managed members."""

    def __init__(self, *, count: int, factory: MemberFactory[T]) -> None:
        if count < 1:
            raise ValueError("count must be at least 1")
        self._count = count
        self._factory = factory
        self._members: list[T] = []
        self._stack: ExitStack | None = None

    def __enter__(self) -> Fleet[T]:
        if self._stack is not None:
            raise RuntimeError("fleet is already running")

        stack = ExitStack()
        stack.__enter__()
        self._stack = stack
        try:
            for index in range(self._count):
                self._members.append(stack.enter_context(self._factory(index)))
        except BaseException:
            self._members.clear()
            self._stack = None
            stack.__exit__(*sys.exc_info())
            raise
        return self

    def __exit__(self, exc_type, exc_value, traceback) -> bool | None:
        stack = self._stack
        if stack is None:
            raise RuntimeError("fleet is not running")

        try:
            return stack.__exit__(exc_type, exc_value, traceback)
        finally:
            self._members.clear()
            self._stack = None

    def _running_members(self) -> list[T]:
        if self._stack is None:
            raise RuntimeError("fleet members are only available inside the context")
        return self._members

    @overload
    def __getitem__(self, index: int) -> T: ...

    @overload
    def __getitem__(self, index: slice) -> Sequence[T]: ...

    def __getitem__(self, index: int | slice) -> T | Sequence[T]:
        return self._running_members()[index]

    def __len__(self) -> int:
        return len(self._running_members())

    def __iter__(self) -> Iterator[T]:
        return iter(self._running_members())
