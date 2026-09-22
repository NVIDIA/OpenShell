# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Typed mutation results, separate from transport success."""

from dataclasses import dataclass
from enum import IntEnum


class DeletionOutcome(IntEnum):
    """Only COMPLETED and ALREADY_ABSENT establish logical deletion completion."""

    UNSPECIFIED = 0
    COMPLETED = 1
    ACCEPTED = 2
    ALREADY_ABSENT = 3

    @classmethod
    def _missing_(cls, value):
        if not isinstance(value, int):
            return None
        member = int.__new__(cls, value)
        member._name_ = f"UNKNOWN_{value}"
        member._value_ = value
        return member


@dataclass(frozen=True)
class DeletionResult:
    """Outcome for the original target; unknown outcomes never imply completion."""

    outcome: DeletionOutcome
    sandbox_id: str | None = None
