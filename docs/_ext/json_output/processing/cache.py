# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Caching and incremental build support for JSON output extension."""

from collections.abc import Callable
from pathlib import Path
from threading import Lock
from typing import Any, ClassVar

from sphinx.util import logging

logger = logging.getLogger(__name__)


class JSONOutputCache:
    """Manages caching and incremental builds for JSON output."""

    # Class-level shared caches with thread safety
    _shared_cache_lock = Lock()
    _shared_metadata_cache: ClassVar[dict[str, Any]] = {}
    _shared_frontmatter_cache: ClassVar[dict[str, Any]] = {}
    _shared_content_cache: ClassVar[dict[str, Any]] = {}
    _file_timestamps: ClassVar[dict[str, float]] = {}  # Track file modification times

    def __init__(self):
        """Initialize cache instance with shared caches."""
        with self._shared_cache_lock:
            self._metadata_cache = self._shared_metadata_cache
            self._frontmatter_cache = self._shared_frontmatter_cache
            self._content_cache = self._shared_content_cache
            self._timestamps = self._file_timestamps

    def get_metadata_cache(self) -> dict[str, Any]:
        """Get the metadata cache."""
        return self._metadata_cache

    def get_frontmatter_cache(self) -> dict[str, Any]:
        """Get the frontmatter cache."""
        return self._frontmatter_cache

    def get_content_cache(self) -> dict[str, Any]:
        """Get the content cache."""
        return self._content_cache

    def needs_update(self, docname: str, source_path: Path, incremental_enabled: bool = False) -> bool:
        """Check if document needs to be updated based on modification time."""
        if not incremental_enabled:
            return True  # Process all files if incremental build is disabled

        try:
            if not source_path or not source_path.exists():
                return True

            current_mtime = source_path.stat().st_mtime

            # Check if we have a recorded timestamp
            if docname in self._timestamps:
                return current_mtime > self._timestamps[docname]
            else:
                # First time processing this file
                self._timestamps[docname] = current_mtime
                return True

        except Exception as e:  # noqa: BLE001
            logger.debug(f"Error checking modification time for {docname}: {e}")
            return True  # Process if we can't determine modification time

    def mark_updated(self, docname: str, source_path: Path) -> None:
        """Mark document as processed with current timestamp."""
        try:
            if source_path and source_path.exists():
                self._timestamps[docname] = source_path.stat().st_mtime
        except Exception:  # noqa: BLE001
            logger.debug(f"Could not update timestamp for {docname}")

    def clear_caches(self) -> None:
        """Clear all caches (useful for testing or memory cleanup)."""
        with self._shared_cache_lock:
            self._metadata_cache.clear()
            self._frontmatter_cache.clear()
            self._content_cache.clear()
            self._timestamps.clear()

    def get_cache_stats(self) -> dict[str, int]:
        """Get cache statistics for debugging."""
        return {
            "metadata_cache_size": len(self._metadata_cache),
            "frontmatter_cache_size": len(self._frontmatter_cache),
            "content_cache_size": len(self._content_cache),
            "timestamps_size": len(self._timestamps),
        }

    def with_cache_lock(self, func: Callable[..., Any], *args: Any, **kwargs: Any) -> Any:  # noqa: ANN401
        """Execute function with cache lock held."""
        with self._shared_cache_lock:
            return func(*args, **kwargs)
