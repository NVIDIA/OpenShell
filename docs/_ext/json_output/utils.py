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

"""Utility functions for JSON output."""

import fnmatch
from typing import Any

from sphinx.application import Sphinx
from sphinx.config import Config
from sphinx.util import logging

logger = logging.getLogger(__name__)


def validate_content_gating_integration(app: Sphinx) -> None:
    """Validate that content gating integration is working properly."""
    # Check if content_gating extension is loaded
    if "content_gating" in app.extensions:
        logger.info("Content gating extension detected - JSON output will respect content gating rules")
    else:
        logger.debug("Content gating extension not detected - JSON output will process all documents")

    # Log current exclude patterns for debugging
    exclude_patterns = getattr(app.config, "exclude_patterns", [])
    if exclude_patterns:
        logger.debug(f"Current exclude patterns: {exclude_patterns}")

    # Check current build tags for debugging
    if hasattr(app, "tags"):
        try:
            current_tags = set(app.tags)
            if current_tags:
                logger.info(f"Active build tags: {current_tags}")
            else:
                logger.info("No build tags active")
        except (TypeError, AttributeError):
            logger.debug("Could not determine active build tags")


def get_setting(config: Config, key: str, default: Any = None) -> Any:  # noqa: ANN401
    """Get a setting from json_output_settings with fallback to old config names."""
    settings = getattr(config, "json_output_settings", {})

    # Try new settings format first
    if key in settings:
        return settings[key]

    # Fallback to old config names for backward compatibility
    old_config_map = {
        "enabled": "json_output_enabled",
        "exclude_patterns": "json_output_exclude_patterns",
        "verbose": "json_output_verbose",
        "parallel": "json_output_parallel",
        "include_children": "json_output_include_children",
        "include_child_content": "json_output_include_child_content",
        "main_index_mode": "json_output_main_index_mode",
        "max_main_index_docs": "json_output_max_main_index_docs",
    }

    old_key = old_config_map.get(key)
    if old_key and hasattr(config, old_key):
        return getattr(config, old_key)

    return default


def is_content_gated(config: Config, docname: str) -> bool:
    """
    Check if a document is content gated by checking Sphinx's exclude_patterns.
    This works with the content_gating extension that adds restricted documents
    to exclude_patterns during config-inited event.
    """
    sphinx_exclude_patterns = getattr(config, "exclude_patterns", [])
    if not sphinx_exclude_patterns:
        return False

    # Convert docname to potential file paths that might be in exclude_patterns
    possible_paths = [docname + ".md", docname + ".rst", docname]

    for possible_path in possible_paths:
        # Check if this path matches any exclude pattern using fnmatch (supports glob patterns)
        for pattern in sphinx_exclude_patterns:
            if isinstance(pattern, str) and fnmatch.fnmatch(possible_path, pattern):
                logger.debug(f"Document {docname} is content gated (matches pattern: {pattern})")
                return True

    return False


def should_generate_json(config: Config, docname: str) -> bool:
    """Check if JSON should be generated for this document."""
    if not get_setting(config, "enabled", True):
        return False

    if not docname or not isinstance(docname, str):
        logger.warning(f"Invalid docname for JSON generation: {docname}")
        return False

    # CRITICAL: Check content gating first - if document is content gated, don't generate JSON
    if is_content_gated(config, docname):
        logger.info(f"Excluding {docname} from JSON generation due to content gating")
        return False

    # Check JSON output extension's own exclude patterns
    for pattern in get_setting(config, "exclude_patterns", []):
        if isinstance(pattern, str) and docname.startswith(pattern):
            return False

    return True


def get_document_url(app: Sphinx, docname: str) -> str:
    """Get the URL for a document."""
    if not docname or not isinstance(docname, str):
        logger.warning(f"Invalid docname for URL generation: {docname}")
        return "invalid.html"

    try:
        if hasattr(app.builder, "get_target_uri"):
            return app.builder.get_target_uri(docname)
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Failed to get target URI for {docname}: {e}")

    return docname + ".html"
