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

"""Main content extraction orchestration."""

from typing import Any

from docutils import nodes
from sphinx.environment import BuildEnvironment
from sphinx.util import logging

from .structured import extract_code_blocks, extract_headings, extract_images, extract_links
from .text import (
    clean_text_for_llm,
    extract_clean_text_content,
    extract_keywords,
    extract_raw_markdown,
    extract_summary,
    extract_text_content,
)

logger = logging.getLogger(__name__)


def extract_document_content(env: BuildEnvironment, docname: str, content_cache: dict) -> dict[str, Any]:
    """Extract content from document optimized for LLM/search use cases."""
    if docname in content_cache:
        return content_cache[docname]

    try:
        logger.debug(f"Starting content extraction for {docname}")
        doctree = env.get_doctree(docname)

        # Get extraction settings
        extraction_settings = _get_extraction_settings(env)

        # Extract main content
        content = _extract_main_content(doctree, env, docname, extraction_settings)

        # Extract additional features based on settings (pass env for link resolution)
        _extract_additional_features(content, doctree, docname, extraction_settings, env)

        # Cache and return result
        content_cache[docname] = content
        logger.debug(f"Successfully extracted content for {docname}")

    except Exception:
        logger.exception(f"Critical error extracting content from {docname}")
        content = _get_empty_content_dict()
        content_cache[docname] = content

    return content_cache[docname]


def _get_extraction_settings(env: BuildEnvironment) -> dict[str, bool]:
    """Extract all extraction-related settings from environment config."""
    config = getattr(env.app, "config", None)
    json_settings = getattr(config, "json_output_settings", {}) if config else {}

    return {
        "fast_extraction": json_settings.get("fast_text_extraction", False),
        "lazy_extraction": json_settings.get("lazy_extraction", False),
        "skip_complex": json_settings.get("skip_complex_parsing", False),
        "filter_clutter": json_settings.get("filter_search_clutter", True),
    }


def _extract_main_content(
    doctree: nodes.document, env: BuildEnvironment, docname: str, settings: dict[str, bool]
) -> dict[str, Any]:
    """Extract main text content with appropriate strategy."""
    content = {}

    try:
        if settings["fast_extraction"]:
            content["content"] = extract_text_content(doctree)
            content["format"] = "text"
            logger.debug(f"Fast text extraction for {docname}: {len(content['content'])} chars")
        else:
            content = _extract_with_fallbacks(doctree, env, docname)

        # Apply content filtering if enabled
        if settings["filter_clutter"] and content.get("content"):
            _apply_content_filtering(content, docname)

    except Exception as e:  # noqa: BLE001
        logger.warning(f"Error extracting main content from {docname}: {e}")
        content = {"content": "", "format": "text"}

    return content


def _extract_with_fallbacks(doctree: nodes.document, env: BuildEnvironment, docname: str) -> dict[str, Any]:
    """Extract content with multiple fallback strategies."""
    # Try clean text first (pass env for link title resolution)
    clean_text = extract_clean_text_content(doctree, env)
    if clean_text:
        logger.debug(f"Extracted clean text content for {docname}: {len(clean_text)} chars")
        return {"content": clean_text, "format": "text"}

    # Fallback to raw markdown
    raw_markdown = extract_raw_markdown(env, docname)
    if raw_markdown:
        logger.debug(f"Fallback to raw markdown for {docname}: {len(raw_markdown)} chars")
        return {"content": raw_markdown, "format": "markdown"}

    # Final fallback to basic text
    logger.debug(f"Fallback to basic text extraction for {docname}")
    return {"content": extract_text_content(doctree), "format": "text"}


def _apply_content_filtering(content: dict[str, Any], docname: str) -> None:
    """Apply content filtering to remove clutter."""
    original_length = len(content["content"])
    content["content"] = clean_text_for_llm(content["content"])
    filtered_length = len(content["content"])

    if original_length != filtered_length:
        logger.debug(f"Content filtering for {docname}: {original_length} -> {filtered_length} chars")


def _extract_additional_features(
    content: dict[str, Any],
    doctree: nodes.document,
    docname: str,
    settings: dict[str, bool],
    env: BuildEnvironment | None = None,
) -> None:
    """Extract additional features based on extraction settings."""
    if settings["lazy_extraction"]:
        _set_empty_additional_features(content)
        return

    # Extract basic features
    _extract_basic_features(content, doctree, docname)

    # Extract complex features if not skipped
    if not settings["skip_complex"]:
        _extract_complex_features(content, doctree, docname, env)
    else:
        _set_empty_complex_features(content)

    # Extract keywords if not lazy
    if not settings["lazy_extraction"]:
        _extract_keywords_feature(content, docname)
    else:
        content["keywords"] = []


def _extract_basic_features(content: dict[str, Any], doctree: nodes.document, docname: str) -> None:
    """Extract basic features: headings and summary."""
    features = [
        ("headings", extract_headings, []),
        ("summary", extract_summary, ""),
    ]

    for feature_name, extract_func, default_value in features:
        try:
            result = extract_func(doctree)
            content[feature_name] = result
            if feature_name == "headings":
                logger.debug(f"Extracted {len(result)} headings from {docname}")
        except Exception as e:  # noqa: BLE001, PERF203
            logger.warning(f"Error extracting {feature_name} from {docname}: {e}")
            content[feature_name] = default_value


def _extract_complex_features(
    content: dict[str, Any],
    doctree: nodes.document,
    docname: str,
    env: BuildEnvironment | None = None,
) -> None:
    """Extract complex features: code blocks, links, and images."""
    # Code blocks and images don't need env
    simple_features = [
        ("code_blocks", extract_code_blocks),
        ("images", extract_images),
    ]

    for feature_name, extract_func in simple_features:
        try:
            result = extract_func(doctree)
            content[feature_name] = result
            logger.debug(f"Extracted {len(result)} {feature_name} from {docname}")
        except Exception as e:  # noqa: BLE001, PERF203
            logger.warning(f"Error extracting {feature_name} from {docname}: {e}")
            content[feature_name] = []

    # Links need env for title resolution
    try:
        content["links"] = extract_links(doctree, env, docname)
        logger.debug(f"Extracted {len(content['links'])} links from {docname}")
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Error extracting links from {docname}: {e}")
        content["links"] = []


def _extract_keywords_feature(content: dict[str, Any], docname: str) -> None:
    """Extract keywords from content and headings."""
    try:
        content["keywords"] = extract_keywords(content.get("content", ""), content.get("headings", []))
        logger.debug(f"Extracted {len(content['keywords'])} keywords from {docname}")
    except Exception as e:  # noqa: BLE001
        logger.warning(f"Error extracting keywords from {docname}: {e}")
        content["keywords"] = []


def _set_empty_additional_features(content: dict[str, Any]) -> None:
    """Set empty values for all additional features (lazy extraction)."""
    features = ["headings", "summary", "code_blocks", "links", "images", "keywords"]
    for feature in features:
        content[feature] = [] if feature != "summary" else ""


def _set_empty_complex_features(content: dict[str, Any]) -> None:
    """Set empty values for complex features only."""
    for feature in ["code_blocks", "links", "images"]:
        content[feature] = []


def _get_empty_content_dict() -> dict[str, Any]:
    """Get empty content dictionary for error cases."""
    return {
        "content": "",
        "format": "text",
        "headings": [],
        "summary": "",
        "code_blocks": [],
        "links": [],
        "images": [],
        "keywords": [],
    }
