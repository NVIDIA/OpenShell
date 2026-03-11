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

"""Configuration management for JSON output extension."""

from typing import Any

from sphinx.application import Sphinx
from sphinx.config import Config
from sphinx.util import logging

logger = logging.getLogger(__name__)

# Constants
MAX_PARALLEL_WORKERS = 32


def get_default_settings() -> dict[str, Any]:
    """Get default configuration settings for json_output extension."""
    return {
        "enabled": True,
        "exclude_patterns": ["_build", "_templates", "_static"],
        "verbose": True,  # Enable by default for better user feedback
        "parallel": True,  # Enable parallel processing by default for speed
        "include_children": True,
        "include_child_content": True,
        "main_index_mode": "full",  # 'disabled', 'metadata_only', 'full'
        "max_main_index_docs": 0,  # No limit by default for comprehensive search
        # Search optimization features
        "extract_code_blocks": True,  # Include code blocks in search data
        "extract_links": True,  # Include internal/external links
        "extract_images": True,  # Include image references
        "extract_keywords": True,  # Auto-extract technical keywords
        "include_doc_type": True,  # Auto-detect document types
        "include_section_path": True,  # Include hierarchical section paths
        # Link extraction options
        "link_normalization": True,  # Normalize internal URLs to absolute paths
        "link_include_ref_type": True,  # Include ref_type metadata (ref, doc, etc.)
        "link_include_target_doc": True,  # Include target_doc for cross-references
        "link_resolve_titles": True,  # Resolve filename-like link text to document titles
        # Performance controls
        "content_max_length": 50000,  # Max content length per document (0 = no limit)
        "summary_max_length": 500,  # Max summary length
        "keywords_max_count": 50,  # Max keywords per document
        # Output format options
        "minify_json": True,  # Minify JSON by default for better performance
        "separate_content": False,  # Store content in separate .content.json files
        # Speed optimizations
        "parallel_workers": "auto",  # Number of parallel workers
        "batch_size": 50,  # Process documents in batches
        "cache_aggressive": True,  # Enable aggressive caching
        "lazy_extraction": False,  # Skip feature extraction (keywords, links, etc.) for faster builds
        "skip_large_files": 100000,  # Skip files larger than N bytes
        "incremental_build": True,  # Only process changed files
        "memory_limit_mb": 512,  # Memory limit per worker
        "fast_text_extraction": True,  # Use faster text extraction
        "skip_complex_parsing": False,  # Skip complex parsing features
        # Content filtering
        "filter_search_clutter": True,  # Remove SVG, toctree, and other non-searchable content
        # Global metadata from conf.py
        "global_metadata": {},  # User-defined global fields (book, product, site)
        "infer_global_metadata": True,  # Auto-infer from Sphinx config (project, release)
    }


def apply_config_defaults(settings: dict[str, Any]) -> dict[str, Any]:
    """Apply default values to settings dictionary."""
    defaults = get_default_settings()

    for key, default_value in defaults.items():
        if key not in settings:
            settings[key] = default_value

    return settings


def validate_config(_app: Sphinx, config: Config) -> None:
    """Validate configuration values."""
    settings = _ensure_settings_dict(config)
    settings = apply_config_defaults(settings)
    config.json_output_settings = settings

    _validate_core_settings(settings)
    _validate_content_limits(settings)
    _validate_boolean_settings(settings)
    _validate_integer_settings(settings)
    _validate_parallel_workers(settings)
    _validate_global_metadata(settings)


def _ensure_settings_dict(config: Config) -> dict[str, Any]:
    """Ensure settings is a valid dictionary."""
    settings = getattr(config, "json_output_settings", {})
    if not isinstance(settings, dict):
        logger.warning("json_output_settings must be a dictionary. Using defaults.")
        settings = {}
        config.json_output_settings = settings
    return settings


def _validate_core_settings(settings: dict[str, Any]) -> None:
    """Validate core configuration settings."""
    # Validate main index mode
    valid_modes = ["disabled", "metadata_only", "full"]
    mode = settings.get("main_index_mode", "full")
    if mode not in valid_modes:
        logger.warning(f"Invalid main_index_mode '{mode}'. Using 'full'. Valid options: {valid_modes}")
        settings["main_index_mode"] = "full"

    # Validate exclude patterns
    patterns = settings.get("exclude_patterns", [])
    if not isinstance(patterns, list):
        logger.warning("exclude_patterns must be a list. Using default.")
        settings["exclude_patterns"] = ["_build", "_templates", "_static"]


def _validate_content_limits(settings: dict[str, Any]) -> None:
    """Validate content-related limit settings."""
    limit_settings = {
        "max_main_index_docs": (0, "0 (no limit)"),
        "content_max_length": (50000, "50000 (0 = no limit)"),
        "summary_max_length": (500, "500"),
        "keywords_max_count": (50, "50"),
    }

    for setting, (default_val, description) in limit_settings.items():
        value = settings.get(setting, default_val)
        if not isinstance(value, int) or value < 0:
            logger.warning(f"Invalid {setting} '{value}'. Using {description}.")
            settings[setting] = default_val


def _validate_boolean_settings(settings: dict[str, Any]) -> None:
    """Validate boolean configuration settings."""
    bool_settings = [
        "enabled",
        "verbose",
        "parallel",
        "include_children",
        "include_child_content",
        "extract_code_blocks",
        "extract_links",
        "extract_images",
        "extract_keywords",
        "include_doc_type",
        "include_section_path",
        "link_normalization",
        "link_include_ref_type",
        "link_include_target_doc",
        "link_resolve_titles",
        "minify_json",
        "separate_content",
        "cache_aggressive",
        "lazy_extraction",
        "incremental_build",
        "fast_text_extraction",
        "skip_complex_parsing",
        "filter_search_clutter",
        "infer_global_metadata",
    ]

    defaults = get_default_settings()
    for setting in bool_settings:
        if setting in settings and not isinstance(settings.get(setting), bool):
            logger.warning(f"Setting '{setting}' must be boolean. Using default.")
            settings[setting] = defaults[setting]


def _validate_integer_settings(settings: dict[str, Any]) -> None:
    """Validate integer configuration settings with ranges."""
    int_settings = {
        "batch_size": (1, 1000),  # min, max
        "skip_large_files": (0, None),  # 0 = disabled
        "memory_limit_mb": (64, 8192),  # reasonable memory limits
    }

    defaults = get_default_settings()
    for setting, (min_val, max_val) in int_settings.items():
        if setting in settings:
            value = settings[setting]
            if not isinstance(value, int) or value < min_val or (max_val and value > max_val):
                logger.warning(
                    f"Setting '{setting}' must be integer between {min_val} and {max_val or 'unlimited'}. Using default."
                )
                settings[setting] = defaults[setting]


def _validate_parallel_workers(settings: dict[str, Any]) -> None:
    """Validate parallel_workers setting (can be 'auto' or integer)."""
    if "parallel_workers" in settings:
        value = settings["parallel_workers"]
        if value != "auto" and (not isinstance(value, int) or value < 1 or value > MAX_PARALLEL_WORKERS):
            logger.warning(
                f"Setting 'parallel_workers' must be 'auto' or integer between 1 and {MAX_PARALLEL_WORKERS}. Using default."
            )
            defaults = get_default_settings()
            settings["parallel_workers"] = defaults["parallel_workers"]


def _validate_global_metadata(settings: dict[str, Any]) -> None:
    """Validate global_metadata setting structure."""
    global_metadata = settings.get("global_metadata", {})

    if not isinstance(global_metadata, dict):
        logger.warning("global_metadata must be a dictionary. Using empty default.")
        settings["global_metadata"] = {}
        return

    # Validate known top-level keys have dict values
    valid_sections = ["book", "product", "site"]
    for section in valid_sections:
        if section in global_metadata and not isinstance(global_metadata[section], dict):
            logger.warning(f"global_metadata.{section} must be a dictionary. Removing invalid value.")
            del global_metadata[section]
