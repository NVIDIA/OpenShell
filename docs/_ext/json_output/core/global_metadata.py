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

"""Global metadata extraction from Sphinx configuration.

This module provides functions to extract and build global metadata
from conf.py settings for inclusion in JSON output files.
"""

import re
from typing import Any

from sphinx.config import Config
from sphinx.util import logging

logger = logging.getLogger(__name__)


def get_global_metadata(config: Config) -> dict[str, Any]:
    """Build global metadata from Sphinx config settings.

    Combines explicit global_metadata settings with auto-inferred values
    from standard Sphinx configuration (project, release, etc.).

    Args:
        config: Sphinx configuration object

    Returns:
        Dictionary with global metadata (book, product, site sections)
    """
    settings = getattr(config, "json_output_settings", {})

    # Start with explicit global_metadata if provided
    global_meta = _deep_copy_dict(settings.get("global_metadata", {}))

    # Auto-infer if enabled
    if settings.get("infer_global_metadata", True):
        _infer_book_metadata(global_meta, config)
        _infer_product_metadata(global_meta, config)
        _infer_site_metadata(global_meta, config)

    # Remove empty sections
    return {k: v for k, v in global_meta.items() if v}


def _deep_copy_dict(d: dict) -> dict:
    """Create a deep copy of a nested dictionary."""
    result = {}
    for k, v in d.items():
        if isinstance(v, dict):
            result[k] = _deep_copy_dict(v)
        elif isinstance(v, list):
            result[k] = list(v)
        else:
            result[k] = v
    return result


def _infer_book_metadata(global_meta: dict, config: Config) -> None:
    """Infer book metadata from Sphinx config."""
    global_meta.setdefault("book", {})
    book = global_meta["book"]

    # book.title from project
    if "title" not in book and hasattr(config, "project"):
        book["title"] = config.project

    # book.version from release
    if "version" not in book and hasattr(config, "release"):
        book["version"] = config.release


def _infer_product_metadata(global_meta: dict, config: Config) -> None:
    """Infer product metadata from Sphinx config."""
    global_meta.setdefault("product", {})
    product = global_meta["product"]

    # Try to get from html_context first (explicit config)
    html_context = getattr(config, "html_context", {})

    # product.name
    if "name" not in product:
        if html_context.get("product_name"):
            product["name"] = html_context["product_name"]
        elif hasattr(config, "project"):
            product["name"] = _extract_product_name(config.project)

    # product.family
    if "family" not in product and html_context.get("product_family"):
        family = html_context["product_family"]
        product["family"] = family if isinstance(family, list) else [family]

    # product.version (can differ from book.version)
    if "version" not in product and hasattr(config, "release"):
        product["version"] = config.release


def _infer_site_metadata(global_meta: dict, config: Config) -> None:
    """Infer site metadata from Sphinx config."""
    html_context = getattr(config, "html_context", {})

    # Only add site section if we have data
    site_name = html_context.get("site_name")
    if site_name:
        global_meta.setdefault("site", {})
        if "name" not in global_meta["site"]:
            global_meta["site"]["name"] = site_name


def _extract_product_name(project: str) -> str:
    """Extract product name from project string.

    Examples:
        'NVIDIA DORI' -> 'DORI'
        'NVIDIA NeMo Curator User Guide' -> 'NeMo Curator'
        'NeMo Framework Documentation' -> 'NeMo Framework'

    Args:
        project: The Sphinx project name

    Returns:
        Extracted product name
    """
    name = project

    # Remove NVIDIA prefix
    name = re.sub(r"^NVIDIA\s+", "", name, flags=re.IGNORECASE)

    # Remove common documentation suffixes
    suffixes = [
        r"\s+User Guide$",
        r"\s+User Manual$",
        r"\s+Developer Guide$",
        r"\s+Documentation$",
        r"\s+Reference$",
        r"\s+Reference Guide$",
        r"\s+API Reference$",
        r"\s+Docs$",
    ]
    for suffix in suffixes:
        name = re.sub(suffix, "", name, flags=re.IGNORECASE)

    return name.strip()
