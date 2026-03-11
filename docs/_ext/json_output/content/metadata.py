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

"""Metadata and frontmatter extraction functions."""

from typing import Any

from sphinx.environment import BuildEnvironment
from sphinx.util import logging

# Import YAML at module level with error handling
try:
    import yaml

    YAML_AVAILABLE = True
except ImportError:
    YAML_AVAILABLE = False
    yaml = None

logger = logging.getLogger(__name__)


def extract_document_metadata(
    env: BuildEnvironment, docname: str, metadata_cache: dict, frontmatter_cache: dict
) -> dict[str, Any]:
    """Extract metadata from document with caching."""
    if docname in metadata_cache:
        return metadata_cache[docname]

    metadata = {}

    try:
        if hasattr(env, "metadata") and docname in env.metadata:
            metadata.update(env.metadata[docname])

        source_path = env.doc2path(docname)
        if source_path and str(source_path).endswith(".md"):
            frontmatter = extract_frontmatter(str(source_path), frontmatter_cache)
            if frontmatter:
                metadata.update(frontmatter)

        metadata_cache[docname] = metadata
        logger.debug(f"Successfully extracted metadata for {docname}: {len(metadata)} items")

    except Exception as e:  # noqa: BLE001
        logger.warning(f"Error extracting metadata from {docname}: {e}")
        metadata_cache[docname] = {}

    return metadata_cache[docname]


def extract_frontmatter(file_path: str, frontmatter_cache: dict) -> dict[str, Any] | None:
    """Extract YAML frontmatter from markdown files."""
    if file_path in frontmatter_cache:
        return frontmatter_cache[file_path]

    result = None

    # Check prerequisites
    if not YAML_AVAILABLE:
        logger.debug("PyYAML not available, skipping frontmatter extraction")
    else:
        try:
            with open(file_path, encoding="utf-8") as f:
                content = f.read()

            # Check for valid frontmatter format
            if content.startswith("---"):
                end_marker = content.find("\n---\n", 3)
                if end_marker != -1:
                    frontmatter_text = content[3:end_marker]
                    result = yaml.safe_load(frontmatter_text)

        except yaml.YAMLError as e:
            logger.warning(f"YAML parsing error in frontmatter for {file_path}: {e}")
            result = None
        except Exception as e:  # noqa: BLE001
            logger.debug(f"Could not extract frontmatter from {file_path}: {e}")
            result = None

    frontmatter_cache[file_path] = result
    return result
