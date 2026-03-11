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

"""JSONOutputBuilder class for handling JSON output generation."""

from typing import Any

from sphinx.application import Sphinx
from sphinx.util import logging

from ..content import extract_document_content as _extract_document_content
from ..content import extract_document_metadata as _extract_document_metadata
from ..processing.cache import JSONOutputCache
from ..utils import get_setting, should_generate_json
from .document_discovery import DocumentDiscovery
from .hierarchy_builder import HierarchyBuilder
from .json_formatter import JSONFormatter
from .json_writer import JSONWriter

logger = logging.getLogger(__name__)


class JSONOutputBuilder:
    """Handles JSON output generation for documents."""

    def __init__(self, app: Sphinx):
        self.app = app
        self.env = app.env
        self.config = app.config

        # Initialize cache manager
        self.cache = JSONOutputCache()

        # Initialize modular components
        self.document_discovery = DocumentDiscovery(app, self)
        self.json_formatter = JSONFormatter(app, self)
        self.json_writer = JSONWriter(app)
        self.hierarchy_builder = HierarchyBuilder(app, self, self.document_discovery, self.json_formatter)

    def should_generate_json(self, docname: str) -> bool:
        """Check if JSON should be generated for this document."""
        return should_generate_json(self.config, docname)

    def needs_update(self, docname: str) -> bool:
        """Check if document needs to be updated based on modification time."""
        incremental_enabled = get_setting(self.config, "incremental_build", False)
        source_path = self.env.doc2path(docname)
        return self.cache.needs_update(docname, source_path, incremental_enabled)

    def mark_updated(self, docname: str) -> None:
        """Mark document as processed with current timestamp."""
        source_path = self.env.doc2path(docname)
        self.cache.mark_updated(docname, source_path)

    def extract_document_metadata(self, docname: str) -> dict[str, Any]:
        """Extract metadata from document with caching."""
        return self.cache.with_cache_lock(
            _extract_document_metadata,
            self.env,
            docname,
            self.cache.get_metadata_cache(),
            self.cache.get_frontmatter_cache(),
        )

    def extract_document_content(self, docname: str) -> dict[str, Any]:
        """Extract content from document optimized for LLM/search use cases."""
        return self.cache.with_cache_lock(_extract_document_content, self.env, docname, self.cache.get_content_cache())

    def build_json_data(self, docname: str) -> dict[str, Any]:
        """Build optimized JSON data structure for LLM/search use cases."""
        # Use the JSON formatter for base data
        data = self.json_formatter.build_json_data(docname)

        # Add children for directory indexes using hierarchy builder
        self.hierarchy_builder.add_children_to_data(data, docname)

        return data

    def write_json_file(self, docname: str, data: dict[str, Any]) -> None:
        """Write JSON data to file."""
        self.json_writer.write_json_file(docname, data)

    # Delegate methods to maintain API compatibility
    def get_child_documents(self, parent_docname: str) -> list[str]:
        """Get all child documents for a parent directory."""
        return self.document_discovery.get_child_documents(parent_docname)

    def is_hidden_document(self, docname: str) -> bool:
        """Check if a document should be considered hidden."""
        return self.document_discovery.is_hidden_document(docname)

    def get_all_documents_recursive(self) -> list[str]:
        """Get all non-hidden documents recursively."""
        return self.document_discovery.get_all_documents_recursive()

    def build_child_json_data(self, docname: str, include_content: bool | None = None) -> dict[str, Any]:
        """Build optimized JSON data for child documents (LLM/search focused)."""
        return self.json_formatter.build_child_json_data(docname, include_content)
