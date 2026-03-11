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

"""Hierarchy building for complex document structures like main index."""

from typing import TYPE_CHECKING, Any

from sphinx.application import Sphinx
from sphinx.util import logging

from ..utils import get_setting

if TYPE_CHECKING:
    from .builder import JSONOutputBuilder
    from .document_discovery import DocumentDiscovery
    from .json_formatter import JSONFormatter

logger = logging.getLogger(__name__)


class HierarchyBuilder:
    """Handles complex hierarchy building for indexes."""

    def __init__(
        self,
        app: Sphinx,
        json_builder: "JSONOutputBuilder",
        document_discovery: "DocumentDiscovery",
        json_formatter: "JSONFormatter",
    ):
        self.app = app
        self.config = app.config
        self.json_builder = json_builder
        self.document_discovery = document_discovery
        self.json_formatter = json_formatter

    def add_children_to_data(self, data: dict[str, Any], docname: str) -> None:
        """Add children documents to data structure for directory indexes."""
        include_children = get_setting(self.config, "include_children", True)
        if not include_children or not (docname == "index" or docname.endswith("/index")):
            return

        if docname == "index":
            self._handle_main_index(data, docname)
        else:
            self._handle_directory_index(data, docname)

    def _handle_main_index(self, data: dict[str, Any], docname: str) -> None:
        """Handle main index behavior: optimized for search index generation."""
        main_index_mode = get_setting(self.config, "main_index_mode", "full")
        max_main_index_docs = get_setting(self.config, "max_main_index_docs", 1000)

        if main_index_mode == "disabled":
            logger.info("Main index children disabled by configuration")
            data["children"] = []
            data["total_documents"] = 0
        elif main_index_mode == "metadata_only":
            self._build_metadata_only_index(data, docname, max_main_index_docs)
        else:  # 'full' mode - comprehensive search index
            self._build_full_search_index(data, docname, max_main_index_docs)

    def _build_metadata_only_index(self, data: dict[str, Any], docname: str, max_docs: int) -> None:
        """Build metadata-only search index for main index page."""
        logger.info("Building metadata-only search index for main index page...")
        all_docs = self.document_discovery.get_all_documents_recursive()

        # Apply document limit if set (0 = no limit)
        if max_docs > 0:
            all_docs = all_docs[:max_docs]
            if len(self.document_discovery.get_all_documents_recursive()) > max_docs:
                logger.info(f"Limited to {max_docs} documents (set max_main_index_docs to 0 for no limit)")

        # Build flat array of documents for search index
        documents = []
        for child_docname in all_docs:
            if child_docname != docname:  # Don't include self
                try:
                    child_data = self.json_formatter.build_child_json_data(child_docname, include_content=False)
                    documents.append(child_data)
                except Exception as e:  # noqa: BLE001
                    logger.warning(f"Failed to build child metadata for {child_docname}: {e}")

        # Store as flat array - will be output as array at root level
        data["_documents_array"] = documents
        data["total_documents"] = len(self.document_discovery.get_all_documents_recursive())

        logger.info(f"Generated metadata-only search index with {len(documents)} documents")

    def _build_full_search_index(self, data: dict[str, Any], docname: str, max_docs: int) -> None:
        """Build comprehensive search index for main index page."""
        logger.info("Building comprehensive search index for main index page...")
        all_docs = self.document_discovery.get_all_documents_recursive()

        # Apply document limit if set (0 = no limit)
        if max_docs > 0:
            all_docs = all_docs[:max_docs]
            if len(self.document_discovery.get_all_documents_recursive()) > max_docs:
                logger.info(f"Limited to {max_docs} documents (set max_main_index_docs to 0 for no limit)")

        # Build flat array of documents for search index
        documents = []
        for child_docname in all_docs:
            if child_docname != docname:  # Don't include self
                try:
                    child_data = self.json_formatter.build_child_json_data(child_docname)
                    documents.append(child_data)
                except Exception as e:  # noqa: BLE001
                    logger.warning(f"Failed to build child data for {child_docname}: {e}")

        # Store as flat array - will be output as array at root level
        data["_documents_array"] = documents
        data["total_documents"] = len(self.document_discovery.get_all_documents_recursive())

        logger.info(f"Generated comprehensive search index with {len(documents)} documents")

    def _handle_directory_index(self, data: dict[str, Any], docname: str) -> None:
        """Handle directory index: gets direct children."""
        children = self.document_discovery.get_child_documents(docname)
        data["children"] = []

        for child_docname in children:
            try:
                child_data = self.json_formatter.build_child_json_data(child_docname)
                data["children"].append(child_data)
            except Exception as e:  # noqa: BLE001, PERF203
                logger.warning(f"Failed to build child data for {child_docname}: {e}")

        logger.debug(f"Included {len(data['children'])} child documents for {docname}")
