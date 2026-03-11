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

"""JSON file writing and output operations."""

import json
from pathlib import Path
from typing import Any

from sphinx.application import Sphinx
from sphinx.util import logging

from ..utils import get_setting

logger = logging.getLogger(__name__)


class JSONWriter:
    """Handles JSON file writing operations."""

    def __init__(self, app: Sphinx):
        self.app = app
        self.config = app.config

    def write_json_file(self, docname: str, data: dict[str, Any]) -> None:
        """Write JSON data to file."""
        try:
            outdir = Path(self.app.outdir)

            if docname == "index":
                json_path = outdir / "index.json"
            elif docname.endswith("/index"):
                json_path = outdir / docname[:-6] / "index.json"
            else:
                json_path = outdir / f"{docname}.json"

            json_path.parent.mkdir(parents=True, exist_ok=True)

            # For main index.json, output as array of page objects
            if docname == "index" and "_documents_array" in data:
                self._write_array_index(json_path, data)
            # Handle separate content files option
            elif get_setting(self.config, "separate_content", False) and "content" in data:
                self._write_separate_content(json_path, data)
            else:
                self._write_single_file(json_path, data)

            logger.debug(f"Generated JSON: {json_path}")

        except Exception:
            logger.exception(f"Failed to write JSON for {docname}")

    def _write_array_index(self, json_path: Path, data: dict[str, Any]) -> None:
        """Write main index.json as an array of page objects for search engines."""
        # Extract the documents array and write as root-level array
        documents = data.get("_documents_array", [])
        self._write_json_data(json_path, documents)
        logger.info(f"Generated search index array with {len(documents)} documents")

    def _write_separate_content(self, json_path: Path, data: dict[str, Any]) -> None:
        """Write content to separate file when separate_content is enabled."""
        # Write content to separate file
        content_path = json_path.with_suffix(".content.json")
        content_data = {
            "id": data["id"],
            "content": data["content"],
            "format": data.get("format", "text"),
            "content_length": data.get("content_length", 0),
            "word_count": data.get("word_count", 0),
        }

        self._write_json_data(content_path, content_data)

        # Remove content from main data and add reference
        main_data = data.copy()
        del main_data["content"]
        main_data["content_file"] = str(content_path.name)

        self._write_json_data(json_path, main_data)

    def _write_single_file(self, json_path: Path, data: dict[str, Any]) -> None:
        """Write all data to a single JSON file."""
        self._write_json_data(json_path, data)

    def _write_json_data(self, file_path: Path, data: dict[str, Any]) -> None:
        """Write JSON data to file with appropriate formatting."""
        with open(file_path, "w", encoding="utf-8") as f:
            if get_setting(self.config, "minify_json", False):
                json.dump(data, f, ensure_ascii=False, separators=(",", ":"))
            else:
                json.dump(data, f, ensure_ascii=False, indent=2)
