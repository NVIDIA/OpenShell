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

"""Structured content extraction functions for headings, code blocks, links, and images."""

import re
from typing import TYPE_CHECKING, Any

from docutils import nodes
from sphinx import addnodes
from sphinx.util import logging

if TYPE_CHECKING:
    from sphinx.environment import BuildEnvironment

logger = logging.getLogger(__name__)


def extract_headings(doctree: nodes.document) -> list[dict[str, Any]]:
    """Extract headings from document tree."""
    headings = []

    # Extract headings from section nodes
    for node in doctree.traverse(nodes.section):
        # Get the title node
        title_node = node.next_node(nodes.title)
        if title_node:
            title_text = title_node.astext().strip()
            if title_text:
                # Determine heading level based on nesting
                level = 1
                parent = node.parent
                while parent and isinstance(parent, nodes.section):
                    level += 1
                    parent = parent.parent

                # Generate ID (similar to how Sphinx does it)
                heading_id = re.sub(r"[^\w\-_]", "", title_text.lower().replace(" ", "-"))

                headings.append({"text": title_text, "level": level, "id": heading_id})

    # Also check for standalone title nodes (like document title)
    for node in doctree.traverse(nodes.title):
        if node.parent and not isinstance(node.parent, nodes.section):
            title_text = node.astext().strip()
            if title_text:
                heading_id = re.sub(r"[^\w\-_]", "", title_text.lower().replace(" ", "-"))
                headings.append({"text": title_text, "level": 1, "id": heading_id})

    # Remove duplicates while preserving order
    seen = set()
    unique_headings = []
    for heading in headings:
        heading_key = (heading["text"], heading["level"])
        if heading_key not in seen:
            seen.add(heading_key)
            unique_headings.append(heading)

    return unique_headings


def extract_code_blocks(doctree: nodes.document) -> list[dict[str, Any]]:
    """Extract code blocks from document tree."""
    code_blocks = []

    for node in doctree.traverse(nodes.literal_block):
        code_content = node.astext().strip()
        if code_content:
            # Try to determine language from classes or attributes
            language = "text"  # default

            if hasattr(node, "attributes") and "classes" in node.attributes:
                classes = node.attributes["classes"]
                for cls in classes:
                    if cls.startswith("language-"):
                        language = cls[9:]  # Remove 'language-' prefix
                        break
                    elif cls in [
                        "python",
                        "bash",
                        "javascript",
                        "json",
                        "yaml",
                        "sql",
                        "html",
                        "css",
                        "cpp",
                        "c",
                        "java",
                        "rust",
                        "go",
                    ]:
                        language = cls
                        break

            # Also check for highlight language
            if hasattr(node, "attributes") and "highlight_args" in node.attributes:
                highlight_args = node.attributes["highlight_args"]
                if "language" in highlight_args:
                    language = highlight_args["language"]

            code_blocks.append({"content": code_content, "language": language})

    return code_blocks


def extract_links(
    doctree: nodes.document,
    env: "BuildEnvironment | None" = None,
    docname: str = "",
) -> list[dict[str, Any]]:
    """Extract links from document tree with enhanced metadata.

    Args:
        doctree: The document tree to extract links from
        env: Optional Sphinx build environment for title resolution
        docname: Current document name for relative URL resolution

    Returns:
        List of link dictionaries with text, url, type, and optional metadata
    """
    links = []

    # Extract standard reference nodes
    for node in doctree.traverse(nodes.reference):
        link = _extract_reference_node(node, env, docname)
        if link:
            links.append(link)

    # Extract download reference nodes
    for node in doctree.traverse(addnodes.download_reference):
        link = _extract_download_reference(node)
        if link:
            links.append(link)

    return links


def _extract_reference_node(
    node: nodes.reference,
    env: "BuildEnvironment | None",
    current_docname: str,
) -> dict[str, Any] | None:
    """Extract metadata from a reference node."""
    link_text = node.astext().strip()
    if not link_text:
        return None

    attrs = getattr(node, "attributes", {})
    link: dict[str, Any] = {"text": link_text, "type": "internal"}

    # Extract URL from various attributes
    if "refuri" in attrs:
        link["url"] = attrs["refuri"]
        # Classify link type
        if attrs["refuri"].startswith(("http://", "https://", "ftp://", "mailto:")):
            link["type"] = "external"
        elif attrs["refuri"].startswith("#"):
            link["type"] = "anchor"
        else:
            link["type"] = "internal"
            # Normalize internal URLs
            link["url"] = _normalize_internal_url(attrs["refuri"], current_docname)
    elif "refid" in attrs:
        link["url"] = f"#{attrs['refid']}"
        link["type"] = "anchor"
    elif "reftarget" in attrs:
        link["url"] = attrs["reftarget"]
        link["type"] = "internal"

    # Extract cross-reference metadata (from :ref:, :doc:, {ref}, {doc}, etc.)
    if "refdoc" in attrs:
        link["target_doc"] = attrs["refdoc"]
        if link["type"] == "internal":
            link["type"] = "cross_reference"

    if "reftype" in attrs:
        link["ref_type"] = attrs["reftype"]

    # Try to improve link text if it looks like a filename
    if env and _looks_like_filename(link_text):
        better_text = _resolve_link_text(link_text, attrs, env)
        if better_text and better_text != link_text:
            link["text"] = better_text
            link["original_text"] = link_text  # Keep original for debugging

    # Only return if we have a URL or target_doc
    if link.get("url") or link.get("target_doc"):
        return link
    return None


def _extract_download_reference(node: addnodes.download_reference) -> dict[str, Any] | None:
    """Extract metadata from a download reference node."""
    link_text = node.astext().strip()
    attrs = getattr(node, "attributes", {})

    if not link_text:
        return None

    link: dict[str, Any] = {
        "text": link_text,
        "type": "download",
    }

    if "reftarget" in attrs:
        link["url"] = attrs["reftarget"]
    if "filename" in attrs:
        link["filename"] = attrs["filename"]

    return link if link.get("url") else None


def _normalize_internal_url(url: str, current_docname: str) -> str:
    """Normalize internal URLs to consistent format.

    Converts .md/.rst extensions to .html and resolves relative paths.
    """
    if not url:
        return url

    # Already absolute or external
    if url.startswith(("/", "http://", "https://", "#")):
        # Just normalize extension for absolute internal paths
        if url.startswith("/"):
            return _normalize_extension(url)
        return url

    # Relative URL - resolve against current document
    if current_docname:
        # Get directory of current document
        if "/" in current_docname:
            base_dir = current_docname.rsplit("/", 1)[0]
            url = f"{base_dir}/{url}"

    return _normalize_extension(url)


def _normalize_extension(url: str) -> str:
    """Normalize file extensions to .html."""
    # Split off anchor if present
    anchor = ""
    if "#" in url:
        url, anchor = url.rsplit("#", 1)
        anchor = f"#{anchor}"

    # Replace source extensions with .html
    for ext in (".md", ".rst", ".txt"):
        if url.endswith(ext):
            url = url[: -len(ext)] + ".html"
            break

    # Add .html if no extension
    if url and not url.endswith(".html") and "." not in url.rsplit("/", 1)[-1]:
        url = url + ".html"

    return url + anchor


def _looks_like_filename(text: str) -> bool:
    """Check if text looks like a filename/docname rather than readable text."""
    if not text:
        return False

    # Single word with no spaces, possibly with path separators
    if " " not in text and ("/" in text or text == text.lower()):
        # But not if it's a reasonable title-like word
        if len(text) > 2 and text[0].isupper() and text[1:].islower():
            return False
        return True

    # Contains path separators
    if "/" in text or "\\" in text:
        return True

    # Ends with file extension
    if re.search(r"\.(md|rst|html|txt)$", text, re.IGNORECASE):
        return True

    return False


def _resolve_link_text(
    text: str,
    attrs: dict[str, Any],
    env: "BuildEnvironment",
) -> str:
    """Try to resolve a filename-like link text to a proper title."""
    # Try to get the target document name
    target_doc = attrs.get("refdoc") or attrs.get("reftarget", "")

    # Clean up the target
    target_doc = target_doc.replace(".html", "").replace(".md", "").replace(".rst", "")

    if target_doc and hasattr(env, "titles") and target_doc in env.titles:
        title_node = env.titles[target_doc]
        if title_node:
            return title_node.astext().strip()

    # Fallback: humanize the filename
    return _humanize_filename(text)


def _humanize_filename(filename: str) -> str:
    """Convert a filename to human-readable text."""
    # Get just the filename part
    if "/" in filename:
        filename = filename.rsplit("/", 1)[-1]

    # Remove extension
    for ext in (".md", ".rst", ".html", ".txt"):
        if filename.endswith(ext):
            filename = filename[: -len(ext)]
            break

    # Replace separators with spaces
    filename = filename.replace("-", " ").replace("_", " ")

    # Title case
    return filename.title()


def extract_images(doctree: nodes.document) -> list[dict[str, Any]]:
    """Extract images from document tree."""
    images = []

    # Extract standalone images
    images.extend(_extract_standalone_images(doctree))

    # Extract images within figures
    images.extend(_extract_figure_images(doctree))

    return images


def _extract_standalone_images(doctree: nodes.document) -> list[dict[str, Any]]:
    """Extract standalone image nodes."""
    images = []

    for node in doctree.traverse(nodes.image):
        if hasattr(node, "attributes"):
            image_info = _build_image_info(node.attributes)
            if image_info:
                images.append(image_info)

    return images


def _extract_figure_images(doctree: nodes.document) -> list[dict[str, Any]]:
    """Extract images from figure nodes."""
    images = []

    for node in doctree.traverse(nodes.figure):
        for img_node in node.traverse(nodes.image):
            if hasattr(img_node, "attributes"):
                image_info = _build_image_info(img_node.attributes)
                if image_info:
                    # Add caption from figure
                    caption = _extract_figure_caption(node)
                    if caption:
                        image_info["caption"] = caption
                    images.append(image_info)

    return images


def _build_image_info(attrs: dict[str, Any]) -> dict[str, Any] | None:
    """Build image info dictionary from attributes."""
    image_src = attrs.get("uri", "")
    if not image_src:
        return None

    image_info = {"src": image_src, "alt": attrs.get("alt", "")}

    # Add optional attributes
    for attr_name in ["title", "width", "height"]:
        if attr_name in attrs:
            image_info[attr_name] = attrs[attr_name]

    return image_info


def _extract_figure_caption(figure_node: nodes.figure) -> str:
    """Extract caption text from figure node."""
    for caption_node in figure_node.traverse(nodes.caption):
        return caption_node.astext().strip()
    return ""
