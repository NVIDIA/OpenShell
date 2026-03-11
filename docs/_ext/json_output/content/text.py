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

"""Text content extraction functions."""

import re
from typing import Any

from docutils import nodes
from sphinx.environment import BuildEnvironment
from sphinx.util import logging

logger = logging.getLogger(__name__)

# Constants
MIN_SUBSTANTIAL_CONTENT_LENGTH = 50
MAX_SUMMARY_LENGTH = 300
MIN_KEYWORD_LENGTH = 3
MAX_KEYWORDS_RETURNED = 50


def extract_raw_markdown(env: BuildEnvironment, docname: str) -> str | None:
    """Extract raw markdown from source file."""
    try:
        source_path = env.doc2path(docname)
        if not source_path or not source_path.exists():
            return None

        with open(source_path, encoding="utf-8") as f:
            content = f.read()

        # Remove frontmatter if present
        if content.startswith("---"):
            end_marker = content.find("\n---\n", 3)
            if end_marker != -1:
                content = content[end_marker + 5 :]  # Skip the second ---\n

        return content.strip()

    except Exception as e:  # noqa: BLE001
        logger.debug(f"Could not extract raw markdown from {docname}: {e}")
        return None


def extract_text_content(doctree: nodes.document) -> str:
    """Extract plain text content from document tree."""
    text_parts = []

    for node in doctree.traverse(nodes.Text):
        text_parts.append(node.astext())

    return " ".join(text_parts).strip()


def extract_clean_text_content(doctree: nodes.document, env: BuildEnvironment | None = None) -> str:
    """Extract clean text content, filtering out navigation elements.

    Args:
        doctree: The document tree to extract text from
        env: Optional Sphinx environment for resolving link titles

    Returns:
        Cleaned text content suitable for search/LLM consumption
    """
    text_parts = []
    # Track nodes we've already processed (to avoid duplicate text from references)
    processed_refs = set()

    for node in doctree.traverse():
        # Skip certain node types that aren't content
        if isinstance(node, (nodes.target, nodes.substitution_definition)):
            continue

        # Skip toctree and other directive content
        if hasattr(node, "tagname") and node.tagname in ["toctree", "index", "meta"]:
            continue

        # Handle reference nodes specially - extract and potentially improve link text
        if isinstance(node, nodes.reference):
            ref_id = id(node)
            if ref_id not in processed_refs:
                processed_refs.add(ref_id)
                link_text = _get_improved_link_text(node, env)
                if link_text:
                    text_parts.append(link_text)
            continue

        # Extract text from text nodes (but skip if inside a reference we already processed)
        if isinstance(node, nodes.Text):
            # Check if this text node is inside a reference
            parent = node.parent
            if isinstance(parent, nodes.reference) and id(parent) in processed_refs:
                continue  # Already handled by reference processing

            text = node.astext().strip()
            if text and not text.startswith("¶"):  # Skip permalink symbols
                text_parts.append(text)

    # Join and clean up the text
    full_text = " ".join(text_parts)

    # Clean up whitespace
    full_text = re.sub(r"\s+", " ", full_text)

    return full_text.strip()


def _get_improved_link_text(node: nodes.reference, env: BuildEnvironment | None) -> str:
    """Get improved link text, resolving filenames to titles where possible."""
    text = node.astext().strip()
    if not text:
        return ""

    # If text doesn't look like a filename, use it as-is
    if not _text_looks_like_filename(text):
        return text

    # Try to resolve to a better title
    attrs = getattr(node, "attributes", {})

    # Try refdoc first (target document for cross-references)
    target_doc = attrs.get("refdoc", "")

    # Try reftarget as fallback
    if not target_doc:
        target_doc = attrs.get("reftarget", "")
        # Clean up the target
        target_doc = target_doc.replace(".html", "").replace(".md", "").replace(".rst", "")

    # Look up title in env.titles
    if target_doc and env and hasattr(env, "titles") and target_doc in env.titles:
        title_node = env.titles[target_doc]
        if title_node:
            resolved_title = title_node.astext().strip()
            if resolved_title:
                return resolved_title

    # Fallback: humanize the filename
    return _humanize_link_text(text)


def _text_looks_like_filename(text: str) -> bool:
    """Check if text looks like a filename rather than readable text."""
    if not text:
        return False

    # Contains path separators
    if "/" in text or "\\" in text:
        return True

    # Ends with file extension
    if re.search(r"\.(md|rst|html|txt)$", text, re.IGNORECASE):
        return True

    # Single lowercase word (like "index", "readme", "configuration")
    if " " not in text and text == text.lower() and len(text) > 2:
        # But allow proper nouns that happen to be lowercase in context
        return True

    return False


def _humanize_link_text(text: str) -> str:
    """Convert filename-like text to human-readable form."""
    # Get just the filename part
    if "/" in text:
        text = text.rsplit("/", 1)[-1]

    # Remove extension
    for ext in (".md", ".rst", ".html", ".txt"):
        if text.endswith(ext):
            text = text[: -len(ext)]
            break

    # Replace separators with spaces
    text = text.replace("-", " ").replace("_", " ")

    # Title case
    return text.title()


def clean_text_for_llm(text: str) -> str:
    """Clean text content to make it more suitable for LLM processing and search indexing."""
    if not text:
        return ""

    # Remove SVG content (common in documentation)
    text = re.sub(r"<svg[^>]*>.*?</svg>", "", text, flags=re.DOTALL | re.IGNORECASE)

    # Remove HTML comments
    text = re.sub(r"<!--.*?-->", "", text, flags=re.DOTALL)

    # Remove empty directive blocks (common MyST artifacts)
    text = re.sub(r"^\s*```\{[^}]+\}\s*```\s*$", "", text, flags=re.MULTILINE)

    # Remove toctree artifacts
    text = re.sub(r"^\s*:caption:.*$", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*:hidden:\s*$", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*:glob:\s*$", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*:maxdepth:\s*\d+\s*$", "", text, flags=re.MULTILINE)

    # Remove common MyST directive markers that aren't useful for search
    text = re.sub(r"^\s*:::\{[^}]+\}\s*$", "", text, flags=re.MULTILINE)
    text = re.sub(r"^\s*:::\s*$", "", text, flags=re.MULTILINE)

    # Clean up code block language indicators
    text = re.sub(r"```(\w+)\s*\n", "```\n", text)

    # Remove excessive whitespace but preserve paragraph breaks
    text = re.sub(r"\n\s*\n\s*\n+", "\n\n", text)  # Multiple line breaks -> double
    text = re.sub(r"[ \t]+", " ", text)  # Multiple spaces/tabs -> single space

    # Remove lines that are just punctuation or symbols
    lines = text.split("\n")
    cleaned_lines = []
    for line in lines:
        stripped = line.strip()
        # Keep line if it has actual words (not just punctuation/symbols)
        if stripped and re.search(r"[a-zA-Z0-9]", stripped):
            # Remove standalone punctuation at start/end
            stripped = re.sub(r"^[^\w\s]+\s*", "", stripped)
            stripped = re.sub(r"\s*[^\w\s]+$", "", stripped)
            if stripped:
                cleaned_lines.append(stripped)

    text = "\n".join(cleaned_lines)

    # Final cleanup
    return text.strip()


def extract_directive_content(directive_block: str) -> str:
    """Extract meaningful content from MyST directive blocks."""
    if not directive_block:
        return ""

    # Remove the directive syntax but keep the content
    lines = directive_block.split("\n")
    content_lines = []
    in_content = False

    for line in lines:
        # Skip directive header lines
        if line.strip().startswith(":::") or line.strip().startswith("```{"):
            in_content = True
            continue
        elif line.strip() == ":::" or line.strip() == "```":
            continue
        elif line.strip().startswith(":") and not in_content:
            # Skip directive options
            continue

        # Include content lines
        if in_content or not line.strip().startswith(":"):
            content_lines.append(line)

    return "\n".join(content_lines).strip()


def extract_summary(doctree: nodes.document) -> str:
    """Extract a summary from the document (first paragraph or section)."""
    # Try to find the first substantial paragraph
    for node in doctree.traverse(nodes.paragraph):
        text = node.astext().strip()
        if text and len(text) > MIN_SUBSTANTIAL_CONTENT_LENGTH:  # Substantial content
            # Clean and truncate
            text = re.sub(r"\s+", " ", text)
            if len(text) > MAX_SUMMARY_LENGTH:
                text = text[:297] + "..."
            return text

    # Fallback: use first MAX_SUMMARY_LENGTH characters of any text
    text = extract_text_content(doctree)
    if text:
        text = re.sub(r"\s+", " ", text)
        if len(text) > MAX_SUMMARY_LENGTH:
            text = text[:297] + "..."
        return text

    return ""


def extract_keywords(content: str, headings: list[dict[str, Any]]) -> list[str]:
    """Extract relevant keywords from content for search optimization."""
    if not content:
        return []

    keywords = set()

    # Add heading text as keywords
    for heading in headings:
        if "text" in heading:
            # Split heading into words and add significant ones
            words = re.findall(r"\b[a-zA-Z]{3,}\b", heading["text"].lower())
            keywords.update(words)

    # Extract technical terms (often capitalized or have specific patterns)
    # API names, class names, function names, etc.
    tech_terms = re.findall(r"\b[A-Z][a-zA-Z0-9_]*[a-z][a-zA-Z0-9_]*\b", content)
    keywords.update(term.lower() for term in tech_terms)

    # Extract quoted terms (often important concepts)
    quoted_terms = re.findall(r'["`]([^"`]{3,20})["`]', content)
    for term in quoted_terms:
        if re.match(r"^[a-zA-Z][a-zA-Z0-9_\-\s]*$", term):
            keywords.add(term.lower().strip())

    # Extract common patterns for documentation keywords
    # Configuration keys, file extensions, command names
    config_keys = re.findall(r"\b[a-z_]+[a-z0-9_]*\s*[:=]", content)
    keywords.update(key.rstrip(":=").strip() for key in config_keys)

    # File extensions
    extensions = re.findall(r"\.[a-z]{2,4}\b", content.lower())
    keywords.update(ext.lstrip(".") for ext in extensions)

    # Remove common stop words and very short terms
    stop_words = {
        "the",
        "and",
        "for",
        "are",
        "but",
        "not",
        "you",
        "all",
        "can",
        "had",
        "her",
        "was",
        "one",
        "our",
        "out",
        "day",
        "get",
        "has",
        "him",
        "his",
        "how",
        "its",
        "may",
        "new",
        "now",
        "old",
        "see",
        "two",
        "who",
        "boy",
        "did",
        "she",
        "use",
        "way",
        "what",
        "when",
        "will",
    }
    keywords = {kw for kw in keywords if len(kw) >= MIN_KEYWORD_LENGTH and kw not in stop_words}

    # Return sorted list, limited to reasonable number
    return sorted(keywords)[:MAX_KEYWORDS_RETURNED]
