#!/usr/bin/env python3
# SPDX-FileCopyrightText: Copyright (c) 2025 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Convert MyST Markdown syntax to Fern MDX components.

Handles: admonitions, dropdowns, tab sets, grid cards, toctree removal,
HTML comments, plus: {image}, {contents}, {literalinclude}, {admonition},
{code-block}, {doctest}.
Also converts <url> and <email> to Markdown links so MDX doesn't parse them as JSX.
Run convert_automodel_specific.py first if needed.
"""

import argparse
import re
from pathlib import Path

API_DOCS_BASE = "https://docs.nvidia.com/openshell/latest"


def convert_admonitions(content: str) -> str:
    """Convert MyST admonitions to Fern components."""
    admonition_map = {
        "note": "Note",
        "warning": "Warning",
        "tip": "Tip",
        "important": "Info",
        "seealso": "Note",
        "caution": "Warning",
        "danger": "Warning",
        "attention": "Warning",
        "hint": "Tip",
    }

    for myst_type, fern_component in admonition_map.items():
        pattern = rf"```\{{{myst_type}\}}\s*\n(.*?)```"
        replacement = rf"<{fern_component}>\n\1</{fern_component}>"
        content = re.sub(pattern, replacement, content, flags=re.DOTALL | re.IGNORECASE)

        # :::, ::::, ::::: with optional space before {
        for colons in [r":::", r"::::", r":::::"]:
            pattern = rf"{colons}\s*\{{{myst_type}\}}\s*\n(.*?){colons}"
            content = re.sub(pattern, replacement, content, flags=re.DOTALL | re.IGNORECASE)
            pattern = rf"{colons}\s+\{{{myst_type}\}}\s*\n(.*?){colons}"
            content = re.sub(pattern, replacement, content, flags=re.DOTALL | re.IGNORECASE)

        # Shorthand :::note (no braces)
        pattern = rf":::\s*{myst_type}\s*\n(.*?):::"
        content = re.sub(pattern, replacement, content, flags=re.DOTALL | re.IGNORECASE)
        for colons in [r"::::", r":::::"]:
            pattern = rf"{colons}\s*{myst_type}\s*\n(.*?){colons}"
            content = re.sub(pattern, replacement, content, flags=re.DOTALL | re.IGNORECASE)

    return content


def convert_admonition_directive(content: str) -> str:
    """Convert {admonition} Title :class: dropdown to Accordion."""
    pattern = r"```\{admonition\}\s+([^\n]+)(?:\s*\n(?::[^\n]+\n)*)?\n(.*?)```"
    def replace(match: re.Match[str]) -> str:
        title = match.group(1).strip().replace('"', "'")
        body = match.group(2).strip()
        return f'<Accordion title="{title}">\n{body}\n</Accordion>'
    return re.sub(pattern, replace, content, flags=re.DOTALL)


def convert_dropdowns(content: str) -> str:
    """Convert MyST dropdowns to Fern Accordion components."""
    pattern = r"```\{dropdown\}\s+([^\n]+)\s*\n(.*?)```"
    def replace_dropdown(match: re.Match[str]) -> str:
        title = match.group(1).strip()
        body = match.group(2).strip()
        if '"' in title:
            title = title.replace('"', "'")
        return f'<Accordion title="{title}">\n{body}\n</Accordion>'
    return re.sub(pattern, replace_dropdown, content, flags=re.DOTALL)


def convert_tab_sets(content: str) -> str:
    """Convert MyST tab sets to Fern Tabs components."""
    content = re.sub(r"::::+\s*\{tab-set\}\s*", "<Tabs>\n", content)
    content = re.sub(r"```\{tab-set\}\s*", "<Tabs>\n", content)

    def replace_tab_item(match: re.Match[str]) -> str:
        title = match.group(1).strip()
        return f'<Tab title="{title}">'

    content = re.sub(r"::::*\s*\{tab-item\}\s+([^\n]+)", replace_tab_item, content)
    content = re.sub(r":::*\s*\{tab-item\}\s+([^\n]+)", replace_tab_item, content)

    lines = content.split("\n")
    result = []
    in_tab = False

    for line in lines:
        if '<Tab title="' in line:
            if in_tab:
                result.append("</Tab>\n")
            in_tab = True
            result.append(line)
        elif line.strip() in [":::::", "::::", ":::", "</Tabs>"]:
            if in_tab and line.strip() != "</Tabs>":
                result.append("</Tab>")
                in_tab = False
            if line.strip() in [":::::", "::::"]:
                result.append("</Tabs>")
            else:
                result.append(line)
        else:
            result.append(line)

    content = "\n".join(result)
    content = re.sub(r"\n::::+\n", "\n", content)
    content = re.sub(r"\n:::+\n", "\n", content)
    return content


def convert_grid_cards(content: str) -> str:
    """Convert MyST grid cards to Fern Cards components."""
    content = re.sub(r"::::+\s*\{grid\}[^\n]*\n", "<Cards>\n", content)
    content = re.sub(r"```\{grid\}[^\n]*\n", "<Cards>\n", content)

    def replace_card(match: re.Match[str]) -> str:
        full_match = match.group(0)
        title_match = re.search(r"\{grid-item-card\}\s+(.+?)(?:\n|$)", full_match)
        title = title_match.group(1).strip() if title_match else "Card"
        link_match = re.search(r":link:\s*(\S+)", full_match)
        href = link_match.group(1) if link_match else ""
        if href and href != "apidocs/index":
            if not href.startswith("http"):
                href = "/" + href.replace(".md", "").replace(".mdx", "")
            return f'<Card title="{title}" href="{href}">'
        if href == "apidocs/index":
            return f'<Card title="{title}" href="{API_DOCS_BASE}/">'
        return f'<Card title="{title}">'

    content = re.sub(
        r"::::*\s*\{grid-item-card\}[^\n]*(?:\n:link:[^\n]*)?(?:\n:link-type:[^\n]*)?",
        replace_card,
        content,
    )
    content = re.sub(
        r":::*\s*\{grid-item-card\}[^\n]*(?:\n:link:[^\n]*)?(?:\n:link-type:[^\n]*)?",
        replace_card,
        content,
    )

    lines = content.split("\n")
    result = []
    in_card = False

    for line in lines:
        if '<Card title="' in line:
            if in_card:
                result.append("</Card>\n")
            in_card = True
            result.append(line)
        elif line.strip() in [":::::", "::::", ":::", "</Cards>"]:
            if in_card and line.strip() != "</Cards>":
                result.append("\n</Card>")
                in_card = False
            if line.strip() in [":::::", "::::"]:
                result.append("\n</Cards>")
        else:
            result.append(line)

    return "\n".join(result)


def remove_toctree(content: str) -> str:
    """Remove toctree blocks entirely."""
    content = re.sub(r"```\{toctree\}.*?```", "", content, flags=re.DOTALL)
    content = re.sub(r":::\{toctree\}.*?:::", "", content, flags=re.DOTALL)
    return content


def remove_contents(content: str) -> str:
    """Remove {contents} directive (Fern has its own nav)."""
    content = re.sub(r"```\{contents\}.*?```", "", content, flags=re.DOTALL)
    content = re.sub(r":::\{contents\}.*?:::", "", content, flags=re.DOTALL)
    return content


def convert_figure(content: str, filepath: Path) -> str:
    """Convert {figure} directive to markdown image."""
    # ::: or :::: or :::::{figure} ./path.png with optional :alt: :name: and caption

    def replace(match: re.Match[str]) -> str:
        img_path = match.group(1).strip()
        full_match = match.group(0)
        alt_match = re.search(r":alt:\s*(.+)", full_match)
        alt = alt_match.group(1).strip() if alt_match else img_path.split("/")[-1]
        if img_path.startswith("./"):
            img_name = img_path[2:]
        else:
            img_name = img_path
        return f"![{alt}](/assets/training/images/{img_name})"

    for colons in [r"::::+", r":::"]:
        pattern = rf"{colons}\s*\{{figure\}}\s+([^\s\n]+)[\s\S]*?{colons}"
        content = re.sub(pattern, replace, content)
    return content


def convert_raw_html(content: str) -> str:
    """Convert {raw} html directive - extract and pass through HTML content."""
    pattern = r":::\s*\{raw\}\s+html\s*\n(.*?):::"
    def replace(match: re.Match[str]) -> str:
        return match.group(1).strip()
    return re.sub(pattern, replace, content, flags=re.DOTALL)


def convert_image(content: str, filepath: Path, repo_root: Path) -> str:
    """Convert {image} path to markdown image. Path relative to current file."""
    pattern = r"```\{image\}\s+([^\s\n]+)(?:\s*\n(?::[^\n]+\n)*)?```"
    def replace(match: re.Match[str]) -> str:
        img_path = match.group(1).strip()
        img_name = img_path.split("images/")[-1] if "images/" in img_path else img_path.split("/")[-1]
        return f"![{img_name}](/assets/training/images/{img_name})"
    return re.sub(pattern, replace, content)


def convert_literalinclude(content: str, filepath: Path, repo_root: Path) -> str:
    """Convert {literalinclude} to fenced code block. Inlines full file."""
    pattern = r"```\{literalinclude\}\s+([^\s\n]+)(?:\s*\n(?::[^\n]+\n)*)?\s*```"
    def replace(match: re.Match[str]) -> str:
        inc_path = match.group(1).strip()
        resolved = (repo_root / "docs" / inc_path).resolve()
        if not resolved.exists():
            resolved = (repo_root / inc_path.replace("../", "")).resolve()
        if not resolved.exists():
            return f"<!-- literalinclude not found: {inc_path} -->"
        lang = "python" if resolved.suffix == ".py" else ""
        try:
            body = resolved.read_text()
        except Exception:
            return f"<!-- Error reading {inc_path} -->"
        return f"```{lang}\n{body}\n```"
    return re.sub(pattern, replace, content)


def convert_code_block(content: str) -> str:
    """Convert {code-block} lang to standard ```lang."""
    pattern = r"```\{code-block\}\s+(\w+)(?:\s*\n(?::[^\n]+\n)*)?\n(.*?)```"
    def replace(match: re.Match[str]) -> str:
        lang = match.group(1)
        body = match.group(2).rstrip()
        return f"```{lang}\n{body}\n```"
    return re.sub(pattern, replace, content, flags=re.DOTALL)


def convert_doctest(content: str) -> str:
    """Convert {doctest} to standard code block."""
    pattern = r"```\{doctest\}\s*\n(.*?)```"
    def replace(match: re.Match[str]) -> str:
        body = match.group(1).strip()
        return f"```python\n{body}\n```"
    return re.sub(pattern, replace, content, flags=re.DOTALL)


def escape_sphinx_doc_refs(content: str) -> str:
    """Escape Sphinx doc refs like <project:apidocs/index.rst> that MDX parses as JSX."""
    content = re.sub(
        r"<project:apidocs/index\.rst>",
        f"[API Documentation]({API_DOCS_BASE}/)",
        content,
    )
    return content


def convert_picture_to_img(content: str) -> str:
    """Convert <picture><source/><img/></picture> to <img/> for MDX compatibility."""
    pattern = r"<picture>[\s\S]*?<img([^>]*)/?>[\s\S]*?</picture>"
    def replace(match: re.Match[str]) -> str:
        img_attrs = match.group(1).strip()
        return f"<img {img_attrs} />"
    return re.sub(pattern, replace, content, flags=re.IGNORECASE)


def convert_angle_bracket_urls_and_emails(content: str) -> str:
    """Convert <url> and <email> to Markdown links so MDX doesn't parse them as JSX tags."""
    content = re.sub(
        r"<(https?://[^>]+)>",
        r"[\1](\1)",
        content,
    )
    content = re.sub(
        r"<([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})>",
        r"[\1](mailto:\1)",
        content,
    )
    return content


def convert_html_comments(content: str) -> str:
    """Convert HTML comments to JSX comments."""
    return re.sub(r"<!--\s*(.*?)\s*-->", r"{/* \1 */}", content, flags=re.DOTALL)


def remove_directive_options(content: str) -> str:
    """Remove MyST directive options."""
    for opt in [
        ":icon:", ":class:", ":columns:", ":gutter:", ":margin:", ":padding:",
        ":link-type:", ":maxdepth:", ":titlesonly:", ":hidden:", ":link:",
        ":caption:", ":language:", ":pyobject:", ":linenos:", ":emphasize-lines:",
        ":width:", ":align:", ":relative-docs:",
    ]:
        content = re.sub(rf"\n{re.escape(opt)}[^\n]*", "", content)
    return content


def fix_malformed_tags(content: str) -> str:
    """Fix common malformed tag issues."""
    content = re.sub(r'title=""', 'title="Details"', content)
    content = re.sub(
        r"<(Note|Warning|Tip|Info)([^>]*)/>\s*\n([^<]+)",
        r"<\1\2>\n\3</\1>",
        content,
    )
    return content


def clean_multiple_newlines(content: str) -> str:
    """Clean up excessive newlines."""
    content = re.sub(r"\n{3,}", "\n\n", content)
    return content.strip() + "\n"


def convert_file(filepath: Path, repo_root: Path) -> bool:
    """Convert a single file. Returns True if changes were made."""
    content = filepath.read_text()
    original = content

    content = convert_figure(content, filepath)
    content = convert_raw_html(content)
    content = convert_admonitions(content)
    content = convert_admonition_directive(content)
    content = convert_dropdowns(content)
    content = convert_grid_cards(content)
    content = convert_tab_sets(content)
    content = remove_toctree(content)
    content = remove_contents(content)
    content = convert_image(content, filepath, repo_root)
    content = convert_literalinclude(content, filepath, repo_root)
    content = convert_code_block(content)
    content = convert_doctest(content)
    content = escape_sphinx_doc_refs(content)
    content = convert_picture_to_img(content)
    content = convert_angle_bracket_urls_and_emails(content)
    content = convert_html_comments(content)
    content = remove_directive_options(content)
    content = fix_malformed_tags(content)
    content = clean_multiple_newlines(content)

    if content != original:
        filepath.write_text(content)
        return True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Convert MyST syntax to Fern MDX in pages directory"
    )
    parser.add_argument(
        "pages_dir",
        type=Path,
        help="Path to pages directory (e.g. fern/v0.1.0/pages)",
    )
    args = parser.parse_args()

    pages_dir = args.pages_dir.resolve()
    if not pages_dir.exists():
        raise SystemExit(f"Error: pages directory not found at {pages_dir}")

    repo_root = pages_dir.parent.parent.parent

    changed = []
    for mdx_file in sorted(pages_dir.rglob("*.mdx")):
        if convert_file(mdx_file, repo_root):
            changed.append(mdx_file.relative_to(pages_dir))
            print(f"  Converted: {mdx_file.relative_to(pages_dir)}")

    print(f"\nConverted {len(changed)} files")


if __name__ == "__main__":
    main()
