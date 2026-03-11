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

"""
Enhanced Search Extension for Sphinx
Provides enhanced search page functionality without interfering with default search
"""

import os
import re
import shutil
from typing import Any

from sphinx.application import Sphinx
from sphinx.config import Config
from sphinx.util import logging

logger = logging.getLogger(__name__)


def bundle_javascript_modules(extension_dir: str, output_path: str, minify: bool = False) -> None:
    """Bundle all JavaScript modules into a single file."""

    # Define the module loading order (dependencies first)
    module_files = [
        ("modules", "Utils.js"),
        ("modules", "DocumentLoader.js"),
        ("modules", "SearchEngine.js"),
        ("modules", "SearchInterface.js"),
        ("modules", "ResultRenderer.js"),
        ("modules", "EventHandler.js"),
        ("modules", "SearchPageManager.js"),
        ("", "main.js"),  # Main file in root
    ]

    bundled_content = []
    bundled_content.append("// Enhanced Search Bundle - Generated automatically")
    bundled_content.append(
        "// Contains: Utils, DocumentLoader, SearchEngine, SearchInterface, ResultRenderer, EventHandler, SearchPageManager, main"
    )
    bundled_content.append("")

    for subdir, filename in module_files:
        if subdir:
            module_path = os.path.join(extension_dir, subdir, filename)
        else:
            module_path = os.path.join(extension_dir, filename)

        if os.path.exists(module_path):
            with open(module_path, encoding="utf-8") as f:
                content = f.read()

            # Remove module loading code since everything is bundled
            content = content.replace("await this.loadModules();", "// Modules bundled - no loading needed")
            content = content.replace(
                "await this.loadModuleWithFallback(name)", "// Modules bundled - no loading needed"
            )

            # Simple minification if requested
            if minify:
                # Remove extra whitespace and comments (basic minification)
                # Remove single-line comments but preserve URLs
                content = re.sub(r"^\s*//.*$", "", content, flags=re.MULTILINE)
                # Remove multi-line comments
                content = re.sub(r"/\*.*?\*/", "", content, flags=re.DOTALL)
                # Remove extra whitespace
                content = re.sub(r"\n\s*\n", "\n", content)
                content = re.sub(r"^\s+", "", content, flags=re.MULTILINE)

            bundled_content.append(f"// === {filename} ===")
            bundled_content.append(content)
            bundled_content.append("")

            logger.info(f"Bundled: {filename}")
        else:
            logger.warning(f"Module not found for bundling: {module_path}")

    # Write the bundled file
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(bundled_content))

    file_size = os.path.getsize(output_path)
    size_kb = file_size / 1024
    logger.info(f"Enhanced Search JavaScript bundle created: {output_path} ({size_kb:.1f}KB)")


def add_template_path(_app: Sphinx, config: Config) -> None:
    """Add template path during config initialization."""
    extension_dir = os.path.dirname(os.path.abspath(__file__))
    templates_path = os.path.join(extension_dir, "templates")

    if os.path.exists(templates_path):
        # Ensure templates_path is a list
        if not isinstance(config.templates_path, list):
            config.templates_path = list(config.templates_path) if config.templates_path else []

        # Add our template path if not already present
        if templates_path not in config.templates_path:
            config.templates_path.append(templates_path)
            logger.info(f"Enhanced search templates added: {templates_path}")


def copy_assets(app: Sphinx, exc: Exception | None) -> None:
    """Copy assets to _static after build."""
    if exc is not None:  # Only run if build succeeded
        return

    extension_dir = os.path.dirname(os.path.abspath(__file__))
    static_path = os.path.join(app.outdir, "_static")
    os.makedirs(static_path, exist_ok=True)

    # Copy CSS file
    css_file = os.path.join(extension_dir, "enhanced-search.css")
    if os.path.exists(css_file):
        shutil.copy2(css_file, os.path.join(static_path, "enhanced-search.css"))
        logger.info("Enhanced search CSS copied")

    # Copy main JavaScript file
    main_js = os.path.join(extension_dir, "main.js")
    if os.path.exists(main_js):
        shutil.copy2(main_js, os.path.join(static_path, "main.js"))
        logger.info("Enhanced search main.js copied")

    # Copy module files
    modules_dir = os.path.join(extension_dir, "modules")
    if os.path.exists(modules_dir):
        modules_static_dir = os.path.join(static_path, "modules")
        os.makedirs(modules_static_dir, exist_ok=True)
        for module_file in os.listdir(modules_dir):
            if module_file.endswith(".js"):
                shutil.copy2(os.path.join(modules_dir, module_file), os.path.join(modules_static_dir, module_file))
        logger.info("Enhanced search modules copied")


def copy_assets_early(app: Sphinx, _docname: str, _source: list[str]) -> None:
    """Copy bundled assets to _static early in the build process."""
    # Only copy once - use a flag to prevent multiple copies
    if hasattr(app, "_search_assets_copied"):
        return

    extension_dir = os.path.dirname(os.path.abspath(__file__))
    static_path = os.path.join(app.outdir, "_static")
    os.makedirs(static_path, exist_ok=True)

    # Copy CSS file
    css_file = os.path.join(extension_dir, "enhanced-search.css")
    if os.path.exists(css_file):
        shutil.copy2(css_file, os.path.join(static_path, "enhanced-search.css"))
        logger.info("Enhanced search CSS copied")

    # Create bundled JavaScript file instead of copying individual modules
    bundle_path = os.path.join(static_path, "search-assets.bundle.js")
    bundle_javascript_modules(extension_dir, bundle_path)

    # Mark as copied
    app._search_assets_copied = True


def setup(app: Sphinx) -> dict[str, Any]:
    """Setup the enhanced search extension."""

    # Get the directory where this extension is located
    extension_dir = os.path.dirname(os.path.abspath(__file__))

    # Connect to config-inited event to add template path
    app.connect("config-inited", add_template_path)

    # Copy assets early in the build process so JS modules are available
    app.connect("source-read", copy_assets_early)

    # Add CSS file
    css_file = os.path.join(extension_dir, "enhanced-search.css")
    if os.path.exists(css_file):
        app.add_css_file("enhanced-search.css")
        logger.info("Enhanced search CSS loaded")
    else:
        logger.warning(f"Enhanced search CSS not found at {css_file}")

    # Add the bundled JavaScript file (contains all modules)
    app.add_js_file("search-assets.bundle.js")
    logger.info("Enhanced search bundled JS will be loaded")

    # Connect to build events (backup)
    app.connect("build-finished", copy_assets)

    return {
        "version": "2.0.0",
        "parallel_read_safe": True,
        "parallel_write_safe": True,
    }
