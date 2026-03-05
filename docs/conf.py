# SPDX-FileCopyrightText: Copyright (c) 2025-2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

import sys
from datetime import date
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

project = "NVIDIA NemoClaw Developer Guide"
this_year = date.today().year
copyright = f"2025-{this_year}, NVIDIA Corporation"
author = "NVIDIA Corporation"
release = "0.1.0"

extensions = [
    "myst_parser",
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.napoleon",
    "sphinx.ext.viewcode",
    "sphinx.ext.intersphinx",
    "sphinx_copybutton",
    "sphinx_design",
    "sphinxcontrib.mermaid",
]

autodoc_default_options = {
    "members": True,
    "undoc-members": False,
    "show-inheritance": True,
    "member-order": "bysource",
}
autodoc_typehints = "description"
autodoc_class_signature = "separated"

copybutton_exclude = ".linenos, .gp, .go"

exclude_patterns = [
    "README.md",
    "_build/**",
]

myst_linkify_fuzzy_links = False
myst_heading_anchors = 4
myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "dollarmath",
    "fieldlist",
    "substitution",
]
myst_links_external_new_tab = True

myst_substitutions = {
    "version": release,
}

templates_path = ["_templates"]

html_theme = "nvidia_sphinx_theme"
html_copy_source = False
html_show_sourcelink = False
html_show_sphinx = False

html_domain_indices = False
html_use_index = False
highlight_language = "console"

html_theme_options = {
    "icon_links": [
        {
            "name": "GitHub",
            "url": "https://github.com/NVIDIA/NemoClaw",
            "icon": "fa-brands fa-github",
            "type": "fontawesome",
        },
    ],
}
