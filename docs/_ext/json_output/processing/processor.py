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

"""Document processing and build orchestration for JSON output extension."""

import multiprocessing
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor

from sphinx.application import Sphinx
from sphinx.config import Config
from sphinx.util import logging

from ..core.builder import JSONOutputBuilder
from ..utils import get_setting, validate_content_gating_integration

logger = logging.getLogger(__name__)


def on_build_finished(app: Sphinx, exception: Exception) -> None:
    """Generate JSON files after HTML build is complete."""
    if exception is not None:
        return

    verbose = get_setting(app.config, "verbose", False)
    log_func = logger.info if verbose else logger.debug
    log_func("Generating JSON output files...")

    # Setup and validation
    json_builder = _setup_json_builder(app)
    if not json_builder:
        return

    # Get and filter documents
    all_docs = _filter_documents(app, json_builder, log_func)

    # Process documents
    generated_count, failed_count = _process_documents(app, json_builder, all_docs, log_func)

    # Final logging
    _log_results(log_func, generated_count, failed_count)


def _setup_json_builder(app: Sphinx) -> JSONOutputBuilder | None:
    """Setup and validate JSON builder."""
    validate_content_gating_integration(app)

    try:
        return JSONOutputBuilder(app)
    except Exception:
        logger.exception("Failed to initialize JSONOutputBuilder")
        return None


def _filter_documents(app: Sphinx, json_builder: JSONOutputBuilder, log_func: Callable[[str], None]) -> list[str]:
    """Filter documents based on gating, incremental build, and size limits."""
    all_docs, gated_docs = _get_initial_documents(app, json_builder)

    if gated_docs:
        log_func(f"Content gating: excluding {len(gated_docs)} documents from JSON generation")
        verbose = get_setting(app.config, "verbose", False)
        if verbose and gated_docs:
            logger.debug(f"Gated documents: {', '.join(sorted(gated_docs))}")

    all_docs = _apply_incremental_filtering(app, json_builder, all_docs, log_func)
    return _apply_size_filtering(app, all_docs, log_func)


def _get_initial_documents(app: Sphinx, json_builder: JSONOutputBuilder) -> tuple[list[str], list[str]]:
    """Get initial document lists, separating processable from gated documents."""
    all_docs = []
    gated_docs = []

    for docname in app.env.all_docs:
        if json_builder.should_generate_json(docname):
            all_docs.append(docname)
        else:
            gated_docs.append(docname)

    return all_docs, gated_docs


def _apply_incremental_filtering(
    app: Sphinx, json_builder: JSONOutputBuilder, all_docs: list[str], log_func: Callable[[str], None]
) -> list[str]:
    """Apply incremental build filtering if enabled."""
    if not get_setting(app.config, "incremental_build", False):
        return all_docs

    incremental_docs = [docname for docname in all_docs if json_builder.needs_update(docname)]
    skipped_count = len(all_docs) - len(incremental_docs)
    if skipped_count > 0:
        log_func(f"Incremental build: skipping {skipped_count} unchanged files")
    return incremental_docs


def _apply_size_filtering(app: Sphinx, all_docs: list[str], log_func: Callable[[str], None]) -> list[str]:
    """Apply file size filtering if enabled."""
    skip_large_files = get_setting(app.config, "skip_large_files", 0)
    if skip_large_files <= 0:
        return all_docs

    filtered_docs = []
    for docname in all_docs:
        try:
            source_path = app.env.doc2path(docname)
            if source_path and source_path.stat().st_size <= skip_large_files:
                filtered_docs.append(docname)
            else:
                log_func(f"Skipping large file: {docname} ({source_path.stat().st_size} bytes)")
        except Exception:  # noqa: BLE001, PERF203
            filtered_docs.append(docname)  # Include if we can't check size
    return filtered_docs


def _process_documents(
    app: Sphinx, json_builder: JSONOutputBuilder, all_docs: list[str], log_func: Callable[[str], None]
) -> tuple[int, int]:
    """Process documents either in parallel or sequentially."""
    if get_setting(app.config, "parallel", False):
        return process_documents_parallel(json_builder, all_docs, app.config, log_func)
    else:
        return process_documents_sequential(json_builder, all_docs)


def _log_results(log_func: Callable[[str], None], generated_count: int, failed_count: int) -> None:
    """Log final processing results."""
    log_func(f"Generated {generated_count} JSON files")
    if failed_count > 0:
        logger.warning(f"Failed to generate {failed_count} JSON files")


def process_documents_parallel(
    json_builder: JSONOutputBuilder, all_docs: list[str], config: Config, log_func: Callable[[str], None]
) -> tuple[int, int]:
    """Process documents in parallel batches."""
    parallel_workers = get_setting(config, "parallel_workers", "auto")
    if parallel_workers == "auto":
        cpu_count = multiprocessing.cpu_count() or 1
        max_workers = min(cpu_count, 8)  # Limit to 8 threads max
    else:
        max_workers = min(int(parallel_workers), 16)  # Cap at 16 for safety

    batch_size = get_setting(config, "batch_size", 50)

    generated_count = 0
    failed_count = 0

    # Process in batches to control memory usage
    for i in range(0, len(all_docs), batch_size):
        batch_docs = all_docs[i : i + batch_size]
        log_func(
            f"Processing batch {i // batch_size + 1}/{(len(all_docs) - 1) // batch_size + 1} ({len(batch_docs)} docs)"
        )

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            futures = {}
            for docname in batch_docs:
                future = executor.submit(process_document, json_builder, docname)
                futures[future] = docname

            for future, docname in futures.items():
                try:
                    if future.result():
                        generated_count += 1
                    else:
                        failed_count += 1
                except Exception:  # noqa: PERF203
                    logger.exception(f"Error generating JSON for {docname}")
                    failed_count += 1

    return generated_count, failed_count


def process_documents_sequential(json_builder: JSONOutputBuilder, all_docs: list[str]) -> tuple[int, int]:
    """Process documents sequentially."""
    generated_count = 0
    failed_count = 0

    for docname in all_docs:
        try:
            json_data = json_builder.build_json_data(docname)
            json_builder.write_json_file(docname, json_data)
            generated_count += 1
        except Exception:  # noqa: PERF203
            logger.exception(f"Error generating JSON for {docname}")
            failed_count += 1

    return generated_count, failed_count


def process_document(json_builder: JSONOutputBuilder, docname: str) -> bool:
    """Process a single document for parallel execution."""
    try:
        json_data = json_builder.build_json_data(docname)
        json_builder.write_json_file(docname, json_data)
        json_builder.mark_updated(docname)  # Mark as processed for incremental builds
    except Exception:
        logger.exception(f"Error generating JSON for {docname}")
        return False
    else:
        return True
