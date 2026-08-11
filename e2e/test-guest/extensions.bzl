"""Bzlmod extensions for pinned test-guest inputs."""

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")
load(":catalog.bzl", "TEST_GUEST_BASE_IMAGES")

def _test_guest_images_impl(module_ctx):
    for image in TEST_GUEST_BASE_IMAGES:
        http_file(
            name = image.repo_name,
            downloaded_file_path = image.downloaded_file_path,
            integrity = image.integrity,
            urls = [image.url],
        )

    return module_ctx.extension_metadata(
        reproducible = True,
        root_module_direct_deps = "all",
        root_module_direct_dev_deps = [],
    )

test_guest_images = module_extension(implementation = _test_guest_images_impl)
