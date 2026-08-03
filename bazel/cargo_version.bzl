def _workspace_version_repository_impl(repository_ctx):
    in_workspace_package = False

    for raw_line in repository_ctx.read(repository_ctx.attr.manifest).splitlines():
        line = raw_line.strip()

        if line.startswith("["):
            in_workspace_package = line == "[workspace.package]"
            continue

        if not in_workspace_package or not line.startswith("version"):
            continue

        value = line.split("=", 1)[1].strip()
        if not value.startswith('"') or value.find('"', 1) == -1:
            fail("workspace package version must be a quoted string")

        version = value[1:value.find('"', 1)]
        repository_ctx.file("BUILD.bazel", 'exports_files(["version.bzl"])\n')
        repository_ctx.file("version.bzl", 'WORKSPACE_VERSION = "{}"\n'.format(version))
        return

    fail("workspace package version not found in {}".format(repository_ctx.attr.manifest))

workspace_version_repository = repository_rule(
    implementation = _workspace_version_repository_impl,
    attrs = {
        "manifest": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
    },
)
