"""Repository rule for the source-built Z3 library."""

def _z3_repository_impl(rctx):
    rctx.download_and_extract(
        url = rctx.attr.urls,
        integrity = rctx.attr.integrity,
        strip_prefix = rctx.attr.strip_prefix,
    )

    python = rctx.which("python3") or rctx.which("python")
    if not python:
        fail("z3_repository requires python3 or python on PATH to generate Z3 sources")

    result = rctx.execute(
        [python, "scripts/mk_make.py", "--build=build-bazel-gen", "--staticlib"],
        environment = {"PYTHONDONTWRITEBYTECODE": "1"},
        quiet = True,
    )
    if result.return_code:
        fail("Z3 source generation failed:\n%s\n%s" % (result.stdout, result.stderr))

    rctx.delete("build-bazel-gen")

    if rctx.path("BUILD.bazel").exists:
        rctx.delete("BUILD.bazel")
    rctx.symlink(rctx.attr.build_file, "BUILD.bazel")

z3_repository = repository_rule(
    implementation = _z3_repository_impl,
    attrs = {
        "build_file": attr.label(
            allow_single_file = True,
            mandatory = True,
        ),
        "integrity": attr.string(mandatory = True),
        "strip_prefix": attr.string(mandatory = True),
        "urls": attr.string_list(mandatory = True),
    },
)
