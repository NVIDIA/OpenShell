"""Rules for staging the embedded openshell-driver-vm runtime."""

_ZSTD_TOOLCHAIN = "@bazel_lib//lib:zstd_toolchain_type"

def _vm_runtime_bundle_impl(ctx):
    output = ctx.actions.declare_directory(ctx.label.name)
    zstd = ctx.toolchains[_ZSTD_TOOLCHAIN].zstdinfo.binary

    resources = [
        (ctx.file.libkrun, ctx.attr.libkrun_name),
        (ctx.file.libkrunfw, ctx.attr.libkrunfw_name),
        (ctx.file.gvproxy, "gvproxy"),
        (ctx.executable.supervisor, "openshell-sandbox"),
        (ctx.file.umoci, "umoci"),
    ]
    commands = ["mkdir -p '{}'".format(output.path)]
    for source, name in resources:
        commands.append("'{}' -q -f '{}' -o '{}/{}.zst'".format(
            zstd.path,
            source.path,
            output.path,
            name,
        ))

    ctx.actions.run_shell(
        command = "set -euo pipefail\n{}".format("\n".join(commands)),
        inputs = [source for source, _ in resources],
        outputs = [output],
        tools = [zstd],
    )

    return [DefaultInfo(files = depset([output]))]

vm_runtime_bundle = rule(
    implementation = _vm_runtime_bundle_impl,
    attrs = {
        "gvproxy": attr.label(allow_single_file = True, mandatory = True),
        "libkrun": attr.label(allow_single_file = True, mandatory = True),
        "libkrun_name": attr.string(mandatory = True),
        "libkrunfw": attr.label(allow_single_file = True, mandatory = True),
        "libkrunfw_name": attr.string(mandatory = True),
        "supervisor": attr.label(executable = True, cfg = "target", mandatory = True),
        "umoci": attr.label(allow_single_file = True, mandatory = True),
    },
    toolchains = [_ZSTD_TOOLCHAIN],
)
