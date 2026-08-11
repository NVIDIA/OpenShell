"""Bazel rules for building and consuming prepared test-guest QCOW2 images."""

load("@rules_shell//shell:sh_binary.bzl", "sh_binary")
load("@rules_shell//shell:sh_test.bzl", "sh_test")

_HOST_TOOLS_TOOLCHAIN = "//nix/test-guest:host_tools_toolchain_type"

TestGuestBaseImageInfo = provider(
    fields = {
        "architecture": "Guest architecture.",
        "distro": "Guest distro catalog name.",
        "image": "Pinned base cloud image.",
        "integrity": "Subresource integrity of the base image.",
        "os_id": "Expected guest operating-system ID.",
        "os_version": "Expected guest operating-system version.",
        "package_family": "Guest package family: deb or rpm.",
        "url": "Provenance URL of the base image.",
    },
)

TestGuestImageInfo = provider(
    fields = {
        "architecture": "Guest architecture.",
        "configurations": "Ordered image configuration names.",
        "disk": "Flattened standalone QCOW2 image.",
        "distro": "Guest distro catalog name.",
        "metadata": "Image compatibility and provenance metadata.",
        "os_id": "Expected guest operating-system ID.",
        "os_version": "Expected guest operating-system version.",
        "package_family": "Guest package family: deb or rpm.",
    },
)

def _test_guest_base_image_impl(ctx):
    return [
        DefaultInfo(files = depset([ctx.file.image])),
        TestGuestBaseImageInfo(
            architecture = ctx.attr.architecture,
            distro = ctx.attr.distro,
            image = ctx.file.image,
            integrity = ctx.attr.integrity,
            os_id = ctx.attr.os_id,
            os_version = ctx.attr.os_version,
            package_family = ctx.attr.package_family,
            url = ctx.attr.url,
        ),
    ]

test_guest_base_image = rule(
    implementation = _test_guest_base_image_impl,
    attrs = {
        "architecture": attr.string(mandatory = True, values = ["aarch64", "x86_64"]),
        "distro": attr.string(mandatory = True),
        "image": attr.label(allow_single_file = True, mandatory = True),
        "integrity": attr.string(mandatory = True),
        "os_id": attr.string(mandatory = True),
        "os_version": attr.string(mandatory = True),
        "package_family": attr.string(mandatory = True, values = ["deb", "rpm"]),
        "url": attr.string(mandatory = True),
    },
)

def _test_guest_host_tools_impl(ctx):
    return [platform_common.ToolchainInfo(
        all_files = ctx.attr.all_files[DefaultInfo].files,
        ansible_version = ctx.file.ansible_version,
        bash = ctx.file.bash,
        jq = ctx.file.jq,
        qemu_img = ctx.file.qemu_img,
        qemu_version = ctx.file.qemu_version,
        runner = ctx.file.runner,
        sha256sum = ctx.file.sha256sum,
    )]

test_guest_host_tools = rule(
    implementation = _test_guest_host_tools_impl,
    attrs = {
        "all_files": attr.label(mandatory = True),
        "ansible_version": attr.label(allow_single_file = True, mandatory = True),
        "bash": attr.label(allow_single_file = True, mandatory = True),
        "jq": attr.label(allow_single_file = True, mandatory = True),
        "qemu_img": attr.label(allow_single_file = True, mandatory = True),
        "qemu_version": attr.label(allow_single_file = True, mandatory = True),
        "runner": attr.label(allow_single_file = True, mandatory = True),
        "sha256sum": attr.label(allow_single_file = True, mandatory = True),
    },
)

def _test_guest_image_impl(ctx):
    if len(ctx.attr.configuration_names) != len(ctx.files.configurations):
        fail("configuration_names and configurations must have the same length")

    tools = ctx.toolchains[_HOST_TOOLS_TOOLCHAIN]
    base = ctx.attr.base_image[TestGuestBaseImageInfo]
    disk = ctx.actions.declare_file(ctx.label.name + ".qcow2")
    metadata = ctx.actions.declare_file(ctx.label.name + ".metadata.json")

    args = ctx.actions.args()
    args.add(ctx.file._builder.path)
    args.add("--runner", tools.runner.path)
    args.add("--qemu-img", tools.qemu_img.path)
    args.add("--jq", tools.jq.path)
    args.add("--sha256sum", tools.sha256sum.path)
    args.add("--seal", ctx.file._seal.path)
    args.add("--base-image", base.image.path)
    args.add("--output", disk.path)
    args.add("--metadata-output", metadata.path)
    args.add("--distro", base.distro)
    args.add("--os-id", base.os_id)
    args.add("--os-version", base.os_version)
    args.add("--package-family", base.package_family)
    args.add("--architecture", base.architecture)
    args.add("--base-image-url", base.url)
    args.add("--base-image-hash", base.integrity)
    args.add("--generation", ctx.attr.generation)
    args.add("--qemu-version-file", tools.qemu_version.path)
    args.add("--ansible-version-file", tools.ansible_version.path)
    for index in range(len(ctx.attr.configuration_names)):
        args.add("--configuration")
        args.add(ctx.attr.configuration_names[index])
        args.add(ctx.files.configurations[index].path)

    ctx.actions.run(
        arguments = [args],
        executable = tools.bash,
        env = {"PATH": tools.bash.dirname},
        execution_requirements = {
            "no-remote-exec": "1",
            "no-sandbox": "1",
            "requires-network": "1",
        },
        inputs = depset(
            direct = [
                ctx.file._builder,
                ctx.file._seal,
                base.image,
                tools.ansible_version,
                tools.qemu_version,
            ] + ctx.files.configurations,
            transitive = [tools.all_files],
        ),
        mnemonic = "TestGuestImage",
        outputs = [disk, metadata],
        progress_message = "Building prepared test guest image %{label}",
        tools = tools.all_files,
    )

    return [
        DefaultInfo(files = depset([disk, metadata])),
        TestGuestImageInfo(
            architecture = base.architecture,
            configurations = ctx.attr.configuration_names,
            disk = disk,
            distro = base.distro,
            metadata = metadata,
            os_id = base.os_id,
            os_version = base.os_version,
            package_family = base.package_family,
        ),
    ]

test_guest_image = rule(
    implementation = _test_guest_image_impl,
    attrs = {
        "base_image": attr.label(mandatory = True, providers = [TestGuestBaseImageInfo]),
        "configuration_names": attr.string_list(),
        "configurations": attr.label_list(allow_files = [".yml"]),
        "generation": attr.int(default = 1),
        "_builder": attr.label(
            allow_single_file = True,
            default = "//nix/test-guest:build-image.sh",
        ),
        "_seal": attr.label(
            allow_single_file = True,
            default = "//nix/test-guest:image-seal.sh",
        ),
    },
    toolchains = [_HOST_TOOLS_TOOLCHAIN],
)

def _shell_quote(value):
    return "'{}'".format(value.replace("'", "'\"'\"'"))

def _rlocation_path(ctx, file):
    if file.short_path.startswith("../"):
        return file.short_path[3:]
    return ctx.workspace_name + "/" + file.short_path

def _launcher_content(ctx, image, tools, fixed_args, is_test):
    base_args = [
        "--distro",
        image.distro,
        "--os-id",
        image.os_id,
        "--os-version",
        image.os_version,
        "--package-family",
        image.package_family,
    ]
    for configuration in image.configurations:
        base_args.extend(["--with", configuration])

    package_files = []
    for target in ctx.attr.packages:
        files = target[DefaultInfo].files.to_list()
        if len(files) != 1:
            fail("package targets must provide exactly one file: {}".format(target.label))
        package_files.append(files[0])

    copy_files = []
    for target, destination in ctx.attr.copies.items():
        files = target[DefaultInfo].files.to_list()
        if len(files) != 1:
            fail("copy targets must provide exactly one file: {}".format(target.label))
        copy_files.append((files[0], destination))

    lines = [
        "#!/usr/bin/env bash",
        "set -Eeuo pipefail",
        "runner=$(rlocation {})".format(_shell_quote(_rlocation_path(ctx, tools.runner))),
        "export OPENSHELL_TEST_GUEST_IMAGE_OVERRIDE=$(rlocation {})".format(_shell_quote(_rlocation_path(ctx, image.disk))),
    ]
    if is_test:
        lines.append("export TMPDIR=${TEST_TMPDIR:-${TMPDIR:-/tmp}}")
    lines.append("args=({})".format(" ".join([_shell_quote(arg) for arg in base_args])))
    for package in package_files:
        lines.append("args+=(--install \"$(rlocation {})\")".format(_shell_quote(_rlocation_path(ctx, package))))
    for file, destination in copy_files:
        lines.append("args+=(--copy \"$(rlocation {}):{}\")".format(
            _shell_quote(_rlocation_path(ctx, file)),
            destination,
        ))
    for forward_port in ctx.attr.forward_ports:
        lines.append("args+=(--forward-port {})".format(_shell_quote(forward_port)))
    for arg in fixed_args:
        lines.append("args+=({})".format(_shell_quote(arg)))
    lines.append("exec \"${runner}\" \"${args[@]}\" \"$@\"")
    return "\n".join(lines) + "\n", package_files, [item[0] for item in copy_files]

def _test_guest_launcher_impl(ctx):
    image = ctx.attr.image[TestGuestImageInfo]
    tools = ctx.toolchains[_HOST_TOOLS_TOOLCHAIN]
    launcher = ctx.actions.declare_file(ctx.label.name + ".sh")
    fixed_args = (["--"] + ctx.attr.command) if ctx.attr.is_test else []
    content, packages, copies = _launcher_content(ctx, image, tools, fixed_args, ctx.attr.is_test)
    ctx.actions.write(launcher, content, is_executable = True)

    runfiles = ctx.runfiles(
        files = [image.disk, tools.runner] + packages + copies,
        transitive_files = tools.all_files,
    )
    dependency_runfiles = [ctx.attr.image[DefaultInfo].default_runfiles]
    for target in ctx.attr.data:
        dependency_runfiles.append(target[DefaultInfo].default_runfiles)
        dependency_runfiles.append(ctx.runfiles(transitive_files = target[DefaultInfo].files))
    runfiles = runfiles.merge_all(dependency_runfiles)
    return [DefaultInfo(files = depset([launcher]), runfiles = runfiles)]

def _test_guest_launcher_validate(ctx):
    if ctx.attr.is_test and not ctx.attr.command:
        fail("command must not be empty")
    return _test_guest_launcher_impl(ctx)

_CONSUMER_ATTRS = {
    "command": attr.string_list(),
    "copies": attr.label_keyed_string_dict(allow_files = True),
    "data": attr.label_list(allow_files = True),
    "forward_ports": attr.string_list(),
    "image": attr.label(mandatory = True, providers = [TestGuestImageInfo]),
    "is_test": attr.bool(),
    "packages": attr.label_list(allow_files = True),
}

_test_guest_launcher = rule(
    implementation = _test_guest_launcher_validate,
    attrs = _CONSUMER_ATTRS,
    toolchains = [_HOST_TOOLS_TOOLCHAIN],
)

def test_guest_binary(name, image, copies = {}, data = [], forward_ports = [], packages = [], tags = [], **kwargs):
    """Create an interactive test-guest executable backed by an image target."""
    launcher = name + "_launcher"
    _test_guest_launcher(
        name = launcher,
        copies = copies,
        data = data,
        forward_ports = forward_ports,
        image = image,
        packages = packages,
        testonly = kwargs.get("testonly", False),
    )
    sh_binary(
        name = name,
        srcs = [":" + launcher],
        tags = tags,
        use_bash_launcher = True,
        **kwargs
    )

def test_guest_test(name, image, command, copies = {}, data = [], forward_ports = [], packages = [], tags = [], **kwargs):
    """Create a locally executed, remotely cacheable test-guest test."""
    launcher = name + "_launcher"
    _test_guest_launcher(
        name = launcher,
        command = command,
        copies = copies,
        data = data,
        forward_ports = forward_ports,
        image = image,
        is_test = True,
        packages = packages,
        testonly = True,
    )
    sh_test(
        name = name,
        srcs = [":" + launcher],
        tags = tags + [
            "no-remote-exec",
            "no-sandbox",
            "requires-network",
        ],
        use_bash_launcher = True,
        **kwargs
    )

def test_guest_variant(name, configurations, **kwargs):
    """Create a prepared image and its interactive runner."""
    image_name = name + "_image"
    test_guest_image(
        name = image_name,
        configuration_names = [configuration.split("/")[-1].split(".")[0] for configuration in configurations],
        configurations = configurations,
        tags = ["manual"],
        **kwargs
    )
    test_guest_binary(
        name = name,
        image = ":" + image_name,
        tags = ["manual"],
    )
