"""z3-sys build-script replacement."""

load("@bazel_lib//lib:copy_to_directory.bzl", "copy_to_directory")
load("@rules_cc//cc:defs.bzl", "CcInfo", "cc_library")
load("@rules_rs//rs:rules_rust_bindgen.bzl", "rust_bindgen")
load("@rules_rust//rust:rust_common.bzl", "BuildInfo")

_ENUMS = [
    "ast_kind",
    "ast_print_mode",
    "decl_kind",
    "error_code",
    "goal_prec",
    "param_kind",
    "parameter_kind",
    "sort_kind",
    "symbol_kind",
]

def _z3_sys_build_info_impl(ctx):
    out_dir = ctx.file.out_dir
    if not out_dir.is_directory:
        fail("out_dir must be a directory")

    return [
        BuildInfo(
            compile_data = depset(),
            dep_env = None,
            flags = None,
            linker_flags = None,
            link_search_paths = None,
            out_dir = out_dir,
            rustc_env = None,
        ),
        ctx.attr.cc_lib[CcInfo],
    ]

_z3_sys_build_info = rule(
    implementation = _z3_sys_build_info_impl,
    attrs = {
        "cc_lib": attr.label(mandatory = True, providers = [CcInfo]),
        "out_dir": attr.label(allow_single_file = True, mandatory = True),
    },
)

def z3_sys(name, z3):
    """Injects generated enum bindings and native Z3 into z3-sys."""
    wrapper = name + "_wrapper"
    out_dir = name + "_out_dir"

    cc_library(
        name = wrapper,
        hdrs = ["wrapper.h"],
        deps = [z3],
    )

    bindings = []
    for enum in _ENUMS:
        rust_bindgen(
            name = enum,
            bindgen_flags = [
                "--allowlist-type=Z3_" + enum,
                "--no-doc-comments",
                "--rustified-enum=Z3_" + enum,
            ],
            cc_lib = wrapper,
            header = "wrapper.h",
        )
        bindings.append(enum)

    copy_to_directory(
        name = out_dir,
        srcs = bindings,
    )

    _z3_sys_build_info(
        name = name,
        cc_lib = wrapper,
        out_dir = out_dir,
        visibility = ["//visibility:public"],
    )
