# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.
# SPDX-License-Identifier: Apache-2.0

"""Generate native async SDK methods from the synchronous operation bodies.

This deliberately small source transform knows the SDK's I/O boundaries:
stub calls, pager fetches, stream iteration, and polling sleeps. Transport and
resource ownership are handwritten in _async_runtime.py. No reflection or
dynamic method binding runs in the installed SDK.
"""

from __future__ import annotations

import ast
from copy import deepcopy
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CLASSES = {
    "SandboxClient",
    "SandboxSession",
    "SandboxTemplateClient",
    "WorkspaceClient",
    "ProviderClient",
}
STREAM_RPCS = {"ExecSandbox", "WatchSandbox"}
STREAM_METHODS = {"exec_stream", "watch"}
FACTORIES = {
    "__init__",
    "from_active_cluster",
    "from_channel",
    "from_sandbox_client",
    "providers",
    "sandbox_templates",
    "workspaces",
    "list",
    "list_for_all_workspaces",
    "list_services",
    "list_providers",
    "list_policies",
    "_rpc_timeout",
}


def dotted(node: ast.AST) -> str:
    return ast.unparse(node)


class AsyncMethods(ast.NodeTransformer):
    def __init__(self, asynchronous: set[str]) -> None:
        self.asynchronous = asynchronous

    def visit_Name(self, node: ast.Name):
        if node.id in CLASSES or node.id == "Pager":
            node.id = "Async" + node.id
        return node

    def visit_Subscript(self, node: ast.Subscript):
        if isinstance(node.value, ast.Name) and node.value.id in {
            "Iterator",
            "Generator",
        }:
            item_type = (
                node.slice.elts[0] if isinstance(node.slice, ast.Tuple) else node.slice
            )
            return ast.Subscript(
                ast.Name("AsyncGenerator", ast.Load()),
                ast.Tuple([self.visit(item_type), ast.Constant(None)], ast.Load()),
                ast.Load(),
            )
        return self.generic_visit(node)

    def visit_Attribute(self, node: ast.Attribute):
        if dotted(node) == "grpc.Channel":
            return ast.parse("grpc.aio.Channel", mode="eval").body
        return self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom):
        # ProviderClient is defined in this generated module.
        if node.module == "providers":
            return None
        return node

    def visit_Call(self, node: ast.Call):
        original = dotted(node.func)
        self.generic_visit(node)
        if original == "_error_mapping_channel":
            return node.args[0]
        if original.startswith("self._stub."):
            if original.rsplit(".", 1)[1] in STREAM_RPCS:
                return node
            return ast.Await(ast.Call(ast.Name("_await_rpc", ast.Load()), [node], []))
        if original == "time.sleep":
            node.func = ast.parse("asyncio.sleep", mode="eval").body
            return ast.Await(node)
        if original == "stream.close":
            node.func = ast.parse("stream.aclose", mode="eval").body
            return ast.Await(node)
        if isinstance(node.func, ast.Attribute) and (
            node.func.attr == "all"
            or (
                node.func.attr in self.asynchronous
                and original.startswith(("self.", "client."))
            )
        ):
            return ast.Await(node)
        return node

    def visit_For(self, node: ast.For):
        original = dotted(node.iter)
        self.generic_visit(node)
        if original == "stream" or any(
            f".{method}(" in original for method in STREAM_METHODS
        ):
            return ast.AsyncFor(
                node.target, node.iter, node.body, node.orelse, node.type_comment
            )
        return node

    def visit_Expr(self, node: ast.Expr):
        if isinstance(node.value, ast.YieldFrom):
            return ast.AsyncFor(
                ast.Name("item", ast.Store()),
                self.visit(node.value.value),
                [ast.Expr(ast.Yield(ast.Name("item", ast.Load())))],
                [],
                None,
            )
        return self.generic_visit(node)

    def visit_FunctionDef(self, node: ast.FunctionDef):
        self.generic_visit(node)
        if (
            node.name in self.asynchronous
            or node.name in STREAM_METHODS
            or node.name == "fetch"
        ):
            # Stream failures occur during iteration; catch them at the method
            # boundary without swallowing task cancellation.
            if node.name in STREAM_METHODS:
                doc = (
                    node.body[:1]
                    if isinstance(node.body[0], ast.Expr)
                    and isinstance(node.body[0].value, ast.Constant)
                    else []
                )
                handler = ast.parse(
                    "try:\n pass\nexcept grpc.RpcError as error:\n raise from_grpc_error(error) from error"
                ).body[0]
                assert isinstance(handler, ast.Try)
                handler.body = node.body[len(doc) :]
                node.body = [*doc, handler]
            return ast.AsyncFunctionDef(
                name=node.name,
                args=node.args,
                body=node.body,
                decorator_list=node.decorator_list,
                returns=node.returns,
                type_comment=node.type_comment,
            )
        return node


def generate(root: Path = ROOT) -> str:
    sources = [
        ast.parse((root / f"python/openshell/{name}.py").read_text())
        for name in ("sandbox", "providers")
    ]
    classes = [
        deepcopy(node)
        for source in sources
        for node in source.body
        if isinstance(node, ast.ClassDef) and node.name in CLASSES
    ]
    for cls in classes:
        if cls.name == "SandboxClient":
            # Native call metadata and owner routing differ between grpc and
            # grpc.aio; the async runtime owns these two implementations.
            cls.body = [
                node
                for node in cls.body
                if not isinstance(node, ast.FunctionDef)
                or node.name not in {"_owner_of", "_open_exec"}
            ]
    asynchronous = {
        method.name
        for cls in classes
        for method in cls.body
        if isinstance(method, ast.FunctionDef)
        and method.name not in FACTORIES | STREAM_METHODS
        and any(
            isinstance(node, ast.Call) and dotted(node.func).startswith("self._stub.")
            for node in ast.walk(method)
        )
    }
    asynchronous |= {
        "exec",
        "exec_python",
        "get_session",
        "create_session",
        "create_session_from_template",
        "wait_deleted",
        "_wait_for_phase",
        "wait_completed",
    }
    # Propagate async through helper calls and pager collection.
    while True:
        previous = asynchronous.copy()
        for cls in classes:
            for method in cls.body:
                if (
                    not isinstance(method, ast.FunctionDef)
                    or method.name in FACTORIES | STREAM_METHODS
                ):
                    continue
                if any(
                    isinstance(node, ast.Call)
                    and isinstance(node.func, ast.Attribute)
                    and (node.func.attr in asynchronous or node.func.attr == "all")
                    for node in ast.walk(method)
                ):
                    asynchronous.add(method.name)
        if previous == asynchronous:
            break
    result = []
    for cls in classes:
        if cls.name == "SandboxClient":
            cls.bases = [ast.Name("AsyncTransport", ast.Load())]
            cls.body = [
                node
                for node in cls.body
                if not isinstance(node, ast.FunctionDef)
                or node.name
                not in {"__init__", "close", "__enter__", "__exit__", "from_channel"}
            ]
        cls.name = "Async" + cls.name
        result.append(AsyncMethods(asynchronous).visit(cls))
    tree = ast.fix_missing_locations(ast.Module(result, type_ignores=[]))
    used = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
    imports = [
        "from __future__ import annotations",
        "import asyncio",
        "import grpc.aio",
        "from collections.abc import AsyncGenerator",
        "from ._async_runtime import AsyncPager, AsyncTransport, _await_rpc",
        "from .errors import from_grpc_error",
    ]
    for source, module in zip(sources, ("sandbox", "providers"), strict=True):
        for node in source.body:
            if isinstance(node, (ast.Import, ast.ImportFrom)) and not (
                isinstance(node, ast.ImportFrom) and node.module == "__future__"
            ):
                imports.append(ast.unparse(node))
            if isinstance(node, ast.If) and dotted(node.test) == "TYPE_CHECKING":
                for child in node.body:
                    if isinstance(child, (ast.Import, ast.ImportFrom)) and not (
                        isinstance(child, ast.ImportFrom)
                        and child.module in {"providers", "sandbox"}
                    ):
                        imports.append(ast.unparse(child))
        definitions = {
            node.name
            for node in source.body
            if isinstance(node, (ast.ClassDef, ast.FunctionDef))
        } | {
            target.id
            for node in source.body
            if isinstance(node, ast.Assign)
            for target in node.targets
            if isinstance(target, ast.Name)
        }
        names = sorted((definitions & used) - CLASSES - {"Pager", "T"})
        if names:
            imports.append(f"from .{module} import ({', '.join(names)})")
    header = "# SPDX-FileCopyrightText: Copyright (c) 2026 NVIDIA CORPORATION & AFFILIATES. All rights reserved.\n# SPDX-License-Identifier: Apache-2.0\n\n# Generated by tasks/scripts/generate_python_async.py. Do not edit.\n"
    return (
        header + "\n".join(dict.fromkeys(imports)) + "\n\n" + ast.unparse(tree) + "\n"
    )


if __name__ == "__main__":
    (ROOT / "python/openshell/aio.py").write_text(generate())
