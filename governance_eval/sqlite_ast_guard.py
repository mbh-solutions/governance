from __future__ import annotations

import ast
from collections.abc import Mapping, Sequence
from typing import TypeVar


_Value = TypeVar("_Value")


def locally_shadowed(
    node: ast.AST,
    reference: str,
    parents: Mapping[int, ast.AST],
    cache: dict[int, tuple[set[str], set[str]]],
) -> bool:
    if reference.split(".", 1)[0] in comprehension_bound_names(node, parents):
        return True
    function = _enclosing_function_body(node, parents)
    if function is None:
        return False
    local, declared_global = cache.setdefault(
        id(function), _function_scope_bindings(function)
    )
    return reference.split(".", 1)[0] in local - declared_global


def comprehension_bound_names(
    node: ast.AST, parents: Mapping[int, ast.AST]
) -> set[str]:
    bound: set[str] = set()
    branches: dict[int, str] = {}
    child = node
    parent = parents.get(id(child))
    while parent is not None:
        if isinstance(parent, ast.comprehension):
            branches[id(parent)] = (
                "ifs"
                if child in parent.ifs
                else "target"
                if child is parent.target
                else "iter"
            )
        elif isinstance(
            parent, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            if isinstance(child, ast.comprehension):
                index = parent.generators.index(child)
                generators = list(parent.generators[:index])
                if branches.get(id(child)) == "ifs":
                    generators.append(child)
            else:
                generators = parent.generators
            bound.update(
                name.id
                for generator in generators
                for name in ast.walk(generator.target)
                if isinstance(name, ast.Name) and isinstance(name.ctx, ast.Store)
            )
        child = parent
        parent = parents.get(id(parent))
    return bound


def comprehension_is_statically_empty(
    node: ast.AST, parents: Mapping[int, ast.AST]
) -> bool:
    branches: dict[int, str] = {}
    child = node
    parent = parents.get(id(child))
    while parent is not None:
        if isinstance(parent, ast.comprehension):
            branches[id(parent)] = (
                "ifs"
                if child in parent.ifs
                else "target"
                if child is parent.target
                else "iter"
            )
        elif isinstance(
            parent, (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)
        ):
            if isinstance(child, ast.comprehension):
                index = parent.generators.index(child)
                count = index + (branches.get(id(child)) == "ifs")
                generators = parent.generators[:count]
            else:
                generators = parent.generators
            if any(_literal_empty(generator.iter) for generator in generators):
                return True
        child = parent
        parent = parents.get(id(parent))
    return False


def call_arguments_prove_empty(node: ast.Call) -> bool:
    if any(isinstance(argument, ast.Starred) for argument in node.args) or any(
        keyword.arg is None for keyword in node.keywords
    ):
        return False
    arguments = [*node.args, *(keyword.value for keyword in node.keywords)]
    return bool(arguments) and all(_literal_empty(argument) for argument in arguments)


def call_argument_mutation_names(
    node: ast.Call,
    parents: Mapping[int, ast.AST],
    cache: dict[int, tuple[set[str], set[str]]],
    shadowed: set[str],
    zero_iteration: bool,
    unknown_alias: str,
) -> set[str]:
    names: set[str] = set()
    for argument in (*node.args, *(item.value for item in node.keywords)):
        if not isinstance(argument, ast.Name):
            continue
        if argument.id in shadowed:
            if not zero_iteration:
                names.add(unknown_alias)
        elif not locally_shadowed(node, argument.id, parents, cache):
            names.add(argument.id)
    return names


def _literal_empty(node: ast.AST) -> bool:
    return bool(
        isinstance(node, (ast.List, ast.Tuple, ast.Set))
        and not node.elts
        or isinstance(node, ast.Dict)
        and not node.keys
    )


def without_shadowed_bindings(
    values: Mapping[str, _Value], shadowed: set[str]
) -> dict[str, _Value]:
    return {
        name: value
        for name, value in values.items()
        if name.split(".", 1)[0] not in shadowed
    }


def mapping_mutation_root(node: ast.Call) -> str:
    assert isinstance(node.func, ast.Attribute)
    target = (
        node.args[0]
        if isinstance(node.func.value, ast.Name)
        and node.func.value.id == "dict"
        and node.args
        else node.func.value
    )
    while isinstance(target, (ast.Attribute, ast.Subscript)):
        target = target.value
    return target.id if isinstance(target, ast.Name) else ""


def namespace_subscript_name(node: ast.Subscript) -> str | None:
    current: ast.AST = node
    while isinstance(current, ast.Subscript):
        if (
            isinstance(current.value, ast.Call)
            and isinstance(current.value.func, ast.Name)
            and current.value.func.id in {"globals", "locals", "vars"}
            and not current.value.args
            and not current.value.keywords
            and isinstance(current.slice, ast.Constant)
            and isinstance(current.slice.value, str)
        ):
            return current.slice.value
        current = current.value
    return None


def mutation_target_name(node: ast.AST) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Subscript):
        return namespace_subscript_name(node) or mutation_target_name(node.value)
    if isinstance(node, ast.Attribute):
        return mutation_target_name(node.value)
    return None


def target_names(node: ast.AST) -> set[str]:
    if isinstance(node, ast.Name):
        return {node.id}
    if isinstance(node, (ast.Tuple, ast.List)):
        return {name for item in node.elts for name in target_names(item)}
    if isinstance(node, ast.Subscript):
        if name := namespace_subscript_name(node):
            return {name}
    name = mutation_target_name(node)
    return {name.split(".", 1)[0]} if name else set()


def function_binding_mutations(node: ast.AST, globals_declared: set[str]) -> set[str]:
    targets: Sequence[ast.AST] = ()
    if isinstance(node, ast.Assign):
        targets = node.targets
    elif isinstance(node, (ast.AnnAssign, ast.AugAssign, ast.NamedExpr)):
        targets = (node.target,)
    elif isinstance(node, ast.Delete):
        targets = node.targets
    return {
        name
        for target in targets
        for name in target_names(target)
        if isinstance(target, (ast.Subscript, ast.Attribute))
        or isinstance(target, ast.Name)
        and target.id in globals_declared
    }


def dynamic_sink_lookup_errors(
    path: str, tree: ast.Module, sinks: frozenset[str]
) -> list[str]:
    parents = {
        id(child): parent
        for parent in ast.walk(tree)
        for child in ast.iter_child_nodes(parent)
    }
    errors: list[str] = []
    for node in ast.walk(tree):
        parent = parents.get(id(node))
        called = isinstance(parent, ast.Call) and parent.func is node
        getattribute = (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "__getattribute__"
            and any(
                isinstance(argument, ast.Constant) and argument.value in sinks
                for argument in node.args
            )
        )
        mapping_lookup = (
            isinstance(node, ast.Subscript)
            and isinstance(node.slice, ast.Constant)
            and node.slice.value in sinks
        )
        if called and (getattribute or mapping_lookup):
            errors.append(
                f"{path}:{getattr(node, 'lineno', 0)}: dynamic SQLite dispatch"
            )
    return errors


def _enclosing_function_body(
    node: ast.AST, parents: Mapping[int, ast.AST]
) -> ast.FunctionDef | ast.AsyncFunctionDef | None:
    child = node
    parent = parents.get(id(child))
    while parent is not None:
        if isinstance(parent, (ast.FunctionDef, ast.AsyncFunctionDef)):
            if child in parent.body:
                return parent
        child = parent
        parent = parents.get(id(parent))
    return None


def _function_scope_bindings(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[set[str], set[str]]:
    nodes = _body_nodes(function)
    declared_global = {
        name for node in nodes if isinstance(node, ast.Global) for name in node.names
    }
    local = {
        argument.arg
        for argument in (
            *function.args.posonlyargs,
            *function.args.args,
            *function.args.kwonlyargs,
        )
    }
    local.update(
        node.id
        for node in nodes
        if isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del))
    )
    local.update(
        item.asname or item.name.split(".", 1)[0]
        for node in nodes
        if isinstance(node, (ast.Import, ast.ImportFrom))
        for item in node.names
        if item.name != "*"
    )
    local.update(
        node.name
        for node in nodes
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))
    )
    local.update(
        node.name for node in nodes if isinstance(node, ast.ExceptHandler) and node.name
    )
    return local, declared_global


def _body_nodes(
    function: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[ast.AST]:
    found: list[ast.AST] = []
    pending: list[ast.AST] = list(function.body)
    while pending:
        node = pending.pop()
        found.append(node)
        if isinstance(
            node,
            (
                ast.FunctionDef,
                ast.AsyncFunctionDef,
                ast.ClassDef,
                ast.Lambda,
                ast.ListComp,
                ast.SetComp,
                ast.DictComp,
                ast.GeneratorExp,
            ),
        ):
            continue
        pending.extend(ast.iter_child_nodes(node))
    return found
