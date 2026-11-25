"""Check static dependencies across the shipped platform packages."""

import ast
import re
from importlib.util import resolve_name
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src"
Roots = ("riswan_platform", "riswan_security_data", "riswan_ir", "riswan_app")
ENTRYPOINTS = {
    "riswan_ir.__main__",
    "riswan_ir.connectors.cli",
    "riswan_ir.evidence.cli",
    "riswan_ir.detection.cli",
}
PURE_DOMAINS = {
    "models",
    "investigation",
    "normalization",
    "correlation",
    "detection",
    "risk",
    "memory",
    "knowledge_graph",
    "response",
}
ADAPTERS = {
    "riswan_ir.correlation.temporal.repository",
    "riswan_ir.knowledge_graph.repository",
    "riswan_ir.risk.repository",
    "riswan_ir.risk.reassessment",
    "riswan_ir.memory.repository",
    "riswan_ir.memory.ingestion",
    "riswan_ir.memory.intelligence",
}


def pure(module):
    parts = module.split(".")
    return (
        len(parts) >= 2
        and parts[0] == "riswan_ir"
        and parts[1] in PURE_DOMAINS
        and module not in ADAPTERS | ENTRYPOINTS
    )


def sources():
    return {
        ".".join(path.relative_to(SRC).with_suffix("").parts).removesuffix(".__init__"): path
        for root in sorted({*Roots, *(path.name for path in SRC.glob("riswan_*") if path.is_dir())})
        for path in (SRC / root).rglob("*.py")
    }


def dependencies(path, module):
    package = module if path.name == "__init__.py" else module.rpartition(".")[0]
    for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
        if isinstance(node, ast.Import):
            yield from (part.name for part in node.names)
        elif isinstance(node, ast.ImportFrom):
            base = node.module or ""
            if node.level:
                base = resolve_name("." * node.level + base, package)
            yield base
            for part in node.names:
                yield f"{base}.{part.name}"


def test_shared_packages_and_domain_have_one_way_dependencies():
    failures = []
    for name, path in sources().items():
        root = name.split(".")[0]
        for target in dependencies(path, name):
            target_root = target.split(".")[0]
            if root == "riswan_platform" and (
                target_root.startswith("riswan_")
                and target_root != root
                or target_root in {"sqlite3", "sentinelforge"}
            ):
                failures.append((name, target))
            if root == "riswan_security_data" and target_root in {
                "riswan_ir",
                "riswan_app",
                "sqlite3",
            }:
                failures.append((name, target))
            if (
                root == "riswan_ir"
                and name not in ENTRYPOINTS
                and (
                    target_root == "sentinelforge"
                    or (
                        target_root.startswith("riswan_")
                        and target_root not in {root, "riswan_platform", "riswan_security_data"}
                    )
                )
            ):
                failures.append((name, target))
            if root == "riswan_ir" and target.startswith("riswan_ir.storage.sqlite"):
                failures.append((name, target))
            if pure(name) and (target_root == "sqlite3" or target.startswith("riswan_ir.storage")):
                failures.append((name, target))
    assert failures == []


def test_module_dependency_graph_has_no_cycles():
    files = sources()
    graph = {
        name: {target for target in dependencies(path, name) if target in files and target != name}
        for name, path in files.items()
    }
    stack = []
    active = set()
    done = set()

    def visit(module):
        if module in active:
            raise AssertionError(" -> ".join([*stack, module]))
        if module in done:
            return
        active.add(module)
        stack.append(module)
        for dependency in sorted(graph[module]):
            visit(dependency)
        stack.pop()
        active.remove(module)
        done.add(module)

    for module in graph:
        visit(module)


def test_collection_and_pure_domain_do_not_access_owned_tables_directly():
    sql_methods = {"execute", "executemany", "executescript"}
    for module, path in sources().items():
        if not (pure(module) or module.startswith("riswan_ir.ingestion")):
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in sql_methods:
                continue
            assert (
                module.startswith("riswan_ir.ingestion")
                and len(node.args) == 1
                and isinstance(node.args[0], ast.Constant)
                and node.args[0].value == "BEGIN IMMEDIATE"
            ), (module, node.lineno)


def test_table_writes_stay_with_the_owners():
    statements = {}
    owners = {}
    for module, path in sources().items():
        # Values are assembled from source literals. This intentionally checks static SQL.
        values = [
            node.value
            for node in ast.walk(ast.parse(path.read_text(encoding="utf-8")))
            if isinstance(node, ast.Constant) and isinstance(node.value, str)
        ]
        statements[module] = values
        for value in values:
            for table in re.findall(r"CREATE TABLE IF NOT EXISTS (\w+)", value, re.I):
                assert table not in owners
                owners[table] = module
    assert {"investigations", "raw_evidence", "risk_assessments", "memory_records"} <= owners.keys()
    for module, values in statements.items():
        for value in values:
            for table in re.findall(
                r"\b(?:INSERT(?: OR IGNORE)? INTO|UPDATE|DELETE FROM) (\w+)", value, re.I
            ):
                if table in owners:
                    assert owners[table] == module, (table, module)
