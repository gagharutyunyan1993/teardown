"""Architecture conformance checks that import-linter cannot express.

Run via ``make arch``. Exit 1 with one line per violation.
Rules (see docs/architecture/ARCHITECTURE.md §3-4):
  A1 domain/ imports only stdlib, retool.shared and its own domain package.
  A2 cross-context imports use the context's public API (``retool.<ctx>``), never deep paths.
  A3 a context's __init__ re-exports nothing from infrastructure.
  A4 no third-party imports in domain/ or application/.
  A5 dataclasses in domain/ are frozen.
  A6 no ``Any`` annotations and no bare ``# type: ignore`` in src/.
  A7 interface/ contains no business logic markers (struct.unpack, parsing loops).
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

SRC = Path(__file__).resolve().parent.parent / "src" / "retool"
STDLIB = set(sys.stdlib_module_names)
NON_CONTEXT = {"shared", "interface"}


def contexts() -> set[str]:
    return {p.name for p in SRC.iterdir() if p.is_dir() and not p.name.startswith("_")} - NON_CONTEXT


def imports(tree: ast.AST) -> list[tuple[str, int]]:
    out: list[tuple[str, int]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            out.extend((a.name, node.lineno) for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            out.append((node.module, node.lineno))
    return out


def check(path: Path, violations: list[str]) -> None:
    rel = path.relative_to(SRC)
    parts = rel.parts
    text = path.read_text()
    tree = ast.parse(text, filename=str(path))
    ctx = parts[0] if parts[0] not in NON_CONTEXT else None
    layer = parts[1] if ctx and len(parts) > 2 else None
    where = f"src/retool/{rel}"

    for mod, line in imports(tree):
        top = mod.split(".")[0]
        if top == "retool":
            segs = mod.split(".")
            target_ctx = segs[1] if len(segs) > 1 else None
            if ctx and target_ctx in contexts() and target_ctx != ctx and len(segs) > 2:
                violations.append(f"{where}:{line} A2 deep import across contexts: {mod} (use retool.{target_ctx})")
            if layer == "domain" and target_ctx not in {"shared", ctx}:
                violations.append(f"{where}:{line} A1 domain imports {mod}")
            if layer == "domain" and target_ctx == ctx and len(segs) > 2 and segs[2] != "domain":
                violations.append(f"{where}:{line} A1 domain imports its own {segs[2]} layer")
            if parts[-1] == "__init__.py" and ctx and "infrastructure" in segs:
                violations.append(f"{where}:{line} A3 public API re-exports infrastructure: {mod}")
        elif top not in STDLIB and layer in {"domain", "application"}:
            violations.append(f"{where}:{line} A4 third-party import in {layer}: {mod}")

    if layer == "domain":
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef):
                for dec in node.decorator_list:
                    if isinstance(dec, ast.Call) and getattr(dec.func, "id", getattr(dec.func, "attr", "")) == "dataclass":
                        frozen = any(k.arg == "frozen" and isinstance(k.value, ast.Constant) and k.value.value is True for k in dec.keywords)
                        if not frozen:
                            violations.append(f"{where}:{node.lineno} A5 domain dataclass {node.name} is not frozen")
                    elif isinstance(dec, ast.Name) and dec.id == "dataclass":
                        violations.append(f"{where}:{node.lineno} A5 domain dataclass {node.name} is not frozen")

    for i, ln in enumerate(text.splitlines(), 1):
        if re.search(r"\bAny\b", ln) and not ln.lstrip().startswith("#"):
            violations.append(f"{where}:{i} A6 'Any' annotation")
        if re.search(r"#\s*type:\s*ignore(?!\[)", ln):
            violations.append(f"{where}:{i} A6 bare 'type: ignore' (add [code] and a reason)")
    if parts[0] == "interface" and re.search(r"struct\.(unpack|unpack_from)|ByteRange\(", text):
        violations.append(f"{where} A7 parsing logic in interface layer")


def main() -> int:
    violations: list[str] = []
    for path in sorted(SRC.rglob("*.py")):
        check(path, violations)
    for v in violations:
        print(v)
    print(f"archcheck: {len(violations)} violation(s)" if violations else "archcheck: ok")
    return 1 if violations else 0


if __name__ == "__main__":
    raise SystemExit(main())
