#!/usr/bin/env python3
"""Enforce the layering the architecture depends on.

`prefetch_core` returns records; the CLI and GUI are consumers. That is easy to state and easy
to erode - one `from PySide6...` inside the core, added for a quick fix, and:

  * the CLI can no longer run on a headless collection box without Qt installed;
  * the packaging spec's `excludes=["PySide6"]` for the CLI silently starts producing a broken
    binary, which only shows up when someone runs the frozen build;
  * the core stops being testable without a display.

Nothing else catches this, because everything still works on a dev machine that has Qt.

Run:  python3 test_layering.py
"""

import ast
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import corpus  # noqa: E402

GUI_ONLY = {"PySide6", "shiboken6"}
CLI_ONLY = {"argparse"}

failures = []


def top_level_imports(path):
    tree = ast.parse(open(path, encoding="utf-8").read())
    found = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            found |= {a.name.split(".")[0] for a in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module.split(".")[0])
    return found


def package_imports(package):
    directory = os.path.join(ROOT, package)
    combined = set()
    for name in sorted(os.listdir(directory)):
        if name.endswith(".py"):
            combined |= top_level_imports(os.path.join(directory, name))
    return combined


def check(label, ok, detail=""):
    print(f"  {label:56} {'ok' if ok else 'FAIL'}{'  ' + detail if not ok else ''}")
    if not ok:
        failures.append(f"{label} {detail}")


def main():
    core = package_imports("prefetch_core")
    cli = package_imports("pfcli")
    gui = package_imports("pfgui")

    print("prefetch_core is pure:")
    check("core does not import Qt", not (core & GUI_ONLY), str(sorted(core & GUI_ONLY)))
    check("core does not import argparse", not (core & CLI_ONLY))
    check("core does not import pfcli/pfgui", not (core & {"pfcli", "pfgui"}))

    print("\npfcli stays headless:")
    check("cli does not import Qt", not (cli & GUI_ONLY), str(sorted(cli & GUI_ONLY)))
    check("cli imports the core", "prefetch_core" in cli)

    print("\npfgui is a consumer, not a parser:")
    check("gui imports the core", "prefetch_core" in gui)
    check("gui does not re-implement struct parsing", "struct" not in gui)

    # The core must import and run with Qt made unavailable - the condition on a headless box.
    print("\ncore imports with Qt blocked:")
    import subprocess
    probe = (
        "import sys;"
        "sys.modules['PySide6']=None;"
        "sys.path.insert(0,%r);"
        "import prefetch_core;"
        "from prefetch_core.store import Store;"
        "from prefetch_core.artifacts import scan_folder;"
        "pf=prefetch_core.parse_file(%r);"
        "print('OK', pf.executable_name)"
    ) % (ROOT, "" + corpus.WIN10 + "/7ZFM.EXE-7C92DCA0.pf")
    r = subprocess.run([sys.executable, "-c", probe], capture_output=True, text=True)
    check("core parses a file with PySide6 poisoned", r.returncode == 0 and "OK" in r.stdout,
          r.stderr.strip().splitlines()[-1] if r.stderr.strip() else "")

    print("\nfrozen-build guards:")
    for module in ("pfcli/__main__.py", "pfgui/__main__.py"):
        text = open(os.path.join(ROOT, module), encoding="utf-8").read()
        if "sys.path.insert" in text:
            # Injecting a __file__-derived directory inside a PyInstaller bundle points outside
            # it. The insert is only correct when running from a source checkout.
            check(f"{module} guards sys.path with sys.frozen",
                  'getattr(sys, "frozen", False)' in text)

    print("\nPASS" if not failures else f"\nFAIL: {failures}")
    return 0 if not failures else 1


if __name__ == "__main__":
    sys.exit(main())
