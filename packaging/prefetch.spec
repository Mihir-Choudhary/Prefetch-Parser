# PyInstaller spec: builds both the CLI and the GUI into one --onedir distribution.
#
# --onedir, not --onefile, and deliberately:
#   * onefile unpacks to a temp directory on every launch, which is slow for a Qt app and
#     leaves artefacts on the machine an analyst may be treating as evidence;
#   * onefile self-extraction is a strong AV heuristic, and a packed Python binary is already
#     flagged often enough. onedir plus code signing is the mitigation recorded in STATE.md.
#
# Two binaries share one bundle directory so PySide6 is not duplicated:
#   pfcli   - no Qt needed, but it costs nothing to ship alongside
#   pfgui   - windowed
#
# Build:  pyinstaller packaging/prefetch.spec --noconfirm

import os

block_cipher = None
ROOT = os.path.abspath(os.getcwd())

# The core is pure stdlib. Qt is only reachable from pfgui, so the CLI analysis excludes it -
# a headless collection box should not need Qt present to run the CLI from the bundle.
CLI_EXCLUDES = ["PySide6", "shiboken6", "tkinter", "matplotlib", "numpy", "PIL"]
GUI_EXCLUDES = ["tkinter", "matplotlib", "numpy", "PIL"]

cli_a = Analysis(
    [os.path.join(ROOT, "pfcli", "__main__.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[],
    # ctypes.WinDLL is resolved at runtime behind a capability probe, so nothing to add here;
    # the pure XPRESS decoder is plain Python and gets picked up by the import graph.
    hiddenimports=["prefetch_core", "prefetch_core.artifacts", "prefetch_core.store"],
    hookspath=[],
    runtime_hooks=[],
    excludes=CLI_EXCLUDES,
    cipher=block_cipher,
    noarchive=False,
)

gui_a = Analysis(
    [os.path.join(ROOT, "pfgui", "__main__.py")],
    pathex=[ROOT],
    binaries=[],
    datas=[],
    hiddenimports=["prefetch_core", "prefetch_core.artifacts", "prefetch_core.store",
                   "pfgui.model", "pfgui.filterpopup"],
    hookspath=[],
    runtime_hooks=[],
    excludes=GUI_EXCLUDES,
    cipher=block_cipher,
    noarchive=False,
)

MERGE((cli_a, "pfcli", "pfcli"), (gui_a, "pfgui", "pfgui"))

cli_pyz = PYZ(cli_a.pure, cli_a.zipped_data, cipher=block_cipher)
gui_pyz = PYZ(gui_a.pure, gui_a.zipped_data, cipher=block_cipher)

cli_exe = EXE(
    cli_pyz, cli_a.scripts, [],
    exclude_binaries=True,
    name="pfcli",
    debug=False,
    strip=False,
    upx=False,          # UPX compression is another AV heuristic; not worth the megabytes
    console=True,
)

gui_exe = EXE(
    gui_pyz, gui_a.scripts, [],
    exclude_binaries=True,
    name="pfgui",
    debug=False,
    strip=False,
    upx=False,
    console=False,      # windowed
)

COLLECT(
    cli_exe, cli_a.binaries, cli_a.zipfiles, cli_a.datas,
    gui_exe, gui_a.binaries, gui_a.zipfiles, gui_a.datas,
    strip=False,
    upx=False,
    name="prefetch-explorer",
)
