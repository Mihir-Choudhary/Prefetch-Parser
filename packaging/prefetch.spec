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

# The GUI imports exactly three Qt modules: QtWidgets, QtCore, QtGui. PySide6's PyInstaller
# hook collects the whole family regardless, which cost 23.7 MB of shared libraries the tool
# never loads - Quick and Qml alone were 14.4 MB - plus OpenSSL dragged in behind QtNetwork.
#
# Two levers are needed, because they do different things:
#   * `excludes` stops the Python *binding* modules being imported at all;
#   * the shared libraries survive that, because the hook adds them as data, so they are
#     filtered out of `binaries`/`datas` below by name.
#
# Deliberately NOT excluded:
#   QtDBus  - Linux platform integration reaches for it; dropping it risks the theme.
#   ICU     - libicudata is 30.6 MB but Qt6Core links it on Linux, so removing it stops Qt
#             loading at all. It is a Linux cost: Windows Qt6 uses the OS locale APIs and does
#             not ship it, so a Windows build starts ~30 MB lower without any help from here.
UNUSED_QT = [
    "Quick", "Quick3D", "QuickControls2", "QuickWidgets", "QuickTest",
    "Qml", "QmlModels", "QmlWorkerScript", "QmlLocalStorage", "QmlXmlListModel",
    "Pdf", "PdfWidgets", "Network", "NetworkAuth",
    "WebEngineCore", "WebEngineWidgets", "WebEngineQuick", "WebChannel", "WebSockets",
    "Multimedia", "MultimediaWidgets", "MultimediaQuick", "SpatialAudio",
    "OpenGL", "OpenGLWidgets", "Sql", "Test", "Designer", "Help", "UiTools",
    "Charts", "DataVisualization", "Graphs",
    "3DCore", "3DRender", "3DInput", "3DLogic", "3DAnimation", "3DExtras", "3DQuick",
    "Bluetooth", "Nfc", "Positioning", "PositioningQuick", "Sensors", "SerialPort",
    "SerialBus", "TextToSpeech", "VirtualKeyboard", "ShaderTools", "Scxml", "StateMachine",
    "RemoteObjects", "Location", "Svg", "SvgWidgets", "PrintSupport", "Concurrent", "Xml",
]
GUI_EXCLUDES = (["tkinter", "matplotlib", "numpy", "PIL"]
                + [f"PySide6.Qt{name}" for name in UNUSED_QT])


def without_unused_qt(entries):
    """Drop shared libraries and plugins belonging to Qt modules the GUI never imports.

    `excludes` alone does not remove these: the PySide6 hook contributes them as binaries and
    data rather than as imports, so they ride along even when nothing can import them.
    """
    kept = []
    for entry in entries:
        dest = entry[0]
        base = os.path.basename(dest)
        parts = dest.replace("\\", "/").split("/")
        drop = any(
            base.startswith(f"libQt6{name}.")          # Linux  libQt6Quick.so.6
            or base.startswith(f"Qt6{name}.")          # Windows Qt6Quick.dll
            or base.startswith(f"Qt{name}.abi3")       # the PySide6 binding itself
            or base.startswith(f"Qt{name}.pyi")
            for name in UNUSED_QT
        )
        # The QML tree is only reachable from Qt Quick, which is excluded above.
        drop = drop or "qml" in [p.lower() for p in parts]
        if not drop:
            kept.append(entry)
    return kept

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

# Applied after MERGE, so the shared bundle is filtered rather than one analysis' view of it.
gui_a.binaries = without_unused_qt(gui_a.binaries)
gui_a.datas = without_unused_qt(gui_a.datas)

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
