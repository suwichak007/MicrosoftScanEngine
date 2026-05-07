# agent.spec
from PyInstaller.utils.hooks import collect_all, collect_submodules

block_cipher = None

datas = [
    ("scanner", "scanner"),
]

hiddenimports = [
    "scanner",
    "scanner.security_scanner",
    "scanner.mappings",
    "scanner.data_sources",
    "scanner.checkers",
    "scanner.helpers",
    "scanner.base_executor",
    "scanner.local_executor",
]

for pkg in ["pandas", "openpyxl", "et_xmlfile"]:
    d, b, _ = collect_all(pkg)
    datas          += d
    hiddenimports  += b
    hiddenimports  += collect_submodules(pkg)

a = Analysis(
    ["agent.py"],
    pathex=["."],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "scipy"],
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    name="MicrosoftScanAgent",
    debug=False,
    strip=False,
    upx=False,
    console=True,
)