# -*- mode: python ; coding: utf-8 -*-
# PyInstaller one-folder build for Phone Media Vault.
# Build from the repository root:  pyinstaller phone_media_vault/installer/phone_media_vault.spec
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

package_dir = Path(SPECPATH).parent          # .../phone_media_vault
icon = package_dir / "installer" / "assets" / "app.ico"

datas = [(str(package_dir / "ui"), "phone_media_vault/ui")]
platform_tools = package_dir / "platform-tools"
if any(p.name != ".gitkeep" for p in platform_tools.glob("*")):
    # Bundled ADB lands in _internal/platform-tools, which AdbManager checks first.
    datas.append((str(platform_tools), "platform-tools"))

a = Analysis(
    [str(package_dir / "main.py")],
    pathex=[str(package_dir.parent)],
    datas=datas,
    hiddenimports=collect_submodules("phone_media_vault") + collect_submodules("webview"),
    excludes=["tkinter", "unittest", "phone_media_vault.tests"],
    noarchive=False,
)
pyz = PYZ(a.pure)
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="PhoneMediaVault",
    console=False,
    icon=str(icon) if icon.is_file() else None,
    version=None,
)
coll = COLLECT(exe, a.binaries, a.datas, strip=False, upx=False, name="PhoneMediaVault")
