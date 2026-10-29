# PyInstaller spec for the AgentShield desktop app (Kivy).
# Build:  venv\Scripts\pyinstaller AgentShield.spec --noconfirm --clean
# Result: dist\AgentShield\AgentShield.exe (onedir). Needs Ollama installed
# separately and running.

from kivy_deps import glew, sdl2
from kivy.tools.packaging.pyinstaller_hooks import get_deps_minimal, hookspath, runtime_hooks

# Explicitly pull the image/text/window/clipboard providers (and exclude the
# unused video/audio/camera ones) - without this the frozen app can't load any
# image provider and aborts.
kivy_extra = get_deps_minimal(video=None, audio=None, camera=None, spelling=None)

a = Analysis(
    ['frontend/app.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('frontend/app.kv', '.'),
        ('frontend/assets', 'assets'),
        ('models/agentshield-villain.Modelfile', 'models'),
    ],
    hiddenimports=kivy_extra['hiddenimports'] + ['PIL._imaging'],
    hookspath=hookspath(),
    hooksconfig={},
    runtime_hooks=runtime_hooks(),
    excludes=['mcp', 'pytest'] + kivy_extra.get('excludes', []),
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    exclude_binaries=True,
    name='AgentShield',
    debug=False,
    strip=False,
    upx=True,
    console=False,
    icon='frontend/assets/icon.ico',
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    *[Tree(p) for p in (sdl2.dep_bins + glew.dep_bins)],
    strip=False,
    upx=True,
    name='AgentShield',
)
