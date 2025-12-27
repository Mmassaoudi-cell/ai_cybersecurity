# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller spec file for AI Cybersecurity Platform - Enhanced Final Version
With logo, immunization functionality, and all dependencies properly bundled
"""

from PyInstaller.utils.hooks import collect_all, collect_submodules
import os

# Get the current directory - use __file__ or current working directory as fallback
try:
    SPEC_DIR = os.path.dirname(os.path.abspath(SPECPATH))
except:
    SPEC_DIR = os.getcwd()
    
# Ensure we're in the plateform directory
if not os.path.exists(os.path.join(SPEC_DIR, 'main.py')):
    SPEC_DIR = r'C:\Users\mohamed.massaoudi\Desktop\finilized documents\A_Unified_Platform_for_Automated_Cybersecurity_Vulnerability_Assessment_in_Machine_Learning_Models_and_AI_Agents\plateform'

# Verify logo exists
logo_path = os.path.join(SPEC_DIR, 'logo.png')
if os.path.exists(logo_path):
    print(f"[OK] Logo found at: {logo_path}")
else:
    print(f"[WARNING] Logo NOT found at: {logo_path}")

# Data files to include - logo in multiple locations for fallback
datas = [
    ('ai_cybersecurity', 'ai_cybersecurity'),
    ('templates', 'templates'),
]

# Add logo to multiple locations for fallback
if os.path.exists(logo_path):
    datas.append(('logo.png', '.'))  # Root directory
    datas.append(('logo.png', 'logo.png'))  # As file

binaries = []

# Hidden imports for all required modules
hiddenimports = [
    # AI Cybersecurity modules
    'ai_cybersecurity',
    'ai_cybersecurity.immunization',
    'ai_cybersecurity.ml_scanner',
    'ai_cybersecurity.agent_scanner',
    'ai_cybersecurity.reporting',
    'ai_cybersecurity.utils',
    'ai_cybersecurity.integration',
    'ai_cybersecurity.config',
    
    # Cryptography modules (for immunization)
    'cryptography',
    'cryptography.fernet',
    'cryptography.hazmat',
    'cryptography.hazmat.primitives',
    'cryptography.hazmat.primitives.hashes',
    'cryptography.hazmat.primitives.kdf',
    'cryptography.hazmat.primitives.kdf.pbkdf2',
    'cryptography.hazmat.primitives.ciphers',
    'cryptography.hazmat.backends',
    'cryptography.hazmat.backends.openssl',
    
    # PIL/Pillow (for logo)
    'PIL',
    'PIL.Image',
    'PIL.ImageTk',
    'PIL._tkinter_finder',
    
    # Scientific computing
    'numpy',
    'numpy.core',
    'numpy.core._methods',
    'numpy.lib.format',
    'pandas',
    'sklearn',
    'sklearn.utils._cython_blas',
    'sklearn.neighbors._typedefs',
    'sklearn.tree._utils',
    'scipy',
    'scipy.ndimage',
    'scipy.special._ufuncs_cxx',
    
    # Standard library
    'tkinter',
    'tkinter.ttk',
    'tkinter.filedialog',
    'tkinter.messagebox',
    'tkinter.scrolledtext',
    'json',
    'hashlib',
    'pickle',
    'joblib',
    'threading',
    'pathlib',
    'datetime',
    'webbrowser',
    'tempfile',
    'shutil',
    'base64',
    'secrets',
    'hmac',
    'ast',
    're',
    'logging',
    'warnings',
    
    # Pydantic
    'pydantic',
    'pydantic.main',
    'pydantic_core',
]

# Collect all required packages
packages_to_collect = ['sklearn', 'numpy', 'pandas', 'cryptography', 'PIL', 'scipy', 'pydantic', 'joblib']

for package in packages_to_collect:
    try:
        tmp_ret = collect_all(package)
        datas += tmp_ret[0]
        binaries += tmp_ret[1]
        hiddenimports += tmp_ret[2]
        print(f"[OK] Collected package: {package}")
    except Exception as e:
        print(f"[WARNING] Could not collect {package}: {e}")

# Analysis
a = Analysis(
    ['main.py'],
    pathex=[SPEC_DIR],
    binaries=binaries,
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[
        'matplotlib',
        'IPython',
        'jupyter',
        'notebook',
        'pytest',
        'sphinx',
        'docutils',
        'torch',
        'tensorflow',
    ],
    noarchive=False,
    optimize=0,
)

# Remove duplicates
a.datas = list(set(a.datas))
a.binaries = list(set(a.binaries))

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='AI_Cybersecurity_Platform_Enhanced_Final',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Set to True for debugging
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
