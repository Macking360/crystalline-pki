
from __future__ import annotations

import os
import platform
import shutil
import sqlite3
import ssl
import subprocess
import sys

import cryptography

from . import APP_NAME, __version__

IS_WINDOWS = os.name == "nt"
IS_ANDROID = "ANDROID_ROOT" in os.environ or "com.termux" in os.environ.get("PREFIX", "").lower()
IS_MACOS = sys.platform == "darwin"
IS_LINUX = sys.platform.startswith("linux") and not IS_ANDROID

if IS_ANDROID:
    PLATFORM_NAME = "Android / Termux"
elif IS_WINDOWS:
    PLATFORM_NAME = "Windows"
elif IS_LINUX:
    PLATFORM_NAME = "Linux"
elif IS_MACOS:
    PLATFORM_NAME = "macOS"
else:
    PLATFORM_NAME = platform.system() or "Unknown"


def loose_key_files(workspace) -> list:
    if IS_WINDOWS:
        return []
    loose = []
    for path in workspace.private_keys():
        if path.is_file() and path.stat().st_mode & 0o077:
            loose.append(str(path))
    return loose


def diagnostics(workspace) -> dict:
    usage = shutil.disk_usage(workspace.home)
    return {
        "application": APP_NAME,
        "version": __version__,
        "platform": PLATFORM_NAME,
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "python": sys.version,
        "openssl": ssl.OPENSSL_VERSION,
        "cryptography": cryptography.__version__,
        "sqlite": sqlite3.sqlite_version,
        "home": str(workspace.home),
        "workspace_writable": os.access(workspace.home, os.W_OK),
        "storage_bytes": {"total": usage.total, "used": usage.used, "free": usage.free},
        "database_exists": workspace.database.exists(),
        "pki_ready": workspace.pki_ready(),
        "key_file_protection": (
            "Windows: POSIX modes are not applied; protect the workspace with your profile ACLs"
            if IS_WINDOWS
            else "POSIX modes (0600 for keys, 0700 for directories)"
        ),
        "loose_key_files": loose_key_files(workspace),
    }


def open_workspace(workspace) -> bool:
    try:
        if IS_WINDOWS:
            os.startfile(str(workspace.home))
        elif IS_MACOS:
            subprocess.Popen(["open", str(workspace.home)])
        elif IS_ANDROID:
            subprocess.Popen(["termux-open", str(workspace.home)])
        elif IS_LINUX:
            subprocess.Popen(["xdg-open", str(workspace.home)])
        else:
            return False
        return True
    except OSError:
        return False
