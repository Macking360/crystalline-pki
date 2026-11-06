from __future__ import annotations

import os
import ssl
import sys
from pathlib import Path

MINIMUM_ROOTS = 20


def _candidates() -> list:
    found = []
    env = os.environ.get("SSL_CERT_FILE")
    if env:
        found.append(("SSL_CERT_FILE environment variable", env))
    try:
        import certifi
        found.append(("certifi package", certifi.where()))
    except Exception:
        pass
    default = ssl.get_default_verify_paths()
    if default.cafile:
        found.append(("Python/OpenSSL default", default.cafile))
    if os.name == "nt":
        for base in (os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), os.environ.get("LOCALAPPDATA")):
            if base:
                found.append(("Git for Windows", str(Path(base) / "Git" / "mingw64" / "etc" / "ssl" / "certs" / "ca-bundle.crt")))
                found.append(("Git for Windows", str(Path(base) / "Programs" / "Git" / "mingw64" / "etc" / "ssl" / "certs" / "ca-bundle.crt")))
        found.append(("MSYS2", r"C:\msys64\usr\ssl\certs\ca-bundle.crt"))
    prefix = os.environ.get("PREFIX")
    if prefix:
        found.append(("Termux", str(Path(prefix) / "etc" / "tls" / "cert.pem")))
    for label, path in (
        ("Debian/Ubuntu", "/etc/ssl/certs/ca-certificates.crt"),
        ("RHEL/Fedora", "/etc/pki/tls/certs/ca-bundle.crt"),
        ("openSUSE", "/etc/ssl/ca-bundle.pem"),
        ("macOS/BSD", "/etc/ssl/cert.pem"),
        ("Homebrew", "/opt/homebrew/etc/ca-certificates/cert.pem"),
        ("Homebrew (Intel)", "/usr/local/etc/openssl/cert.pem"),
    ):
        found.append((label, path))
    return found


def _count_roots(path: str) -> int:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.load_verify_locations(cafile=path)
    return int(context.cert_store_stats().get("x509_ca", 0))


def find_ca_bundles() -> list:
    results, seen = [], set()
    for label, path in _candidates():
        try:
            resolved = str(Path(path).resolve())
        except OSError:
            continue
        if resolved in seen or not Path(resolved).is_file():
            continue
        seen.add(resolved)
        try:
            count = _count_roots(resolved)
        except (ssl.SSLError, OSError):
            continue
        if count >= MINIMUM_ROOTS:
            results.append({"source": label, "path": resolved, "roots": count})
    return results


def best_ca_bundle():
    bundles = find_ca_bundles()
    return bundles[0] if bundles else None


def system_store_summary() -> dict:
    context = ssl.create_default_context()
    stats = context.cert_store_stats()
    return {
        "platform": sys.platform,
        "roots_visible_to_python": int(stats.get("x509_ca", 0)),
        "note": ("Python on Windows only sees roots Windows has already installed; "
                 "a bundle file lets the tool verify sites whose root has not been installed yet."
                 if os.name == "nt" else "Python reads the operating system's root store."),
    }


def root_trust_instructions(root_pem_path) -> list:
    path = str(root_pem_path)
    return [
        {"platform": "Windows (current user)", "command": 'certutil -user -addstore Root "%s"' % path},
        {"platform": "macOS (login keychain)",
         "command": 'security add-trusted-cert -r trustRoot -k ~/Library/Keychains/login.keychain-db "%s"' % path},
        {"platform": "Debian/Ubuntu (system)",
         "command": 'sudo cp "%s" /usr/local/share/ca-certificates/crystalline-pki-root.crt && sudo update-ca-certificates' % path},
        {"platform": "Firefox", "command": "Settings > Privacy & Security > Certificates > View Certificates > Authorities > Import"},
        {"platform": "Android", "command": "Settings > Security > Encryption & credentials > Install a certificate > CA certificate"},
    ]
