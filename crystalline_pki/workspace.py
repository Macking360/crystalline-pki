
from __future__ import annotations

import os
from pathlib import Path

from .util import restrict


class Workspace:

    def __init__(self, home=None):
        raw = home or os.environ.get("CRYSTALLINE_PKI_HOME") or str(Path.home() / ".crystalline-pki")
        self.home = Path(raw).expanduser().resolve()
        self.pki = self.home / "pki"
        self.root = self.pki / "root"
        self.intermediate = self.pki / "intermediate"
        self.server = self.pki / "server"
        self.client = self.pki / "client"
        self.devices = self.pki / "devices"
        self.issued = self.pki / "issued"
        self.crl = self.pki / "crl"
        self.backups = self.home / "pki-backups"
        self.logs = self.home / "logs"
        self.reports = self.home / "reports"
        self.exports = self.home / "exports"
        self.database = self.home / "crystalline-pki.db"
        self.config_file = self.home / "config.json"

    @property
    def root_cert(self) -> Path:
        return self.root / "root-cert.pem"

    @property
    def root_key(self) -> Path:
        return self.root / "root-key.pem"

    @property
    def intermediate_cert(self) -> Path:
        return self.intermediate / "intermediate-cert.pem"

    @property
    def intermediate_key(self) -> Path:
        return self.intermediate / "intermediate-key.pem"

    @property
    def server_cert(self) -> Path:
        return self.server / "server-cert.pem"

    @property
    def server_key(self) -> Path:
        return self.server / "server-key.pem"

    @property
    def server_chain(self) -> Path:
        return self.server / "server-chain.pem"

    @property
    def client_cert(self) -> Path:
        return self.client / "client-cert.pem"

    @property
    def client_key(self) -> Path:
        return self.client / "client-key.pem"

    @property
    def client_chain(self) -> Path:
        return self.client / "client-chain.pem"

    @property
    def crl_pem(self) -> Path:
        return self.crl / "intermediate-crl.pem"

    @property
    def crl_der(self) -> Path:
        return self.crl / "intermediate.crl"

    @property
    def trust_bundle(self) -> Path:
        return self.crl / "trust-bundle.pem"

    def private_keys(self) -> list:
        keys = [self.root_key, self.intermediate_key, self.server_key, self.client_key]
        if self.devices.is_dir():
            keys.extend(sorted(self.devices.rglob("key-*.pem")))
        return keys

    def required_pki_files(self) -> list:
        return [
            self.root_cert, self.root_key,
            self.intermediate_cert, self.intermediate_key,
            self.server_cert, self.server_key, self.server_chain,
            self.client_cert, self.client_key, self.client_chain,
            self.crl_pem, self.trust_bundle,
        ]

    def pki_ready(self) -> bool:
        return all(path.is_file() for path in self.required_pki_files())

    def ensure(self) -> None:
        for directory in (self.home, self.pki, self.logs, self.reports, self.exports):
            directory.mkdir(parents=True, exist_ok=True)
            restrict(directory, 0o700)
