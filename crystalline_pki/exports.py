from __future__ import annotations

import csv
import shutil

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from .pki import load_cert, load_key, validate_name
from .util import atomic_write, json_bytes, new_id, now_dt, restrict, safe_name


class Exporter:
    def __init__(self, workspace, audit, registry):
        self.workspace = workspace
        self.audit = audit
        self.registry = registry

    def _stamp(self) -> str:
        return now_dt().strftime("%Y%m%d-%H%M%S") + "-" + new_id()[:8]

    def export_public_certificates(self) -> dict:
        ws = self.workspace
        if not ws.pki_ready():
            raise RuntimeError("Create the local PKI first")
        destination = ws.exports / ("public-certs-" + self._stamp())
        destination.mkdir(parents=True)
        sources = [ws.root_cert, ws.intermediate_cert, ws.server_cert, ws.server_chain,
                   ws.client_cert, ws.client_chain, ws.crl_pem]
        for source in sources:
            shutil.copyfile(source, destination / source.name)
            restrict(destination / source.name, 0o644)
        self.audit.record("Public certificates exported", "exports", "EXPORT", "INFO", str(destination),
                          {"files": [p.name for p in sources], "private_keys_included": False})
        return {"directory": str(destination), "files": [p.name for p in sources]}

    def export_device_bundle(self, name: str, password: str, legacy: bool = False) -> dict:
        ws = self.workspace
        name = validate_name(name)
        record = self.registry.get(name)
        if record is None or record["kind"] not in ("device", "client"):
            raise ValueError("No device certificate named %r" % name)
        if not record.get("key_path") or not shutil.os.path.isfile(record["key_path"]):
            raise ValueError("The private key for this certificate is not in the workspace")
        if len(password) < 8:
            raise ValueError("The bundle password must be at least 8 characters")
        key = load_key(record["key_path"])
        leaf = load_cert(record["cert_path"])
        intermediate = load_cert(ws.intermediate_cert)
        if legacy:
            encryption = (
                serialization.PrivateFormat.PKCS12.encryption_builder()
                .kdf_rounds(50000)
                .key_cert_algorithm(pkcs12.PBES.PBESv1SHA1And3KeyTripleDESCBC)
                .hmac_hash(hashes.SHA1())
                .build(password.encode())
            )
        else:
            encryption = serialization.BestAvailableEncryption(password.encode())
        blob = pkcs12.serialize_key_and_certificates(name.encode(), key, leaf, [intermediate], encryption)
        destination = ws.exports / ("device-%s-%s" % (name, self._stamp()))
        destination.mkdir(parents=True)
        bundle = destination / (name + ".p12")
        atomic_write(bundle, blob, 0o600)
        shutil.copyfile(ws.root_cert, destination / "root-cert.pem")
        self.audit.record("Device bundle exported", "exports", "EXPORT", "WARNING", name, {
            "serial": record["serial"], "format": "PKCS#12", "legacy_encryption": bool(legacy),
            "contains_private_key": True, "directory": str(destination)})
        return {"directory": str(destination), "bundle": str(bundle), "root": str(destination / "root-cert.pem")}

    def export_events_csv(self):
        path = self.workspace.exports / ("events-" + self._stamp() + ".csv")
        rows = self.audit.all_events()
        columns = ["id", "event_id", "timestamp", "session_id", "component", "category", "severity",
                   "action", "target", "details", "previous_hash", "integrity_hash"]
        with open(path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.writer(handle)
            writer.writerow(columns)
            for row in rows:
                writer.writerow([row[column] for column in columns])
        restrict(path, 0o600)
        self.audit.record("Audit events exported to CSV", "exports", "EXPORT", "INFO", str(path), {"records": len(rows)})
        return path

    def report(self, name: str, data: dict):
        path = self.workspace.reports / (safe_name(name, "crystalline-pki") + "-" + self._stamp() + ".json")
        atomic_write(path, json_bytes(data), 0o600)
        self.audit.record("Report generated", "exports", "REPORT", "INFO", str(path))
        return path
