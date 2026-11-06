from __future__ import annotations

import ipaddress
import re
import shutil
import uuid
from datetime import datetime, timedelta
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID, ObjectIdentifier

from . import APP_NAME, __version__
from .platform_info import IS_WINDOWS, loose_key_files
from .util import atomic_write, json_bytes, new_id, now_dt, now_iso, sha256_hex

CUSTOM_OID = ObjectIdentifier("2.25." + str(uuid.UUID("3b1f6d0a-7c52-4d8e-9a41-5e2f0c8b7a19").int))
NAME_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
SERVER_NAME = "localhost"
CLIENT_NAME = "local-client"
MAX_CSR_BYTES = 65536
ALLOWED_CURVES = ("secp256r1", "secp384r1", "secp521r1")

REASONS = {
    "unspecified": x509.ReasonFlags.unspecified,
    "key_compromise": x509.ReasonFlags.key_compromise,
    "superseded": x509.ReasonFlags.superseded,
    "cessation_of_operation": x509.ReasonFlags.cessation_of_operation,
    "affiliation_changed": x509.ReasonFlags.affiliation_changed,
}


def validate_name(name: str) -> str:
    name = str(name).strip()
    if not NAME_PATTERN.match(name):
        raise ValueError("Names use letters, digits, dot, dash and underscore, start with a letter or digit, and are at most 63 characters")
    return name


def fingerprint(cert: x509.Certificate) -> str:
    return sha256_hex(cert.public_bytes(serialization.Encoding.DER))


def serial_hex(cert: x509.Certificate) -> str:
    return format(cert.serial_number, "x")


def cert_pem(cert) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)


def key_pem(key) -> bytes:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def load_cert(path) -> x509.Certificate:
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def load_key(path):
    return serialization.load_pem_private_key(Path(path).read_bytes(), password=None)


def _rsa_key(bits):
    return rsa.generate_private_key(public_exponent=65537, key_size=int(bits))


def _subject(common_name: str, config) -> x509.Name:
    attributes = []
    if config.get("country"):
        attributes.append(x509.NameAttribute(NameOID.COUNTRY_NAME, config.get("country")))
    if config.get("province"):
        attributes.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, config.get("province")))
    attributes.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, config.get("organization")))
    attributes.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(attributes)


def _metadata(builder, profile: str):
    value = ('{"application":"%s","profile":"%s","version":"%s"}' % (APP_NAME, profile, __version__)).encode()
    return builder.add_extension(x509.UnrecognizedExtension(CUSTOM_OID, value), critical=False)


def _build_ca(subject, issuer, public_key, signing_key, days, path_length):
    current = now_dt()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(current - timedelta(minutes=5))
        .not_valid_after(current + timedelta(days=int(days)))
        .add_extension(x509.BasicConstraints(ca=True, path_length=path_length), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=False,
            data_encipherment=False, key_agreement=False, key_cert_sign=True,
            crl_sign=True, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(signing_key.public_key()), critical=False)
    )
    return _metadata(builder, "certificate-authority").sign(signing_key, hashes.SHA256())


def _build_leaf(subject, issuer_cert, issuer_key, public_key, days, eku, san, encipher):
    current = now_dt()
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer_cert.subject)
        .public_key(public_key)
        .serial_number(x509.random_serial_number())
        .not_valid_before(current - timedelta(minutes=5))
        .not_valid_after(current + timedelta(days=int(days)))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.KeyUsage(
            digital_signature=True, content_commitment=False, key_encipherment=bool(encipher),
            data_encipherment=False, key_agreement=False, key_cert_sign=False,
            crl_sign=False, encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.ExtendedKeyUsage([eku]), critical=False)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(public_key), critical=False)
        .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()), critical=False)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
    )
    return _metadata(builder, "end-entity").sign(issuer_key, hashes.SHA256())


def _check_public_key(public_key) -> None:
    if isinstance(public_key, rsa.RSAPublicKey):
        if public_key.key_size < 2048:
            raise ValueError("RSA keys must be at least 2048 bits")
        return
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        if public_key.curve.name not in ALLOWED_CURVES:
            raise ValueError("EC keys must use P-256, P-384 or P-521")
        return
    raise ValueError("Only RSA and EC public keys are accepted")


def _validity_window(cert):
    return cert.not_valid_before_utc, cert.not_valid_after_utc


class LocalPKI:
    def __init__(self, workspace, config, audit, registry):
        self.workspace = workspace
        self.config = config
        self.audit = audit
        self.registry = registry

    def ready(self) -> bool:
        return self.workspace.pki_ready()

    def _require_ready(self) -> None:
        if not self.ready():
            raise RuntimeError("Create the local PKI first")

    def generate(self, replace: bool = False) -> dict:
        ws, cfg = self.workspace, self.config
        if self.ready() and not replace:
            raise RuntimeError("A PKI already exists. Confirm replacement to rebuild it.")
        stage = ws.home / ("pki-stage-" + new_id())
        try:
            bits = cfg.get("rsa_bits")
            root_key, int_key, server_key, client_key = (_rsa_key(bits) for _ in range(4))
            root_name = _subject("Crystalline PKI Root CA", cfg)
            root = _build_ca(root_name, root_name, root_key.public_key(), root_key, cfg.get("root_days"), 1)
            intermediate = _build_ca(_subject("Crystalline PKI Intermediate CA", cfg), root.subject,
                                     int_key.public_key(), root_key, cfg.get("intermediate_days"), 0)
            server = _build_leaf(
                _subject(SERVER_NAME, cfg), intermediate, int_key, server_key.public_key(),
                cfg.get("certificate_days"), ExtendedKeyUsageOID.SERVER_AUTH,
                [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))], True)
            client = _build_leaf(
                _subject(CLIENT_NAME, cfg), intermediate, int_key, client_key.public_key(),
                cfg.get("certificate_days"), ExtendedKeyUsageOID.CLIENT_AUTH,
                [x509.UniformResourceIdentifier("urn:crystalline-pki:client:local")], False)
            files = {
                ws.root_key: (key_pem(root_key), 0o600),
                ws.root_cert: (cert_pem(root), 0o644),
                ws.intermediate_key: (key_pem(int_key), 0o600),
                ws.intermediate_cert: (cert_pem(intermediate), 0o644),
                ws.server_key: (key_pem(server_key), 0o600),
                ws.server_cert: (cert_pem(server), 0o644),
                ws.server_chain: (cert_pem(server) + cert_pem(intermediate), 0o644),
                ws.client_key: (key_pem(client_key), 0o600),
                ws.client_cert: (cert_pem(client), 0o644),
                ws.client_chain: (cert_pem(client) + cert_pem(intermediate), 0o644),
            }
            for final_path, (data, mode) in files.items():
                atomic_write(stage / final_path.relative_to(ws.pki), data, mode)
            manifest = {
                "created": now_iso(),
                "root_sha256": fingerprint(root),
                "intermediate_sha256": fingerprint(intermediate),
                "server_sha256": fingerprint(server),
                "client_sha256": fingerprint(client),
                "rsa_bits": int(bits),
                "private_key_storage": "unencrypted PEM; protect the workspace",
            }
            atomic_write(stage / "manifest.json", json_bytes(manifest), 0o600)
            backup = None
            if ws.pki.exists():
                if any(p.is_file() for p in ws.pki.rglob("*")):
                    ws.backups.mkdir(parents=True, exist_ok=True)
                    backup = ws.backups / ("pki-" + now_dt().strftime("%Y%m%d-%H%M%S") + "-" + new_id()[:8])
                    ws.pki.replace(backup)
                else:
                    shutil.rmtree(ws.pki)
            try:
                stage.replace(ws.pki)
            except Exception:
                if backup and backup.exists() and not ws.pki.exists():
                    backup.replace(ws.pki)
                raise
        except Exception:
            shutil.rmtree(stage, ignore_errors=True)
            raise
        self.registry.clear()
        self._register(server, SERVER_NAME, "server", ws.server_cert, ws.server_chain, ws.server_key)
        self._register(client, CLIENT_NAME, "client", ws.client_cert, ws.client_chain, ws.client_key)
        crl = self.refresh_crl()
        manifest["crl_number"] = crl["number"]
        manifest["previous_pki_backup"] = str(backup) if backup else None
        self.audit.record("Local PKI generated", "pki", "PKI", "INFO", details=manifest)
        return manifest

    def _register(self, cert, name, kind, cert_path, chain_path, key_path) -> None:
        self.registry.add({
            "serial": serial_hex(cert), "name": name, "kind": kind,
            "subject": cert.subject.rfc4514_string(),
            "not_before": cert.not_valid_before_utc.isoformat(),
            "not_after": cert.not_valid_after_utc.isoformat(),
            "fingerprint": fingerprint(cert),
            "cert_path": str(cert_path), "chain_path": str(chain_path), "key_path": str(key_path),
        })

    def _intermediate(self):
        return load_cert(self.workspace.intermediate_cert), load_key(self.workspace.intermediate_key)

    def create_device_request(self, name: str) -> dict:
        self._require_ready()
        name = validate_name(name)
        folder = self.workspace.devices / name
        folder.mkdir(parents=True, exist_ok=True)
        token = new_id()[:8]
        key = ec.generate_private_key(ec.SECP256R1())
        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)]))
            .add_extension(x509.SubjectAlternativeName(
                [x509.UniformResourceIdentifier("urn:crystalline-pki:device:" + name)]), critical=False)
            .sign(key, hashes.SHA256())
        )
        key_path = folder / ("key-" + token + ".pem")
        csr_path = folder / ("request-" + token + ".csr.pem")
        atomic_write(key_path, key_pem(key), 0o600)
        atomic_write(csr_path, csr.public_bytes(serialization.Encoding.PEM), 0o644)
        self.audit.record("Device key and certificate request created (device side)", "pki", "LIFECYCLE", "INFO",
                          name, {"key_type": "EC P-256", "csr": str(csr_path)})
        return {"name": name, "key_path": str(key_path), "csr_path": str(csr_path)}

    def issue_from_csr(self, csr_bytes: bytes, name=None, key_path=None, days=None) -> dict:
        self._require_ready()
        if len(csr_bytes) > MAX_CSR_BYTES:
            raise ValueError("Certificate request is too large")
        try:
            csr = x509.load_pem_x509_csr(csr_bytes)
        except ValueError:
            raise ValueError("Not a valid PEM certificate request")
        if not csr.is_signature_valid:
            raise ValueError("The certificate request signature is invalid")
        _check_public_key(csr.public_key())
        if name is None:
            names = csr.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
            if not names:
                raise ValueError("The request has no common name; pass a name")
            name = names[0].value
        name = validate_name(name)
        days = int(days or self.config.get("device_days"))
        if not 1 <= days < int(self.config.get("intermediate_days")):
            raise ValueError("Requested lifetime must be shorter than the intermediate CA's")
        intermediate, int_key = self._intermediate()
        cert = _build_leaf(
            _subject(name, self.config), intermediate, int_key, csr.public_key(), days,
            ExtendedKeyUsageOID.CLIENT_AUTH,
            [x509.UniformResourceIdentifier("urn:crystalline-pki:device:" + name)], False)
        folder = self.workspace.issued / name
        leaf_path = folder / (serial_hex(cert) + ".pem")
        chain_path = folder / (serial_hex(cert) + "-chain.pem")
        atomic_write(leaf_path, cert_pem(cert), 0o644)
        atomic_write(chain_path, cert_pem(cert) + cert_pem(intermediate), 0o644)
        self._register(cert, name, "device", leaf_path, chain_path, key_path or "")
        self.audit.record("Certificate issued (authority side)", "pki", "LIFECYCLE", "INFO", name, {
            "serial": serial_hex(cert), "days": days, "not_after": cert.not_valid_after_utc.isoformat(),
            "eku": "clientAuth"})
        return self.registry.get(serial_hex(cert))

    def enroll_device(self, name: str, days=None) -> dict:
        name = validate_name(name)
        if self.registry.active_for(name):
            raise ValueError("%s already has an active certificate; rotate it instead" % name)
        request = self.create_device_request(name)
        csr_bytes = Path(request["csr_path"]).read_bytes()
        return self.issue_from_csr(csr_bytes, name=name, key_path=request["key_path"], days=days)

    def revoke(self, identifier: str, reason: str = "unspecified") -> dict:
        self._require_ready()
        if reason not in REASONS:
            raise ValueError("Reason must be one of: " + ", ".join(REASONS))
        record = self.registry.get(identifier)
        if record is None:
            raise ValueError("No certificate matches %r" % identifier)
        if record["state"] == "revoked":
            raise ValueError("That certificate is already revoked")
        self.registry.mark_revoked(record["serial"], reason)
        crl = self.refresh_crl()
        self.audit.record("Certificate revoked", "pki", "LIFECYCLE", "WARNING", record["name"], {
            "serial": record["serial"], "reason": reason, "crl_number": crl["number"]})
        return self.registry.get(record["serial"])

    def rotate_device(self, name: str, destroy_old_key: bool = False) -> dict:
        self._require_ready()
        old = self.registry.get(validate_name(name))
        if old is None or old["kind"] != "device":
            raise ValueError("No enrolled device named %r" % name)
        if old["state"] == "revoked":
            raise ValueError("That certificate is revoked; enroll a new device name instead")
        request = self.create_device_request(old["name"])
        new = self.issue_from_csr(Path(request["csr_path"]).read_bytes(), name=old["name"],
                                  key_path=request["key_path"])
        if old["state"] == "active":
            self.revoke(old["serial"], "superseded")
        if destroy_old_key and old.get("key_path"):
            Path(old["key_path"]).unlink(missing_ok=True)
        self.audit.record("Device certificate rotated", "pki", "LIFECYCLE", "INFO", old["name"], {
            "old_serial": old["serial"], "new_serial": new["serial"], "old_key_destroyed": bool(destroy_old_key)})
        return {"old": self.registry.get(old["serial"]), "new": new}

    def renew_service(self, kind: str) -> dict:
        self._require_ready()
        if kind not in ("server", "client"):
            raise ValueError("kind must be server or client")
        ws, cfg = self.workspace, self.config
        intermediate, int_key = self._intermediate()
        key = _rsa_key(cfg.get("rsa_bits"))
        if kind == "server":
            name, eku, encipher = SERVER_NAME, ExtendedKeyUsageOID.SERVER_AUTH, True
            san = [x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))]
            cert_path, key_path, chain_path = ws.server_cert, ws.server_key, ws.server_chain
        else:
            name, eku, encipher = CLIENT_NAME, ExtendedKeyUsageOID.CLIENT_AUTH, False
            san = [x509.UniformResourceIdentifier("urn:crystalline-pki:client:local")]
            cert_path, key_path, chain_path = ws.client_cert, ws.client_key, ws.client_chain
        cert = _build_leaf(_subject(name, cfg), intermediate, int_key, key.public_key(),
                           cfg.get("certificate_days"), eku, san, encipher)
        previous = self.registry.active_for(name)
        atomic_write(key_path, key_pem(key), 0o600)
        atomic_write(cert_path, cert_pem(cert), 0o644)
        atomic_write(chain_path, cert_pem(cert) + cert_pem(intermediate), 0o644)
        self._register(cert, name, kind, cert_path, chain_path, key_path)
        for old in previous:
            self.registry.mark_revoked(old["serial"], "superseded")
        self.refresh_crl()
        self.audit.record("Built-in %s certificate renewed" % kind, "pki", "LIFECYCLE", "INFO", name, {
            "new_serial": serial_hex(cert), "superseded": [o["serial"] for o in previous],
            "not_after": cert.not_valid_after_utc.isoformat()})
        return self.registry.get(serial_hex(cert))

    def expiring(self, within_days: int = 30) -> list:
        return [r for r in self.registry.list() if r["state"] == "active" and r["days_left"] <= within_days]

    def refresh_crl(self) -> dict:
        ws = self.workspace
        intermediate, int_key = self._intermediate()
        current = now_dt()
        number = self.registry.next_crl_number()
        builder = (
            x509.CertificateRevocationListBuilder()
            .issuer_name(intermediate.subject)
            .last_update(current - timedelta(minutes=5))
            .next_update(current + timedelta(days=int(self.config.get("crl_days"))))
            .add_extension(x509.CRLNumber(number), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(int_key.public_key()), critical=False)
        )
        revoked = self.registry.revoked()
        for record in revoked:
            entry = (
                x509.RevokedCertificateBuilder()
                .serial_number(int(record["serial"], 16))
                .revocation_date(datetime.fromisoformat(record["revoked_at"]))
                .add_extension(x509.CRLReason(REASONS[record["reason"]]), critical=False)
                .build()
            )
            builder = builder.add_revoked_certificate(entry)
        crl = builder.sign(int_key, hashes.SHA256())
        atomic_write(ws.crl_pem, crl.public_bytes(serialization.Encoding.PEM), 0o644)
        atomic_write(ws.crl_der, crl.public_bytes(serialization.Encoding.DER), 0o644)
        atomic_write(ws.trust_bundle, cert_pem(load_cert(ws.root_cert)) + crl.public_bytes(serialization.Encoding.PEM), 0o644)
        self.audit.record("Revocation list published", "pki", "LIFECYCLE", "INFO", details={
            "crl_number": number, "revoked_count": len(revoked), "next_update": crl.next_update_utc.isoformat()})
        return {"number": number, "revoked_count": len(revoked), "next_update": crl.next_update_utc.isoformat()}

    def crl_status(self) -> dict:
        ws = self.workspace
        if not ws.crl_pem.is_file():
            return {"exists": False}
        crl = x509.load_pem_x509_crl(ws.crl_pem.read_bytes())
        intermediate = load_cert(ws.intermediate_cert)
        remaining = crl.next_update_utc - now_dt()
        return {
            "exists": True,
            "number": crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number,
            "this_update": crl.last_update_utc.isoformat(),
            "next_update": crl.next_update_utc.isoformat(),
            "hours_left": round(remaining.total_seconds() / 3600, 1),
            "revoked_count": len(list(crl)),
            "signature_valid": crl.is_signature_valid(intermediate.public_key()),
        }

    def ensure_fresh_crl(self, min_hours: float = 24.0) -> dict:
        status = self.crl_status()
        if not status["exists"] or status["hours_left"] < min_hours:
            self.refresh_crl()
            status = self.crl_status()
        return status

    def verify_chain(self) -> dict:
        self._require_ready()
        ws = self.workspace
        root, intermediate = load_cert(ws.root_cert), load_cert(ws.intermediate_cert)
        server, client = load_cert(ws.server_cert), load_cert(ws.client_cert)
        checks = []

        def run(label, function):
            try:
                function()
                checks.append({"check": label, "result": "PASS"})
            except Exception as error:
                checks.append({"check": label, "result": "FAIL", "error": str(error) or type(error).__name__})

        def validity(cert):
            before, after = _validity_window(cert)
            if not before <= now_dt() <= after:
                raise ValueError("Certificate is outside its validity period")

        def constraints(cert, expected):
            value = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
            if not value.ca or value.path_length != expected:
                raise ValueError("CA constraints are incorrect")

        def link(cert, issuer):
            cert.verify_directly_issued_by(issuer)

        def eku(cert, expected):
            if expected not in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value:
                raise ValueError("Required extended key usage is missing")

        def names():
            san = server.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
            if "localhost" not in san.get_values_for_type(x509.DNSName):
                raise ValueError("localhost is not in the server certificate")
            if ipaddress.ip_address("127.0.0.1") not in san.get_values_for_type(x509.IPAddress):
                raise ValueError("127.0.0.1 is not in the server certificate")

        def pair(cert_path, key_path):
            cert, key = load_cert(cert_path), load_key(key_path)
            fmt = serialization.PublicFormat.SubjectPublicKeyInfo
            if cert.public_key().public_bytes(serialization.Encoding.DER, fmt) != \
                    key.public_key().public_bytes(serialization.Encoding.DER, fmt):
                raise ValueError("Private key does not match certificate")

        def crl_signature():
            status = self.crl_status()
            if not status["exists"]:
                raise ValueError("No revocation list has been published")
            if not status["signature_valid"]:
                raise ValueError("Revocation list signature does not verify")

        def crl_fresh():
            status = self.crl_status()
            if not status["exists"] or status["hours_left"] <= 0:
                raise ValueError("Revocation list is missing or expired")

        def permissions():
            loose = loose_key_files(ws)
            if loose:
                raise ValueError("Keys readable by others: " + ", ".join(loose))

        run("Root self-signature", lambda: link(root, root))
        run("Root validity", lambda: validity(root))
        run("Root CA constraints", lambda: constraints(root, 1))
        run("Intermediate validity", lambda: validity(intermediate))
        run("Intermediate issuer/signature", lambda: link(intermediate, root))
        run("Intermediate CA constraints", lambda: constraints(intermediate, 0))
        run("Server validity", lambda: validity(server))
        run("Server issuer/signature", lambda: link(server, intermediate))
        run("Server EKU", lambda: eku(server, ExtendedKeyUsageOID.SERVER_AUTH))
        run("Server name coverage", names)
        run("Client validity", lambda: validity(client))
        run("Client issuer/signature", lambda: link(client, intermediate))
        run("Client EKU", lambda: eku(client, ExtendedKeyUsageOID.CLIENT_AUTH))
        run("Root certificate/key match", lambda: pair(ws.root_cert, ws.root_key))
        run("Intermediate certificate/key match", lambda: pair(ws.intermediate_cert, ws.intermediate_key))
        run("Server certificate/key match", lambda: pair(ws.server_cert, ws.server_key))
        run("Client certificate/key match", lambda: pair(ws.client_cert, ws.client_key))
        run("Revocation list signature", crl_signature)
        run("Revocation list freshness", crl_fresh)
        if not IS_WINDOWS:
            run("Private key file permissions", permissions)
        result = {
            "timestamp": now_iso(),
            "passed": sum(item["result"] == "PASS" for item in checks),
            "failed": sum(item["result"] == "FAIL" for item in checks),
            "checks": checks,
        }
        self.audit.record("Certificate chain verification completed", "pki", "PKI",
                          "INFO" if result["failed"] == 0 else "WARNING", details=result)
        return result
