from __future__ import annotations

from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import AuthorityInformationAccessOID

from .pki import fingerprint, serial_hex
from .util import now_dt, sha256_hex

MAX_CERT_FILE_BYTES = 1024 * 1024


def _extension(cert, extension_class):
    try:
        return cert.extensions.get_extension_for_class(extension_class).value
    except x509.ExtensionNotFound:
        return None


def _key_usage_names(cert) -> list:
    usage = _extension(cert, x509.KeyUsage)
    if usage is None:
        return []
    names = []
    for flag in ("digital_signature", "content_commitment", "key_encipherment", "data_encipherment",
                 "key_agreement", "key_cert_sign", "crl_sign"):
        if getattr(usage, flag):
            names.append(flag)
    if usage.key_agreement:
        for flag in ("encipher_only", "decipher_only"):
            if getattr(usage, flag):
                names.append(flag)
    return names


def _extra_details(cert) -> dict:
    access = _extension(cert, x509.AuthorityInformationAccess)
    ocsp, issuers = [], []
    for description in access or []:
        value = getattr(description.access_location, "value", str(description.access_location))
        if description.access_method == AuthorityInformationAccessOID.OCSP:
            ocsp.append(value)
        elif description.access_method == AuthorityInformationAccessOID.CA_ISSUERS:
            issuers.append(value)
    crl_points = []
    for point in _extension(cert, x509.CRLDistributionPoints) or []:
        for name in point.full_name or []:
            crl_points.append(getattr(name, "value", str(name)))
    scts = []
    for sct in _extension(cert, x509.PrecertificateSignedCertificateTimestamps) or []:
        scts.append({"log_id": sct.log_id.hex(), "timestamp": sct.timestamp.isoformat(), "version": sct.version.name})
    policies = [p.policy_identifier.dotted_string for p in (_extension(cert, x509.CertificatePolicies) or [])]
    ski = _extension(cert, x509.SubjectKeyIdentifier)
    aki = _extension(cert, x509.AuthorityKeyIdentifier)
    public_key = cert.public_key()
    spki = public_key.public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    oid = cert.signature_algorithm_oid
    return {
        "version": cert.version.name,
        "signature_algorithm": getattr(oid, "_name", oid.dotted_string),
        "signature_algorithm_oid": oid.dotted_string,
        "key_usage": _key_usage_names(cert),
        "certificate_policies": policies,
        "ocsp_urls": ocsp,
        "ca_issuer_urls": issuers,
        "crl_distribution_points": crl_points,
        "signed_certificate_timestamps": scts,
        "subject_key_id": ski.digest.hex() if ski else None,
        "authority_key_id": aki.key_identifier.hex() if aki and aki.key_identifier else None,
        "spki_sha256": sha256_hex(spki),
        "public_key_exponent": public_key.public_numbers().e if isinstance(public_key, rsa.RSAPublicKey) else None,
        "validity_days": (cert.not_valid_after_utc - cert.not_valid_before_utc).days,
        "extension_oids": [ext.oid.dotted_string for ext in cert.extensions],
        "critical_extension_oids": [ext.oid.dotted_string for ext in cert.extensions if ext.critical],
    }


NAME_LABELS = (
    (x509.DNSName, "DNS"),
    (x509.IPAddress, "IP"),
    (x509.UniformResourceIdentifier, "URI"),
    (x509.RFC822Name, "email"),
)


def _format_name(name) -> str:
    for kind, label in NAME_LABELS:
        if isinstance(name, kind):
            return "%s:%s" % (label, name.value)
    return str(name)


def describe_certificate(cert: x509.Certificate) -> dict:
    public_key = cert.public_key()
    if isinstance(public_key, rsa.RSAPublicKey):
        key_type, key_detail = "RSA", str(public_key.key_size)
    elif isinstance(public_key, ec.EllipticCurvePublicKey):
        key_type, key_detail = "EC", public_key.curve.name
    else:
        key_type, key_detail = type(public_key).__name__, ""
    try:
        san = [_format_name(value) for value in cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
    except x509.ExtensionNotFound:
        san = []
    try:
        eku = [oid.dotted_string for oid in cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value]
    except x509.ExtensionNotFound:
        eku = []
    try:
        constraints = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        is_ca, path_length = constraints.ca, constraints.path_length
    except x509.ExtensionNotFound:
        is_ca, path_length = None, None
    not_after = cert.not_valid_after_utc
    seconds_left = (not_after - now_dt()).total_seconds()
    details = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "self_signed": cert.subject == cert.issuer,
        "serial_number": str(cert.serial_number),
        "serial_positive": cert.serial_number > 0,
        "serial_hex": serial_hex(cert),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": not_after.isoformat(),
        "days_remaining": int(seconds_left // 86400),
        "expired": seconds_left <= 0,
        "signature_hash": cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else None,
        "public_key_type": key_type,
        "public_key_detail": key_detail,
        "is_ca": is_ca,
        "path_length": path_length,
        "subject_alternative_names": san,
        "extended_key_usage": eku,
        "sha256_fingerprint": fingerprint(cert),
    }
    details.update(_extra_details(cert))
    return details


class CertificateInspector:
    def __init__(self, audit):
        self.audit = audit

    def inspect(self, path, label=None) -> list:
        path = Path(path).expanduser()
        if not path.is_file():
            raise FileNotFoundError("No such file: %s" % path)
        if path.stat().st_size > MAX_CERT_FILE_BYTES:
            raise ValueError("File is larger than 1 MiB; refusing to parse it")
        data = path.read_bytes()
        try:
            if b"-----BEGIN CERTIFICATE-----" in data:
                certificates = x509.load_pem_x509_certificates(data)
            else:
                certificates = [x509.load_der_x509_certificate(data)]
        except ValueError:
            raise ValueError("No certificate could be read from %s" % path.name)
        results = []
        for index, cert in enumerate(certificates, 1):
            details = describe_certificate(cert)
            details["file"] = str(path)
            details["certificate_index"] = index
            results.append(details)
            self.audit.add_certificate(label or path.name, details)
        self.audit.record("Certificate inspected", "inspector", "CERTIFICATE", "INFO", str(path),
                          {"count": len(results)})
        return results
