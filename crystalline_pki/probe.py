from __future__ import annotations

import http.client
import ipaddress
import socket
import ssl
import time
from urllib.parse import quote, urlsplit

from cryptography import x509

from .certinspect import describe_certificate
from .httpanalysis import analyse_headers
from .util import new_id, now_iso

MAX_HTTP_HEADERS = 128
DROPPED_HEADERS = ("authorization", "proxy-authenticate", "www-authenticate")
TLS_VERSIONS = (("TLSv1.3", ssl.TLSVersion.TLSv1_3), ("TLSv1.2", ssl.TLSVersion.TLSv1_2))


def validate_url(url: str):
    url = url.strip()
    if not url or any(ord(ch) <= 32 or ord(ch) == 127 for ch in url):
        raise ValueError("The URL is empty or contains whitespace or control characters")
    parsed = urlsplit(url)
    if parsed.scheme.lower() != "https":
        raise ValueError("Only HTTPS URLs are accepted")
    if not parsed.hostname:
        raise ValueError("A hostname is required")
    if parsed.username or parsed.password:
        raise ValueError("URLs containing embedded credentials are rejected")
    try:
        port = parsed.port
    except ValueError:
        raise ValueError("The URL has an invalid port")
    if port not in (None, 443):
        raise ValueError("Only standard HTTPS port 443 is supported")
    host = parsed.hostname.rstrip(".")
    try:
        ipaddress.ip_address(host)
    except ValueError:
        pass
    else:
        raise ValueError("Use a DNS hostname, not a direct IP address")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise ValueError("Invalid internationalized hostname")
    if not host or len(host) > 253:
        raise ValueError("Invalid hostname")
    return parsed, host


def resolve_public(host: str, audit=None) -> list:
    try:
        answers = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except socket.gaierror as error:
        raise ValueError("DNS resolution failed: %s" % error)
    addresses, rejected = [], []
    for answer in answers:
        address = answer[4][0]
        try:
            parsed = ipaddress.ip_address(address)
        except ValueError:
            continue
        if parsed.is_global:
            if address not in addresses:
                addresses.append(address)
        else:
            rejected.append(address)
    if rejected and audit:
        audit.record("Non-public DNS answers rejected", "probe", "EXTERNAL_TLS", "WARNING", host,
                     {"addresses": rejected})
    if not addresses or rejected:
        raise ValueError("DNS returned no exclusively public address set; request blocked")
    return addresses


class ProbeVerificationError(ValueError):
    def __init__(self, message, diagnosis):
        super().__init__(message)
        self.diagnosis = diagnosis


def _explain_verification_failure(code, message, used_custom_bundle):
    text = str(message or "")
    if "local issuer" in text or code in (20, 21):
        cause = ("The chain could not be completed to a root this computer trusts. Either the server did not send its "
                 "intermediate certificate, or the root is missing from the trust store in use.")
        if not used_custom_bundle:
            cause += (" On Windows, Python only sees roots that are already installed, and Windows installs some "
                      "lazily. Retry with a trust bundle (--cafile or the ca_bundle setting) to tell these apart.")
        return cause
    if "expired" in text:
        return "The served certificate (or one in its chain) is past its end date."
    if "hostname" in text or "match" in text:
        return "The certificate does not list this hostname in its subject alternative names."
    if "self-signed" in text or "self signed" in text:
        return "The server presented a self-signed certificate that no trust store vouches for."
    return "Verification failed for the reason shown in the technical detail."


def _milliseconds(start: float, end: float) -> float:
    return round((end - start) * 1000, 2)


def _presented_chain(tls):
    sslobj = getattr(tls, "_sslobj", None)
    for attribute, source in (("get_verified_chain", "verified"), ("get_unverified_chain", "unverified")):
        getter = getattr(sslobj, attribute, None)
        if getter is None:
            continue
        try:
            raw = getter()
            if not raw:
                continue
            certificates = [x509.load_pem_x509_certificate(c.public_bytes(ssl._ssl.ENCODING_PEM).encode()) for c in raw]
            return certificates, source
        except Exception:
            continue
    return [x509.load_der_x509_certificate(tls.getpeercert(binary_form=True))], "leaf-only"


def _served_count(tls):
    sslobj = getattr(tls, "_sslobj", None)
    getter = getattr(sslobj, "get_unverified_chain", None)
    if getter is None:
        return None
    try:
        return len(getter() or [])
    except Exception:
        return None


def _cipher_assessment(version, cipher_name):
    return {
        "forward_secrecy": version == "TLSv1.3" or "ECDHE" in cipher_name or "DHE" in cipher_name,
        "authenticated_encryption": any(tag in cipher_name for tag in ("GCM", "CHACHA20", "CCM")),
    }


class ExternalProbe:
    def __init__(self, config, audit):
        self.config = config
        self.audit = audit

    def _context(self, bundle, minimum=ssl.TLSVersion.TLSv1_2, maximum=None, alpn=("http/1.1",)):
        context = ssl.create_default_context(cafile=bundle) if bundle else ssl.create_default_context()
        context.minimum_version = minimum
        if maximum is not None:
            context.maximum_version = maximum
        context.check_hostname = True
        context.verify_mode = ssl.CERT_REQUIRED
        if alpn:
            context.set_alpn_protocols(list(alpn))
        return context

    def _unverified_peek(self, address, host, timeout, port):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((address, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    chain, source = _presented_chain(tls)
                    return {
                        "verified": False,
                        "note": "Handshake only, no HTTP request sent. Read for diagnosis; do not trust it.",
                        "tls_version": tls.version(),
                        "cipher": list(tls.cipher()),
                        "chain_source": source,
                        "chain": [describe_certificate(c) for c in chain],
                    }
        except (OSError, ssl.SSLError) as error:
            return {"verified": False, "error": str(error)}

    def _protocol_support(self, address, host, timeout, port, bundle):
        support = {}
        for label, version in TLS_VERSIONS:
            entry = {"supported": False}
            try:
                context = self._context(bundle, minimum=version, maximum=version)
                with socket.create_connection((address, port), timeout=timeout) as raw:
                    with context.wrap_socket(raw, server_hostname=host) as tls:
                        entry = {"supported": True, "cipher": tls.cipher()[0]}
            except (OSError, ssl.SSLError) as error:
                entry["error"] = getattr(error, "reason", None) or str(error)
            support[label] = entry
        preference = {"offered": ["h2", "http/1.1"]}
        try:
            context = self._context(bundle, alpn=("h2", "http/1.1"))
            with socket.create_connection((address, port), timeout=timeout) as raw:
                with context.wrap_socket(raw, server_hostname=host) as tls:
                    preference["negotiated"] = tls.selected_alpn_protocol()
        except (OSError, ssl.SSLError) as error:
            preference["error"] = str(error)
        return {"tls_versions": support, "alpn_preference": preference,
                "note": "Three extra handshakes that send no HTTP request."}

    def examine(self, url: str, authorized: bool = False, *, cafile=None, deep: bool = False,
                _port: int = 443, _resolver=None) -> dict:
        if not authorized:
            raise PermissionError("Explicit authorization is required: only test hosts you own or may test")
        parsed, host = validate_url(url)
        bundle = cafile or self.config.get("ca_bundle") or None
        try:
            timeout = int(self.config.get("external_timeout"))
            t_start = time.monotonic()
            addresses = (_resolver or (lambda h: resolve_public(h, self.audit)))(host)
            t_dns = time.monotonic()
            context = self._context(bundle)
            raw = socket.create_connection((addresses[0], _port), timeout=timeout)
            t_tcp = time.monotonic()
            try:
                tls = context.wrap_socket(raw, server_hostname=host)
            except ssl.SSLCertVerificationError as error:
                raw.close()
                diagnosis = {
                    "verify_code": error.verify_code,
                    "verify_message": error.verify_message,
                    "trust_store": bundle or "system default",
                    "likely_cause": _explain_verification_failure(error.verify_code, error.verify_message, bool(bundle)),
                    "served_certificate": self._unverified_peek(addresses[0], host, timeout, _port),
                }
                raise ProbeVerificationError(
                    "Certificate verification failed (%s). %s" % (error.verify_message, diagnosis["likely_cause"]), diagnosis)
            except Exception:
                raw.close()
                raise
            t_tls = time.monotonic()
            try:
                tls.settimeout(timeout)
                version = tls.version()
                cipher = tls.cipher()
                chain, chain_source = _presented_chain(tls)
                served_count = _served_count(tls)
                local, remote = tls.getsockname(), tls.getpeername()
                path = quote(parsed.path or "/", safe="/%:@!$&'()*+,;=-._~")
                request_text = ("HEAD %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n"
                                % (path, host, self.config.get("external_user_agent")))
                t_send = time.monotonic()
                tls.sendall(request_text.encode("ascii"))
                response = http.client.HTTPResponse(tls, method="HEAD")
                response.begin()
                t_first = time.monotonic()
                all_headers = [(k, v) for k, v in response.getheaders()[:MAX_HTTP_HEADERS]]
                status, reason = response.status, response.reason
                http_version = {10: "HTTP/1.0", 11: "HTTP/1.1"}.get(response.version, str(response.version))
                tls_session = {
                    "version": version,
                    "cipher_name": cipher[0],
                    "cipher_protocol": cipher[1],
                    "cipher_secret_bits": cipher[2],
                    "assessment": _cipher_assessment(version, cipher[0]),
                    "alpn_negotiated": tls.selected_alpn_protocol(),
                    "compression": tls.compression(),
                    "session_reused": tls.session_reused,
                    "client_minimum_version": context.minimum_version.name,
                    "client_maximum_version": context.maximum_version.name,
                    "verify_mode": "CERT_REQUIRED",
                    "hostname_checked": context.check_hostname,
                    "sni": host,
                    "offered_ciphers": [c["name"] for c in context.get_ciphers()],
                    "openssl": ssl.OPENSSL_VERSION,
                }
            finally:
                tls.close()
            t_end = time.monotonic()
            safe_headers = []
            for key, value in all_headers:
                lowered = key.lower()
                if lowered in DROPPED_HEADERS:
                    continue
                if lowered == "location":
                    value = urlsplit(value)._replace(query="", fragment="").geturl()
                safe_headers.append([key, value[:500]])
            described_chain = []
            for index, certificate in enumerate(chain):
                item = describe_certificate(certificate)
                item["position"] = "leaf" if index == 0 else ("root" if item["self_signed"] else "intermediate")
                described_chain.append(item)
            leaf = described_chain[0]
            deep_result = self._protocol_support(addresses[0], host, timeout, _port, bundle) if deep else None
            result = {
                "host": host,
                "url": "https://" + host + (parsed.path or "/"),
                "addresses": addresses,
                "resolved_ip": addresses[0],
                "port": 443,
                "connection": {
                    "local_endpoint": "%s:%s" % (local[0], local[1]),
                    "remote_endpoint": "%s:%s" % (remote[0], remote[1]),
                    "ip_version": "IPv6" if ":" in remote[0] else "IPv4",
                    "address_count": len(addresses),
                },
                "timing_ms": {
                    "dns": _milliseconds(t_start, t_dns),
                    "tcp_connect": _milliseconds(t_dns, t_tcp),
                    "tls_handshake": _milliseconds(t_tcp, t_tls),
                    "time_to_first_byte": _milliseconds(t_send, t_first),
                    "total": _milliseconds(t_start, t_end),
                },
                "method": "HEAD",
                "tls_version": version,
                "cipher": list(cipher),
                "tls": tls_session,
                "trust_store": bundle or "system default",
                "chain_source": chain_source,
                "served_count": served_count,
                "chain": described_chain,
                "certificate": leaf,
                "certificate_sha256": leaf["sha256_fingerprint"],
                "request": {
                    "sent": request_text,
                    "method": "HEAD",
                    "path": path,
                    "headers_sent": [["Host", host], ["User-Agent", self.config.get("external_user_agent")],
                                     ["Accept", "*/*"], ["Connection", "close"]],
                },
                "response": {
                    "http_version": http_version,
                    "status": status,
                    "reason": reason,
                    "status_line": "%s %s %s" % (http_version, status, reason),
                    "headers": safe_headers,
                    "header_count": len(safe_headers),
                    "analysis": analyse_headers(safe_headers),
                },
                "http_status": status,
                "http_reason": reason,
                "headers": {k: v for k, v in safe_headers},
                "protocol_support": deep_result,
                "duration_seconds": round(t_end - t_start, 4),
                "timestamp": now_iso(),
                "note": "One authorized HEAD request; the query string and fragment were not transmitted. Cookie values are redacted.",
            }
        except Exception as error:
            self.audit.record("External HTTPS diagnostic failed", "probe", "EXTERNAL_TLS", "ERROR", host,
                              {"error": str(error), "diagnosis": getattr(error, "diagnosis", None)})
            raise
        event = self.audit.record("External HTTPS diagnostic completed", "probe", "EXTERNAL_TLS", "INFO", host, {
            "tls_version": version, "cipher": cipher[0], "http_status": status,
            "certificate_sha256": result["certificate_sha256"], "days_remaining": leaf["days_remaining"],
            "chain_length": len(described_chain), "deep": bool(deep)})
        self.audit.add_test({
            "test_id": new_id(), "timestamp": result["timestamp"],
            "target": result["url"], "hostname": host, "port": 443,
            "result": str(status), "duration": result["duration_seconds"], "component": "probe",
            "details": result, "event_hash": event["integrity_hash"],
        })
        return result
