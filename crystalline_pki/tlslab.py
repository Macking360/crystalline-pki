from __future__ import annotations

import http.client
import json
import os
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from cryptography import x509

from .pki import fingerprint
from .util import new_id, now_iso, sha256_hex

LOOPBACK = "127.0.0.1"
HANDSHAKE_TIMEOUT = 10
MAX_BODY = 8192


class _TLSServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = os.name != "nt"
    tls_context = None
    on_reject = None

    def process_request_thread(self, request, client_address):
        try:
            request.settimeout(HANDSHAKE_TIMEOUT)
            secured = self.tls_context.wrap_socket(request, server_side=True)
        except (ssl.SSLError, OSError) as error:
            if self.on_reject:
                self.on_reject(client_address, error)
            self.shutdown_request(request)
            return
        super().process_request_thread(secured, client_address)


def _handler_for(audit):
    class Handler(BaseHTTPRequestHandler):
        server_version = "crystalline-pki"

        def do_GET(self):
            if self.path != "/":
                self.send_error(404)
                return
            raw = self.connection.getpeercert(binary_form=True)
            subject = digest = None
            if raw:
                peer = x509.load_der_x509_certificate(raw)
                subject, digest = peer.subject.rfc4514_string(), fingerprint(peer)
            payload = json.dumps({
                "status": "mutual TLS endpoint operational",
                "client_subject": subject,
                "client_sha256": digest,
                "tls_version": self.connection.version(),
                "cipher": self.connection.cipher()[0],
                "timestamp": now_iso(),
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(payload)
            audit.record("Local mTLS request served", "mtls-server", "LOCAL_TLS", "INFO", subject or "",
                         {"client_sha256": digest, "tls_version": self.connection.version()})

        def log_message(self, format_string, *args):
            return

    return Handler


class MutualTLSServer:
    def __init__(self, workspace, config, audit, pki):
        self.workspace = workspace
        self.config = config
        self.audit = audit
        self.pki = pki
        self._server = None
        self._thread = None
        self._lock = threading.RLock()

    @property
    def running(self) -> bool:
        return self._server is not None

    @property
    def port(self):
        return self._server.server_address[1] if self._server else None

    def context(self) -> ssl.SSLContext:
        ws = self.workspace
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(ws.server_chain), str(ws.server_key))
        context.load_verify_locations(cafile=str(ws.trust_bundle))
        context.verify_mode = ssl.CERT_REQUIRED
        context.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_CRL_CHECK_LEAF
        return context

    def _rejected(self, address, error):
        self.audit.record("mTLS handshake rejected", "mtls-server", "LOCAL_TLS", "WARNING", address[0],
                          {"reason": getattr(error, "reason", None) or str(error)})

    def start(self, port=None) -> dict:
        with self._lock:
            if self._server:
                return {"status": "already running", "port": self.port}
            if not self.workspace.pki_ready():
                raise RuntimeError("Create the local PKI before starting the server")
            self.pki.ensure_fresh_crl()
            server = _TLSServer((LOOPBACK, int(self.config.get("local_port") if port is None else port)),
                                _handler_for(self.audit))
            server.tls_context = self.context()
            server.on_reject = self._rejected
            self._server = server
            self._thread = threading.Thread(target=server.serve_forever, daemon=True)
            self._thread.start()
            self.audit.record("Local mTLS server started", "mtls-server", "LOCAL_TLS", "INFO", LOOPBACK,
                              {"port": self.port, "client_certificates": "required", "revocation_check": "leaf"})
            return {"status": "running", "host": LOOPBACK, "port": self.port}

    def reload(self) -> dict:
        with self._lock:
            if not self._server:
                return {"status": "not running"}
            self._server.tls_context = self.context()
            self.audit.record("mTLS trust material reloaded", "mtls-server", "LOCAL_TLS", "INFO", LOOPBACK)
            return {"status": "reloaded", "port": self.port}

    def stop(self) -> dict:
        with self._lock:
            if not self._server:
                return {"status": "not running"}
            server, thread = self._server, self._thread
            self._server = self._thread = None
        server.shutdown()
        server.server_close()
        if thread:
            thread.join(timeout=4)
        self.audit.record("Local mTLS server stopped", "mtls-server", "LOCAL_TLS", "INFO", LOOPBACK)
        return {"status": "stopped"}


class TLSLab:
    def __init__(self, workspace, config, audit, registry, pki, server):
        self.workspace = workspace
        self.config = config
        self.audit = audit
        self.registry = registry
        self.pki = pki
        self.server = server

    def identities(self) -> list:
        found = []
        for record in self.registry.list():
            if record["kind"] not in ("client", "device"):
                continue
            usable = bool(record.get("key_path")) and Path(record["key_path"]).is_file() \
                and bool(record.get("chain_path")) and Path(record["chain_path"]).is_file()
            found.append({
                "label": "%s  [%s, %s]" % (record["name"], record["state"], record["serial"][:8]),
                "name": record["name"], "serial": record["serial"], "state": record["state"],
                "chain_path": record["chain_path"], "key_path": record["key_path"], "usable": usable,
            })
        return found

    def _client_context(self, identity):
        context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH, cafile=str(self.workspace.trust_bundle))
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_CRL_CHECK_LEAF
        if identity:
            context.load_cert_chain(identity["chain_path"], identity["key_path"])
        return context

    def attempt(self, port, identity=None, timeout=8) -> dict:
        started = time.monotonic()
        result = {"presented": identity["name"] if identity else None, "port": port}
        connection = http.client.HTTPSConnection(LOOPBACK, port, context=self._client_context(identity), timeout=timeout)
        try:
            connection.connect()
            result["tls_version"] = connection.sock.version()
            result["cipher"] = list(connection.sock.cipher())
            connection.request("GET", "/", headers={"User-Agent": "crystalline-pki-lab"})
            response = connection.getresponse()
            body = response.read(MAX_BODY).decode("utf-8", errors="replace")
            result["http_status"] = response.status
            result["outcome"] = "accepted" if response.status == 200 else "rejected"
            result["response"] = body
        except (ssl.SSLError, OSError, http.client.HTTPException) as error:
            result["outcome"] = "rejected"
            result["error"] = getattr(error, "reason", None) or str(error)
        finally:
            connection.close()
        result["seconds"] = round(time.monotonic() - started, 4)
        self.audit.record("mTLS client attempt: " + result["outcome"], "mtls-lab", "LOCAL_TLS",
                          "INFO" if result["outcome"] == "accepted" else "WARNING",
                          result["presented"] or "no certificate",
                          {k: v for k, v in result.items() if k != "response"})
        return result

    def run_scenarios(self, progress=None) -> dict:
        started_here = False
        if not self.server.running:
            self.server.start(port=0)
            started_here = True
        port = self.server.port
        steps = []

        def note(title, expect, outcome, detail=None):
            passed = outcome["outcome"] == expect
            step = {"step": title, "expected": expect, "outcome": outcome["outcome"], "passed": passed,
                    "tls_version": outcome.get("tls_version"), "cipher": (outcome.get("cipher") or [None])[0],
                    "detail": outcome.get("error") or detail or ""}
            steps.append(step)
            if progress:
                progress(step)

        def identity_of(name):
            matches = [i for i in self.identities() if i["name"] == name]
            active = [i for i in matches if i["state"] == "active"]
            return (active or matches)[0]

        try:
            self.pki.ensure_fresh_crl()
            self.server.reload()
            builtin = next(i for i in self.identities() if i["name"] == "local-client" and i["state"] == "active")
            note("Built-in client certificate", "accepted", self.attempt(port, builtin),
                 "Signed by the lab intermediate CA and not revoked")
            note("No client certificate", "rejected", self.attempt(port, None),
                 "The server requires a client certificate")
            tag = new_id()[:6]
            phone = "demo-phone-" + tag
            self.pki.enroll_device(phone)
            note("Newly enrolled device " + phone, "accepted", self.attempt(port, identity_of(phone)),
                 "Key made on the device, certificate issued from its request")
            self.pki.revoke(phone, "key_compromise")
            self.server.reload()
            note("Same device after revocation", "rejected", self.attempt(port, identity_of(phone)),
                 "The revocation list now names this certificate")
            laptop = "demo-laptop-" + tag
            self.pki.enroll_device(laptop)
            before = identity_of(laptop)
            self.pki.rotate_device(laptop)
            self.server.reload()
            note("Old %s certificate after rotation" % laptop, "rejected", self.attempt(port, before),
                 "Rotation revoked the superseded certificate")
            note("New %s certificate after rotation" % laptop, "accepted", self.attempt(port, identity_of(laptop)),
                 "Fresh key and fresh certificate")
        finally:
            if started_here:
                self.server.stop()
        summary = {
            "passed": all(s["passed"] for s in steps),
            "steps": steps,
            "run_id": sha256_hex(new_id().encode())[:12],
        }
        self.audit.record("mTLS scenario run finished", "mtls-lab", "LOCAL_TLS",
                          "INFO" if summary["passed"] else "ERROR", details={
                              "passed": summary["passed"], "steps": len(steps)})
        return summary
