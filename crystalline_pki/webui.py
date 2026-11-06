from __future__ import annotations

import hmac
import json
import re
import secrets
import ssl
import threading
import time
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import serialization

from . import APP_NAME, __version__, trust
from .certinspect import describe_certificate
from .knowledge import CHECK_WHY, GLOSSARY, HANDSHAKE, LESSONS, PROBE_HELP, TOUR, explain_attempt, explain_certificate
from .pki import REASONS, load_cert
from .probe import ProbeVerificationError
from .reporting import render_probe
from .tlslab import _TLSServer
from .util import new_id, now_iso, safe_name

ASSET_DIR = Path(__file__).resolve().parent / "web"
MAX_BODY = 1024 * 1024
POLLING = ("/api/events", "/api/jobs/", "/api/self")
CONFIGURABLE = ("ca_bundle", "external_timeout", "theme", "auto_watch", "auto_maintenance_minutes", "renew_within_days",
                "watch_interval_hours")
ASSET_TYPES = {".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8"}


class ApiError(Exception):
    def __init__(self, message, status=400, extra=None):
        super().__init__(message)
        self.status = status
        self.extra = extra or {}


class Job:
    def __init__(self, name):
        self.id = secrets.token_hex(6)
        self.name = name
        self.status = "running"
        self.progress = []
        self.result = None
        self.error = None
        self.started = now_iso()
        self.finished = None

    def snapshot(self) -> dict:
        return {"id": self.id, "name": self.name, "status": self.status, "progress": list(self.progress),
                "result": self.result, "error": self.error, "started": self.started, "finished": self.finished}


class WebUI:
    def __init__(self, app, port=8080, require_client_cert=False):
        self.app = app
        self.host = "127.0.0.1"
        self.port = int(port)
        self.require_client_cert = bool(require_client_cert)
        self.token = secrets.token_urlsafe(32)
        self.jobs = {}
        self._jobs_lock = threading.Lock()
        self._server = None
        self._thread = None
        self.assets = {name: (ASSET_DIR / name).read_bytes() for name in ("index.html", "app.js", "app.css")}

    @property
    def base_url(self) -> str:
        return "https://%s:%d" % (self.host, self.port)

    @property
    def entry_url(self) -> str:
        return "%s/?t=%s" % (self.base_url, self.token)

    def context(self) -> ssl.SSLContext:
        ws = self.app.workspace
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_cert_chain(str(ws.server_chain), str(ws.server_key))
        if self.require_client_cert:
            context.load_verify_locations(cafile=str(ws.trust_bundle))
            context.verify_mode = ssl.CERT_REQUIRED
            context.verify_flags |= ssl.VERIFY_X509_STRICT | ssl.VERIFY_CRL_CHECK_LEAF
        return context

    def reload_context(self) -> None:
        if self._server:
            self._server.tls_context = self.context()

    def start(self, progress=None) -> dict:
        if self._server:
            return {"status": "already running", "url": self.entry_url}
        self.app.autopilot.after_change = self.reload_context
        self.app.autopilot.run_cycle(progress)
        self.app.autopilot.start_background()
        server = _WebServer((self.host, self.port), _make_handler())
        server.tls_context = self.context()
        server.on_reject = self._rejected
        server.webui = self
        self._server = server
        self.port = server.server_address[1]
        self._thread = threading.Thread(target=server.serve_forever, daemon=True)
        self._thread.start()
        self.app.audit.record("Web interface started", "web", "WEB", "INFO", self.base_url,
                              {"client_certificate_required": self.require_client_cert})
        return {"status": "running", "url": self.entry_url, "base_url": self.base_url}

    def stop(self) -> None:
        self.app.autopilot.stop_background()
        if not self._server:
            return
        server, thread = self._server, self._thread
        self._server = self._thread = None
        server.shutdown()
        server.server_close()
        if thread:
            thread.join(timeout=4)
        self.app.audit.record("Web interface stopped", "web", "WEB", "INFO", self.base_url)

    def _rejected(self, address, error):
        self.app.audit.record("Web TLS handshake rejected", "web", "WEB", "WARNING", address[0],
                              {"reason": getattr(error, "reason", None) or str(error)})

    def host_ok(self, header: str) -> bool:
        return header in ("127.0.0.1:%d" % self.port, "localhost:%d" % self.port)

    def origin_ok(self, header) -> bool:
        return header in ("https://127.0.0.1:%d" % self.port, "https://localhost:%d" % self.port)

    def token_ok(self, supplied) -> bool:
        return bool(supplied) and hmac.compare_digest(str(supplied), self.token)

    def start_job(self, name, function) -> dict:
        job = Job(name)
        with self._jobs_lock:
            self.jobs[job.id] = job
            for stale in sorted(self.jobs.values(), key=lambda j: j.started)[:-50]:
                self.jobs.pop(stale.id, None)

        def run():
            try:
                job.result = function(job)
                job.status = "done"
            except ProbeVerificationError as error:
                job.error = {"message": str(error), "diagnosis": error.diagnosis}
                job.status = "error"
            except Exception as error:
                job.error = {"message": str(error) or type(error).__name__}
                job.status = "error"
            job.finished = now_iso()

        threading.Thread(target=run, daemon=True).start()
        return {"job": job.id}

    def get_job(self, job_id) -> dict:
        job = self.jobs.get(job_id)
        if job is None:
            raise ApiError("No such job", 404)
        return job.snapshot()

    def _need_str(self, payload, key, maximum=300) -> str:
        value = payload.get(key)
        if not isinstance(value, str) or not value.strip() or len(value) > maximum:
            raise ApiError("%s is required" % key)
        return value.strip()

    def api_status(self, payload, query):
        status = self.app.status()
        status["web"] = {"url": self.base_url, "client_certificate_required": self.require_client_cert}
        status["theme"] = self.app.config.get("theme")
        status["config"] = {k: self.app.config.get(k) for k in CONFIGURABLE}
        return status

    def api_self(self, payload, query, handler=None):
        connection = handler.connection
        server_cert = describe_certificate(load_cert(self.app.workspace.server_cert))
        cipher = connection.cipher()
        return {
            "tls_version": connection.version(),
            "cipher": list(cipher),
            "alpn": connection.selected_alpn_protocol(),
            "client_address": "%s:%s" % handler.client_address[:2],
            "server_certificate": server_cert,
            "client_certificate_required": self.require_client_cert,
            "root_download": "/ca/root.pem",
            "trusted_by_browser_hint": "If your browser shows a warning, import root-cert.pem into its trust store.",
        }

    def api_certs(self, payload, query):
        return {"certificates": self.app.registry.list(), "crl": self.app.pki.crl_status() if self.app.pki.ready() else None}

    def api_cert_detail(self, payload, query, serial):
        record = self.app.registry.get(serial)
        if record is None:
            raise ApiError("No such certificate", 404)
        cert = load_cert(record["cert_path"])
        details = describe_certificate(cert)
        return {
            "record": record,
            "details": details,
            "explanation": explain_certificate(details),
            "pem": cert.public_bytes(serialization.Encoding.PEM).decode(),
            "history": [
                {k: e[k] for k in ("id", "timestamp", "severity", "action", "component")}
                for e in self.app.audit.events_for_target(record["name"], 50)
            ],
        }

    def api_verify(self, payload, query):
        result = self.app.pki.verify_chain()
        for check in result["checks"]:
            check["why"] = CHECK_WHY.get(check["check"], "")
        return result

    def api_events(self, payload, query):
        after = int(query.get("after", ["0"])[0])
        rows = self.app.audit.events_after(after, 500)
        return {"events": [self._event(r) for r in rows]}

    def api_events_recent(self, payload, query):
        limit = min(int(query.get("limit", ["200"])[0]), 1000)
        severity = query.get("severity", [""])[0].upper()
        category = query.get("category", [""])[0].upper()
        rows = self.app.audit.recent_events(limit)
        if severity:
            rows = [r for r in rows if r["severity"] == severity]
        if category:
            rows = [r for r in rows if r["category"] == category]
        return {"events": [self._event(r) for r in rows]}

    @staticmethod
    def _event(row) -> dict:
        event = dict(row)
        event["details"] = json.loads(event["details"])
        return event

    def api_audit_verify(self, payload, query):
        return self.app.audit.verify_chain()

    def api_knowledge(self, payload, query):
        return {"lessons": LESSONS, "glossary": GLOSSARY, "check_why": CHECK_WHY, "tour": TOUR,
                "handshake": HANDSHAKE, "probe_help": PROBE_HELP, "reasons": sorted(REASONS)}

    def api_watch(self, payload, query):
        return {"hosts": self.app.watch.list()}

    def api_identities(self, payload, query):
        return {"identities": self.app.lab.identities(), "server": {
            "running": self.app.server.running, "port": self.app.server.port}}

    def post_init(self, payload, query):
        replace = bool(payload.get("replace"))
        return self.start_job("init", lambda job: self.app.pki.generate(replace=replace))

    def post_enroll(self, payload, query):
        name = self._need_str(payload, "name", 63)
        return self.app.pki.enroll_device(name)

    def post_rotate(self, payload, query):
        return self._reload_after(self.app.pki.rotate_device(self._need_str(payload, "name", 63)))

    def post_revoke(self, payload, query):
        reason = payload.get("reason", "unspecified")
        return self._reload_after(self.app.pki.revoke(self._need_str(payload, "identifier"), reason))

    def _reload_after(self, value):
        if self.app.server.running:
            self.app.server.reload()
        return value

    def post_crl_refresh(self, payload, query):
        result = self.app.pki.refresh_crl()
        if self.app.server.running:
            self.app.server.reload()
        return {"published": result, "status": self.app.pki.crl_status()}

    def post_inspect(self, payload, query):
        pem = self._need_str(payload, "pem", MAX_BODY)
        try:
            certificates = x509.load_pem_x509_certificates(pem.encode())
        except ValueError:
            raise ApiError("No PEM certificate was found in the text you pasted")
        results = []
        for index, cert in enumerate(certificates, 1):
            details = describe_certificate(cert)
            details["certificate_index"] = index
            self.app.audit.add_certificate("pasted-pem", details)
            results.append({"details": details, "explanation": explain_certificate(details)})
        self.app.audit.record("Certificate inspected (pasted PEM)", "web", "CERTIFICATE", "INFO",
                              details={"count": len(results)})
        return {"certificates": results}

    def post_server_start(self, payload, query):
        return self.app.server.start()

    def post_server_stop(self, payload, query):
        return self.app.server.stop()

    def post_server_reload(self, payload, query):
        return self.app.server.reload()

    def post_lab_connect(self, payload, query):
        if not self.app.server.running:
            raise ApiError("Start the mTLS server first")
        serial = payload.get("serial")
        identity = None
        if serial:
            identity = next((i for i in self.app.lab.identities() if i["serial"] == serial), None)
            if identity is None or not identity["usable"]:
                raise ApiError("That identity's key is not available in this workspace")
        result = self.app.lab.attempt(self.app.server.port, identity)
        result["explanation"] = explain_attempt(result)
        return result

    def post_lab_scenarios(self, payload, query):
        def run(job):
            def progress(step):
                job.progress.append(step)
            summary = self.app.lab.run_scenarios(progress)
            for step in summary["steps"]:
                step["explanation"] = explain_attempt({"outcome": step["outcome"], "error": step["detail"],
                                                       "tls_version": step["tls_version"], "cipher": [step["cipher"]],
                                                       "presented": None if "No client" in step["step"] else "x"})
            return summary
        return self.start_job("lab", run)

    def post_probe(self, payload, query):
        url = self._need_str(payload, "url", 500)
        deep = payload.get("deep", True) is not False

        def run(job):
            result = self.app.autopilot.examine(url, progress=job.progress.append, deep=deep)
            return {"result": result, "report_text": render_probe(result)}
        return self.start_job("probe", run)

    def api_autopilot(self, payload, query):
        return self.app.autopilot.state()

    def post_autopilot_run(self, payload, query):
        return self.start_job("autopilot", lambda job: self.app.autopilot.run_cycle(job.progress.append, first_run=bool(payload.get("selftest"))))

    def api_trust(self, payload, query):
        return {"bundles": trust.find_ca_bundles(), "system": trust.system_store_summary(),
                "configured": self.app.config.get("ca_bundle"),
                "root_instructions": trust.root_trust_instructions(self.app.workspace.root_cert)}

    def post_watch_add(self, payload, query):
        return self.app.watch.add(self._need_str(payload, "host", 253), authorized=True)

    def post_watch_remove(self, payload, query):
        self.app.watch.remove(self._need_str(payload, "host", 253))
        return {"removed": True}

    def post_watch_accept(self, payload, query):
        return self.app.watch.accept(self._need_str(payload, "host", 253))

    def post_watch_check(self, payload, query):
        host = self._need_str(payload, "host", 253)
        return self.start_job("watch", lambda job: self.app.autopilot.check_host(host))

    def post_watch_check_all(self, payload, query):
        return self.start_job("watch-all", lambda job: self.app.autopilot.check_all_hosts())

    def post_config(self, payload, query):
        key = self._need_str(payload, "key", 64)
        if key not in CONFIGURABLE:
            raise ApiError("That setting cannot be changed from the web interface")
        return {key: self.app.config.set(key, payload.get("value", ""))}

    def post_audit_export(self, payload, query):
        return {"path": str(self.app.exporter.export_events_csv())}

    def post_export_certs(self, payload, query):
        return self.app.exporter.export_public_certificates()

    def post_export_p12(self, payload, query):
        return self.app.exporter.export_device_bundle(
            self._need_str(payload, "name", 63), str(payload.get("password", "")), bool(payload.get("legacy")))

    def post_report(self, payload, query):
        name = safe_name(str(payload.get("name", "crystalline-pki")))
        return {"path": str(self.app.exporter.report(name, self.app.report_data()))}

    def post_demo(self, payload, query):
        def run(job):
            def say(title, text, status="ok"):
                job.progress.append({"title": title, "text": text, "status": status})
            if not self.app.pki.ready():
                say(TOUR[0][0], TOUR[0][1] + " (creating it now)", "running")
                self.app.pki.generate()
            else:
                say(TOUR[0][0], "The lab authority already exists, so it is reused.")
            verification = self.app.pki.verify_chain()
            say("Verify the hierarchy", "%d checks passed, %d failed." % (verification["passed"], verification["failed"]),
                "ok" if verification["failed"] == 0 else "error")
            say(TOUR[1][0], TOUR[1][1])
            summary = self.app.lab.run_scenarios(lambda step: say(step["step"], "%s (expected %s, got %s). %s" % (
                "PASS" if step["passed"] else "FAIL", step["expected"], step["outcome"], step["detail"]),
                "ok" if step["passed"] else "error"))
            say("Audit trail", "Every action above is recorded in a hash-linked log.")
            chain = self.app.audit.verify_chain()
            say("Audit chain check", "%d events, chain %s." % (chain["records_checked"], "intact" if chain["valid"] else "BROKEN"),
                "ok" if chain["valid"] else "error")
            return {"scenarios": summary, "verification": verification, "audit": chain}
        return self.start_job("demo", run)

    ROUTES = {
        ("GET", "/api/status"): "api_status",
        ("GET", "/api/self"): "api_self",
        ("GET", "/api/autopilot"): "api_autopilot",
        ("GET", "/api/trust"): "api_trust",
        ("POST", "/api/autopilot/run"): "post_autopilot_run",
        ("GET", "/api/certs"): "api_certs",
        ("GET", "/api/verify"): "api_verify",
        ("GET", "/api/events"): "api_events",
        ("GET", "/api/events/recent"): "api_events_recent",
        ("GET", "/api/audit/verify"): "api_audit_verify",
        ("GET", "/api/knowledge"): "api_knowledge",
        ("GET", "/api/watch"): "api_watch",
        ("GET", "/api/identities"): "api_identities",
        ("POST", "/api/init"): "post_init",
        ("POST", "/api/enroll"): "post_enroll",
        ("POST", "/api/rotate"): "post_rotate",
        ("POST", "/api/revoke"): "post_revoke",
        ("POST", "/api/crl/refresh"): "post_crl_refresh",
        ("POST", "/api/inspect"): "post_inspect",
        ("POST", "/api/server/start"): "post_server_start",
        ("POST", "/api/server/stop"): "post_server_stop",
        ("POST", "/api/server/reload"): "post_server_reload",
        ("POST", "/api/lab/connect"): "post_lab_connect",
        ("POST", "/api/lab/scenarios"): "post_lab_scenarios",
        ("POST", "/api/probe"): "post_probe",
        ("POST", "/api/watch/add"): "post_watch_add",
        ("POST", "/api/watch/remove"): "post_watch_remove",
        ("POST", "/api/watch/accept"): "post_watch_accept",
        ("POST", "/api/watch/check"): "post_watch_check",
        ("POST", "/api/watch/check-all"): "post_watch_check_all",
        ("POST", "/api/config"): "post_config",
        ("POST", "/api/export/audit-csv"): "post_audit_export",
        ("POST", "/api/export/certs"): "post_export_certs",
        ("POST", "/api/export/p12"): "post_export_p12",
        ("POST", "/api/report"): "post_report",
        ("POST", "/api/demo"): "post_demo",
    }


class _WebServer(_TLSServer):
    webui = None


def _make_handler():
    class Handler(BaseHTTPRequestHandler):
        server_version = APP_NAME
        sys_version = ""

        def log_message(self, format_string, *args):
            return

        def _send(self, status, body, content_type, extra_headers=()):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("Referrer-Policy", "no-referrer")
            self.send_header("Content-Security-Policy",
                             "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'")
            self.send_header("Connection", "close")
            for name, value in extra_headers:
                self.send_header(name, value)
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(body)

        def _json(self, status, value):
            self._send(status, json.dumps(value, default=str).encode("utf-8"), "application/json; charset=utf-8")

        def _cookie_token(self):
            for part in self.headers.get("Cookie", "").split(";"):
                name, _, value = part.strip().partition("=")
                if name == "cpki_token":
                    return value
            return None

        def _handle(self, method):
            ui = self.server.webui
            started = time.monotonic()
            parsed = urlsplit(self.path)
            path, query = parsed.path, parse_qs(parsed.query)
            status = 500
            try:
                if not ui.host_ok(self.headers.get("Host", "")):
                    status = 421
                    return self._json(421, {"error": "Unexpected Host header"})
                if path == "/":
                    supplied = query.get("t", [None])[0]
                    if supplied is not None:
                        if not ui.token_ok(supplied):
                            status = 403
                            return self._json(403, {"error": "Invalid access token"})
                        status = 302
                        return self._send(302, b"", "text/plain", [
                            ("Location", "/"),
                            ("Set-Cookie", "cpki_token=%s; Path=/; HttpOnly; Secure; SameSite=Strict" % ui.token)])
                    if not ui.token_ok(self._cookie_token()):
                        status = 401
                        return self._send(401, b"Open the full URL printed by crystalline-pki web, including the access token.",
                                          "text/plain; charset=utf-8")
                    status = 200
                    return self._send(200, ui.assets["index.html"], ASSET_TYPES[".html"])
                if path.startswith("/assets/"):
                    name = path[len("/assets/"):]
                    if name not in ("app.js", "app.css"):
                        status = 404
                        return self._json(404, {"error": "Not found"})
                    status = 200
                    return self._send(200, ui.assets[name], ASSET_TYPES[Path(name).suffix])
                if path == "/ca/root.pem":
                    status = 200
                    return self._send(200, ui.app.workspace.root_cert.read_bytes(), "application/x-pem-file",
                                      [("Content-Disposition", 'attachment; filename="crystalline-pki-root.pem"')])
                if not path.startswith("/api/"):
                    status = 404
                    return self._json(404, {"error": "Not found"})
                if not ui.token_ok(self._cookie_token()):
                    status = 401
                    return self._json(401, {"error": "Missing or invalid access token"})
                payload = {}
                if method == "POST":
                    if self.headers.get("X-Requested-With") != APP_NAME:
                        status = 403
                        return self._json(403, {"error": "Missing X-Requested-With header"})
                    origin = self.headers.get("Origin")
                    if origin is not None and not ui.origin_ok(origin):
                        status = 403
                        return self._json(403, {"error": "Cross-origin request refused"})
                    length = int(self.headers.get("Content-Length") or 0)
                    if length > MAX_BODY:
                        status = 413
                        return self._json(413, {"error": "Request body too large"})
                    raw = self.rfile.read(length) if length else b"{}"
                    try:
                        payload = json.loads(raw or b"{}")
                    except json.JSONDecodeError:
                        status = 400
                        return self._json(400, {"error": "Body must be JSON"})
                    if not isinstance(payload, dict):
                        status = 400
                        return self._json(400, {"error": "Body must be a JSON object"})
                handler_name = ui.ROUTES.get((method, path))
                args = ()
                if handler_name is None:
                    for pattern, name, verb in ((r"^/api/certs/([0-9a-fA-F]{1,64})$", "api_cert_detail", "GET"),
                                                (r"^/api/jobs/([0-9a-f]{12})$", "get_job", "GET")):
                        match = re.match(pattern, path)
                        if match and verb == method:
                            handler_name, args = name, (match.group(1),)
                            break
                if handler_name is None:
                    status = 404
                    return self._json(404, {"error": "Unknown endpoint"})
                function = getattr(ui, handler_name)
                if handler_name == "get_job":
                    value = function(*args)
                elif handler_name == "api_self":
                    value = function(payload, query, handler=self)
                else:
                    value = function(payload, query, *args)
                status = 200
                return self._json(200, value)
            except ApiError as error:
                status = error.status
                return self._json(error.status, {"error": str(error), **error.extra})
            except (ValueError, PermissionError, RuntimeError, KeyError, FileNotFoundError) as error:
                status = 400
                return self._json(400, {"error": str(error) or type(error).__name__})
            except Exception as error:
                status = 500
                return self._json(500, {"error": "Internal error: %s" % type(error).__name__})
            finally:
                if method == "POST" or not any(path.startswith(p) for p in POLLING):
                    ui.app.audit.record("Web request", "web", "WEB", "INFO" if status < 400 else "WARNING", path,
                                        {"method": method, "status": status,
                                         "milliseconds": round((time.monotonic() - started) * 1000, 1),
                                         "client": self.client_address[0]})

        def do_GET(self):
            self._handle("GET")

        def do_POST(self):
            self._handle("POST")

        def do_HEAD(self):
            self._handle("GET")

    return Handler
