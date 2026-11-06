import http.client
import json
import shutil
import ssl
import subprocess
import time
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.serialization import pkcs12

from crystalline_pki.cli import main
from crystalline_pki.config import Config
from crystalline_pki.webui import WebUI


@pytest.fixture
def web(ready):
    ui = WebUI(ready, port=0)
    ui.start()
    context = ssl.create_default_context(cafile=str(ready.workspace.root_cert))

    def request(method, path, body=None, headers=None, token=True, host=None):
        connection = http.client.HTTPSConnection("127.0.0.1", ui.port, context=context, timeout=60)
        merged = dict(headers or {})
        if token:
            merged["Cookie"] = "cpki_token=" + ui.token
        if host:
            connection.putrequest(method, path, skip_host=True)
            connection.putheader("Host", host)
            for key, value in merged.items():
                connection.putheader(key, value)
            connection.endheaders()
        else:
            connection.request(method, path, body=body, headers=merged)
        response = connection.getresponse()
        data = response.read()
        connection.close()
        return response.status, data

    yield ui, request
    ui.stop()


def post(request, path, payload, **kwargs):
    headers = {"Content-Type": "application/json", "X-Requested-With": "crystalline-pki"}
    headers.update(kwargs.pop("headers", {}))
    return request("POST", path, json.dumps(payload).encode(), headers=headers, **kwargs)


def test_web_requires_the_token(web):
    ui, request = web
    assert request("GET", "/", token=False)[0] == 401
    assert request("GET", "/api/status", token=False)[0] == 401
    assert request("GET", "/?t=wrong", token=False)[0] == 403
    assert request("GET", "/?t=" + ui.token, token=False)[0] == 302
    status, body = request("GET", "/")
    assert status == 200 and b"crystalline-pki" in body


def test_web_rejects_rebinding_and_cross_origin(web):
    ui, request = web
    assert request("GET", "/api/status", host="evil.example:%d" % ui.port)[0] == 421
    assert post(request, "/api/enroll", {"name": "x1"}, headers={"Origin": "https://evil.example"})[0] == 403
    status, _ = request("POST", "/api/enroll", b"{}", headers={"Content-Type": "application/json"})
    assert status == 403


def test_web_api_round_trip(web):
    ui, request = web
    status, body = request("GET", "/api/status")
    assert status == 200 and json.loads(body)["pki_ready"]
    status, body = post(request, "/api/enroll", {"name": "web-phone"})
    assert status == 200 and json.loads(body)["state"] == "active"
    status, body = request("GET", "/api/self")
    assert json.loads(body)["tls_version"] in ("TLSv1.2", "TLSv1.3")
    status, body = post(request, "/api/inspect", {"pem": "garbage"})
    assert status == 400
    status, body = post(request, "/api/probe", {"url": "https://127.0.0.1/"})
    job = json.loads(body)["job"]
    for _ in range(50):
        snapshot = json.loads(request("GET", "/api/jobs/" + job)[1])
        if snapshot["status"] != "running":
            break
        time.sleep(0.1)
    assert snapshot["status"] == "error"


def test_web_serves_the_lab_root(web):
    ui, request = web
    status, body = request("GET", "/ca/root.pem", token=False)
    assert status == 200 and body.startswith(b"-----BEGIN CERTIFICATE-----")


def test_cli_end_to_end(tmp_path, capsys):
    home = str(tmp_path / "cli-home")
    assert main(["--home", home, "maintain"]) == 0
    assert main(["--home", home, "verify"]) == 0
    assert main(["--home", home, "audit", "verify"]) == 0
    assert main(["--home", home, "trust"]) == 0
    assert main(["--home", home, "enroll", "cli-device"]) == 0
    assert main(["--home", home, "revoke", "cli-device", "--reason", "superseded"]) == 0
    assert main(["--home", home, "lab"]) == 0


def test_cli_reports_bad_input(tmp_path, capsys):
    home = str(tmp_path / "cli-home2")
    assert main(["--home", home, "maintain"]) == 0
    assert main(["--home", home, "revoke", "nonexistent"]) == 1
    assert main(["--home", home, "auto", "http://example.org/"]) == 1
    assert main(["--version"]) == 0


def test_config_validation(app):
    with pytest.raises(ValueError):
        app.config.set("rsa_bits", 1024)
    with pytest.raises(ValueError):
        app.config.set("ca_bundle", "/no/such/file.pem")
    with pytest.raises(ValueError):
        app.config.set("auto_maintenance_minutes", 2)
    with pytest.raises(KeyError):
        app.config.set("nonsense", 1)
    assert app.config.set("auto_maintenance_minutes", 0) == 0
    assert Config(app.workspace).get("auto_maintenance_minutes") == 0


def test_public_export_has_no_private_keys_and_bundle_loads(ready):
    ready.pki.enroll_device("export-phone")
    exported = ready.exporter.export_public_certificates()
    folder = exported.get("directory")
    for path in Path(folder).rglob("*"):
        if path.is_file():
            assert b"PRIVATE KEY" not in path.read_bytes()
    bundle = ready.exporter.export_device_bundle("export-phone", "correct horse battery", False)
    path = next(v for v in bundle.values() if str(v).endswith(".p12"))
    key, cert, extra = pkcs12.load_key_and_certificates(Path(path).read_bytes(), b"correct horse battery")
    assert key is not None and cert is not None and extra


def _openssl():
    candidates = [shutil.which("openssl"), r"C:\Program Files\Git\usr\bin\openssl.exe", r"C:\Program Files\Git\mingw64\bin\openssl.exe"]
    return next((c for c in candidates if c and shutil.os.path.isfile(c)), None)


@pytest.mark.skipif(_openssl() is None, reason="OpenSSL not installed")
def test_openssl_agrees_with_the_authority(ready):
    ws = ready.workspace
    openssl = _openssl()
    good = subprocess.run([openssl, "verify", "-CAfile", str(ws.root_cert), "-untrusted", str(ws.intermediate_cert), str(ws.server_cert)],
                          capture_output=True, text=True)
    assert good.returncode == 0, good.stdout + good.stderr
    record = ready.pki.enroll_device("ossl-phone")
    ready.pki.revoke(record["serial"], "key_compromise")
    ready.pki.refresh_crl()
    bad = subprocess.run([openssl, "verify", "-crl_check", "-CAfile", str(ws.trust_bundle), "-untrusted", str(ws.intermediate_cert),
                          record["cert_path"]], capture_output=True, text=True)
    assert bad.returncode != 0
    assert "revoked" in (bad.stdout + bad.stderr).lower()
