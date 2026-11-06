import pytest

from conftest import resolver
from crystalline_pki.probe import ProbeVerificationError, validate_url
from crystalline_pki.watchlist import diff_snapshots


def test_scenarios_behave_as_expected(ready):
    summary = ready.lab.run_scenarios()
    assert summary["passed"], [s for s in summary["steps"] if not s["passed"]]
    outcomes = {s["step"]: s["outcome"] for s in summary["steps"]}
    assert "accepted" in outcomes.values() and "rejected" in outcomes.values()
    assert ready.audit.verify_chain()["valid"]


@pytest.mark.parametrize("url", [
    "http://example.org/", "https://127.0.0.1/", "https://10.0.0.5/", "https://user:pw@example.org/",
    "https://example.org:8443/", "ftp://example.org/", "https://[::1]/", "", "https://",
])
def test_validate_url_refuses_unsafe_targets(url):
    with pytest.raises(ValueError):
        validate_url(url)


def test_validate_url_accepts_plain_https():
    parsed, host = validate_url("https://Example.ORG/path?q=1#frag")
    assert host == "example.org"


def test_probe_reads_a_server_it_trusts(ready, local_https):
    server = local_https(headers=["Server: nginx/1.25.3", "Set-Cookie: sid=abc123; Path=/"])
    result = ready.probe.examine("https://localhost/", authorized=True, cafile=str(ready.workspace.root_cert),
                                 deep=True, _port=server.port, _resolver=resolver)
    assert result["tls_version"] in ("TLSv1.2", "TLSv1.3")
    assert len(result["chain"]) >= 2
    assert result["certificate"]["subject_alternative_names"][0] == "DNS:localhost"
    assert result["response"]["analysis"]["cookie_notes"]
    assert result["protocol_support"]["tls_versions"]["TLSv1.3"]["supported"]
    assert server.requests[0].startswith("HEAD / HTTP/1.1")
    assert "sid=abc123" not in str(result["response"]["analysis"]["cookies"])


def test_probe_requires_authorization(ready):
    with pytest.raises(PermissionError):
        ready.probe.examine("https://example.org/")


def test_probe_diagnoses_an_untrusted_root(ready, local_https):
    server = local_https()
    with pytest.raises(ProbeVerificationError) as caught:
        ready.probe.examine("https://localhost/", authorized=True, _port=server.port, _resolver=resolver)
    diagnosis = caught.value.diagnosis
    assert diagnosis["verify_code"] in (19, 20, 21)
    assert diagnosis["served_certificate"]["chain"]


def test_autopilot_falls_back_to_a_trust_bundle(ready, local_https, monkeypatch):
    server = local_https()
    original = ready.probe.examine
    monkeypatch.setattr(ready.probe, "examine", lambda url, **kw: original(url, _port=server.port, _resolver=resolver, **kw))
    monkeypatch.setattr("crystalline_pki.autopilot.trust.best_ca_bundle",
                        lambda: {"source": "test bundle", "path": str(ready.workspace.root_cert), "roots": 1})
    result = ready.autopilot.examine("https://localhost/", deep=False)
    assert result["trust_fallback"]["bundle"]["source"] == "test bundle"
    assert result["assessment"]["grade"] in "ABCDF"
    assert result["narrative"] and result["report_files"]
    assert result["watch"]["first_observation"]
    again = ready.autopilot.examine("https://localhost/", deep=False)
    assert not again["watch"]["first_observation"]


def test_assessment_flags_missing_headers(ready, local_https, monkeypatch):
    server = local_https()
    original = ready.probe.examine
    monkeypatch.setattr(ready.probe, "examine", lambda url, **kw: original(
        url, cafile=str(ready.workspace.root_cert), _port=server.port, _resolver=resolver, **kw))
    result = ready.autopilot.examine("https://localhost/", deep=False)
    titles = [f["title"] for f in result["assessment"]["findings"]]
    assert "No HSTS" in titles
    assert all({"what", "why", "fix"} <= set(f) for f in result["assessment"]["findings"])


def _snapshot(days=100, issuer="CN=A", fingerprint="aa", tls="TLSv1.3", cipher="X", status=200):
    return {"certificate": {"days_remaining": days, "issuer": issuer, "sha256_fingerprint": fingerprint, "not_after": "2030-01-01"},
            "tls_version": tls, "cipher": [cipher], "addresses": ["1.1.1.1"], "http_status": status}


def test_diff_flags_issuer_change_downgrade_and_expiry():
    base = _snapshot()
    codes = {f["code"] for f in diff_snapshots(base, _snapshot(days=3, issuer="CN=B", fingerprint="bb", tls="TLSv1.2"))}
    assert {"expires_soon", "issuer_changed", "tls_downgrade"} <= codes
    assert diff_snapshots(None, base)[0]["code"] == "baseline_created"
    assert not [f for f in diff_snapshots(base, base) if f["level"] != "INFO"]
