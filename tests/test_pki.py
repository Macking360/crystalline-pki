import pytest
from cryptography import x509

from crystalline_pki.pki import load_cert


def test_generate_and_verify(ready):
    result = ready.pki.verify_chain()
    assert result["failed"] == 0
    assert result["passed"] >= 19
    assert ready.pki.ready()


def test_generate_refuses_to_overwrite(ready):
    with pytest.raises(RuntimeError):
        ready.pki.generate()


def test_replace_keeps_backup(ready):
    ready.pki.generate(replace=True)
    assert any(ready.workspace.backups.iterdir())
    assert ready.pki.verify_chain()["failed"] == 0


def test_enroll_revoke_and_crl(ready):
    record = ready.pki.enroll_device("phone-1")
    assert record["state"] == "active"
    with pytest.raises(ValueError):
        ready.pki.enroll_device("phone-1")
    ready.pki.revoke(record["serial"], "key_compromise")
    crl = x509.load_pem_x509_crl(ready.workspace.crl_pem.read_bytes())
    assert [r.serial_number for r in crl] == [int(record["serial"], 16)]
    assert ready.registry.get(record["serial"])["state"] == "revoked"
    with pytest.raises(ValueError):
        ready.pki.revoke(record["serial"])


def test_rotate_supersedes_old_certificate(ready):
    old = ready.pki.enroll_device("phone-2")
    rotated = ready.pki.rotate_device("phone-2")
    assert rotated["old"]["state"] == "revoked"
    assert rotated["new"]["state"] == "active"
    assert rotated["new"]["serial"] != old["serial"]
    assert len(ready.registry.active_for("phone-2")) == 1


def test_invalid_names_rejected(ready):
    for name in ("", "../evil", "a b", "x" * 80, ".hidden"):
        with pytest.raises(ValueError):
            ready.pki.enroll_device(name)


def test_csr_flow_never_needs_private_key(ready):
    request = ready.pki.create_device_request("crew-1")
    record = ready.pki.issue_from_csr(open(request["csr_path"], "rb").read(), name="crew-1")
    cert = load_cert(record["cert_path"])
    assert cert.issuer == load_cert(ready.workspace.intermediate_cert).subject


def test_renew_service_replaces_server_certificate(ready):
    before = load_cert(ready.workspace.server_cert).serial_number
    ready.pki.renew_service("server")
    after = load_cert(ready.workspace.server_cert).serial_number
    assert before != after
    assert ready.pki.verify_chain()["failed"] == 0
    assert len(ready.registry.active_for("localhost")) == 1


def test_crl_stays_fresh(ready):
    status = ready.pki.ensure_fresh_crl(min_hours=1000)
    assert status["number"] >= 2
    assert status["signature_valid"]


def test_expiring_lists_short_lived_devices(ready):
    ready.config.set("device_days", 10)
    ready.pki.enroll_device("short")
    assert [r["name"] for r in ready.pki.expiring(21)] == ["short"]
