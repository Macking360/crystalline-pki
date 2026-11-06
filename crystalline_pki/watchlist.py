from __future__ import annotations

import json
import sqlite3
from contextlib import closing

from .probe import validate_url
from .util import now_iso

LEVELS = ("OK", "INFO", "WARNING", "ERROR", "CRITICAL")
TLS_RANK = {"TLSv1.2": 2, "TLSv1.3": 3}

_SCHEMA = """CREATE TABLE IF NOT EXISTS watch (
    host TEXT PRIMARY KEY,
    added TEXT NOT NULL,
    baseline TEXT,
    last_result TEXT,
    last_checked TEXT,
    last_status TEXT NOT NULL DEFAULT 'NEW'
)"""


def _worst(findings) -> str:
    return max((f["level"] for f in findings), key=LEVELS.index, default="OK")


def diff_snapshots(baseline, current) -> list:
    findings = []
    cert, base = current["certificate"], (baseline or {}).get("certificate")
    days = cert["days_remaining"]
    if days <= 0:
        findings.append({"level": "CRITICAL", "code": "expired", "message": "Certificate has expired"})
    elif days <= 7:
        findings.append({"level": "ERROR", "code": "expires_soon", "message": "Certificate expires in %d days" % days})
    elif days <= 21:
        findings.append({"level": "WARNING", "code": "expiring", "message": "Certificate expires in %d days" % days})
    if baseline is None:
        findings.append({"level": "INFO", "code": "baseline_created", "message": "First check; this result is now the baseline"})
        return findings
    if cert["sha256_fingerprint"] != base["sha256_fingerprint"]:
        if cert["issuer"] != base["issuer"]:
            findings.append({"level": "WARNING", "code": "issuer_changed",
                             "message": "Issuer changed from %s to %s" % (base["issuer"], cert["issuer"])})
        elif cert["not_after"] > base["not_after"]:
            findings.append({"level": "INFO", "code": "renewed", "message": "Certificate was renewed by the same issuer"})
        else:
            findings.append({"level": "WARNING", "code": "certificate_changed",
                             "message": "A different certificate with an earlier or equal expiry is being served"})
    if TLS_RANK.get(current["tls_version"], 0) < TLS_RANK.get(baseline["tls_version"], 0):
        findings.append({"level": "ERROR", "code": "tls_downgrade",
                         "message": "TLS version fell from %s to %s" % (baseline["tls_version"], current["tls_version"])})
    if current["cipher"][0] != baseline["cipher"][0]:
        findings.append({"level": "INFO", "code": "cipher_changed",
                         "message": "Cipher changed from %s to %s" % (baseline["cipher"][0], current["cipher"][0])})
    if set(current["addresses"]) != set(baseline["addresses"]):
        findings.append({"level": "INFO", "code": "dns_changed", "message": "The set of resolved addresses changed"})
    if current["http_status"] != baseline["http_status"]:
        findings.append({"level": "INFO", "code": "status_changed",
                         "message": "HTTP status changed from %s to %s" % (baseline["http_status"], current["http_status"])})
    return findings


class Watchlist:
    def __init__(self, workspace, audit, probe):
        self.workspace = workspace
        self.audit = audit
        self.probe = probe
        with closing(self._connect()) as db:
            db.execute(_SCHEMA)

    def _connect(self):
        connection = sqlite3.connect(str(self.workspace.database), timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def add(self, host: str, authorized: bool = False) -> dict:
        if not authorized:
            raise PermissionError("Explicit authorization is required: only watch hosts you own or may test")
        _, clean = validate_url("https://" + host.strip() + "/")
        with closing(self._connect()) as db:
            db.execute("INSERT OR IGNORE INTO watch (host, added) VALUES (?, ?)", (clean, now_iso()))
        self.audit.record("Host added to watchlist", "watchlist", "WATCH", "INFO", clean)
        return {"host": clean}

    def remove(self, host: str) -> None:
        with closing(self._connect()) as db:
            db.execute("DELETE FROM watch WHERE host=?", (host.strip().lower(),))
        self.audit.record("Host removed from watchlist", "watchlist", "WATCH", "INFO", host)

    def list(self) -> list:
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM watch ORDER BY host").fetchall()
        records = []
        for row in rows:
            record = dict(row)
            last = json.loads(record["last_result"]) if record["last_result"] else None
            record["days_remaining"] = last["certificate"]["days_remaining"] if last else None
            record["issuer"] = last["certificate"]["issuer"] if last else None
            record["tls_version"] = last["tls_version"] if last else None
            records.append(record)
        return records

    def check(self, host: str, cafile=None) -> dict:
        host = host.strip().lower()
        with closing(self._connect()) as db:
            row = db.execute("SELECT * FROM watch WHERE host=?", (host,)).fetchone()
        if row is None:
            raise ValueError("%s is not on the watchlist" % host)
        try:
            current = self.probe.examine("https://%s/" % host, authorized=True, cafile=cafile)
        except Exception as error:
            return self._store(host, row, None, [{"level": "ERROR", "code": "check_failed", "message": str(error)}], "ERROR")
        return self.observe(host, current)

    def observe(self, host: str, current: dict) -> dict:
        host = host.strip().lower()
        _, clean = validate_url("https://" + host + "/")
        with closing(self._connect()) as db:
            db.execute("INSERT OR IGNORE INTO watch (host, added) VALUES (?, ?)", (clean, now_iso()))
            row = db.execute("SELECT * FROM watch WHERE host=?", (clean,)).fetchone()
        findings = diff_snapshots(json.loads(row["baseline"]) if row["baseline"] else None, current)
        return self._store(clean, row, current, findings, _worst(findings))

    def _store(self, host, row, current, findings, status) -> dict:
        baseline = json.loads(row["baseline"]) if row["baseline"] else None
        with closing(self._connect()) as db:
            if current is not None:
                db.execute("UPDATE watch SET last_result=?, last_checked=?, last_status=? WHERE host=?",
                           (json.dumps(current, default=str), now_iso(), status, host))
                if baseline is None:
                    db.execute("UPDATE watch SET baseline=? WHERE host=?", (json.dumps(current, default=str), host))
            else:
                db.execute("UPDATE watch SET last_checked=?, last_status=? WHERE host=?", (now_iso(), status, host))
        self.audit.record("Watchlist check: " + status, "watchlist", "WATCH", "INFO" if status in ("OK", "INFO") else status,
                          host, {"findings": findings})
        return {"host": host, "status": status, "findings": findings, "first_observation": baseline is None and current is not None}

    def check_all(self, cafile=None) -> list:
        return [self.check(record["host"], cafile=cafile) for record in self.list()]

    def accept(self, host: str) -> dict:
        host = host.strip().lower()
        with closing(self._connect()) as db:
            row = db.execute("SELECT last_result FROM watch WHERE host=?", (host,)).fetchone()
            if row is None or not row["last_result"]:
                raise ValueError("Run a successful check before accepting a new baseline")
            db.execute("UPDATE watch SET baseline=?, last_status='OK' WHERE host=?", (row["last_result"], host))
        self.audit.record("Watchlist baseline accepted", "watchlist", "WATCH", "INFO", host)
        return {"host": host, "status": "OK"}
