
from __future__ import annotations

import json
import logging
import sqlite3
import sys
import threading
from contextlib import closing
from logging.handlers import RotatingFileHandler

from . import __version__
from .platform_info import PLATFORM_NAME
from .util import new_id, now_iso, restrict, sha256_hex

GENESIS = "GENESIS"
SEVERITIES = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
MAX_LOG_BYTES = 5 * 1024 * 1024
MAX_LOG_BACKUPS = 10

_HASHED_FIELDS = (
    "event_id", "timestamp", "session_id", "component", "category",
    "severity", "action", "target", "details", "previous_hash",
)

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        event_id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        session_id TEXT NOT NULL,
        component TEXT NOT NULL,
        category TEXT NOT NULL,
        severity TEXT NOT NULL,
        action TEXT NOT NULL,
        target TEXT NOT NULL,
        details TEXT NOT NULL,
        previous_hash TEXT NOT NULL,
        integrity_hash TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS tests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        test_id TEXT UNIQUE NOT NULL,
        timestamp TEXT NOT NULL,
        target TEXT NOT NULL,
        hostname TEXT NOT NULL,
        port INTEGER,
        result TEXT NOT NULL,
        duration REAL NOT NULL,
        component TEXT NOT NULL,
        details TEXT NOT NULL,
        event_hash TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS certificates (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        label TEXT NOT NULL,
        subject TEXT,
        issuer TEXT,
        serial TEXT,
        fingerprint TEXT,
        not_before TEXT,
        not_after TEXT,
        details TEXT NOT NULL
    )""",
    """CREATE TABLE IF NOT EXISTS sessions (
        session_id TEXT PRIMARY KEY,
        started TEXT NOT NULL,
        ended TEXT,
        platform TEXT NOT NULL,
        python_version TEXT NOT NULL,
        application_version TEXT NOT NULL
    )""",
    "CREATE INDEX IF NOT EXISTS events_timestamp ON events(timestamp)",
    "CREATE INDEX IF NOT EXISTS events_category ON events(category)",
    "CREATE INDEX IF NOT EXISTS tests_target ON tests(target)",
    "CREATE INDEX IF NOT EXISTS certificates_fingerprint ON certificates(fingerprint)",
)


def _canonical(event: dict) -> str:
    return json.dumps({key: event[key] for key in _HASHED_FIELDS},
                      sort_keys=True, separators=(",", ":"), default=str)


class AuditLog:
    def __init__(self, workspace):
        workspace.ensure()
        self.workspace = workspace
        self.session_id = new_id()
        self._lock = threading.RLock()
        self._closed = False
        self._init_db()
        self.jsonl_path = workspace.logs / "events.jsonl"
        self._logger = logging.getLogger("crystalline_pki.audit." + self.session_id)
        self._logger.setLevel(logging.DEBUG)
        self._logger.propagate = False
        self._handler = RotatingFileHandler(
            workspace.logs / "crystalline-pki.log",
            maxBytes=MAX_LOG_BYTES, backupCount=MAX_LOG_BACKUPS, encoding="utf-8",
        )
        self._handler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)s | %(message)s"))
        self._logger.addHandler(self._handler)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.workspace.database), timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    def _init_db(self) -> None:
        with closing(self._connect()) as db:
            db.execute("PRAGMA journal_mode=WAL")
            for statement in _SCHEMA:
                db.execute(statement)
        restrict(self.workspace.database, 0o600)

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        self._logger.removeHandler(self._handler)
        self._handler.close()

    def record(self, action, component="app", category="ADMIN", severity="INFO",
               target="", details=None) -> dict:
        severity = str(severity).upper()
        if severity not in SEVERITIES:
            severity = "INFO"
        details = json.loads(json.dumps(details or {}, sort_keys=True, default=str))
        event = {
            "event_id": new_id(),
            "timestamp": now_iso(),
            "session_id": self.session_id,
            "component": str(component),
            "category": str(category),
            "severity": severity,
            "action": str(action),
            "target": str(target),
            "details": details,
        }
        with self._lock:
            event = self._append(event)
            with open(self.jsonl_path, "a", encoding="utf-8") as handle:
                handle.write(json.dumps(event, sort_keys=True, default=str) + "\n")
            restrict(self.jsonl_path, 0o600)
            self._logger.log(getattr(logging, severity), "%s | %s | %s | %s", component, action, target,
                             json.dumps(details, sort_keys=True, default=str))
        return event

    def _append(self, event: dict) -> dict:
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT integrity_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
                event["previous_hash"] = row["integrity_hash"] if row else GENESIS
                event["integrity_hash"] = sha256_hex(_canonical(event).encode("utf-8"))
                db.execute(
                    "INSERT INTO events (event_id, timestamp, session_id, component, category, severity,"
                    " action, target, details, previous_hash, integrity_hash)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (event["event_id"], event["timestamp"], event["session_id"], event["component"],
                     event["category"], event["severity"], event["action"], event["target"],
                     json.dumps(event["details"], sort_keys=True, default=str),
                     event["previous_hash"], event["integrity_hash"]),
                )
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return event

    def add_test(self, record: dict) -> None:
        with closing(self._connect()) as db:
            db.execute(
                "INSERT INTO tests (test_id, timestamp, target, hostname, port, result, duration,"
                " component, details, event_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (record["test_id"], record["timestamp"], record["target"], record["hostname"],
                 record["port"], record["result"], record["duration"], record["component"],
                 json.dumps(record["details"], sort_keys=True, default=str), record["event_hash"]),
            )

    def add_certificate(self, label: str, details: dict) -> None:
        with closing(self._connect()) as db:
            db.execute(
                "INSERT INTO certificates (timestamp, label, subject, issuer, serial, fingerprint,"
                " not_before, not_after, details) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (now_iso(), label, details.get("subject", ""), details.get("issuer", ""),
                 details.get("serial_number", ""), details.get("sha256_fingerprint", ""),
                 details.get("not_before", ""), details.get("not_after", ""),
                 json.dumps(details, sort_keys=True, default=str)),
            )

    def start_session(self) -> None:
        with closing(self._connect()) as db:
            db.execute(
                "INSERT OR REPLACE INTO sessions (session_id, started, ended, platform,"
                " python_version, application_version) VALUES (?, ?, NULL, ?, ?, ?)",
                (self.session_id, now_iso(), PLATFORM_NAME, sys.version, __version__),
            )

    def end_session(self) -> None:
        with closing(self._connect()) as db:
            db.execute("UPDATE sessions SET ended=? WHERE session_id=?", (now_iso(), self.session_id))

    def recent_events(self, limit: int = 100) -> list:
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
        return [dict(row) for row in rows]

    def recent_tests(self, limit: int = 100) -> list:
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM tests ORDER BY id DESC LIMIT ?", (int(limit),)).fetchall()
        return [dict(row) for row in rows]

    def events_after(self, last_id: int, limit: int = 500) -> list:
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM events WHERE id>? ORDER BY id ASC LIMIT ?",
                              (int(last_id), int(limit))).fetchall()
        return [dict(row) for row in rows]

    def events_for_target(self, target: str, limit: int = 100) -> list:
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM events WHERE target=? ORDER BY id DESC LIMIT ?",
                              (str(target), int(limit))).fetchall()
        return [dict(row) for row in rows]

    def all_events(self) -> list:
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM events ORDER BY id ASC").fetchall()
        return [dict(row) for row in rows]

    def head_hash(self) -> str:
        with closing(self._connect()) as db:
            row = db.execute("SELECT integrity_hash FROM events ORDER BY id DESC LIMIT 1").fetchone()
        return row["integrity_hash"] if row else GENESIS

    def verify_chain(self, expect_head=None) -> dict:
        rows = self.all_events()
        previous = GENESIS
        failures = []
        for row in rows:
            event = dict(row)
            try:
                event["details"] = json.loads(row["details"])
            except json.JSONDecodeError:
                failures.append({"event_id": row["event_id"], "problem": "Details are not valid JSON"})
                previous = row["integrity_hash"]
                continue
            if row["previous_hash"] != previous:
                failures.append({"event_id": row["event_id"], "problem": "Previous hash mismatch"})
            expected = sha256_hex(_canonical(event).encode("utf-8"))
            if row["integrity_hash"] != expected:
                failures.append({"event_id": row["event_id"], "problem": "Integrity hash mismatch"})
            previous = row["integrity_hash"]
        if expect_head is not None and expect_head != previous:
            failures.append({"event_id": None, "problem": "Head hash does not match the expected anchor"})
        return {
            "records_checked": len(rows),
            "valid": not failures,
            "head": previous,
            "failures": failures,
        }
