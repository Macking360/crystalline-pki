from __future__ import annotations

import sqlite3
from contextlib import closing
from datetime import datetime, timezone

from .util import now_dt, now_iso

_SCHEMA = (
    """CREATE TABLE IF NOT EXISTS issued (
        serial TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        kind TEXT NOT NULL,
        subject TEXT NOT NULL,
        not_before TEXT NOT NULL,
        not_after TEXT NOT NULL,
        fingerprint TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'active',
        revoked_at TEXT,
        reason TEXT,
        cert_path TEXT,
        chain_path TEXT,
        key_path TEXT,
        created TEXT NOT NULL
    )""",
    "CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)",
    "CREATE INDEX IF NOT EXISTS issued_name ON issued(name)",
)


class Registry:
    def __init__(self, workspace):
        workspace.ensure()
        self.workspace = workspace
        with closing(self._connect()) as db:
            for statement in _SCHEMA:
                db.execute(statement)

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.workspace.database), timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout=30000")
        return connection

    @staticmethod
    def _decorate(row) -> dict:
        record = dict(row)
        not_after = datetime.fromisoformat(record["not_after"])
        delta = not_after - now_dt()
        record["days_left"] = int(delta.total_seconds() // 86400)
        if record["status"] == "revoked":
            record["state"] = "revoked"
        elif delta.total_seconds() <= 0:
            record["state"] = "expired"
        else:
            record["state"] = "active"
        return record

    def add(self, record: dict) -> None:
        with closing(self._connect()) as db:
            db.execute(
                "INSERT INTO issued (serial, name, kind, subject, not_before, not_after, fingerprint,"
                " status, cert_path, chain_path, key_path, created)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?, ?)",
                (record["serial"], record["name"], record["kind"], record["subject"],
                 record["not_before"], record["not_after"], record["fingerprint"],
                 record.get("cert_path"), record.get("chain_path"), record.get("key_path"), now_iso()),
            )

    def list(self, kind=None) -> list:
        with closing(self._connect()) as db:
            if kind:
                rows = db.execute("SELECT * FROM issued WHERE kind=? ORDER BY created DESC, rowid DESC", (kind,)).fetchall()
            else:
                rows = db.execute("SELECT * FROM issued ORDER BY created DESC, rowid DESC").fetchall()
        return [self._decorate(row) for row in rows]

    def get(self, identifier: str):
        key = str(identifier).strip().lower()
        with closing(self._connect()) as db:
            row = db.execute("SELECT * FROM issued WHERE serial=?", (key,)).fetchone()
            if row is None:
                row = db.execute(
                    "SELECT * FROM issued WHERE name=? ORDER BY (status='active') DESC, created DESC, rowid DESC LIMIT 1",
                    (str(identifier).strip(),),
                ).fetchone()
        return self._decorate(row) if row else None

    def active_for(self, name: str) -> list:
        return [r for r in self.list() if r["name"] == name and r["state"] == "active"]

    def revoked(self) -> list:
        with closing(self._connect()) as db:
            rows = db.execute("SELECT * FROM issued WHERE status='revoked' ORDER BY revoked_at").fetchall()
        return [self._decorate(row) for row in rows]

    def mark_revoked(self, serial: str, reason: str) -> None:
        with closing(self._connect()) as db:
            db.execute(
                "UPDATE issued SET status='revoked', revoked_at=?, reason=? WHERE serial=?",
                (now_iso(), reason, serial),
            )

    def next_crl_number(self) -> int:
        with closing(self._connect()) as db:
            db.execute("BEGIN IMMEDIATE")
            try:
                row = db.execute("SELECT value FROM meta WHERE key='crl_number'").fetchone()
                number = int(row["value"]) + 1 if row else 1
                db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('crl_number', ?)", (str(number),))
                db.execute("COMMIT")
            except BaseException:
                db.execute("ROLLBACK")
                raise
        return number

    def clear(self) -> None:
        with closing(self._connect()) as db:
            db.execute("DELETE FROM issued")
            db.execute("DELETE FROM meta")
