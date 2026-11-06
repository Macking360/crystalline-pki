from __future__ import annotations

import json
import threading
import time
from datetime import datetime, timezone

from . import trust
from .advisor import assess, narrative
from .pki import CLIENT_NAME, SERVER_NAME
from .probe import ProbeVerificationError, validate_url
from .reporting import render_probe
from .util import atomic_write, json_bytes, load_json, now_iso, safe_name

TRUST_ERROR_CODES = (20, 21)


class Autopilot:
    def __init__(self, app):
        self.app = app
        self.state_path = app.workspace.reports / "autopilot-state.json"
        self.anchor_path = app.workspace.logs / "audit-anchor.json"
        self.after_change = None
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = None

    def _load(self) -> dict:
        state = load_json(self.state_path, {})
        return state if isinstance(state, dict) else {}

    def _save(self, state: dict) -> None:
        atomic_write(self.state_path, json_bytes(state), 0o600)

    def state(self) -> dict:
        state = self._load()
        state["maintenance_minutes"] = int(self.app.config.get("auto_maintenance_minutes"))
        state["running"] = bool(self._thread and self._thread.is_alive())
        return state

    @staticmethod
    def _emit(steps, progress, title, text, status="ok"):
        step = {"title": title, "text": text, "status": status, "time": now_iso()}
        steps.append(step)
        if progress:
            progress(step)

    def detect_trust(self, steps, progress) -> dict:
        config = self.app.config
        configured = config.get("ca_bundle")
        summary = trust.system_store_summary()
        if configured:
            self._emit(steps, progress, "Trust bundle", "Using the bundle you configured: " + configured)
            return {"bundle": configured, "source": "configured", **summary}
        best = trust.best_ca_bundle()
        if best:
            self._emit(steps, progress, "Trust bundle",
                       "Found a fallback bundle (%s, %d roots) at %s. It is used automatically only when the operating system's store cannot verify a site." % (
                           best["source"], best["roots"], best["path"]))
            return {"bundle": best["path"], "source": best["source"], "roots": best["roots"], **summary}
        self._emit(steps, progress, "Trust bundle", "No fallback bundle found; the operating system's store is the only trust source.", "warn")
        return {"bundle": None, "source": None, **summary}

    def _renew(self, steps, progress) -> bool:
        pki, window = self.app.pki, int(self.app.config.get("renew_within_days"))
        changed = False
        expiring = pki.expiring(window)
        if not expiring:
            self._emit(steps, progress, "Renewal", "No certificate expires within %d days." % window)
            return False
        for record in expiring:
            try:
                if record["kind"] == "device":
                    pki.rotate_device(record["name"])
                elif record["name"] in (SERVER_NAME, CLIENT_NAME):
                    pki.renew_service(record["kind"])
                else:
                    continue
                changed = True
                self._emit(steps, progress, "Renewal", "%s had %d days left and was renewed with a new key; the old certificate was revoked as superseded." % (
                    record["name"], record["days_left"]))
            except Exception as error:
                self._emit(steps, progress, "Renewal", "Could not renew %s: %s" % (record["name"], error), "error")
        return changed

    def _anchor(self, steps, progress) -> None:
        audit = self.app.audit
        chain = audit.verify_chain()
        previous = load_json(self.anchor_path, {})
        if not chain["valid"]:
            self._emit(steps, progress, "Audit trail", "The hash chain is BROKEN: %s" % chain["failures"][:2], "error")
            return
        message = "%d events, chain intact." % chain["records_checked"]
        if isinstance(previous, dict) and previous.get("head"):
            known = {e["integrity_hash"] for e in audit.all_events()}
            if previous["head"] in known:
                message += " The head recorded earlier (%s...) is still part of the chain, so earlier history is unchanged." % previous["head"][:12]
            else:
                self._emit(steps, progress, "Audit trail", "The head hash recorded on %s is NOT in the chain: history was rewritten or truncated." % previous.get("time"), "error")
                return
        atomic_write(self.anchor_path, json_bytes({"head": chain["head"], "records": chain["records_checked"], "time": now_iso()}), 0o600)
        self._emit(steps, progress, "Audit trail", message + " New head recorded in logs/audit-anchor.json.")

    def run_cycle(self, progress=None, first_run=None) -> dict:
        with self._lock:
            app, steps = self.app, []
            state = self._load()
            started = time.monotonic()
            self._emit(steps, progress, "Workspace", "Workspace at %s (keys and logs are stored here)." % app.workspace.home)
            if not app.pki.ready():
                self._emit(steps, progress, "Authority", "No lab authority yet; creating root, intermediate, server and client certificates.", "running")
                app.pki.generate()
                self._emit(steps, progress, "Authority", "Created the lab authority.")
            else:
                self._emit(steps, progress, "Authority", "The lab authority exists.")
            verification = app.pki.verify_chain()
            self._emit(steps, progress, "Verification", "%d of %d hierarchy checks passed." % (
                verification["passed"], verification["passed"] + verification["failed"]),
                "ok" if verification["failed"] == 0 else "error")
            changed = self._renew(steps, progress)
            status = app.pki.crl_status()
            fresh = app.pki.ensure_fresh_crl(min_hours=48.0)
            if status.get("exists") and status["hours_left"] >= 48.0:
                self._emit(steps, progress, "Revocation list", "Revocation list #%d has %.0f hours left." % (fresh["number"], fresh["hours_left"]))
            else:
                self._emit(steps, progress, "Revocation list", "Republished the revocation list as #%d (valid %.0f hours)." % (fresh["number"], fresh["hours_left"]))
                changed = True
            if app.server.running and changed:
                app.server.reload()
            if changed and self.after_change:
                self.after_change()
            trust_info = self.detect_trust(steps, progress)
            if not app.server.running:
                note = ""
                try:
                    try:
                        info = app.server.start()
                    except OSError:
                        info = app.server.start(port=0)
                        note = " (the usual port %s is busy, probably another instance, so a free one was chosen)" % app.config.get("local_port")
                    self._emit(steps, progress, "Mutual TLS server", "Started on 127.0.0.1:%s%s; it accepts only certificates from the lab authority that are not revoked." % (info.get("port"), note))
                except Exception as error:
                    self._emit(steps, progress, "Mutual TLS server", "Could not start: %s" % error, "warn")
            else:
                self._emit(steps, progress, "Mutual TLS server", "Running on port %s." % app.server.port)
            selftest = state.get("selftest")
            if first_run is None:
                first_run = not selftest
            if first_run:
                self._emit(steps, progress, "Self-test", "Running the six mutual TLS scenarios once so the dashboard has proof.", "running")
                summary = app.lab.run_scenarios()
                selftest = {"time": now_iso(), "passed": summary["passed"], "steps": [
                    {k: s.get(k) for k in ("step", "expected", "outcome", "passed", "detail")} for s in summary["steps"]]}
                self._emit(steps, progress, "Self-test", "%d of %d scenarios behaved as expected." % (
                    sum(s["passed"] for s in summary["steps"]), len(summary["steps"])), "ok" if summary["passed"] else "error")
            self._anchor(steps, progress)
            watch_note = self._watch_due(state, steps, progress)
            result = {
                "time": now_iso(), "seconds": round(time.monotonic() - started, 2), "steps": steps,
                "healthy": all(s["status"] in ("ok", "running", "warn") for s in steps),
                "trust": trust_info, "selftest": selftest, "last_watch": watch_note or state.get("last_watch"),
            }
            result["last_cycle"] = {"time": result["time"], "steps": steps}
            merged = dict(state)
            merged.update({"last_cycle": result["last_cycle"], "trust": trust_info, "selftest": selftest, "healthy": result["healthy"]})
            if watch_note:
                merged["last_watch"] = watch_note
            self._save(merged)
            app.audit.record("Autopilot cycle finished", "autopilot", "AUTOPILOT", "INFO" if result["healthy"] else "WARNING",
                             details={"seconds": result["seconds"], "steps": [(s["title"], s["status"]) for s in steps]})
            return result

    def check_host(self, host: str) -> dict:
        result = self.app.watch.check(host)
        if result["status"] == "ERROR" and not self.app.config.get("ca_bundle") and any("issuer" in f["message"] for f in result["findings"]):
            bundle = trust.best_ca_bundle()
            if bundle:
                result = self.app.watch.check(host, cafile=bundle["path"])
        return result

    def check_all_hosts(self) -> list:
        return [self.check_host(record["host"]) for record in self.app.watch.list()]

    def _watch_due(self, state, steps, progress):
        interval = int(self.app.config.get("watch_interval_hours")) * 3600
        now = datetime.now(timezone.utc)
        due = []
        for record in self.app.watch.list():
            checked = record["last_checked"]
            if not checked or (now - datetime.fromisoformat(checked)).total_seconds() >= interval:
                due.append(record["host"])
        if not due:
            return None
        results = [self.check_host(host) for host in due]
        worst = max((r["status"] for r in results), key=("OK", "INFO", "WARNING", "ERROR", "CRITICAL").index, default="OK")
        self._emit(steps, progress, "Watchlist", "Checked %d watched site(s); worst status %s." % (len(results), worst),
                   "ok" if worst in ("OK", "INFO") else "warn")
        return {"time": now_iso(), "results": [{"host": r["host"], "status": r["status"], "findings": r["findings"]} for r in results]}

    def examine(self, url: str, progress=None, deep: bool = True) -> dict:
        app, steps = self.app, []
        parsed, host = validate_url(url)
        self._emit(steps, progress, "Address check", "%s is a public HTTPS address (no credentials, no private network, standard port)." % host)
        app.audit.record("Automated examination requested", "autopilot", "AUTOPILOT", "INFO", host,
                         {"authorization": "declared by submitting the address", "deep": deep})
        fallback = None
        try:
            self._emit(steps, progress, "Connection", "Resolving %s, connecting and verifying its certificate with the operating system's trust store." % host, "running")
            result = app.probe.examine(url, authorized=True, deep=deep)
        except ProbeVerificationError as error:
            diag = error.diagnosis
            bundle = None if app.config.get("ca_bundle") else trust.best_ca_bundle()
            if bundle and diag.get("verify_code") in TRUST_ERROR_CODES:
                self._emit(steps, progress, "Trust fallback",
                           "The system store could not complete the chain (%s). Retrying with %s." % (diag["verify_message"], bundle["source"]), "warn")
                fallback = {"reason": diag["verify_message"], "bundle": bundle}
                result = app.probe.examine(url, authorized=True, cafile=bundle["path"], deep=deep)
            else:
                raise
        self._emit(steps, progress, "Handshake", "%s with %s; %d certificate(s) in the chain." % (
            result["tls_version"], result["cipher"][0], len(result["chain"])))
        if fallback:
            result["trust_fallback"] = fallback
        result["assessment"] = assess(result)
        result["narrative"] = narrative(result)
        self._emit(steps, progress, "Assessment", "Grade %s (%d/100): %s" % (
            result["assessment"]["grade"], result["assessment"]["score"], result["assessment"]["verdict"]),
            "ok" if result["assessment"]["score"] >= 70 else "warn")
        if int(app.config.get("auto_watch")):
            watched = app.watch.observe(result["host"], result)
            result["watch"] = watched
            self._emit(steps, progress, "Change tracking", (
                "First time seen: this result is now the baseline for future comparisons." if watched.get("first_observation")
                else "Compared with the saved baseline: %s." % watched["status"]))
        stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
        base = app.workspace.reports / ("probe-%s-%s" % (safe_name(result["host"]), stamp))
        text = render_probe(result)
        atomic_write(base.with_suffix(".txt"), text.encode("utf-8"), 0o600)
        atomic_write(base.with_suffix(".json"), json.dumps(result, indent=2, default=str).encode("utf-8"), 0o600)
        result["report_files"] = {"text": str(base.with_suffix(".txt")), "json": str(base.with_suffix(".json"))}
        self._emit(steps, progress, "Reports saved", "Text and JSON copies are in %s." % app.workspace.reports)
        result["steps"] = steps
        app.audit.record("Automated examination finished", "autopilot", "AUTOPILOT", "INFO", host, {
            "grade": result["assessment"]["grade"], "score": result["assessment"]["score"],
            "findings": result["assessment"]["counts"], "trust_fallback": bool(fallback)})
        return result

    def start_background(self) -> bool:
        minutes = int(self.app.config.get("auto_maintenance_minutes"))
        if minutes == 0 or (self._thread and self._thread.is_alive()):
            return False
        self._stop.clear()

        def loop():
            while not self._stop.wait(minutes * 60):
                try:
                    self.run_cycle()
                except Exception as error:
                    self.app.audit.record("Autopilot cycle failed", "autopilot", "AUTOPILOT", "ERROR", details={"error": str(error)})

        self._thread = threading.Thread(target=loop, name="autopilot", daemon=True)
        self._thread.start()
        self.app.audit.record("Autopilot maintenance scheduled", "autopilot", "AUTOPILOT", "INFO", details={"every_minutes": minutes})
        return True

    def stop_background(self) -> None:
        self._stop.set()
        thread = self._thread
        if thread:
            thread.join(timeout=2)
        self._thread = None
