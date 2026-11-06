from __future__ import annotations

from . import APP_NAME, __version__
from .audit import AuditLog
from .autopilot import Autopilot
from .certinspect import CertificateInspector
from .config import Config
from .exports import Exporter
from .pki import LocalPKI
from .platform_info import PLATFORM_NAME, diagnostics
from .probe import ExternalProbe
from .registry import Registry
from .tlslab import MutualTLSServer, TLSLab
from .watchlist import Watchlist
from .workspace import Workspace


class App:
    def __init__(self, home=None):
        self.workspace = Workspace(home)
        self.workspace.ensure()
        self.audit = AuditLog(self.workspace)
        self.config = Config(self.workspace)
        self.registry = Registry(self.workspace)
        self.pki = LocalPKI(self.workspace, self.config, self.audit, self.registry)
        self.inspector = CertificateInspector(self.audit)
        self.server = MutualTLSServer(self.workspace, self.config, self.audit, self.pki)
        self.lab = TLSLab(self.workspace, self.config, self.audit, self.registry, self.pki, self.server)
        self.probe = ExternalProbe(self.config, self.audit)
        self.watch = Watchlist(self.workspace, self.audit, self.probe)
        self.exporter = Exporter(self.workspace, self.audit, self.registry)
        self.autopilot = Autopilot(self)
        self._closed = False
        self.audit.start_session()
        self.audit.record("Session started", "app", "SESSION", "INFO",
                          details={"version": __version__, "platform": PLATFORM_NAME})

    def status(self) -> dict:
        ready = self.pki.ready()
        records = self.registry.list() if ready else []
        chain = self.audit.verify_chain()
        return {
            "application": APP_NAME,
            "version": __version__,
            "workspace": str(self.workspace.home),
            "pki_ready": ready,
            "crl": self.pki.crl_status() if ready else {"exists": False},
            "certificates": {
                "active": sum(r["state"] == "active" for r in records),
                "revoked": sum(r["state"] == "revoked" for r in records),
                "expired": sum(r["state"] == "expired" for r in records),
                "expiring_30_days": len(self.pki.expiring(30)) if ready else 0,
            },
            "audit": {"records": chain["records_checked"], "valid": chain["valid"], "head": chain["head"]},
            "mtls_server": {"running": self.server.running, "port": self.server.port},
            "watched_hosts": len(self.watch.list()),
        }

    def report_data(self) -> dict:
        return {
            "application": APP_NAME,
            "version": __version__,
            "diagnostics": diagnostics(self.workspace),
            "status": self.status(),
            "certificates": self.registry.list(),
            "watchlist": self.watch.list(),
            "recent_events": self.audit.recent_events(100),
            "recent_tests": self.audit.recent_tests(100),
        }

    def close(self) -> None:
        if self._closed:
            return
        self._closed = True
        try:
            self.autopilot.stop_background()
            self.server.stop()
        finally:
            self.audit.record("Session ended", "app", "SESSION", "INFO")
            self.audit.end_session()
            self.audit.close()
