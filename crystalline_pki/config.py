
from __future__ import annotations

from pathlib import Path

from . import __version__
from .util import atomic_write, json_bytes, load_json

DEFAULTS = {
    "organization": "Crystalline PKI Lab",
    "country": "",
    "province": "",
    "rsa_bits": 3072,
    "certificate_days": 365,
    "device_days": 90,
    "crl_days": 7,
    "intermediate_days": 1825,
    "root_days": 3650,
    "local_port": 9443,
    "external_timeout": 8,
    "external_user_agent": "crystalline-pki/" + __version__,
    "theme": "plain",
    "ca_bundle": "",
    "auto_watch": 1,
    "auto_maintenance_minutes": 30,
    "renew_within_days": 21,
    "watch_interval_hours": 24,
}

THEMES = ("plain", "care-bears")


def _validate(data: dict) -> None:
    if int(data["rsa_bits"]) not in (2048, 3072, 4096):
        raise ValueError("rsa_bits must be 2048, 3072 or 4096")
    if not 1024 <= int(data["local_port"]) <= 65535:
        raise ValueError("local_port must be between 1024 and 65535")
    if not 2 <= int(data["external_timeout"]) <= 30:
        raise ValueError("external_timeout must be between 2 and 30 seconds")
    leaf, mid, root = (int(data["certificate_days"]), int(data["intermediate_days"]), int(data["root_days"]))
    if leaf < 1:
        raise ValueError("certificate_days must be at least 1")
    device = int(data["device_days"])
    if not 1 <= device < mid:
        raise ValueError("device_days must be at least 1 and less than intermediate_days")
    if not 1 <= int(data["crl_days"]) <= 30:
        raise ValueError("crl_days must be between 1 and 30")
    if not leaf < mid < root:
        raise ValueError("Lifetimes must nest: certificate_days < intermediate_days < root_days")
    organization = str(data["organization"]).strip()
    if not organization or len(organization) > 64:
        raise ValueError("organization must be 1 to 64 characters")
    country = str(data["country"])
    if country and not (len(country) == 2 and country.isalpha() and country.isupper()):
        raise ValueError("country must be empty or a two-letter uppercase code such as CA")
    if len(str(data["province"])) > 128:
        raise ValueError("province must be 128 characters or fewer")
    if data["theme"] not in THEMES:
        raise ValueError("theme must be one of: " + ", ".join(THEMES))
    bundle = str(data["ca_bundle"])
    if bundle and not Path(bundle).expanduser().is_file():
        raise ValueError("ca_bundle must be empty or the path of an existing file")
    if int(data["auto_watch"]) not in (0, 1):
        raise ValueError("auto_watch must be 0 or 1")
    if int(data["auto_maintenance_minutes"]) != 0 and not 5 <= int(data["auto_maintenance_minutes"]) <= 1440:
        raise ValueError("auto_maintenance_minutes must be 0 (off) or between 5 and 1440")
    if not 1 <= int(data["renew_within_days"]) <= 60:
        raise ValueError("renew_within_days must be between 1 and 60")
    if not 1 <= int(data["watch_interval_hours"]) <= 720:
        raise ValueError("watch_interval_hours must be between 1 and 720")
    agent = str(data["external_user_agent"])
    if not agent or len(agent) > 200 or any(ord(ch) < 32 or ord(ch) > 126 for ch in agent):
        raise ValueError("external_user_agent must be 1 to 200 printable ASCII characters")


class Config:
    def __init__(self, workspace):
        self.workspace = workspace
        stored = load_json(workspace.config_file, {})
        if not isinstance(stored, dict):
            stored = {}
        self.data = dict(DEFAULTS)
        self.data.update({k: v for k, v in stored.items() if k in DEFAULTS})
        try:
            _validate(self.data)
        except (ValueError, TypeError) as error:
            raise ValueError("Invalid configuration in %s: %s" % (workspace.config_file, error))
        if not workspace.config_file.exists():
            self.save()

    def get(self, key):
        return self.data[key]

    def set(self, key, value):
        if key not in DEFAULTS:
            raise KeyError("Unknown setting %r. Known: %s" % (key, ", ".join(sorted(DEFAULTS))))
        try:
            coerced = type(DEFAULTS[key])(value)
        except (TypeError, ValueError):
            raise ValueError("%s expects a %s" % (key, type(DEFAULTS[key]).__name__))
        candidate = dict(self.data)
        candidate[key] = coerced
        _validate(candidate)
        self.data = candidate
        self.save()
        return coerced

    def save(self):
        atomic_write(self.workspace.config_file, json_bytes(self.data), 0o600)
