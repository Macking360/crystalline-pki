from __future__ import annotations

import argparse
import getpass
import json
import sys
import time
from pathlib import Path

from . import APP_NAME, __version__
from .app import App
from .config import DEFAULTS
from .knowledge import GLOSSARY, LESSONS
from .pki import REASONS
from .probe import ProbeVerificationError
from .platform_info import diagnostics
from .reporting import render_assessment, render_probe


def emit(value) -> None:
    print(json.dumps(value, indent=2, default=str))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog=APP_NAME, description="Local PKI, X.509 and TLS research lab")
    parser.add_argument("--home", help="workspace directory (default ~/.crystalline-pki)")
    parser.add_argument("--version", action="store_true", help="show the version and exit")
    sub = parser.add_subparsers(dest="command")

    init = sub.add_parser("init", help="create the lab root, intermediate, server and client certificates")
    init.add_argument("--replace", action="store_true", help="replace an existing PKI (the old one is backed up)")

    sub.add_parser("status", help="summary of the workspace")
    sub.add_parser("verify", help="verify the lab certificate hierarchy")
    sub.add_parser("list", help="list issued certificates")

    enroll = sub.add_parser("enroll", help="create a device key and request, then issue its certificate")
    enroll.add_argument("name")
    enroll.add_argument("--days", type=int)

    issue = sub.add_parser("issue-csr", help="issue a client certificate from a PEM certificate request")
    issue.add_argument("csr", help="path to the .csr.pem file")
    issue.add_argument("--name")
    issue.add_argument("--days", type=int)

    rotate = sub.add_parser("rotate", help="give a device a new key and certificate and revoke the old one")
    rotate.add_argument("name")
    rotate.add_argument("--destroy-old-key", action="store_true")

    revoke = sub.add_parser("revoke", help="revoke a certificate by serial number or name")
    revoke.add_argument("identifier")
    revoke.add_argument("--reason", default="unspecified", choices=sorted(REASONS))

    crl = sub.add_parser("crl", help="show or republish the revocation list")
    crl.add_argument("action", choices=("show", "refresh"), nargs="?", default="show")

    inspect = sub.add_parser("inspect", help="inspect a PEM or DER certificate file")
    inspect.add_argument("path")

    serve = sub.add_parser("serve", help="run the loopback mutual TLS server until interrupted")
    serve.add_argument("--port", type=int)

    sub.add_parser("lab", help="run the mutual TLS scenarios: accepted, no certificate, revoked, rotated")

    auto = sub.add_parser("auto", help="fully automatic: prepare the lab, examine a site, explain the result in plain English")
    auto.add_argument("url")
    auto.add_argument("--brief", action="store_true", help="print only the plain-English summary and findings")
    auto.add_argument("--json", action="store_true", help="print the complete result as JSON")
    auto.add_argument("--no-deep", action="store_true", help="skip the extra protocol-support handshakes")

    sub.add_parser("maintain", help="one automatic maintenance cycle (renew, republish revocation list, check logs); suited to a scheduler")
    sub.add_parser("trust", help="show trust bundles found on this computer and how to trust the lab root")

    web = sub.add_parser("web", aliases=["gui"], help="start the HTTPS web interface (default command)")
    web.add_argument("--port", type=int, default=8080)
    web.add_argument("--no-open", action="store_true", help="do not open a browser window")
    web.add_argument("--require-client-cert", action="store_true", help="only accept browsers presenting a lab client certificate")

    probe = sub.add_parser("probe", help="raw JSON from one HEAD request to a public HTTPS site (no automation)")
    probe.add_argument("url")
    probe.add_argument("--cafile", help="PEM bundle of trusted roots to use instead of the system store")
    probe.add_argument("--deep", action="store_true", help="also test TLS version support")

    watch = sub.add_parser("watch", help="track a public site's certificate and TLS posture over time")
    watch_sub = watch.add_subparsers(dest="watch_command", required=True)
    watch_add = watch_sub.add_parser("add")
    watch_add.add_argument("host")
    watch_sub.add_parser("list")
    for name in ("check", "accept", "remove"):
        item = watch_sub.add_parser(name)
        item.add_argument("host")
    watch_sub.add_parser("check-all")

    audit = sub.add_parser("audit", help="audit log tools")
    audit_sub = audit.add_subparsers(dest="audit_command", required=True)
    audit_verify = audit_sub.add_parser("verify")
    audit_verify.add_argument("--expect-head")
    audit_sub.add_parser("head")
    audit_tail = audit_sub.add_parser("tail")
    audit_tail.add_argument("-n", type=int, default=20)
    audit_sub.add_parser("export-csv")

    export = sub.add_parser("export", help="export certificates or a device bundle")
    export_sub = export.add_subparsers(dest="export_command", required=True)
    export_sub.add_parser("certs")
    p12 = export_sub.add_parser("p12", help="password-protected PKCS#12 bundle for importing onto a phone")
    p12.add_argument("name")
    p12.add_argument("--legacy", action="store_true", help="use older 3DES encryption for old devices")

    report = sub.add_parser("report", help="write a JSON report")
    report.add_argument("--name", default="crystalline-pki")

    config = sub.add_parser("config", help="show or change settings")
    config_sub = config.add_subparsers(dest="config_command", required=True)
    config_sub.add_parser("show")
    config_set = config_sub.add_parser("set")
    config_set.add_argument("key")
    config_set.add_argument("value")

    sub.add_parser("diag", help="platform and dependency diagnostics")
    sub.add_parser("learn", help="print the lessons and glossary")
    return parser


SCOPE_NOTICE = ("By giving this address you confirm you own the site or may test it. "
                "Exactly one HEAD request is sent; nothing is scanned, guessed or attacked.")
MARKS = {"ok": "[ ok ]", "running": "[ .. ]", "warn": "[warn]", "error": "[FAIL]"}


def show_step(step) -> None:
    print("%s %-18s %s" % (MARKS.get(step.get("status"), "[ ok ]"), step["title"], step["text"]), flush=True)


def run_web(app, args) -> int:
    import webbrowser
    from .webui import WebUI
    sys.stdout.reconfigure(line_buffering=True)
    ui = WebUI(app, port=args.port, require_client_cert=args.require_client_cert)
    print("Preparing the lab automatically...\n")
    try:
        info = ui.start(progress=show_step)
    except OSError as error:
        print("Could not listen on 127.0.0.1:%d (%s). Try --port with another number." % (args.port, error), file=sys.stderr)
        return 1
    print("\nWeb interface ready. Open this address (it contains your private access token):\n\n  %s\n" % info["url"])
    print("Your browser will warn that the certificate is not trusted: the lab created its own authority a moment ago.")
    print("That is expected. To remove the warning run: crystalline-pki trust\n")
    print("Automatic maintenance runs every %s minutes. Press Ctrl+C to stop." % app.config.get("auto_maintenance_minutes"))
    if not args.no_open:
        webbrowser.open(info["url"])
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping.")
    finally:
        ui.stop()
    return 0


def run_auto(app, args) -> int:
    print(SCOPE_NOTICE + "\n")
    app.autopilot.run_cycle(show_step)
    print()
    try:
        result = app.autopilot.examine(args.url, progress=show_step, deep=not args.no_deep)
    except ProbeVerificationError as error:
        print("\nCould not verify the site: %s\n" % error)
        diagnosis = error.diagnosis
        print("Trust store used:  " + diagnosis["trust_store"])
        print("Verify message:    " + diagnosis["verify_message"])
        served = diagnosis["served_certificate"]
        for cert in served.get("chain", []):
            print("Served (unverified): %s issued by %s, %d days left" % (cert["subject"], cert["issuer"], cert["days_remaining"]))
        return 1
    print()
    if args.json:
        emit(result)
    elif args.brief:
        print("\n".join(render_assessment(result)))
    else:
        print(render_probe(result))
    print("\nSaved: " + result["report_files"]["text"])
    print("Saved: " + result["report_files"]["json"])
    return 0 if result["assessment"]["score"] >= 70 else 3


def run_trust(app) -> int:
    from . import trust
    print("Trust bundles found on this computer (used automatically only as a fallback):\n")
    found = trust.find_ca_bundles()
    for item in found:
        print("  %-26s %4d roots  %s" % (item["source"], item["roots"], item["path"]))
    if not found:
        print("  none")
    print("\n" + trust.system_store_summary()["note"])
    print("\nTo make your browser trust this lab's own web interface, import the root certificate:\n  %s\n" % app.workspace.root_cert)
    for entry in trust.root_trust_instructions(app.workspace.root_cert):
        print("  %-26s %s" % (entry["platform"], entry["command"]))
    print("\nOnly trust a root you created yourself. This tool never changes your trust stores on its own.")
    return 0


def run(app: App, args) -> int:
    command = args.command
    if command == "init":
        emit(app.pki.generate(replace=args.replace))
    elif command == "status":
        emit(app.status())
    elif command == "verify":
        result = app.pki.verify_chain()
        emit(result)
        return 0 if result["failed"] == 0 else 1
    elif command == "list":
        emit(app.registry.list())
    elif command == "enroll":
        emit(app.pki.enroll_device(args.name, args.days))
    elif command == "issue-csr":
        emit(app.pki.issue_from_csr(Path(args.csr).read_bytes(), name=args.name, days=args.days))
    elif command == "rotate":
        emit(app.pki.rotate_device(args.name, args.destroy_old_key))
    elif command == "revoke":
        emit(app.pki.revoke(args.identifier, args.reason))
    elif command == "crl":
        if args.action == "refresh":
            emit(app.pki.refresh_crl())
        emit(app.pki.crl_status())
    elif command == "inspect":
        emit(app.inspector.inspect(args.path))
    elif command == "serve":
        info = app.server.start(port=args.port)
        emit(info)
        print("Press Ctrl+C to stop.", file=sys.stderr)
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            emit(app.server.stop())
    elif command == "lab":
        result = app.lab.run_scenarios()
        emit(result)
        return 0 if result["passed"] else 1
    elif command == "auto":
        return run_auto(app, args)
    elif command == "maintain":
        result = app.autopilot.run_cycle(show_step)
        return 0 if result["healthy"] else 1
    elif command == "trust":
        return run_trust(app)
    elif command == "probe":
        try:
            emit(app.probe.examine(args.url, authorized=True, cafile=args.cafile, deep=args.deep))
        except ProbeVerificationError as error:
            emit({"error": str(error), "diagnosis": error.diagnosis})
            return 1
    elif command == "watch":
        sub = args.watch_command
        if sub == "add":
            print(SCOPE_NOTICE, file=sys.stderr)
            emit(app.watch.add(args.host, authorized=True))
        elif sub == "list":
            emit(app.watch.list())
        elif sub == "check":
            emit(app.watch.check(args.host))
        elif sub == "check-all":
            emit(app.watch.check_all())
        elif sub == "accept":
            emit(app.watch.accept(args.host))
        elif sub == "remove":
            app.watch.remove(args.host)
            emit({"removed": args.host})
    elif command == "audit":
        sub = args.audit_command
        if sub == "verify":
            result = app.audit.verify_chain(expect_head=args.expect_head)
            emit(result)
            return 0 if result["valid"] else 1
        elif sub == "head":
            print(app.audit.head_hash())
        elif sub == "tail":
            emit(app.audit.recent_events(args.n))
        elif sub == "export-csv":
            emit({"path": str(app.exporter.export_events_csv())})
    elif command == "export":
        if args.export_command == "certs":
            emit(app.exporter.export_public_certificates())
        else:
            password = getpass.getpass("Bundle password (8+ characters): ")
            emit(app.exporter.export_device_bundle(args.name, password, legacy=args.legacy))
    elif command == "report":
        emit({"report": str(app.exporter.report(args.name, app.report_data()))})
    elif command == "config":
        if args.config_command == "show":
            emit(app.config.data)
        else:
            emit({args.key: app.config.set(args.key, args.value)})
    elif command == "diag":
        emit(diagnostics(app.workspace))
    elif command == "learn":
        for title, body in LESSONS:
            print("== %s\n%s\n" % (title, body))
        for term, meaning in GLOSSARY.items():
            print("%s: %s" % (term, meaning))
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.version:
        print(APP_NAME, __version__)
        return 0
    if args.command is None:
        raw = list(sys.argv[1:] if argv is None else argv)
        args = parser.parse_args(raw + ["web"])
    app = None
    try:
        app = App(args.home)
        if args.command in ("web", "gui"):
            return run_web(app, args)
        return run(app, args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except (ValueError, RuntimeError, PermissionError, FileNotFoundError, KeyError) as error:
        print("%s error: %s" % (APP_NAME, error), file=sys.stderr)
        return 1
    finally:
        if app is not None:
            app.close()
