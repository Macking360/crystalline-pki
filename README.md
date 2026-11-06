# crystalline-pki — a local PKI and TLS lab that explains itself

[![CI](https://github.com/Macking360/crystalline-pki/actions/workflows/ci.yml/badge.svg)](https://github.com/Macking360/crystalline-pki/actions/workflows/ci.yml)

crystalline-pki builds a private certificate authority on your own machine, runs
the whole certificate lifecycle (issue, enforce, renew, revoke), proves it with
real mutual-TLS connections, and examines any public HTTPS site the way a
browser would — then tells you what it found **in plain English**.

You type one thing: a website address. Everything else is automatic.

```
python -m pip install -r requirements.txt
python -m crystalline_pki auto https://example.org
```

## An open question for full-stack enterprise development

Every service in a modern stack proves who it is with a certificate, and almost
every outage-and-breach story contains a certificate nobody was watching: one
that expired, one that was never revoked, one issued to a device that no longer
exists. The identity layer is built once and then *assumed*.

**Who in your system is responsible for proving, every day, that each identity
is still valid, still needed, and still the right one — and what happens when
that job is nobody's?**

crystalline-pki is a small, honest laboratory for that question. It keeps an
authority (that issues and revokes) deliberately separate from a witness (that
only observes), and automates the unglamorous lifecycle work so you can see what
"nobody's job" looks like when it is somebody's. Fork it, point it at your own
architecture, and argue with it.

## What it does, automatically

| You do | The tool does |
|---|---|
| Type a URL | Validates it is a public HTTPS host, resolves and connects once, verifies the certificate chain, records timing for DNS, TCP, TLS and first byte |
| | If your operating system's trust store cannot complete the chain (common on Windows), finds a standard root bundle and retries |
| | Tests TLS 1.3 / 1.2 support and ALPN with extra handshakes that send no HTTP |
| | Sends exactly one `HEAD` request and analyses headers, cookies and server disclosure |
| | Grades the result, explains every finding (what we saw, why it matters, what to do) and tells the story of the connection in sentences |
| | Remembers the site and shows what changed on later visits (issuer, certificate, TLS version, cipher, DNS, status) |
| | Saves a text and a JSON report |
| Nothing | Creates the lab root, intermediate, server and client certificates on first run and verifies all 19 hierarchy checks |
| Nothing | Renews certificates before they expire (devices are rotated with a new key; the old certificate is revoked as superseded) |
| Nothing | Republishes the revocation list before it lapses and reloads the running server |
| Nothing | Starts the mutual-TLS server and runs six scenarios once as proof |
| Nothing | Anchors the audit log's head hash each cycle so rewritten history is detected |
| Nothing | Re-checks watched sites on a schedule while the web interface runs |

## Use it

### Web interface (default)

```
python -m crystalline_pki
```

Prepares the lab, serves **https://127.0.0.1:8080** using the lab's own server
certificate, prints a URL containing a private access token, and opens it.
Your browser will warn about the certificate because the lab created its own
authority a moment ago; that is expected. `crystalline-pki trust` prints the
commands to import the lab root if you want the warning gone. **The tool never
changes your trust stores itself.**

Tabs: Dashboard (examine a site, autopilot status, self-test), Lifecycle
(hierarchy diagram, enroll, rotate, revoke, phone `.p12` export), mTLS lab,
Site probe, Watchlist, Audit and logs (live event stream, hash-chain blocks,
verify), Learn (lessons, handshake diagram, glossary). Every section carries an
"explain" box.

### Command line

```
crystalline-pki auto <url>          prepare, examine, explain (add --brief or --json)
crystalline-pki web                 the HTTPS interface (--port, --no-open, --require-client-cert)
crystalline-pki maintain            one maintenance cycle; suited to Task Scheduler or cron
crystalline-pki trust               trust bundles found here and how to trust the lab root
crystalline-pki enroll NAME         device key + CSR + short-lived client certificate
crystalline-pki rotate NAME         new key, new certificate, old one revoked
crystalline-pki revoke ID           revoke by serial or name (--reason ...)
crystalline-pki lab                 the mutual-TLS scenarios
crystalline-pki audit verify        check the hash chain (--expect-head HASH)
crystalline-pki export p12 NAME     password-protected bundle for a phone
crystalline-pki probe <url>         raw JSON, no automation
```

Exit codes: `auto` returns 0 for grade C or better, 3 below that, 1 if the site
could not be verified.

## Safety

- The probe sends **one** `HEAD` request, never scans ports, never guesses paths.
  Submitting an address is your declaration that you own the site or may test
  it; the declaration is written to the audit log.
- Refused targets: non-HTTPS, IP literals, credentials in the URL, non-standard
  ports, and any name resolving to a private, loopback or link-local address.
- The web interface listens on loopback only and requires a per-run token
  (HttpOnly, Secure, SameSite=Strict cookie), checks `Host` (anti-rebinding),
  `Origin` and `X-Requested-With` on every POST, caps bodies at 1 MiB, and sends
  a strict CSP. It accepts no file paths from the browser.
- Cookie values and `Authorization`-class headers are redacted from results.

## Limitations — read these

- **Not a production CA.** Private keys are unencrypted PEM files, protected only
  by file permissions. Revocation uses a CRL, not OCSP. No ACME or EST yet.
- The audit chain is **tamper-evident, not tamper-proof**. Anyone who can write
  the database can rebuild the chain; the per-cycle anchor (`logs/audit-anchor.json`)
  only helps if you also store the head hash somewhere else.
- The grade is heuristic: 100 minus 40 per critical, 15 per error, 6 per warning.
  It is a guide, not a certification, and it only sees what a single connection reveals.
- Python reads the operating system's trust store. On Windows that store is
  populated lazily, so valid sites can fail until a root is installed; the
  fallback bundle handles this and the report says when it was used.
- On Python before 3.13 the full served chain is read through private `ssl`
  internals; if they are missing you get the leaf only, and the report says so.
- A phone is not a safe place for a CA. The intended mobile design is an outbound
  client with a hardware-bound key (Android Keystore, Secure Enclave) and
  attestation. That is **not implemented**; `.p12` export is a stopgap.
- Developed on Windows 11 with Python 3.12 and cryptography 46. CI runs the
  test suite on Linux and Windows with Python 3.11 and 3.12; macOS and Termux
  are untested.

## Connecting to OverWatch

This repository is the **authority and examiner**. Its sibling,
[OverWatch](https://github.com/Macking360/overwatch), is a read-only **witness**
for host integrity. They are separate programs with separate codebases. Nothing
is imported in either direction and they are not meant to be merged. The only
thing they share is the open-standard files that TLS already uses.

| Question | Answered by |
| --- | --- |
| Is this server and this device who it claims to be? | crystalline-pki issues the certificates |
| Has this device been tampered with since last time? | OverWatch watches files, processes and autoruns |
| How do the two meet? | A PEM certificate chain, a PEM CA file and a PEM key — nothing else |

OverWatch already has TLS settings that take ordinary PEM files, so the
connection is configuration, not integration. OpenSSL, step-ca or any other CA
can stand in for crystalline-pki without touching OverWatch.

### What was tested

On 2026-11-05 the walkthrough below was run end to end on Windows 11 against a
fresh clone of OverWatch, over loopback (`127.0.0.1`):

- OverWatch served HTTPS using a certificate chain issued by crystalline-pki.
- An agent with no trust configured **refused** the server
  (`CERTIFICATE_VERIFY_FAILED: unable to get local issuer certificate`).
- An agent given the lab root with `--ca-cert` **enrolled and delivered events**
  (`POST /api/enroll` 201, `POST /api/events` 202).
- An agent that also presented a crystalline-pki client certificate connected
  the same way.

### Walkthrough

1. Create the lab authority and a device identity:

   ```
   crystalline-pki init
   crystalline-pki enroll agent-laptop
   ```

2. Start the OverWatch server with the lab server certificate. Use
   `server-chain.pem` (server certificate **plus** intermediate) so clients that
   only trust the root can still build the chain:

   ```
   export OVERWATCH_TLS_CERT=~/.crystalline-pki/pki/server/server-chain.pem
   export OVERWATCH_TLS_KEY=~/.crystalline-pki/pki/server/server-key.pem
   python -m overwatch run
   ```

3. Start an agent that trusts the lab root:

   ```
   python -m overwatch agent --server https://127.0.0.1:8771 \
     --enroll-key <key from the OverWatch instance folder> \
     --name agent-laptop \
     --ca-cert ~/.crystalline-pki/pki/root/root-cert.pem \
     --watch-process
   ```

   Adjust the paths if you set `CRYSTALLINE_PKI_HOME` or `--home`. On Windows
   the default workspace is under your user profile; run
   `crystalline-pki status` to print the exact location.

4. Optional: have the agent present its device certificate with
   `--client-cert <issued chain .pem> --client-key <device key .pem>`
   (both are printed by `crystalline-pki enroll`).

### What this does not do

- **OverWatch does not check client certificates.** Its server does not ask for
  one, so the device certificate in step 4 is presented but never validated.
  Revoking it here changes the CRL and nothing else: in testing, an agent using
  a revoked certificate was still accepted. To cut a device off, revoke it in
  OverWatch (its Devices page and per-device token). Making OverWatch require
  and check client certificates is a change that belongs in OverWatch, not here.
- **The lab server certificate is valid only for `localhost` and `127.0.0.1`.**
  This release cannot issue a server certificate for another hostname, so an
  agent on a different machine will fail hostname verification. Use another CA
  for that, or treat this as the next feature to add.
- **Enrollment is not bridged.** OverWatch's enroll key and device token are
  independent of crystalline-pki's certificates. Nothing links the two
  identities.
- Keys are unencrypted PEM files. This is a lab, not a production CA.

The direction is the part that matters: certificates and CRLs are produced here,
host-integrity evidence is produced there, and a standard TLS handshake is the
only seam between them.

## Termux and Android

`pkg install python python-cryptography` then run the same commands. Use
`--no-open` and browse to the printed address. Untested on a device.
Mutual TLS from the phone side means importing the exported `.p12`.

## Layout

```
crystalline_pki/
  autopilot.py   the automation: prepare, maintain, examine
  advisor.py     grading and plain-English findings
  trust.py       finds fallback root bundles, trust instructions
  pki.py         authority: issue, revoke, rotate, renew, CRL, verification
  tlslab.py      mutual-TLS server and scenarios
  probe.py       the single-request public site examiner
  watchlist.py   change tracking
  audit.py       hash-chained SQLite log, text and JSONL logs
  webui.py, web/ the HTTPS interface
  cli.py         command line
tests/           41 tests incl. an OpenSSL cross-check of chains and revocation
```

Source files carry no comments by choice; explanations live in the interface
(`Learn`, per-check "why", per-finding guidance) and in this README.

## Name

The earlier single-file prototype was called CRYSTALLINE. This project is named
`crystalline-pki` to avoid colliding with the many unrelated projects that use
the bare name.

## License

MIT. See `LICENSE`.
