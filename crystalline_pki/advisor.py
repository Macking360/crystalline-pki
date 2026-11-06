from __future__ import annotations

PENALTY = {"CRITICAL": 40, "ERROR": 15, "WARNING": 6, "INFO": 0}
ORDER = ("CRITICAL", "ERROR", "WARNING", "INFO")
GRADES = ((90, "A"), (80, "B"), (70, "C"), (60, "D"), (0, "F"))


def _finding(level, area, title, what, why, fix):
    return {"level": level, "area": area, "title": title, "what": what, "why": why, "fix": fix}


def _passed(area, title, what):
    return {"area": area, "title": title, "what": what}


def _tls_checks(result, findings, passed):
    tls = result["tls"]
    version = tls["version"]
    if version == "TLSv1.3":
        passed.append(_passed("Protocol", "Modern TLS version", "The connection used TLS 1.3, the current version, which removes every legacy option."))
    elif version == "TLSv1.2" and not (result.get("protocol_support") and
                                        not result["protocol_support"]["tls_versions"].get("TLSv1.3", {}).get("supported")):
        findings.append(_finding("INFO", "Protocol", "Negotiated TLS 1.2, not 1.3",
                                 "This server chose TLS 1.2 although this client also offers TLS 1.3.",
                                 "TLS 1.2 is still considered secure with a good cipher, but TLS 1.3 is faster and safer by design.",
                                 "Enable TLS 1.3 in the web server or CDN settings."))
    elif version not in ("TLSv1.2",):
        findings.append(_finding("ERROR", "Protocol", "Outdated TLS version " + version,
                                 "The connection used " + version + ".", "Versions before TLS 1.2 have known attacks and are rejected by modern clients.",
                                 "Disable everything below TLS 1.2 on the server."))
    if tls["assessment"]["forward_secrecy"]:
        passed.append(_passed("Cipher", "Forward secrecy", "Each session uses throwaway keys, so a future theft of the server key cannot decrypt recorded traffic."))
    else:
        findings.append(_finding("ERROR", "Cipher", "No forward secrecy",
                                 "The cipher suite %s does not use an ephemeral key exchange." % tls["cipher_name"],
                                 "If the server's private key is ever stolen, all previously recorded traffic can be decrypted.",
                                 "Prefer ECDHE cipher suites or TLS 1.3."))
    if tls["assessment"]["authenticated_encryption"]:
        passed.append(_passed("Cipher", "Authenticated encryption", "The cipher (%s) both encrypts and detects tampering." % tls["cipher_name"]))
    else:
        findings.append(_finding("WARNING", "Cipher", "Cipher is not an AEAD mode",
                                 "%s does not provide built-in tamper detection." % tls["cipher_name"],
                                 "Older CBC-style suites have a history of padding-oracle attacks.",
                                 "Prefer AES-GCM or ChaCha20-Poly1305 suites."))
    if tls["compression"]:
        findings.append(_finding("ERROR", "Protocol", "TLS compression is enabled",
                                 "The session negotiated compression: %s." % tls["compression"],
                                 "Compression inside TLS enables the CRIME attack, which can recover secrets.",
                                 "Disable TLS-level compression."))
    else:
        passed.append(_passed("Protocol", "No TLS compression", "Compression is off, which avoids the CRIME attack."))
    bits = tls["cipher_secret_bits"]
    if bits and bits < 128:
        findings.append(_finding("ERROR", "Cipher", "Weak cipher strength",
                                 "The cipher offers only %s secret bits." % bits, "Under 128 bits can be brute-forced.", "Use 128-bit or stronger ciphers."))
    support = result.get("protocol_support")
    if support:
        versions = support["tls_versions"]
        if not versions.get("TLSv1.3", {}).get("supported"):
            findings.append(_finding("WARNING", "Protocol", "TLS 1.3 not supported",
                                     "A handshake restricted to TLS 1.3 failed.", "Missing TLS 1.3 means slower connections and no 1.3-only protections.",
                                     "Upgrade the TLS library or enable TLS 1.3."))
        else:
            passed.append(_passed("Protocol", "TLS 1.3 supported", "A handshake restricted to TLS 1.3 succeeded."))
        if not versions.get("TLSv1.2", {}).get("supported"):
            findings.append(_finding("INFO", "Protocol", "TLS 1.2 not supported",
                                     "A handshake restricted to TLS 1.2 failed.", "Visitors with older software will be unable to connect.",
                                     "Keep TLS 1.2 enabled unless every client is known to support 1.3."))
        alpn = support["alpn_preference"].get("negotiated")
        if alpn == "h2":
            passed.append(_passed("Protocol", "HTTP/2 available", "The server picked h2 when offered; pages load over multiplexed connections."))
        elif alpn is None:
            findings.append(_finding("INFO", "Protocol", "No ALPN negotiation",
                                     "The server did not select an application protocol.", "Without ALPN, browsers cannot upgrade to HTTP/2.", "Enable HTTP/2."))


def _certificate_checks(result, findings, passed):
    leaf = result["certificate"]
    days = leaf["days_remaining"]
    if days <= 0:
        findings.append(_finding("CRITICAL", "Certificate", "Certificate expired", "The certificate ended %d days ago." % abs(days),
                                 "Browsers refuse to connect.", "Renew and deploy a new certificate immediately."))
    elif days <= 7:
        findings.append(_finding("ERROR", "Certificate", "Certificate expires in %d days" % days, "The end date is very close.",
                                 "An outage starts the moment it expires.", "Renew now and confirm automatic renewal works."))
    elif days <= 21:
        findings.append(_finding("WARNING", "Certificate", "Certificate expires in %d days" % days, "Renewal is due soon.",
                                 "Automated renewals typically start 30 days out; this one has not.", "Check the renewal job."))
    else:
        passed.append(_passed("Certificate", "Plenty of validity left", "%d days remain until %s." % (days, leaf["not_after"][:10])))
    if leaf["public_key_type"] == "RSA" and int(leaf["public_key_detail"]) < 2048:
        findings.append(_finding("ERROR", "Certificate", "Short RSA key", "The key is %s bits." % leaf["public_key_detail"],
                                 "Keys under 2048 bits are considered breakable.", "Reissue with RSA 2048+ or an EC P-256 key."))
    else:
        passed.append(_passed("Certificate", "Key strength", "%s %s is considered strong." % (leaf["public_key_type"], leaf["public_key_detail"])))
    if leaf.get("signature_hash") in ("md5", "sha1"):
        findings.append(_finding("ERROR", "Certificate", "Weak signature hash", "Signed with %s." % leaf["signature_hash"],
                                 "Collisions can be manufactured for this hash.", "Reissue with SHA-256 or stronger."))
    if not leaf["subject_alternative_names"]:
        findings.append(_finding("WARNING", "Certificate", "No subject alternative names", "The certificate lists no SAN entries.",
                                 "Modern browsers ignore the common name and require SANs.", "Reissue with the hostnames in the SAN extension."))
    if leaf["validity_days"] > 398:
        findings.append(_finding("INFO", "Certificate", "Long lifetime of %d days" % leaf["validity_days"],
                                 "The certificate was valid for longer than 398 days.",
                                 "Browsers reject public certificates issued after 2020 with lifetimes over 398 days; shorter lifetimes limit damage from key theft.",
                                 "Use short-lived, automatically renewed certificates."))
    if not leaf["ocsp_urls"] and not leaf["crl_distribution_points"]:
        findings.append(_finding("INFO", "Revocation", "No revocation endpoints", "The certificate lists neither OCSP nor CRL locations.",
                                 "Clients have no standard way to learn it was revoked.", "Use an issuer that publishes OCSP or CRL information."))
    else:
        passed.append(_passed("Revocation", "Revocation endpoints listed", "Clients can check for revocation (OCSP: %d, CRL: %d)." % (
            len(leaf["ocsp_urls"]), len(leaf["crl_distribution_points"]))))
    if not leaf["signed_certificate_timestamps"]:
        findings.append(_finding("INFO", "Transparency", "No Certificate Transparency proofs",
                                 "No embedded SCTs were found.", "Public CAs log certificates so mis-issuance can be detected; browsers expect proofs.",
                                 "Ignore for private CAs; for public sites reissue from a CA that logs."))
    else:
        passed.append(_passed("Transparency", "Certificate Transparency", "%d log proofs are embedded." % len(leaf["signed_certificate_timestamps"])))
    odd = [c for c in result["chain"] if not c.get("serial_positive", True)]
    if odd:
        findings.append(_finding("INFO", "Chain", "Non-positive serial number in the chain",
                                 "%d certificate(s) have a zero or negative serial: %s." % (len(odd), "; ".join(c["subject"] for c in odd)),
                                 "RFC 5280 requires positive serial numbers. Today's browsers accept the chain, but newer software may reject it.",
                                 "Ask the issuing CA to reissue; nothing for the site owner to change if the fault is in an intermediate."))
    if result["chain_source"] == "leaf-only":
        findings.append(_finding("INFO", "Chain", "Only the leaf was visible",
                                 "This Python build cannot expose the full served chain.", "The intermediate and root cannot be shown.", "Use Python 3.13 or newer."))
    elif len(result["chain"]) < 2:
        findings.append(_finding("WARNING", "Chain", "Server sent a single certificate",
                                 "No intermediate certificate was presented.", "Clients that do not already know the intermediate will fail to verify the site.",
                                 "Serve the full chain (leaf plus intermediates)."))
    else:
        passed.append(_passed("Chain", "Complete chain presented", "%d certificates were served and verified to a trusted root." % len(result["chain"])))


def _header_checks(result, findings, passed):
    analysis = result["response"]["analysis"]
    table = {s["header"]: s for s in analysis["security_headers"]}
    hsts = table["strict-transport-security"]
    if not hsts["present"]:
        findings.append(_finding("WARNING", "Headers", "No HSTS", "The strict-transport-security header was not sent.",
                                 "Without it, a first visit over plain HTTP can be intercepted and downgraded.",
                                 "Send Strict-Transport-Security: max-age=31536000; includeSubDomains"))
    elif hsts["level"] != "OK":
        findings.append(_finding("WARNING", "Headers", "Weak HSTS", hsts["assessment"], "A short lifetime lets the protection lapse.", "Raise max-age to at least one year."))
    else:
        passed.append(_passed("Headers", "HSTS", hsts["assessment"]))
    if not table["content-security-policy"]["present"]:
        findings.append(_finding("WARNING", "Headers", "No Content-Security-Policy", "No CSP header was sent.",
                                 "CSP limits the damage of injected scripts (XSS).", "Add a CSP that lists the origins your pages need."))
    elif table["content-security-policy"]["level"] != "OK":
        findings.append(_finding("WARNING", "Headers", "Permissive CSP", table["content-security-policy"]["assessment"],
                                 "unsafe-inline weakens the main protection CSP offers.", "Replace inline scripts with nonces or hashes."))
    else:
        passed.append(_passed("Headers", "Content-Security-Policy", "A policy is present."))
    if not table["x-content-type-options"]["present"]:
        findings.append(_finding("INFO", "Headers", "No X-Content-Type-Options", "Not sent.", "Browsers may guess content types and run uploads as scripts.",
                                 "Send X-Content-Type-Options: nosniff"))
    if not table["x-frame-options"]["present"] and "frame-ancestors" not in (table["content-security-policy"].get("value") or ""):
        findings.append(_finding("INFO", "Headers", "Framing not restricted", "Neither X-Frame-Options nor CSP frame-ancestors is set.",
                                 "Other sites could embed this one to trick users into clicking (clickjacking).", "Send X-Frame-Options: DENY or CSP frame-ancestors."))
    if not table["referrer-policy"]["present"]:
        findings.append(_finding("INFO", "Headers", "No Referrer-Policy", "Not sent.", "Full URLs may leak to other sites when users click away.",
                                 "Send Referrer-Policy: strict-origin-when-cross-origin"))
    if analysis["cookie_notes"]:
        findings.append(_finding("WARNING", "Cookies", "%d cookie flag problem(s)" % len(analysis["cookie_notes"]),
                                 "; ".join(analysis["cookie_notes"][:4]), "Missing Secure, HttpOnly or SameSite makes cookies easier to steal or misuse.",
                                 "Set Secure; HttpOnly; SameSite=Lax (or Strict) on session cookies."))
    elif analysis["cookies"]:
        passed.append(_passed("Cookies", "Cookie flags", "All %d cookies carry Secure, HttpOnly and SameSite." % len(analysis["cookies"])))
    versioned = [d for d in analysis["disclosure"] if any(ch.isdigit() for ch in d["value"])]
    if versioned:
        findings.append(_finding("INFO", "Disclosure", "Software versions are advertised",
                                 ", ".join("%s: %s" % (d["header"], d["value"]) for d in versioned),
                                 "Exact versions help attackers pick known exploits.", "Remove or generalise the Server and X-Powered-By headers."))
    status = result["http_status"]
    location = dict((k.lower(), v) for k, v in result["response"]["headers"]).get("location", "")
    if 300 <= status < 400 and location.startswith("http://"):
        findings.append(_finding("WARNING", "Headers", "Redirects to plain HTTP", "Location: " + location,
                                 "The user is moved off TLS.", "Redirect to an https:// address."))
    if status >= 400:
        findings.append(_finding("INFO", "Response", "HTTP status %d" % status,
                                 "The server answered HEAD with %s." % result["response"]["status_line"],
                                 "Some sites or firewalls refuse HEAD or unknown clients; TLS results above are still valid.",
                                 "Try the home page URL or compare with a browser."))
    if result["timing_ms"]["total"] > 2500:
        findings.append(_finding("INFO", "Performance", "Slow connection", "The full exchange took %.0f ms." % result["timing_ms"]["total"],
                                 "Slow handshakes hurt first-load time.", "Check network path, DNS and server load."))


def assess(result: dict) -> dict:
    findings, passed = [], []
    _tls_checks(result, findings, passed)
    _certificate_checks(result, findings, passed)
    _header_checks(result, findings, passed)
    findings.sort(key=lambda f: ORDER.index(f["level"]))
    score = max(0, 100 - sum(PENALTY[f["level"]] for f in findings))
    grade = next(letter for floor, letter in GRADES if score >= floor)
    counts = {level: sum(f["level"] == level for f in findings) for level in ORDER}
    serious = counts["CRITICAL"] + counts["ERROR"]
    if serious:
        verdict = "%d serious issue(s) need attention." % serious
    elif counts["WARNING"]:
        verdict = "No serious problems; %d improvement(s) recommended." % counts["WARNING"]
    else:
        verdict = "No problems found in what this tool can observe."
    return {
        "score": score,
        "grade": grade,
        "verdict": verdict,
        "counts": counts,
        "findings": findings,
        "passed": passed,
        "method": "Heuristic scoring of observable settings: 100 minus 40 per critical, 15 per error, 6 per warning. It is a guide, not a certification.",
    }


def narrative(result: dict) -> list:
    tls, leaf = result["tls"], result["certificate"]
    timing = result["timing_ms"]
    issuer = next((p.split("=", 1)[1] for p in leaf["issuer"].split(",") if p.strip().startswith("CN=")), leaf["issuer"])
    lines = [
        "%s resolved to %d address(es); this tool connected to %s over %s." % (
            result["host"], len(result["addresses"]), result["connection"]["remote_endpoint"], result["connection"]["ip_version"]),
        "The connection took %.0f ms in total: %.0f ms to look up the name, %.0f ms to open the TCP connection, %.0f ms for the TLS handshake and %.0f ms waiting for the first byte." % (
            timing["total"], timing["dns"], timing["tcp_connect"], timing["tls_handshake"], timing["time_to_first_byte"]),
        "Both sides agreed on %s with the cipher suite %s (%s-bit)." % (tls["version"], tls["cipher_name"], tls["cipher_secret_bits"]),
        "The server proved its identity with a certificate issued by %s, valid until %s (%d days from now)." % (issuer, leaf["not_after"][:10], leaf["days_remaining"]),
        "The certificate uses a %s %s key and covers: %s." % (leaf["public_key_type"], leaf["public_key_detail"],
                                                              ", ".join(leaf["subject_alternative_names"][:6]) or "no listed names"),
        "The full chain contains %d certificate(s) (%s), which this tool verified against %s." % (
            len(result["chain"]), result["chain_source"],
            "the operating system's trust store" if result["trust_store"] == "system default" else "the bundle " + result["trust_store"]),
        "A single HEAD request was then sent through the encrypted channel; the server replied \"%s\" with %d headers." % (
            result["response"]["status_line"], result["response"]["header_count"]),
    ]
    if result.get("trust_fallback"):
        lines.append("The operating system's trust store could not complete the chain, so the tool retried with %s and succeeded." %
                     result["trust_fallback"]["bundle"]["source"])
    return lines
