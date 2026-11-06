from __future__ import annotations

from .knowledge import EKU_NAMES, explain_certificate


def _rule(title: str) -> str:
    return "\n" + title + "\n" + "-" * len(title)


def _certificate_block(cert: dict, index: int) -> list:
    lines = [
        "[%d] %s" % (index, cert.get("position", "certificate").upper()),
        "  Subject:             " + cert["subject"],
        "  Issuer:              " + cert["issuer"],
        "  Serial (hex):        " + cert["serial_hex"],
        "  Version:             " + str(cert["version"]),
        "  Valid from:          " + cert["not_before"],
        "  Valid until:         %s  (%d days left, %d day lifetime)" % (cert["not_after"], cert["days_remaining"], cert["validity_days"]),
        "  Signature:           %s (OID %s)" % (cert["signature_algorithm"], cert["signature_algorithm_oid"]),
        "  Public key:          %s %s%s" % (cert["public_key_type"], cert["public_key_detail"],
                                           ("  exponent " + str(cert["public_key_exponent"])) if cert["public_key_exponent"] else ""),
        "  CA / path length:    %s / %s" % (cert["is_ca"], cert["path_length"]),
        "  Key usage:           " + (", ".join(cert["key_usage"]) or "-"),
        "  Extended key usage:  " + (", ".join(EKU_NAMES.get(o, o) for o in cert["extended_key_usage"]) or "-"),
        "  Names (SAN):         " + (", ".join(cert["subject_alternative_names"]) or "-"),
        "  Policies:            " + (", ".join(cert["certificate_policies"]) or "-"),
        "  OCSP responders:     " + (", ".join(cert["ocsp_urls"]) or "-"),
        "  CA issuer URLs:      " + (", ".join(cert["ca_issuer_urls"]) or "-"),
        "  CRL distribution:    " + (", ".join(cert["crl_distribution_points"]) or "-"),
        "  Transparency (SCTs): %d" % len(cert["signed_certificate_timestamps"]),
        "  Subject key id:      " + str(cert["subject_key_id"]),
        "  Authority key id:    " + str(cert["authority_key_id"]),
        "  SHA-256 fingerprint: " + cert["sha256_fingerprint"],
        "  Public key SHA-256:  " + cert["spki_sha256"],
        "  Extensions (OIDs):   " + ", ".join(cert["extension_oids"]),
        "  Critical extensions: " + (", ".join(cert["critical_extension_oids"]) or "-"),
    ]
    for sct in cert["signed_certificate_timestamps"]:
        lines.append("    SCT log %s... at %s" % (sct["log_id"][:16], sct["timestamp"]))
    for level, text in explain_certificate(cert):
        lines.append("  [%s] %s" % (level, text))
    return lines


def render_assessment(result: dict) -> list:
    out = []
    if result.get("narrative"):
        out.append(_rule("WHAT HAPPENED, IN PLAIN ENGLISH"))
        out += ["  " + str(i) + ". " + line for i, line in enumerate(result["narrative"], 1)]
    assessment = result.get("assessment")
    if not assessment:
        return out
    out.append(_rule("ASSESSMENT: GRADE %s (%d/100)" % (assessment["grade"], assessment["score"])))
    out.append("  " + assessment["verdict"])
    out.append("  " + assessment["method"])
    if assessment["findings"]:
        out.append("\n  Findings (most serious first)")
        for finding in assessment["findings"]:
            out += [
                "  [%s] %s: %s" % (finding["level"], finding["area"], finding["title"]),
                "      What we saw: " + finding["what"],
                "      Why it matters: " + finding["why"],
                "      What to do: " + finding["fix"],
            ]
    if assessment["passed"]:
        out.append("\n  Checks that passed")
        out += ["  [PASS] %s: %s - %s" % (p["area"], p["title"], p["what"]) for p in assessment["passed"]]
    return out


def render_probe(result: dict) -> str:
    out = ["TLS AND REQUEST REPORT FOR " + result["host"], "Captured " + result["timestamp"]]
    out += render_assessment(result)
    if result.get("trust_fallback"):
        fallback = result["trust_fallback"]
        out.append(_rule("TRUST FALLBACK USED"))
        out += ["  The system trust store failed: " + fallback["reason"],
                "  Retried with %s (%s)" % (fallback["bundle"]["source"], fallback["bundle"]["path"])]
    if result.get("watch"):
        out.append(_rule("CHANGE TRACKING"))
        out.append("  Status: %s%s" % (result["watch"]["status"], " (first observation; saved as baseline)" if result["watch"].get("first_observation") else ""))
        out += ["  [%s] %s" % (f["level"], f["message"]) for f in result["watch"]["findings"]]
    connection, timing = result["connection"], result["timing_ms"]
    out.append(_rule("CONNECTION"))
    out += [
        "  Target URL:          " + result["url"],
        "  Resolved addresses:  " + ", ".join(result["addresses"]),
        "  Connected to:        %s (%s)" % (connection["remote_endpoint"], connection["ip_version"]),
        "  Local endpoint:      " + connection["local_endpoint"],
        "  Trust store used:    " + result["trust_store"],
    ]
    out.append(_rule("TIMING (milliseconds)"))
    out += ["  %-20s %s" % (key.replace("_", " ").title(), value) for key, value in timing.items()]
    tls = result["tls"]
    out.append(_rule("TLS SESSION"))
    out += [
        "  Protocol version:    " + tls["version"],
        "  Cipher suite:        %s (%s, %s-bit secret)" % (tls["cipher_name"], tls["cipher_protocol"], tls["cipher_secret_bits"]),
        "  Forward secrecy:     " + ("yes" if tls["assessment"]["forward_secrecy"] else "NO"),
        "  Authenticated enc.:  " + ("yes" if tls["assessment"]["authenticated_encryption"] else "NO"),
        "  ALPN negotiated:     " + str(tls["alpn_negotiated"]),
        "  Compression:         " + str(tls["compression"]),
        "  Session reused:      " + str(tls["session_reused"]),
        "  Server name (SNI):   " + tls["sni"],
        "  Hostname checked:    " + str(tls["hostname_checked"]),
        "  Certificate checks:  " + tls["verify_mode"],
        "  Client TLS range:    %s to %s" % (tls["client_minimum_version"], tls["client_maximum_version"]),
        "  OpenSSL:             " + tls["openssl"],
        "  Ciphers we offered (%d):" % len(tls["offered_ciphers"]),
    ]
    out += ["    " + name for name in tls["offered_ciphers"]]
    support = result.get("protocol_support")
    if support:
        out.append(_rule("PROTOCOL SUPPORT (extra handshakes, no HTTP sent)"))
        for version, entry in support["tls_versions"].items():
            detail = entry.get("cipher") or entry.get("error") or ""
            out.append("  %-9s %s  %s" % (version, "SUPPORTED" if entry["supported"] else "not supported", detail))
        alpn = support["alpn_preference"]
        out.append("  ALPN preference when offered h2 and http/1.1: " + str(alpn.get("negotiated", alpn.get("error"))))
    out.append(_rule("CERTIFICATE CHAIN (%s, %d certificates)" % (result["chain_source"], len(result["chain"]))))
    for index, cert in enumerate(result["chain"]):
        out += _certificate_block(cert, index)
        out.append("")
    request = result["request"]
    out.append(_rule("REQUEST SENT"))
    out += ["  " + line for line in request["sent"].rstrip().splitlines()]
    out.append("  (HEAD asks for headers only; no body is requested or received)")
    response = result["response"]
    out.append(_rule("RESPONSE"))
    out.append("  " + response["status_line"])
    out += ["  %s: %s" % (name, value) for name, value in response["headers"]]
    analysis = response["analysis"]
    out.append(_rule("SECURITY HEADER ANALYSIS"))
    for item in analysis["security_headers"]:
        out.append("  [%-7s] %-30s %s" % (item["level"], item["header"], item["assessment"]))
    if analysis["hsts"]:
        hsts = analysis["hsts"]
        out.append("  HSTS: includeSubDomains=%s preload=%s" % (hsts["includeSubDomains"], hsts["preload"]))
    out.append(_rule("COOKIES (values redacted)"))
    if analysis["cookies"]:
        for cookie in analysis["cookies"]:
            out.append("  %s  secure=%s httponly=%s samesite=%s path=%s value_length=%d" % (
                cookie["name"], cookie["secure"], cookie["http_only"], cookie["same_site"], cookie["path"], cookie["value_length"]))
        out += ["  [WARNING] " + note for note in analysis["cookie_notes"]]
    else:
        out.append("  None set on this response")
    out.append(_rule("SERVER FINGERPRINT AND INFRASTRUCTURE"))
    out += ["  %s: %s" % (d["header"], d["value"]) for d in analysis["disclosure"]] or ["  No disclosure headers"]
    out.append("  Infrastructure hints: " + (", ".join(analysis["infrastructure_hints"]) or "none"))
    out.append("  Advertises HTTP/3:    " + str(analysis["advertises_http3"]))
    out.append("  Content type:         " + str(analysis["content_type"]))
    out.append("  Cache control:        " + str(analysis["cache_control"]))
    out.append("\n" + result["note"])
    return "\n".join(out)
