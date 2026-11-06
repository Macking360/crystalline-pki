from __future__ import annotations

SECURITY_HEADERS = (
    ("strict-transport-security", "HSTS: tells browsers to use HTTPS only"),
    ("content-security-policy", "CSP: limits where scripts and content may load from"),
    ("x-frame-options", "Blocks the page being framed by other sites"),
    ("x-content-type-options", "Stops browsers guessing content types"),
    ("referrer-policy", "Controls what the Referer header reveals"),
    ("permissions-policy", "Limits browser features such as camera and location"),
    ("cross-origin-opener-policy", "Isolates the page from cross-origin windows"),
    ("cross-origin-embedder-policy", "Requires embedded resources to opt in"),
    ("cross-origin-resource-policy", "Controls who may load this resource"),
)

DISCLOSURE_HEADERS = ("server", "x-powered-by", "x-aspnet-version", "x-generator", "x-drupal-cache", "via")

CDN_HINTS = (
    ("cf-ray", "Cloudflare"),
    ("x-amz-cf-id", "Amazon CloudFront"),
    ("x-served-by", "Fastly or Varnish"),
    ("x-vercel-id", "Vercel"),
    ("x-azure-ref", "Azure Front Door"),
)


def _lookup(headers) -> dict:
    table = {}
    for name, value in headers:
        table.setdefault(name.lower(), []).append(value)
    return table


def _assess_hsts(value: str):
    parts = [p.strip().lower() for p in value.split(";")]
    max_age = next((int(p.split("=", 1)[1]) for p in parts if p.startswith("max-age=") and p.split("=", 1)[1].isdigit()), None)
    flags = {"includeSubDomains": "includesubdomains" in parts, "preload": "preload" in parts}
    if max_age is None:
        return "ERROR", "No valid max-age", flags
    if max_age < 15552000:
        return "WARNING", "max-age is %d seconds, under 180 days" % max_age, flags
    return "OK", "max-age %d seconds (%d days)" % (max_age, max_age // 86400), flags


def _assess(name: str, value: str):
    lowered = value.lower()
    if name == "strict-transport-security":
        level, text, _ = _assess_hsts(value)
        return level, text
    if name == "content-security-policy":
        if "unsafe-inline" in lowered or "unsafe-eval" in lowered:
            return "WARNING", "Present, but allows unsafe-inline or unsafe-eval"
        return "OK", "Present"
    if name == "x-frame-options":
        return ("OK", value) if lowered in ("deny", "sameorigin") else ("WARNING", "Unusual value: " + value)
    if name == "x-content-type-options":
        return ("OK", "nosniff") if lowered == "nosniff" else ("WARNING", "Expected nosniff, got: " + value)
    return "OK", "Present: " + value[:120]


def parse_cookie(raw: str) -> dict:
    parts = [p.strip() for p in raw.split(";")]
    name, _, value = parts[0].partition("=")
    attributes = {}
    for part in parts[1:]:
        key, _, attr_value = part.partition("=")
        attributes[key.strip().lower()] = attr_value.strip() or True
    return {
        "name": name,
        "value_length": len(value),
        "value": "[redacted]",
        "secure": "secure" in attributes,
        "http_only": "httponly" in attributes,
        "same_site": attributes.get("samesite") if isinstance(attributes.get("samesite"), str) else None,
        "path": attributes.get("path") if isinstance(attributes.get("path"), str) else None,
        "domain": attributes.get("domain") if isinstance(attributes.get("domain"), str) else None,
        "max_age": attributes.get("max-age") if isinstance(attributes.get("max-age"), str) else None,
        "expires": attributes.get("expires") if isinstance(attributes.get("expires"), str) else None,
    }


def analyse_headers(headers) -> dict:
    table = _lookup(headers)
    security = []
    for name, purpose in SECURITY_HEADERS:
        if name in table:
            level, text = _assess(name, table[name][0])
            security.append({"header": name, "purpose": purpose, "present": True, "level": level,
                             "assessment": text, "value": table[name][0][:300]})
        else:
            security.append({"header": name, "purpose": purpose, "present": False, "level": "INFO",
                             "assessment": "Not sent", "value": None})
    hsts = None
    if "strict-transport-security" in table:
        level, text, flags = _assess_hsts(table["strict-transport-security"][0])
        hsts = {"level": level, "assessment": text, **flags}
    cookies = [parse_cookie(value) for value in table.get("set-cookie", [])]
    cookie_notes = []
    for cookie in cookies:
        if not cookie["secure"]:
            cookie_notes.append("Cookie %s is missing the Secure flag" % cookie["name"])
        if not cookie["http_only"]:
            cookie_notes.append("Cookie %s is missing HttpOnly" % cookie["name"])
        if not cookie["same_site"]:
            cookie_notes.append("Cookie %s has no SameSite setting" % cookie["name"])
    disclosure = [{"header": name, "value": table[name][0][:200]} for name in DISCLOSURE_HEADERS if name in table]
    infrastructure = [label for key, label in CDN_HINTS if key in table]
    alt_svc = table.get("alt-svc", [None])[0]
    return {
        "security_headers": security,
        "missing_security_headers": [s["header"] for s in security if not s["present"]],
        "hsts": hsts,
        "cookies": cookies,
        "cookie_notes": cookie_notes,
        "disclosure": disclosure,
        "infrastructure_hints": infrastructure,
        "alt_svc": alt_svc,
        "advertises_http3": bool(alt_svc and "h3" in alt_svc),
        "content_type": table.get("content-type", [None])[0],
        "content_length": table.get("content-length", [None])[0],
        "cache_control": table.get("cache-control", [None])[0],
    }
