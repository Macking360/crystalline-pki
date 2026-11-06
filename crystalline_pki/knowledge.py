from __future__ import annotations

from datetime import datetime

EKU_NAMES = {
    "1.3.6.1.5.5.7.3.1": "serverAuth (proves a server's identity to clients)",
    "1.3.6.1.5.5.7.3.2": "clientAuth (proves a client's identity to servers)",
    "1.3.6.1.5.5.7.3.3": "codeSigning",
    "1.3.6.1.5.5.7.3.4": "emailProtection",
}

GLOSSARY = {
    "PKI": "Public key infrastructure: the people, rules and software that issue, check and cancel digital certificates so strangers can trust each other.",
    "Certificate authority (CA)": "An organisation or program that signs certificates. Its signature says: I checked this key belongs to this name.",
    "Root CA": "The top of a trust chain. It signs itself. You trust it only because you chose to install it, so its private key is the most valuable secret in the system.",
    "Intermediate CA": "A CA signed by the root that does the day-to-day signing, so the root key can stay locked away. If the intermediate is compromised you replace it without replacing the root.",
    "Leaf certificate": "The certificate at the bottom of the chain, used by a server, a person or a device. It cannot sign other certificates.",
    "Private key": "The secret half of a key pair. Whoever holds it can act as that identity. It must never leave the device that made it.",
    "Public key": "The shareable half. It is inside the certificate and lets others check signatures the private key made.",
    "CSR (certificate signing request)": "A small file a device creates containing its public key and its name, signed with its own private key. The CA signs the request into a certificate. The private key never travels.",
    "X.509": "The standard format of certificates and revocation lists.",
    "SAN (subject alternative name)": "The names a certificate is valid for: DNS names, IP addresses or URIs. Modern software checks the SAN and ignores the older common name.",
    "EKU (extended key usage)": "What a certificate may be used for. A client certificate cannot impersonate a server because it lacks serverAuth.",
    "Key usage": "Low-level permissions such as signing certificates or signing data. CA certificates need keyCertSign.",
    "Path length": "How many more CA levels may exist below a CA. The root allows 1 (the intermediate), the intermediate allows 0 (only leaves).",
    "Serial number": "A unique number the CA gives each certificate. Revocation lists name certificates by serial number.",
    "Fingerprint": "A SHA-256 hash of the whole certificate. Two certificates with the same fingerprint are the same certificate.",
    "TLS": "The protocol that secures a connection. First it agrees keys and checks identities (the handshake), then it encrypts traffic.",
    "Cipher suite": "The set of algorithms a connection uses to encrypt and authenticate data. It is negotiated separately from certificates.",
    "Forward secrecy": "Each session uses fresh temporary keys, so recorded traffic stays unreadable even if a long-term key is stolen later. All TLS 1.3 suites provide it.",
    "mTLS (mutual TLS)": "Both sides present certificates. The server proves who it is, and the client proves who it is. The server can then refuse anyone without a valid certificate.",
    "Revocation": "Cancelling a certificate before its expiry date, for example because a phone was lost.",
    "CRL (certificate revocation list)": "A signed list of cancelled serial numbers published by the CA. Servers read it during the handshake.",
    "OCSP": "A way to ask a CA live whether one certificate is revoked. Not implemented in this lab.",
    "Rotation": "Replacing a certificate and its key before they expire or are compromised. Short lifetimes make rotation routine.",
    "Hash chain": "Each log entry stores a hash that includes the previous entry's hash, so changing or removing an old entry breaks every later hash.",
    "Hardware-backed key": "A key generated inside a phone's secure chip (Android Keystore or StrongBox, iOS Secure Enclave) that can sign but can never be exported.",
    "Attestation": "Proof, signed by the phone's maker, that a key really lives in secure hardware and the app is genuine. Not implemented in this lab.",
    "PKCS#12 (.p12)": "A password-protected file holding a certificate, its chain and its private key, used to import an identity onto a phone or computer.",
    "Authority vs witness": "An authority issues and cancels identities. A witness only watches and records. Keeping them separate means the watcher cannot also be the one vouching for itself.",
}

CHECK_WHY = {
    "Root self-signature": "A root vouches for itself. If this fails the root file is damaged or was altered.",
    "Root validity": "Certificates only work between their start and end dates.",
    "Root CA constraints": "The root must be marked as a CA and allow exactly one more CA level below it.",
    "Intermediate validity": "An expired intermediate breaks every certificate it signed.",
    "Intermediate issuer/signature": "Proves the root really signed the intermediate.",
    "Intermediate CA constraints": "The intermediate must be a CA that is only allowed to sign leaves, never further CAs.",
    "Server validity": "An expired server certificate makes clients refuse to connect.",
    "Server issuer/signature": "Proves the intermediate really signed the server certificate.",
    "Server EKU": "The server certificate must be allowed to act as a server.",
    "Server name coverage": "Clients check the address they dialled against the certificate's names. Both localhost and 127.0.0.1 must be listed.",
    "Client validity": "An expired client certificate is refused by the server.",
    "Client issuer/signature": "Proves the intermediate really signed the client certificate.",
    "Client EKU": "The client certificate must be allowed to act as a client.",
    "Root certificate/key match": "Confirms the root key file belongs to the root certificate.",
    "Intermediate certificate/key match": "Confirms the intermediate key file belongs to the intermediate certificate.",
    "Server certificate/key match": "A server cannot start with a key that does not match its certificate.",
    "Client certificate/key match": "A client cannot authenticate with a key that does not match its certificate.",
    "Revocation list signature": "A revocation list is only believed if the intermediate CA signed it.",
    "Revocation list freshness": "An expired revocation list makes strict servers refuse everyone, so it must be republished before it lapses.",
    "Private key file permissions": "Other accounts on this computer must not be able to read private keys.",
}

LESSONS = [
    ("The big picture",
     "A certificate is a signed statement: this public key belongs to this name. A chain of such statements runs from a leaf (a server or a phone) up through an intermediate CA to a root that you chose to trust. "
     "Checking a certificate means walking that chain, checking each signature, each date, and each permission."),
    ("Certificates prove identity; ciphers keep secrets",
     "These are separate jobs done in the same handshake. The certificate answers who are you. The key exchange then creates a fresh, temporary secret that only the two sides know, and the cipher suite uses it to encrypt traffic. "
     "That is why the lab shows a TLS version and a cipher for every connection: you can see both layers working. Weak ciphers or old TLS versions are a separate problem from expired certificates."),
    ("The certificate lifecycle",
     "1. A device makes its own key pair and a signing request (CSR). The private key never leaves the device.\n"
     "2. The authority checks the request and signs a certificate with a short life.\n"
     "3. The device uses the certificate to authenticate.\n"
     "4. Before it expires, the device rotates: new key, new request, new certificate. The old one is revoked.\n"
     "5. If a device is lost or stolen, the authority revokes its certificate at once.\n"
     "6. The revocation list is republished, and servers stop accepting the old certificate."),
    ("Why mutual TLS",
     "Ordinary TLS lets a client check the server. Mutual TLS makes the server check the client too, so a stolen password is not enough: the attacker also needs the device's private key. "
     "Try it in the mTLS lab: connect with no certificate, with a valid one, and with a revoked one."),
    ("Revocation and short lifetimes",
     "A revocation list only helps if servers read a fresh one. Short certificate lifetimes limit the damage when revocation is missed, because a stolen certificate expires on its own. "
     "That is why device certificates here last 90 days by default and public web certificates are moving to even shorter lives."),
    ("Phones and hardware keys",
     "On a phone, the strongest design generates the key inside secure hardware so it can never be copied. The phone sends a CSR, the authority returns a certificate, and the server accepts the phone only while that certificate is valid and unrevoked. "
     "This lab uses software keys on your computer and can export a password-protected PKCS#12 file you can import on a phone to try the flow. "
     "A real mobile agent should be an outbound client only: it needs no open port and works behind carrier networks."),
    ("Authority and witness",
     "This tool is the authority side: it issues, rotates and revokes identities. A separate monitoring tool should only watch and report, and verify identities using standard certificates and revocation lists, never by sharing source code with the authority. "
     "The watchlist tab shows the witness idea on a small scale: it records what a public site's certificate looks like and reports when it changes."),
    ("What this lab is not",
     "It is a learning and research tool. Private keys are stored unencrypted, the root key sits next to the intermediate key, there is no OCSP, no hardware attestation, and no enrolment protocol such as EST. "
     "Do not use it to run a production certificate authority."),
]

TOUR = [
    ("Create the lab authority", "A root CA, an intermediate CA, a server certificate for localhost and a client certificate are created, and the first revocation list is published."),
    ("Start the mutual TLS server", "The server listens only on this computer. It will refuse any client that cannot present a certificate signed by the lab intermediate."),
    ("Built-in client is accepted", "The built-in client presents a certificate chain. The server checks signatures, dates, permissions and the revocation list."),
    ("No certificate is rejected", "A client without a certificate fails the handshake. That is mutual TLS doing its job."),
    ("Enroll a device", "A new device makes an EC P-256 key and a certificate request. The authority signs it into a 90-day certificate."),
    ("Revoke the device", "The authority adds the serial number to the revocation list and the server reloads it. The same device is now refused."),
    ("Rotate a device", "A device gets a fresh key and certificate. The old certificate is revoked as superseded, so only the new one works."),
]

HANDSHAKE = [
    {"from": "client", "step": "ClientHello", "text": "The client says which TLS versions and cipher suites it supports, which server name it wants (SNI), and which application protocols it can speak (ALPN)."},
    {"from": "server", "step": "ServerHello", "text": "The server picks one TLS version and one cipher suite from the client's list, and sends its half of a temporary key exchange."},
    {"from": "server", "step": "Certificate", "text": "The server sends its certificate chain: its own certificate plus the intermediate that signed it. The client will walk this chain up to a root it already trusts."},
    {"from": "server", "step": "CertificateRequest (mTLS only)", "text": "In mutual TLS the server also demands a certificate from the client, and tells it which authorities it accepts."},
    {"from": "client", "step": "Certificate + CertificateVerify (mTLS only)", "text": "The client sends its certificate chain and signs the handshake with its private key, proving it holds the key and is not just replaying a certificate."},
    {"from": "both", "step": "Finished", "text": "Both sides prove they derived the same session keys. From here on everything is encrypted with the negotiated cipher."},
    {"from": "client", "step": "HTTP request", "text": "Only now does the client send the HTTP request, protected by the encrypted session."},
    {"from": "server", "step": "HTTP response", "text": "The server answers with a status line, headers and optionally a body."},
]

PROBE_HELP = {
    "timing": "Each phase of the connection, in order: finding the server's address (DNS), opening the TCP connection, the TLS handshake, then waiting for the first response byte. A slow handshake can mean distance, a busy server, or many round trips.",
    "tls": "The negotiated protocol version and cipher suite. TLS 1.3 is the current standard and always uses forward secrecy. TLS 1.2 is acceptable when it picks an ECDHE suite with AES-GCM or ChaCha20.",
    "ciphers_offered": "The cipher suites this client offered. The server chose one of them; a server that supports only older suites would force a weaker choice.",
    "protocol_support": "Which TLS versions the server accepts, tested one at a time with handshakes that send no HTTP request. A site that supports TLS 1.2 but not 1.3 works securely but is a version behind.",
    "chain": "The certificates the server presented, leaf first. Every certificate except the root must be signed by the next one. A missing intermediate is a common misconfiguration that breaks some clients.",
    "request": "Exactly what was sent. A HEAD request asks only for headers, so no page content is downloaded.",
    "response": "The server's status line and every header it returned. Headers reveal caching, security settings and sometimes the software in use.",
    "security_headers": "Headers that tell browsers to enforce protections. Missing ones are not always faults but each closes a specific class of attack.",
    "cookies": "Cookies set on this response. Secure keeps them to HTTPS, HttpOnly hides them from scripts, SameSite limits cross-site sending. Values are redacted here.",
    "disclosure": "Headers that name the server software or the CDN in front of it. Useful for inventory, and for attackers choosing known weaknesses.",
}

REJECTION_HINTS = (
    ("certificate required", "No client certificate was presented, and this server requires one."),
    ("revoked", "The certificate appears on the revocation list, so the server refuses it."),
    ("unknown ca", "The certificate was signed by an authority this server does not trust."),
    ("expired", "The certificate or the revocation list is past its end date."),
    ("unable to get local issuer", "The chain could not be completed back to a trusted root."),
    ("hostname", "The name in the certificate does not match the address that was dialled."),
)


def explain_attempt(result: dict) -> list:
    lines = []
    if result.get("outcome") == "accepted":
        lines.append("The server verified the client certificate chain, signatures, dates and the revocation list.")
        version, cipher = result.get("tls_version"), (result.get("cipher") or [None])[0]
        if version and cipher:
            lines.append("The session is secured with %s using %s." % (version, cipher))
            if version == "TLSv1.3" or "ECDHE" in cipher:
                lines.append("The key exchange is temporary, so recorded traffic stays private even if a long-term key leaks later (forward secrecy).")
    else:
        error = str(result.get("error", "")).lower()
        matched = next((hint for key, hint in REJECTION_HINTS if key in error), None)
        if matched is None and result.get("presented") is None:
            matched = "No client certificate was presented, and this server requires one."
        lines.append("The connection was refused. " + (matched or "See the technical detail below."))
        if result.get("tls_version"):
            lines.append("Note: with TLS 1.3 the client finishes its side of the handshake before the server checks its certificate, "
                         "so the refusal arrives just after the connection appears to succeed.")
        if result.get("error"):
            lines.append("Technical detail: %s" % result["error"])
    return lines


def explain_certificate(details: dict) -> list:
    notes = []

    def add(level, text):
        notes.append((level, text))

    if details["is_ca"] and details["self_signed"]:
        add("INFO", "This is a root certificate: it vouches for itself. You trust it only because you installed it.")
    elif details["is_ca"]:
        extra = "" if details["path_length"] is None else " It may sign %s more level(s) of CAs below it." % details["path_length"]
        add("INFO", "This is a CA certificate: it can sign other certificates.%s" % extra)
    else:
        add("INFO", "This is a leaf (end-entity) certificate: it identifies one server, person or device and cannot sign others.")
    if details["expired"]:
        add("ERROR", "This certificate has expired. Clients and servers will refuse it. Renew or rotate it.")
    elif details["days_remaining"] <= 30:
        add("WARNING", "This certificate expires in %d days. Plan the renewal now." % details["days_remaining"])
    else:
        add("OK", "This certificate is valid for %d more days." % details["days_remaining"])
    for oid in details["extended_key_usage"]:
        add("INFO", "Allowed use: " + EKU_NAMES.get(oid, oid))
    if not details["is_ca"] and not details["subject_alternative_names"]:
        add("WARNING", "There is no subject alternative name. Modern clients ignore the common name, so name checks may fail.")
    if details["public_key_type"] == "RSA" and int(details["public_key_detail"] or 0) < 2048:
        add("ERROR", "This RSA key is shorter than 2048 bits, which is considered weak.")
    elif details["public_key_type"] == "RSA":
        add("OK", "RSA %s-bit key: acceptable." % details["public_key_detail"])
    elif details["public_key_type"] == "EC":
        add("OK", "Elliptic-curve key (%s): small, fast and the usual choice for phones." % details["public_key_detail"])
    if details["signature_hash"] in ("md5", "sha1"):
        add("ERROR", "Signed with %s, which is broken or deprecated." % details["signature_hash"])
    lifetime = (datetime.fromisoformat(details["not_after"]) - datetime.fromisoformat(details["not_before"])).days
    if not details["is_ca"]:
        if lifetime > 398:
            add("INFO", "This certificate lives %d days, longer than public browsers allow for web certificates." % lifetime)
        else:
            add("OK", "Lifetime of %d days is short, which limits damage if a key leaks." % lifetime)
    return notes
