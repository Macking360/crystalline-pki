(() => {
"use strict";
const SVGNS = "http://www.w3.org/2000/svg";
const state = { status: null, knowledge: null, tab: "dashboard", lastEvent: 0, onEvents: null, live: true };
const TABS = [["dashboard", "Dashboard"], ["lifecycle", "Lifecycle"], ["lab", "mTLS lab"], ["probe", "Site probe"],
  ["watch", "Watchlist"], ["audit", "Audit & logs"], ["learn", "Learn"]];

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v === false || v == null) continue;
    if (k === "class") el.className = v;
    else if (k === "text") el.textContent = v;
    else if (k.startsWith("on")) el[k] = v;
    else if (k === "style" && typeof v === "object") Object.assign(el.style, v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}
function s(tag, attrs, ...kids) {
  const el = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (k === "style" && typeof v === "object") Object.assign(el.style, v);
    else el.setAttribute(k, v);
  }
  for (const kid of kids.flat(Infinity)) { if (kid != null) el.append(kid.nodeType ? kid : document.createTextNode(String(kid))); }
  return el;
}
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const short = (v, n = 12) => (v ? String(v).slice(0, n) + (String(v).length > n ? "…" : "") : "-");
const pill = (text, cls) => h("span", { class: "pill " + (cls || text) }, text);
const explain = (title, text) => h("div", { class: "explain" }, h("b", { class: "t", text: title }), text);

function toast(message, good) {
  const el = document.getElementById("toast");
  el.textContent = message;
  el.className = "toast" + (good ? " good" : "");
  el.hidden = false;
  clearTimeout(toast.t);
  toast.t = setTimeout(() => { el.hidden = true; }, good ? 3000 : 7000);
}

async function api(path, body) {
  const options = body === undefined ? {} : {
    method: "POST",
    headers: { "Content-Type": "application/json", "X-Requested-With": "crystalline-pki" },
    body: JSON.stringify(body),
  };
  const response = await fetch(path, options);
  const data = await response.json().catch(() => ({ error: "Unreadable response" }));
  if (!response.ok) { const error = new Error(data.error || response.statusText); error.data = data; throw error; }
  return data;
}
async function runJob(path, body, onProgress) {
  const { job } = await api(path, body || {});
  for (;;) {
    const snap = await api("/api/jobs/" + job);
    if (onProgress) onProgress(snap);
    if (snap.status !== "running") return snap;
    await sleep(450);
  }
}
async function guard(fn) {
  try { return await fn(); } catch (error) { toast(error.message); return null; }
}

function kv(pairs) {
  return h("div", { class: "kv" }, pairs.filter((p) => p && p[1] !== undefined && p[1] !== null && p[1] !== "")
    .map(([k, v]) => [h("div", { text: k }), h("div", { class: "mono" }, v)]));
}
function notes(list) {
  return list.map(([level, text]) => h("div", { class: "note " + level }, h("b", { text: level + "  " }), text));
}
function download(name, text, type) {
  const url = URL.createObjectURL(new Blob([text], { type: type || "text/plain" }));
  const a = h("a", { href: url, download: name });
  document.body.append(a); a.click(); a.remove(); URL.revokeObjectURL(url);
}

function validityBar(rec) {
  const a = Date.parse(rec.not_before), b = Date.parse(rec.not_after);
  const f = Math.max(0, Math.min(1, (Date.now() - a) / (b - a)));
  const state_ = rec.state || (rec.expired ? "expired" : "active");
  return h("div", { class: "bar " + state_, title: rec.not_before + " to " + rec.not_after },
    h("i", { style: { width: (f * 100) + "%" } }), h("u", { style: { left: (f * 100) + "%" } }));
}

function hierarchySvg(certs, selected, onPick) {
  const leaves = certs.slice().reverse();
  const width = Math.max(720, leaves.length * 168 + 20);
  const svg = s("svg", { viewBox: "0 0 " + width + " 300", width: "100%", style: { maxHeight: "320px" } });
  const box = (x, y, w, label, sub, color, onclick, on) => {
    const g = s("g", { style: { cursor: onclick ? "pointer" : "default" } },
      s("rect", { x, y, width: w, height: 54, rx: 9, style: { fill: "var(--panel2)", stroke: color, "stroke-width": on ? 3 : 1.5 } }),
      s("text", { x: x + w / 2, y: y + 22, "text-anchor": "middle", "font-size": 13, "font-weight": 600 }, label),
      s("text", { x: x + w / 2, y: y + 40, "text-anchor": "middle", "font-size": 11, class: "muted-t" }, sub));
    if (onclick) g.onclick = onclick;
    return g;
  };
  const mid = width / 2;
  svg.append(
    s("line", { x1: mid, y1: 64, x2: mid, y2: 104, style: { stroke: "var(--accent)", "stroke-width": 2 } }),
    box(mid - 110, 10, 220, "Root CA", "self-signed; the trust anchor", "var(--accent)"),
    box(mid - 110, 104, 220, "Intermediate CA", "signs end certificates, path length 0", "var(--info)"));
  leaves.forEach((c, i) => {
    const x = 10 + i * 168 + (width - leaves.length * 168 - 20) / 2;
    const color = c.state === "active" ? "var(--ok)" : c.state === "revoked" ? "var(--err)" : "var(--warn)";
    svg.append(
      s("path", { d: "M" + mid + " 158 V190 H" + (x + 78) + " V210", fill: "none", style: { stroke: color, "stroke-width": 1.5, opacity: .7 } }),
      box(x, 210, 156, c.name.length > 18 ? c.name.slice(0, 17) + "…" : c.name,
        c.kind + " · " + c.state + (c.state === "active" ? " · " + c.days_left + "d" : ""), color,
        () => onPick(c.serial), c.serial === selected));
  });
  return svg;
}

function handshakeSvg(steps, ctx) {
  ctx = ctx || {};
  const rowH = 54, H = 70 + steps.length * rowH, L = 130, R = 590;
  const svg = s("svg", { viewBox: "0 0 720 " + H, width: "100%" });
  svg.append(
    s("text", { x: L, y: 22, "text-anchor": "middle", "font-weight": 700 }, "Client"),
    s("text", { x: R, y: 22, "text-anchor": "middle", "font-weight": 700 }, "Server"),
    s("line", { x1: L, y1: 32, x2: L, y2: H - 8, style: { stroke: "var(--line)", "stroke-width": 2 } }),
    s("line", { x1: R, y1: 32, x2: R, y2: H - 8, style: { stroke: "var(--line)", "stroke-width": 2 } }),
    s("defs", {}, s("marker", { id: "ah", markerWidth: 8, markerHeight: 8, refX: 7, refY: 4, orient: "auto" },
      s("path", { d: "M0 0 L8 4 L0 8 z", style: { fill: "var(--accent)" } }))));
  steps.forEach((st, i) => {
    const y = 58 + i * rowH;
    const mtlsOnly = st.step.includes("mTLS only");
    const dim = mtlsOnly && !ctx.mtls;
    const x1 = st.from === "server" ? R : L, x2 = st.from === "server" ? L : R;
    const line = st.from === "both"
      ? s("line", { x1: L + 4, y1: y, x2: R - 4, y2: y, style: { stroke: "var(--accent)", "stroke-width": 2, "stroke-dasharray": "2 4" } })
      : s("line", { x1, y1: y, x2: x2 + (x2 > x1 ? -6 : 6), y2: y, "marker-end": "url(#ah)",
        style: { stroke: "var(--accent)", "stroke-width": 2, "stroke-dasharray": dim ? "5 5" : "none", opacity: dim ? .4 : 1 } });
    const detail = (ctx.details && ctx.details[st.step]) || "";
    svg.append(line,
      s("text", { x: 360, y: y - 7, "text-anchor": "middle", "font-size": 12.5, "font-weight": 600, style: { opacity: dim ? .5 : 1 } }, st.step),
      s("text", { x: 360, y: y + 14, "text-anchor": "middle", "font-size": 11, class: "muted-t" }, detail));
  });
  return svg;
}

function waterfall(timing) {
  const parts = [["DNS lookup", timing.dns], ["TCP connect", timing.tcp_connect], ["TLS handshake", timing.tls_handshake],
    ["Wait for first byte", timing.time_to_first_byte]];
  const total = parts.reduce((a, p) => a + p[1], 0) || 1;
  let offset = 0;
  const rows = [];
  parts.forEach(([name, ms]) => {
    const left = (offset / total) * 100;
    rows.push(h("div", { text: name }),
      h("div", { style: { position: "relative", height: "14px" } },
        h("div", { class: "seg", style: { position: "absolute", left: left + "%", width: Math.max((ms / total) * 100, 0.8) + "%" } })),
      h("div", { class: "mono", text: ms + " ms" }));
    offset += ms;
  });
  rows.push(h("b", { text: "Total" }), h("div"), h("b", { class: "mono", text: timing.total + " ms" }));
  return h("div", { class: "wf" }, rows);
}

function chainSvg(chain) {
  const items = chain.slice().reverse();
  const H = 20 + items.length * 78;
  const svg = s("svg", { viewBox: "0 0 760 " + H, width: "100%" });
  items.forEach((c, i) => {
    const y = 10 + i * 78;
    const color = c.expired ? "var(--err)" : c.days_remaining <= 21 && c.position === "leaf" ? "var(--warn)" : "var(--ok)";
    if (i > 0) svg.append(s("line", { x1: 380, y1: y - 24, x2: 380, y2: y, style: { stroke: "var(--accent)", "stroke-width": 2 } }),
      s("text", { x: 392, y: y - 8, "font-size": 11, class: "muted-t" }, "signs"));
    svg.append(s("rect", { x: 80, y, width: 600, height: 54, rx: 9, style: { fill: "var(--panel2)", stroke: color, "stroke-width": 1.8 } }),
      s("text", { x: 96, y: y + 20, "font-size": 13, "font-weight": 600 }, c.position.toUpperCase() + "  " + short(commonName(c.subject), 60)),
      s("text", { x: 96, y: y + 40, "font-size": 11, class: "muted-t" },
        c.public_key_type + " " + c.public_key_detail + " · " + c.signature_algorithm + " · " +
        (c.expired ? "EXPIRED" : c.days_remaining + " days left")));
  });
  return svg;
}
function commonName(dn) { const m = /CN=([^,]+)/.exec(dn); return m ? m[1] : dn; }

function certTable(c) {
  return kv([
    ["Subject", c.subject], ["Issuer", c.issuer], ["Serial (hex)", c.serial_hex], ["Version", c.version],
    ["Valid from", c.not_before], ["Valid until", c.not_after + "  (" + c.days_remaining + " days left; " + c.validity_days + " day lifetime)"],
    ["Signature", c.signature_algorithm + " (OID " + c.signature_algorithm_oid + ")"],
    ["Public key", c.public_key_type + " " + c.public_key_detail + (c.public_key_exponent ? ", exponent " + c.public_key_exponent : "")],
    ["CA / path length", c.is_ca + " / " + c.path_length], ["Key usage", c.key_usage.join(", ")],
    ["Extended key usage", c.extended_key_usage.join(", ")], ["Names (SAN)", c.subject_alternative_names.join(", ")],
    ["Policies", c.certificate_policies.join(", ")], ["OCSP", c.ocsp_urls.join(", ")], ["CA issuer URLs", c.ca_issuer_urls.join(", ")],
    ["CRL distribution", c.crl_distribution_points.join(", ")], ["Transparency logs (SCTs)", String(c.signed_certificate_timestamps.length)],
    ["Subject key id", c.subject_key_id], ["Authority key id", c.authority_key_id],
    ["SHA-256 fingerprint", c.sha256_fingerprint], ["Public key SHA-256", c.spki_sha256],
    ["Extension OIDs", c.extension_oids.join(", ")], ["Critical OIDs", c.critical_extension_oids.join(", ")],
  ]);
}

function eventRow(e, onClick) {
  return h("tr", { class: "click", onclick: () => onClick(e) },
    h("td", { class: "mono", text: e.timestamp.slice(11, 19) }), h("td", {}, pill(e.severity)),
    h("td", { text: e.component }), h("td", { text: e.action }), h("td", { class: "mono", text: short(e.target, 38) }));
}

async function pollEvents() {
  try {
    const data = await api("/api/events?after=" + state.lastEvent);
    if (data.events.length) {
      state.lastEvent = data.events[data.events.length - 1].id;
      const last = data.events[data.events.length - 1];
      document.getElementById("ticker").textContent = last.timestamp.slice(11, 19) + "  [" + last.severity + "]  " + last.component + ": " + last.action + (last.target ? "  " + short(last.target, 60) : "");
      if (state.onEvents) state.onEvents(data.events);
    }
    document.getElementById("tickdot").style.background = "var(--ok)";
  } catch (e) { document.getElementById("tickdot").style.background = "var(--err)"; }
}

async function refreshStatus() { state.status = await api("/api/status"); return state.status; }

function stepList(steps) {
  return h("div", { class: "steps" }, steps.map((p) => h("div", { class: "step " + (p.status === "warn" ? "running" : p.status || "ok") },
    h("b", { text: p.title }), p.text)));
}

function assessmentPanel(r) {
  const a = r.assessment, wrap = h("div", { class: "card assess" });
  if (!a) return wrap;
  wrap.append(
    h("div", { class: "gradebox" },
      h("div", { class: "grade G" + a.grade, text: a.grade }),
      h("div", {}, h("div", { class: "big", text: a.score + " / 100" }), h("div", { text: a.verdict }),
        h("div", { class: "row" }, ["CRITICAL", "ERROR", "WARNING", "INFO"].map((k) => pill(a.counts[k] + " " + k.toLowerCase(), a.counts[k] ? k : "INFO"))))),
    h("p", { class: "muted", text: a.method }),
    h("h3", { text: "What happened, in plain English" }), h("ol", {}, r.narrative.map((line) => h("li", { text: line }))));
  if (r.trust_fallback) {
    wrap.append(explain("Automatic trust fallback", "The operating system's trust store could not complete this site's chain (" + r.trust_fallback.reason +
      "). The tool found a standard root bundle (" + r.trust_fallback.bundle.source + ") and retried, which verified the site. This is the known Windows lazy-root behaviour, not a fault in the site."));
  }
  wrap.append(h("h3", { text: "Findings, most serious first" }));
  if (!a.findings.length) wrap.append(h("p", { class: "muted", text: "Nothing to report." }));
  a.findings.forEach((f) => wrap.append(h("details", f.level === "CRITICAL" || f.level === "ERROR" ? { open: true } : {},
    h("summary", {}, pill(f.level), " ", f.area + ": " + f.title),
    h("div", { class: "finding" }, h("b", { text: "What we saw  " }), f.what, h("br"), h("b", { text: "Why it matters  " }), f.why, h("br"),
      h("b", { text: "What to do  " }), f.fix))));
  wrap.append(h("details", {}, h("summary", { text: "Checks that passed (" + a.passed.length + ")" }),
    h("table", {}, h("tbody", {}, a.passed.map((p) => h("tr", {}, h("td", {}, pill("PASS", "OK")), h("td", { text: p.area + ": " + p.title }), h("td", { class: "muted", text: p.what })))))));
  if (r.watch) {
    wrap.append(h("h3", { text: "Change tracking" }), explain("What this does", "Every examined site is remembered. The next time you examine it (or the background check runs), this tool compares issuer, certificate, TLS version, cipher, addresses and status with this baseline and reports what changed."),
      h("div", { class: "row" }, pill(r.watch.status, r.watch.status === "OK" || r.watch.status === "INFO" ? "OK" : r.watch.status), r.watch.first_observation ? pill("first observation: baseline saved", "INFO") : null),
      ...notes(r.watch.findings.map((f) => [f.level === "CRITICAL" ? "ERROR" : f.level, f.message])));
  }
  if (r.steps) wrap.append(h("h3", { text: "What the tool did automatically" }), stepList(r.steps));
  if (r.report_files) wrap.append(h("p", { class: "muted" }, "Reports saved: ", h("span", { class: "mono", text: r.report_files.text }), "  and  ", h("span", { class: "mono", text: r.report_files.json })));
  return wrap;
}

function examineWidget(prefill) {
  const url = h("input", { type: "text", placeholder: "https://example.org", size: 40, value: prefill || localStorage.getItem("cpki.lastUrl") || "" });
  const out = h("div"), progress = h("div"), go = h("button", { class: "btn", text: "Examine" });
  const submit = () => guard(async () => {
    localStorage.setItem("cpki.lastUrl", url.value);
    go.disabled = true; out.replaceChildren(); progress.replaceChildren(h("div", { class: "step running" }, h("b", { text: "Working" }), "Starting…"));
    const snap = await runJob("/api/probe", { url: url.value }, (j) => { if (j.progress.length) progress.replaceChildren(stepList(j.progress)); });
    go.disabled = false;
    if (snap.status === "error") { progress.replaceChildren(); renderProbeError(out, snap.error); return; }
    progress.replaceChildren(); renderProbeResult(out, snap.result);
  }).finally(() => { go.disabled = false; });
  go.onclick = submit;
  url.onkeydown = (e) => { if (e.key === "Enter") submit(); };
  const el = h("div", {},
    h("div", { class: "row" }, url, go),
    h("p", { class: "muted", text: "By giving an address you confirm you own the site or may test it. One HEAD request is sent. Nothing is scanned." }),
    progress, out);
  return el;
}

function renderProbeError(box, error) {
  box.replaceChildren(h("div", { class: "step error" }, h("b", { text: "The connection could not be verified" }), error.message));
  const d = error.diagnosis;
  if (d) {
    box.append(explain("Likely cause", d.likely_cause), kv([["Verify code", String(d.verify_code)], ["Verify message", d.verify_message], ["Trust store used", d.trust_store]]));
    const sc = d.served_certificate;
    if (sc && sc.chain) {
      box.append(h("h3", { text: "What the server presented (read without trusting it)" }),
        explain("Caution", sc.note + " Use it to decide whether the problem is the server's chain or your trust store."), chainSvg(sc.chain),
        ...sc.chain.map((c) => h("details", {}, h("summary", { text: c.position + ": " + commonName(c.subject) }), certTable(c))));
    }
  }
}

function renderProbeResult(box, payload) {
  const r = payload.result, k = state.knowledge.probe_help;
  box.replaceChildren();
  const leaf = r.certificate, tls = r.tls;
  box.append(assessmentPanel(r));
  box.append(
    h("div", { class: "row" },
      pill(r.tls_version, "INFO"), pill(tls.cipher_name, "INFO"), pill("HTTP " + r.http_status, r.http_status < 400 ? "OK" : "ERROR"),
      pill(leaf.days_remaining + " days left", leaf.days_remaining > 21 ? "OK" : "WARNING"),
      pill(tls.assessment.forward_secrecy ? "forward secrecy" : "NO forward secrecy", tls.assessment.forward_secrecy ? "OK" : "ERROR"),
      pill(r.chain.length + " certificates", "INFO"), pill(r.connection.ip_version + " " + r.resolved_ip, "INFO")),
    h("div", { class: "row" },
      h("button", { class: "btn alt", onclick: () => download(r.host + "-tls-report.txt", payload.report_text), text: "Download text report" }),
      h("button", { class: "btn alt", onclick: () => download(r.host + "-tls-report.json", JSON.stringify(r, null, 2), "application/json"), text: "Download JSON" })),
    h("h3", { text: "1. Timing" }), explain("What this shows", k.timing), waterfall(r.timing_ms),
    h("h3", { text: "2. The TLS handshake that just happened" }),
    explain("Reading the diagram", "Arrows show who sends what. The values under each step are from this real connection. Dashed arrows are the mutual-TLS steps, which an ordinary website does not use."),
    handshakeSvg(state.knowledge.handshake, { mtls: false, details: {
      "ClientHello": tls.offered_ciphers.length + " ciphers offered · SNI " + tls.sni + " · ALPN http/1.1",
      "ServerHello": tls.version + " · " + tls.cipher_name,
      "Certificate": r.chain.length + " certificates presented (" + r.chain_source + ")",
      "Finished": "session reused: " + tls.session_reused + " · compression: " + tls.compression,
      "HTTP request": r.request.method + " " + r.request.path,
      "HTTP response": r.response.status_line } }),
    h("h3", { text: "3. TLS session details" }), explain("What this shows", k.tls),
    kv([["Protocol", tls.version], ["Cipher suite", tls.cipher_name], ["Cipher protocol / secret bits", tls.cipher_protocol + " / " + tls.cipher_secret_bits],
      ["Forward secrecy", String(tls.assessment.forward_secrecy)], ["Authenticated encryption", String(tls.assessment.authenticated_encryption)],
      ["ALPN negotiated", String(tls.alpn_negotiated)], ["Compression", String(tls.compression)], ["Session reused", String(tls.session_reused)],
      ["SNI sent", tls.sni], ["Hostname verified", String(tls.hostname_checked)], ["Certificate checks", tls.verify_mode],
      ["Client TLS range", tls.client_minimum_version + " to " + tls.client_maximum_version], ["Trust store", r.trust_store],
      ["Local endpoint", r.connection.local_endpoint], ["Remote endpoint", r.connection.remote_endpoint], ["OpenSSL", tls.openssl]]),
    h("details", {}, h("summary", { text: "Cipher suites this client offered (" + tls.offered_ciphers.length + ")" }), explain("What this shows", k.ciphers_offered),
      h("pre", { text: tls.offered_ciphers.join("\n") })));
  if (r.protocol_support) {
    const ps = r.protocol_support;
    box.append(h("h3", { text: "4. Protocol support (extra handshakes, no HTTP sent)" }), explain("What this shows", k.protocol_support),
      h("table", {}, h("thead", {}, h("tr", {}, h("th", { text: "Version" }), h("th", { text: "Result" }), h("th", { text: "Detail" }))),
        h("tbody", {}, Object.entries(ps.tls_versions).map(([v, e]) => h("tr", {}, h("td", { text: v }),
          h("td", {}, pill(e.supported ? "supported" : "not supported", e.supported ? "OK" : "WARNING")), h("td", { class: "mono", text: e.cipher || e.error || "" }))))),
      h("p", { class: "muted", text: "ALPN when offered h2 and http/1.1: " + (ps.alpn_preference.negotiated || ps.alpn_preference.error) }));
  }
  box.append(h("h3", { text: "5. Certificate chain" }), explain("What this shows", k.chain), chainSvg(r.chain));
  r.chain.forEach((c, i) => {
    box.append(h("details", i === 0 ? { open: true } : {}, h("summary", { text: c.position.toUpperCase() + ": " + commonName(c.subject) }),
      certTable(c), ...state.explainCert(c)));
  });
  box.append(h("h3", { text: "6. The request that was sent" }), explain("What this shows", k.request), h("pre", { text: r.request.sent }),
    h("h3", { text: "7. The response" }), explain("What this shows", k.response),
    h("div", { class: "row" }, pill(r.response.status_line, r.http_status < 400 ? "OK" : "ERROR"), pill(r.response.header_count + " headers", "INFO")),
    h("table", {}, h("tbody", {}, r.response.headers.map(([n, v]) => h("tr", {}, h("td", { class: "mono", text: n }), h("td", { class: "mono", text: v }))))));
  const a = r.response.analysis;
  box.append(h("h3", { text: "8. Security header scorecard" }), explain("What this shows", k.security_headers),
    h("table", {}, h("tbody", {}, a.security_headers.map((x) => h("tr", {}, h("td", {}, pill(x.present ? x.level : "missing", x.present ? x.level : "WARNING")),
      h("td", { class: "mono", text: x.header }), h("td", { text: x.purpose }), h("td", { class: "mono", text: x.assessment }))))),
    h("h3", { text: "9. Cookies" }), explain("What this shows", k.cookies),
    a.cookies.length ? h("table", {}, h("thead", {}, h("tr", {}, ["Name", "Secure", "HttpOnly", "SameSite", "Path", "Value length"].map((t) => h("th", { text: t })))),
      h("tbody", {}, a.cookies.map((c) => h("tr", {}, [c.name, c.secure, c.http_only, c.same_site, c.path, c.value_length].map((v) => h("td", { class: "mono", text: String(v) })))))) : h("p", { class: "muted", text: "No cookies on this response." }),
    ...a.cookie_notes.map((n) => h("div", { class: "note WARNING", text: n })),
    h("h3", { text: "10. What the server reveals about itself" }), explain("What this shows", k.disclosure),
    kv([["Software headers", a.disclosure.map((d) => d.header + ": " + d.value).join("  |  ") || "none"], ["Infrastructure hints", a.infrastructure_hints.join(", ") || "none"],
      ["Advertises HTTP/3", String(a.advertises_http3)], ["Content type", a.content_type], ["Cache control", a.cache_control]]),
    h("details", {}, h("summary", { text: "Full text report" }), h("pre", { text: payload.report_text })),
    h("p", { class: "muted", text: r.note }));
}

async function viewDashboard(view) {
  const st = await refreshStatus();
  const self = await api("/api/self");
  const auto = await api("/api/autopilot");
  const crl = st.crl || {};
  const cycleBox = h("div"), selftestBox = h("div");
  const paintCycle = (cycle) => {
    cycleBox.replaceChildren(cycle && cycle.steps ? stepList(cycle.steps) : h("p", { class: "muted", text: "No cycle has run yet." }));
  };
  paintCycle(auto.last_cycle);
  const paintSelftest = (t) => {
    selftestBox.replaceChildren(t ? h("div", {}, h("div", { class: "row" }, pill(t.passed ? "all scenarios as expected" : "UNEXPECTED RESULT", t.passed ? "OK" : "ERROR"),
      h("span", { class: "muted", text: "run " + t.time.slice(0, 19).replace("T", " ") })),
      h("table", {}, h("tbody", {}, t.steps.map((s) => h("tr", {}, h("td", {}, pill(s.outcome)), h("td", { text: s.step }), h("td", { class: "muted", text: s.detail })))))) :
      h("p", { class: "muted", text: "Not run yet." }));
  };
  paintSelftest(auto.selftest);
  const runNow = h("button", { class: "btn alt", text: "Run maintenance now" });
  runNow.onclick = () => guard(async () => {
    runNow.disabled = true;
    const snap = await runJob("/api/autopilot/run", {}, (j) => paintCycle({ steps: j.progress }));
    runNow.disabled = false;
    if (snap.status === "error") return toast(snap.error.message);
    paintCycle(snap.result); toast("Maintenance finished", true);
  }).finally(() => { runNow.disabled = false; });
  const retest = h("button", { class: "btn alt", text: "Repeat the self-test" });
  retest.onclick = () => guard(async () => {
    retest.disabled = true;
    const snap = await runJob("/api/autopilot/run", { selftest: true }, (j) => paintCycle({ steps: j.progress }));
    retest.disabled = false;
    if (snap.status === "error") return toast(snap.error.message);
    paintCycle(snap.result); paintSelftest(snap.result.selftest); toast("Self-test finished", true);
  }).finally(() => { retest.disabled = false; });
  view.append(
    h("div", { class: "card hero" },
      h("h2", { text: "Examine any public website" }),
      explain("Everything else is automatic", "Type an address and press Enter. The lab authority, trust bundle, certificate renewal, revocation list, audit anchoring and site memory are all handled for you. You get a grade, a plain-English story, every finding explained with what to do, and the full technical detail."),
      examineWidget()),
    h("h2", { text: "Dashboard" }),
    h("div", { class: "grid" },
      h("div", { class: "card" }, h("h3", { text: "Authority" }), h("div", { class: "big", text: st.pki_ready ? "Ready" : "Not created" }),
        h("p", { class: "muted", text: "Root and intermediate CA, server and client certificates, created and kept healthy automatically." })),
      h("div", { class: "card" }, h("h3", { text: "Revocation list" }), h("div", { class: "big", text: crl.exists ? "#" + crl.number : "-" }),
        h("p", { class: "muted", text: crl.exists ? crl.revoked_count + " revoked; republished automatically before it expires (" + crl.hours_left + " hours left)" : "None published" })),
      h("div", { class: "card" }, h("h3", { text: "Certificates" }), h("div", { class: "big", text: st.certificates.active + " active" }),
        h("p", { class: "muted", text: st.certificates.revoked + " revoked · " + st.certificates.expired + " expired · renewed automatically " + st.config.renew_within_days + " days before expiry" })),
      h("div", { class: "card" }, h("h3", { text: "Audit trail" }), h("div", { class: "big" }, pill(st.audit.valid ? "chain intact" : "chain BROKEN", st.audit.valid ? "OK" : "ERROR")),
        h("p", { class: "muted", text: st.audit.records + " events · head " + short(st.audit.head, 16) + " · re-anchored every cycle" })),
      h("div", { class: "card" }, h("h3", { text: "mTLS server" }), h("div", { class: "big", text: st.mtls_server.running ? "Running" : "Stopped" }),
        h("p", { class: "muted", text: st.mtls_server.running ? "Port " + st.mtls_server.port : "Starts automatically" })),
      h("div", { class: "card" }, h("h3", { text: "Watched sites" }), h("div", { class: "big", text: String(st.watched_hosts) }),
        h("p", { class: "muted", text: "Every site you examine is remembered and re-checked every " + st.config.watch_interval_hours + " hours" }))),
    h("h3", { text: "Autopilot" }),
    explain("What it does for you", "Every " + (auto.maintenance_minutes || "(disabled)") + " minutes this interface checks the whole lab: creates the authority if missing, verifies the hierarchy, renews certificates about to expire, republishes the revocation list, finds a trust bundle, starts the mutual TLS server, anchors the audit log so rewriting history is detected, and re-checks watched sites. Nothing needs a click."),
    h("div", { class: "row" }, runNow, retest, pill(auto.healthy === false ? "needs attention" : "healthy", auto.healthy === false ? "ERROR" : "OK")),
    h("h3", { text: "Last cycle" }), cycleBox,
    h("h3", { text: "Mutual TLS self-test" }),
    explain("What it proves", "Six real connections: the built-in client is accepted, a client with no certificate is refused, a newly enrolled device is accepted, the same device is refused after revocation, and a rotated device works only with its new certificate."),
    selftestBox,
    h("h3", { text: "How this page reached you" }),
    explain("Self-reference", "This page was delivered over TLS using the lab's own server certificate, issued by the lab's own intermediate CA. The details below are this very connection."),
    h("div", { class: "card" }, kv([["TLS version", self.tls_version], ["Cipher suite", self.cipher[0] + " (" + self.cipher[1] + ", " + self.cipher[2] + "-bit)"],
      ["ALPN", String(self.alpn)], ["Your address", self.client_address], ["Server certificate", self.server_certificate.subject],
      ["Issued by", self.server_certificate.issuer], ["Expires", self.server_certificate.not_after + " (" + self.server_certificate.days_remaining + " days)"],
      ["Names it covers", self.server_certificate.subject_alternative_names.join(", ")], ["Client certificate required", String(self.client_certificate_required)]])),
    h("details", {}, h("summary", { text: "Why does my browser warn about this certificate?" }),
      explain("Trust is a choice you make", "Browsers ship with a list of root authorities. This lab's root is not on that list, because the lab created it for you. To remove the warning, import the root certificate into your browser or operating system. This tool never changes your trust stores itself."),
      h("div", { class: "row" }, h("a", { class: "btn alt", href: "/ca/root.pem", text: "Download lab root certificate" })),
      h("pre", { text: "Windows (current user):  certutil -user -addstore Root crystalline-pki-root.pem\nAll platforms:           crystalline-pki trust" })));
}

async function viewLifecycle(view) {
  const [{ certificates, crl }, k] = [await api("/api/certs"), state.knowledge];
  let selected = (certificates.find((c) => c.state === "active" && c.kind === "device") || certificates[0] || {}).serial;
  const detail = h("div", { class: "card" });
  const verifyBox = h("div");
  const hierarchy = h("div");
  const paint = async () => {
    hierarchy.replaceChildren(hierarchySvg(certificates, selected, (serial) => { selected = serial; paint(); }),
      h("div", { class: "legend" }, "green: active", "red: revoked", "amber: expired", "click a certificate for details"));
    table.replaceChildren(...certificates.map((c) => h("tr", { class: "click" + (c.serial === selected ? " sel" : ""), onclick: () => { selected = c.serial; paint(); } },
      h("td", { text: c.name }), h("td", { text: c.kind }), h("td", {}, pill(c.state)), h("td", { text: c.state === "revoked" ? "-" : String(c.days_left) }),
      h("td", { class: "mono", text: short(c.serial, 10) }), h("td", {}, validityBar(c)))));
    if (!selected) { detail.replaceChildren(h("p", { class: "muted", text: "Nothing issued yet." })); return; }
    const d = await api("/api/certs/" + selected);
    const reason = h("select", {}, k.reasons.map((r) => h("option", { value: r, text: r })));
    const pw = h("input", { type: "password", placeholder: "bundle password (8+)" });
    const rec = d.record;
    detail.replaceChildren(
      h("h3", { text: rec.name }), h("div", { class: "row" }, pill(rec.state), pill(rec.kind, "INFO"), pill(rec.state === "revoked" ? "revoked: " + rec.reason : rec.days_left + " days left", rec.state)),
      validityBar(rec),
      h("h3", { text: "Plain-English reading" }), ...notes(d.explanation),
      h("h3", { text: "Actions" }),
      rec.state === "revoked" ? h("p", { class: "muted", text: "Already revoked on " + rec.revoked_at + "." }) :
        h("div", { class: "row" }, reason, h("button", { class: "btn danger", text: "Revoke", onclick: () => guard(async () => {
          if (!confirm("Revoke " + rec.name + "? Servers will refuse it once they reload the revocation list.")) return;
          await api("/api/revoke", { identifier: rec.serial, reason: reason.value }); toast("Revoked", true); render();
        }) })),
      rec.kind === "device" && rec.state !== "revoked" ? h("div", { class: "row" }, h("button", { class: "btn", text: "Rotate (new key, new certificate)", onclick: () => guard(async () => {
        await api("/api/rotate", { name: rec.name }); toast("Rotated; the old certificate is revoked", true); render();
      }) })) : null,
      rec.kind !== "server" ? h("div", { class: "row" }, pw, h("button", { class: "btn alt", text: "Export phone bundle (.p12)", onclick: () => guard(async () => {
        const out = await api("/api/export/p12", { name: rec.name, password: pw.value }); toast("Written to " + out.directory, true);
      }) })) : null,
      h("details", {}, h("summary", { text: "All certificate fields" }), certTable(d.details)),
      h("details", {}, h("summary", { text: "Lifecycle history (from the audit log)" }), h("table", {}, h("tbody", {}, d.history.map((e) =>
        h("tr", {}, h("td", { class: "mono", text: e.timestamp.slice(0, 19) }), h("td", {}, pill(e.severity)), h("td", { text: e.action })))))),
      h("details", {}, h("summary", { text: "Certificate (PEM, public)" }), h("pre", { text: d.pem })));
  };
  const table = h("tbody");
  const name = h("input", { type: "text", placeholder: "device name, e.g. crew-phone-1", maxlength: 63 });
  view.append(h("h2", { text: "Certificate lifecycle" }),
    explain("The lifecycle in one line", "A device makes its own key and a signing request; the authority signs a short-lived certificate; before it expires the device rotates to a new one; if it is lost the authority revokes it and publishes a new revocation list."),
    h("div", { class: "card" }, h("h3", { text: "Enroll a device" }),
      explain("What happens", "A new EC P-256 key pair is generated (the device side), a certificate signing request is built, and the authority signs a client-auth certificate valid for 90 days (the authority side). Only the request travels between them, never the private key."),
      h("div", { class: "row" }, name, h("button", { class: "btn", text: "Enroll", onclick: () => guard(async () => {
        await api("/api/enroll", { name: name.value }); toast("Enrolled " + name.value, true); render();
      }) }), h("button", { class: "btn alt", text: "Republish revocation list", onclick: () => guard(async () => {
        const out = await api("/api/crl/refresh", {}); toast("Revocation list #" + out.status.number + " published", true); render();
      }) }), h("button", { class: "btn alt", text: "Export public certificates", onclick: () => guard(async () => {
        const out = await api("/api/export/certs", {}); toast("Exported to " + out.directory, true);
      }) }))),
    h("h3", { text: "Hierarchy" }), hierarchy,
    h("div", { class: "cols" },
      h("div", { class: "card" }, h("h3", { text: "Issued certificates" }), h("div", { class: "scroll" }, h("table", {},
        h("thead", {}, h("tr", {}, ["Name", "Kind", "State", "Days", "Serial", "Lifetime"].map((t) => h("th", { text: t })))), table))),
      detail),
    h("h3", { text: "Revocation list" }),
    explain("Why it matters", k.glossary["CRL (certificate revocation list)"]),
    crl ? kv([["Number", String(crl.number)], ["Published", crl.this_update], ["Must be republished by", crl.next_update], ["Hours left", String(crl.hours_left)],
      ["Revoked entries", String(crl.revoked_count)], ["Signature valid", String(crl.signature_valid)]]) : null,
    h("h3", { text: "Verify the whole hierarchy" }),
    h("div", { class: "row" }, h("button", { class: "btn", text: "Run verification", onclick: () => guard(async () => {
      const v = await api("/api/verify");
      verifyBox.replaceChildren(h("div", { class: "row" }, pill(v.passed + " passed", "OK"), pill(v.failed + " failed", v.failed ? "ERROR" : "OK")),
        h("table", {}, h("tbody", {}, v.checks.map((c) => h("tr", {}, h("td", {}, pill(c.result)), h("td", { text: c.check }), h("td", { class: "muted", text: c.why + (c.error ? "  [" + c.error + "]" : "") }))))));
    }) })), verifyBox);
  await paint();
}

async function viewLab(view) {
  const [ids, k] = [await api("/api/identities"), state.knowledge];
  const out = h("div"), scenarios = h("div", { class: "steps" });
  const select = h("select", {}, h("option", { value: "", text: "(no certificate)" }), ids.identities.map((i) =>
    h("option", { value: i.serial, text: i.label + (i.usable ? "" : "  - key unavailable") })));
  const serverCard = h("div", { class: "card" });
  const paintServer = (info) => serverCard.replaceChildren(h("h3", { text: "Mutual TLS server" }),
    h("div", { class: "row" }, pill(info.running ? "running on 127.0.0.1:" + info.port : "stopped", info.running ? "OK" : "WARNING"),
      h("button", { class: "btn", text: "Start", onclick: () => guard(async () => { await api("/api/server/start", {}); render(); }) }),
      h("button", { class: "btn alt", text: "Reload trust + revocation list", onclick: () => guard(async () => { await api("/api/server/reload", {}); toast("Reloaded", true); }) }),
      h("button", { class: "btn alt", text: "Stop", onclick: () => guard(async () => { await api("/api/server/stop", {}); render(); }) })));
  paintServer(ids.server);
  view.append(h("h2", { text: "Mutual TLS lab" }),
    explain("What mutual TLS adds", k.glossary["mTLS (mutual TLS)"] + " The server below accepts only clients whose certificate chains to the lab intermediate and is not on the revocation list."),
    serverCard,
    h("div", { class: "card" }, h("h3", { text: "Try a connection" }), h("div", { class: "row" }, select, h("button", { class: "btn", text: "Connect", onclick: () => guard(async () => {
      const r = await api("/api/lab/connect", { serial: select.value || null });
      const mtlsDetails = { "ClientHello": "SNI 127.0.0.1", "ServerHello": (r.tls_version || "?") + " · " + ((r.cipher || [])[0] || ""),
        "Certificate": "lab server chain", "CertificateRequest (mTLS only)": "client certificate required",
        "Certificate + CertificateVerify (mTLS only)": r.presented ? "presenting " + r.presented : "client sent none" };
      out.replaceChildren(h("div", { class: "row" }, pill(r.outcome), pill(r.presented || "no certificate", "INFO"), pill(r.seconds + " s", "INFO")),
        ...r.explanation.map((t) => h("div", { class: "note " + (r.outcome === "accepted" ? "OK" : "WARNING"), text: t })),
        r.response ? h("pre", { text: JSON.stringify(JSON.parse(r.response), null, 2) }) : null,
        handshakeSvg(k.handshake, { mtls: true, details: mtlsDetails }));
    }) })), out),
    h("div", { class: "card" }, h("h3", { text: "Scenario run" }),
      explain("What it proves", "Six connections in a row: the built-in client is accepted, a client with no certificate is refused, a newly enrolled device is accepted, the same device is refused after revocation, and a rotated device works only with its new certificate."),
      h("div", { class: "row" }, h("button", { class: "btn", text: "Run scenarios", onclick: () => guard(async () => {
        scenarios.replaceChildren();
        const snap = await runJob("/api/lab/scenarios", {}, (j) => scenarios.replaceChildren(...j.progress.map(stepCard)));
        if (snap.status === "error") toast(snap.error.message);
        else { scenarios.replaceChildren(...snap.result.steps.map(stepCard)); toast(snap.result.passed ? "All scenarios behaved as expected" : "A scenario did not behave as expected", snap.result.passed); }
      }) })), scenarios));
  function stepCard(s_) {
    return h("div", { class: "step " + (s_.passed ? "ok" : "error") }, h("b", {}, s_.step, "  ", pill(s_.outcome), "  ", pill(s_.passed ? "as expected" : "UNEXPECTED", s_.passed ? "OK" : "ERROR")),
      h("span", { class: "muted", text: (s_.tls_version || "") + " " + (s_.cipher || "") }), h("div", { text: s_.detail }), ...(s_.explanation || []).map((t) => h("div", { class: "muted", text: t })));
  }
}

async function viewProbe(view) {
  const trustInfo = await api("/api/trust");
  const bundle = h("input", { type: "text", size: 48, value: trustInfo.configured, placeholder: "optional path to a CA bundle .pem" });
  view.append(h("h2", { text: "Site probe" }),
    explain("What this does", "Type an address and everything else is automatic: the tool prepares itself, makes one ordinary HTTPS connection exactly as a browser would, verifies the certificate (retrying with a standard root bundle if your operating system's store is missing a root), tests which TLS versions the server supports, grades the result, explains every finding in plain English, saves a text and JSON report, and remembers the site so later runs show what changed."),
    h("div", { class: "card" }, examineWidget()),
    h("details", {}, h("summary", { text: "Trust sources this computer offers (detected automatically)" }),
      explain("Why this exists", trustInfo.system.note),
      kv([["Roots visible to Python", String(trustInfo.system.roots_visible_to_python)], ["Configured bundle", trustInfo.configured || "none (automatic)"]]),
      h("table", {}, h("thead", {}, h("tr", {}, ["Source", "Roots", "Path"].map((t) => h("th", { text: t })))),
        h("tbody", {}, trustInfo.bundles.map((b) => h("tr", {}, h("td", { text: b.source }), h("td", { text: String(b.roots) }), h("td", { class: "mono", text: b.path }))))),
      h("div", { class: "row" }, bundle, h("button", { class: "btn alt", text: "Override bundle", onclick: () => guard(async () => {
        await api("/api/config", { key: "ca_bundle", value: bundle.value }); toast("Saved", true);
      }) }))));
}

async function viewWatch(view) {
  const data = await api("/api/watch");
  const host = h("input", { type: "text", placeholder: "example.org", size: 30 });
  const out = h("div");
  const show = (res) => out.replaceChildren(h("h3", { text: res.host + ": " + res.status }), ...notes(res.findings.map((f) => [f.level === "CRITICAL" ? "ERROR" : f.level, f.message])));
  view.append(h("h2", { text: "Watchlist: the witness" }),
    explain("Authority versus witness", state.knowledge.glossary["Authority vs witness"] + " This list records what a public site's certificate looked like the first time, then reports what changed: a new issuer, a TLS downgrade, a certificate about to expire."),
    h("div", { class: "card" }, h("div", { class: "row" }, host, h("button", { class: "btn", text: "Add to watchlist", onclick: () => guard(async () => {
      await api("/api/watch/add", { host: host.value }); render();
    }) }), h("button", { class: "btn alt", text: "Check all", onclick: () => guard(async () => {
      const j = await runJob("/api/watch/check-all", {}); if (j.status === "error") return toast(j.error.message);
      j.result.forEach(show); render();
    }) })), h("p", { class: "muted", text: "Hosts are checked automatically every " + (state.status.config.watch_interval_hours) + " hours while this interface is running. Any site you examine is added here automatically. By adding a host you confirm you may test it." })),
    h("div", { class: "card" }, h("table", {}, h("thead", {}, h("tr", {}, ["Host", "Status", "Days left", "TLS", "Issuer", "Last checked", ""].map((t) => h("th", { text: t })))),
      h("tbody", {}, data.hosts.map((x) => h("tr", {}, h("td", { text: x.host }), h("td", {}, pill(x.last_status === "NEW" ? "INFO" : x.last_status, x.last_status === "NEW" ? "INFO" : x.last_status)),
        h("td", { text: x.days_remaining == null ? "-" : String(x.days_remaining) }), h("td", { text: x.tls_version || "-" }),
        h("td", { class: "mono", text: short(x.issuer, 44) }), h("td", { class: "mono", text: x.last_checked ? x.last_checked.slice(0, 19) : "never" }),
        h("td", {}, h("div", { class: "row" },
          h("button", { class: "btn alt", text: "Check", onclick: () => guard(async () => { const j = await runJob("/api/watch/check", { host: x.host }); if (j.status === "error") return toast(j.error.message); show(j.result); render(); }) }),
          h("button", { class: "btn alt", text: "Accept new baseline", onclick: () => guard(async () => { await api("/api/watch/accept", { host: x.host }); render(); }) }),
          h("button", { class: "btn alt", text: "Remove", onclick: () => guard(async () => { await api("/api/watch/remove", { host: x.host }); render(); }) }))))))),
      data.hosts.length ? null : h("p", { class: "muted", text: "No hosts yet." })), out);
}

async function viewAudit(view) {
  const sev = h("select", {}, ["", "INFO", "WARNING", "ERROR", "CRITICAL"].map((v) => h("option", { value: v, text: v || "all severities" })));
  const cat = h("input", { type: "text", placeholder: "category, e.g. LIFECYCLE", size: 22 });
  const text = h("input", { type: "text", placeholder: "search", size: 20 });
  const live = h("input", { type: "checkbox", checked: true });
  const body = h("tbody"), detail = h("pre", { text: "Click an event to see its full details." }), chainBox = h("div"), blocks = h("div", { class: "blocks" });
  let rows = [];
  const draw = () => {
    const q = text.value.toLowerCase();
    body.replaceChildren(...rows.filter((e) => !q || (e.action + e.target + e.component + JSON.stringify(e.details)).toLowerCase().includes(q))
      .slice(0, 400).map((e) => eventRow(e, (ev) => { detail.textContent = JSON.stringify(ev, null, 2); })));
    const recent = rows.slice(0, 10).reverse();
    blocks.replaceChildren(...recent.map((e) => h("div", { class: "block" }, h("b", { text: "#" + e.id }), h("div", { class: "mono", text: "prev " + short(e.previous_hash, 10) }),
      h("div", { class: "mono", text: "hash " + short(e.integrity_hash, 10) }), h("div", { class: "muted", text: short(e.action, 24) }))));
  };
  const load = async () => {
    const q = "limit=300&severity=" + encodeURIComponent(sev.value) + "&category=" + encodeURIComponent(cat.value);
    rows = (await api("/api/events/recent?" + q)).events; draw();
  };
  sev.onchange = cat.onchange = load; text.oninput = draw;
  state.onEvents = (events) => { if (live.checked) { rows = events.filter((e) => (!sev.value || e.severity === sev.value) && (!cat.value || e.category === cat.value.toUpperCase())).reverse().concat(rows).slice(0, 400); draw(); } };
  view.append(h("h2", { text: "Audit and logs" }),
    explain("How the audit trail protects itself", "Every event stores a SHA-256 hash that includes the previous event's hash, so changing or deleting any past entry breaks every hash after it. This detects accidental or naive tampering. Someone who can rewrite the database could rebuild the whole chain, so record the head hash somewhere else and compare it later."),
    h("div", { class: "row" }, h("button", { class: "btn", text: "Verify the chain", onclick: () => guard(async () => {
      const v = await api("/api/audit/verify");
      chainBox.replaceChildren(h("div", { class: "row" }, pill(v.valid ? "chain intact" : "CHAIN BROKEN", v.valid ? "OK" : "ERROR"), pill(v.records_checked + " events", "INFO")),
        kv([["Head hash (record this elsewhere)", v.head]]), ...v.failures.map((f) => h("div", { class: "note ERROR", text: (f.event_id || "head") + ": " + f.problem })));
    }) }), h("button", { class: "btn alt", text: "Export CSV", onclick: () => guard(async () => { const o = await api("/api/export/audit-csv", {}); toast("Written to " + o.path, true); }) }),
      h("button", { class: "btn alt", text: "Write full JSON report", onclick: () => guard(async () => { const o = await api("/api/report", {}); toast("Written to " + o.path, true); }) })), chainBox,
    h("h3", { text: "The last ten links of the chain" }), blocks,
    h("h3", { text: "Event log" }),
    h("div", { class: "row" }, sev, cat, text, h("label", { class: "check" }, live, "live")),
    h("div", { class: "cols" }, h("div", { class: "card scroll" }, h("table", {}, h("thead", {}, h("tr", {}, ["Time", "Level", "Component", "Action", "Target"].map((t) => h("th", { text: t })))), body)),
      h("div", { class: "card" }, h("h3", { text: "Event detail" }), detail)));
  await load();
}

async function viewLearn(view) {
  const k = state.knowledge, q = h("input", { type: "text", class: "search", placeholder: "search the glossary" });
  const gl = h("div");
  const draw = () => {
    const needle = q.value.toLowerCase();
    gl.replaceChildren(...Object.entries(k.glossary).filter(([a, b]) => !needle || (a + b).toLowerCase().includes(needle)).map(([a, b]) =>
      h("div", { class: "card", style: { marginBottom: "8px" } }, h("b", { text: a }), h("div", { text: b }))));
  };
  q.oninput = draw; draw();
  view.append(h("h2", { text: "Learn" }), ...k.lessons.map(([t, b]) => h("div", { class: "card", style: { marginBottom: "10px" } }, h("h3", { text: t }), ...b.split("\n").map((l) => h("p", { text: l })))),
    h("h3", { text: "The TLS handshake, step by step" }), handshakeSvg(k.handshake, { mtls: true }),
    h("div", { class: "steps" }, k.handshake.map((x) => h("div", { class: "step ok" }, h("b", { text: x.step }), x.text))),
    h("h3", { text: "What each verification check means" }), h("table", {}, h("tbody", {}, Object.entries(k.check_why).map(([a, b]) => h("tr", {}, h("td", { text: a }), h("td", { class: "muted", text: b }))))),
    h("h3", { text: "Glossary" }), q, gl);
}

const VIEWS = { dashboard: viewDashboard, lifecycle: viewLifecycle, lab: viewLab, probe: viewProbe, watch: viewWatch, audit: viewAudit, learn: viewLearn };

async function render() {
  const view = document.getElementById("view");
  state.onEvents = null;
  const fresh = h("div");
  try { await VIEWS[state.tab](fresh); } catch (error) { fresh.append(h("div", { class: "step error" }, h("b", { text: "Could not load this view" }), error.message)); }
  view.replaceChildren(...fresh.childNodes);
  document.querySelectorAll("#nav button").forEach((b) => b.classList.toggle("on", b.dataset.tab === state.tab));
}

state.explainCert = (c) => {
  const out = [];
  if (c.is_ca && c.self_signed) out.push(["INFO", "A root certificate: it vouches for itself, and is trusted only because it was installed."]);
  else if (c.is_ca) out.push(["INFO", "An intermediate CA: it can sign other certificates but is not a trust anchor."]);
  else out.push(["INFO", "A leaf certificate: it identifies one server and cannot sign others."]);
  out.push([c.expired ? "ERROR" : c.days_remaining <= 21 ? "WARNING" : "OK", c.expired ? "Expired." : c.days_remaining + " days remaining."]);
  if (!c.is_ca && !c.subject_alternative_names.length) out.push(["WARNING", "No subject alternative names."]);
  if (c.public_key_type === "RSA" && Number(c.public_key_detail) < 2048) out.push(["ERROR", "RSA key under 2048 bits."]);
  if (["md5", "sha1"].includes(c.signature_hash)) out.push(["ERROR", "Weak signature hash: " + c.signature_hash]);
  if (!c.is_ca && c.validity_days > 398) out.push(["INFO", "Lifetime of " + c.validity_days + " days exceeds the 398 days browsers allow for web certificates."]);
  return notes(out);
};

async function boot() {
  const nav = document.getElementById("nav");
  TABS.forEach(([id, label]) => nav.append(h("button", { "data-tab": id, text: label, onclick: () => { state.tab = id; location.hash = id; window.scrollTo(0, 0); render(); } })));
  state.knowledge = await api("/api/knowledge");
  const status = await api("/api/status");
  state.status = status;
  document.getElementById("version").textContent = "v" + status.version;
  if (status.theme && status.theme !== "plain") document.documentElement.dataset.theme = status.theme;
  try {
    const self = await api("/api/self");
    document.getElementById("conn").replaceChildren(h("b", { text: self.tls_version }), " · " + self.cipher[0]);
  } catch (e) { document.getElementById("conn").textContent = ""; }
  const wanted = location.hash.slice(1);
  if (VIEWS[wanted]) state.tab = wanted;
  await render();
  setInterval(pollEvents, 2000);
  pollEvents();
}
boot().catch((error) => { document.getElementById("view").append(h("div", { class: "step error" }, h("b", { text: "Could not start" }), error.message)); });
})();
