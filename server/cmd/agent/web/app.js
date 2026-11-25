"use strict";
// Talks to the SecureTunnel service through window.stCall (bound by the Go host).

const $ = (id) => document.getElementById(id);

// Appearance: System (follow Windows / macOS), Light or Dark. Remembered per user.
function applyTheme(t) {
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
  else delete document.documentElement.dataset.theme;
  document.querySelectorAll("#theme-seg button").forEach((b) => b.classList.toggle("on", b.dataset.theme === (t || "system")));
}
let savedTheme = "system";
try { savedTheme = localStorage.getItem("st-theme") || "system"; } catch (e) { /* storage unavailable */ }
applyTheme(savedTheme);
document.addEventListener("click", (ev) => {
  const b = ev.target.closest && ev.target.closest("#theme-seg button");
  if (!b) return;
  try { localStorage.setItem("st-theme", b.dataset.theme); } catch (e) { /* storage unavailable */ }
  applyTheme(b.dataset.theme);
});
let tab = "home";
let status = null;
let update = null;
let speed = null;
let ips = null;
let notice = null;
let owner = null; // who connected the tunnel (another Windows user on shared PCs)

function renderNotice() {
  const box = $("notice");
  if (!notice) { box.classList.add("hidden"); return; }
  $("notice-text").textContent = notice.text;
  const t = ts(notice.at);
  $("notice-meta").textContent = (notice.from ? notice.from + " · " : "") + (t ? new Date(t).toLocaleTimeString([], { hour: "numeric", minute: "2-digit" }) : "");
  box.classList.remove("hidden");
}
let serviceDown = false;
let busy = false;
// Sign-in options belong to the server that returned them.
let auth = { server: "", config: null, checkedAt: 0, error: "", pending: null };
let showLocal = false, msWaiting = false;
function loadAuth(force) {
  const server = status && status.server;
  if (!server) return;
  if (auth.server !== server) auth = { server, config: null, checkedAt: 0, error: "", pending: null };
  const request = auth;
  if (request.pending) return;
  const retryAfter = request.config ? 5 * 60e3 : 15e3;
  if (!force && Date.now() - request.checkedAt < retryAfter) return;
  request.pending = call({ cmd: "auth_config" }).then((r) => {
    request.pending = null;
    if (auth !== request || !status || status.server !== server) return;
    request.config = r.ok && r.auth ? r.auth : null;
    request.error = request.config ? "" : (r.error || "Couldn't check the server's sign-in options.");
    request.checkedAt = Date.now();
    render();
  });
}

async function call(req) {
  if (!window.stCall) return { ok: false, error: "Not running inside the SecureTunnel app." };
  try {
    const r = JSON.parse(await window.stCall(JSON.stringify(req)));
    if (req.cmd === "auth_config") return r;
    serviceDown = !!r.service_down;
    if (r.status) status = r.status;
    if (r.update) update = r.update;
    if (r.speed) speed = r.speed;
    if (r.ips) ips = r.ips;
    if (r.status) notice = r.notice || null;
    if (r.status) owner = r.owner || null;
    return r;
  } catch (e) {
    return { ok: false, error: String(e) };
  }
}

function dur(s) {
  s = Math.max(0, Math.round(s));
  if (s < 60) return s + "s";
  const m = Math.floor(s / 60);
  if (m < 60) return m + "m";
  const h = Math.floor(m / 60);
  return h + "h " + (m % 60) + "m";
}
const ts = (iso) => { const t = Date.parse(iso); return t && t > Date.UTC(1971, 0, 1) ? t : 0; };
function timeLeft(iso) {
  const t = ts(iso);
  if (!t) return "–";
  return dur((t - Date.now()) / 1000);
}

function show(view) {
  for (const v of ["setup", "signin", "busy", "status", "diag", "about"]) $("v-" + v).classList.toggle("hidden", v !== view);
}

// ---- speed test card (Status and Diagnose tabs) ----
// One compact row: label, download/upload, latency and age.
function speedBox(label, s, connectedOnly) {
  const row = document.createElement("div");
  row.className = "st-row";
  const k = document.createElement("span"); k.className = "k"; k.textContent = label;
  const v = document.createElement("span"); v.className = "v";
  const sub = document.createElement("span"); sub.className = "s";
  if (s) {
    v.textContent = "↓ " + fmtBps(s.down_bps) + "  ↑ " + fmtBps(s.up_bps);
    sub.textContent = s.latency_ms + " ms · " + dur((Date.now() - ts(s.at)) / 1000) + " ago";
  } else {
    v.textContent = "–";
    sub.textContent = connectedOnly ? "when connected" : "not run yet";
  }
  row.append(k, v, sub);
  return row;
}

function renderSpeed() {
  const sp = speed || {};
  const phase = { internet: "Testing your internet…", vpn: "Testing through the VPN…" }[sp.phase] || "Testing…";
  document.querySelectorAll("[data-speed]").forEach((card) => {
    const head = document.createElement("div");
    head.className = "st-head";
    const title = document.createElement("span");
    title.className = "strong";
    title.textContent = "Speed test";
    const btn = document.createElement("button");
    btn.className = "btn sm";
    btn.textContent = sp.running ? phase : "Run test";
    btn.disabled = !!sp.running;
    btn.addEventListener("click", runSpeed);
    head.append(title, btn);
    const grid = document.createElement("div");
    grid.className = "st-grid";
    grid.append(speedBox("Internet", sp.internet, false), speedBox("VPN", sp.vpn, true));
    card.title = "Internet: your connection's own speed, outside the VPN. VPN: speed through the tunnel. " +
      (sp.interval_hours > 0 ? "Runs automatically about every " + sp.interval_hours + " hours when your PC is idle." : "Automatic tests are off.");
    const parts = [head, grid];
    if (sp.error) {
      const note = document.createElement("p");
      note.className = "error";
      note.textContent = sp.error;
      parts.push(note);
    }
    card.replaceChildren(...parts);
  });
}

async function runSpeed() {
  speed = Object.assign({}, speed || {}, { running: true, phase: "internet", error: "" });
  renderSpeed();
  await call({ cmd: "speedtest" });
  renderSpeed();
}

$("notice-ok").addEventListener("click", async () => {
  const id = notice && notice.id;
  notice = null;
  renderNotice();
  await call({ cmd: "dismiss_notice", id });
});

function render() {
  renderSpeed();
  renderNotice();
  document.querySelectorAll(".tabs button").forEach((b) => b.classList.toggle("on", b.dataset.tab === tab));
  const st = status;
  $("top-user").textContent = st && st.user ? st.user : "";
  if (tab === "diag") return show("diag");
  if (tab === "about") return renderAbout();

  if (serviceDown || !st) {
    show("signin");
    $("si-title").textContent = "Service not running";
    $("si-sub").textContent = "Restart the PC or reinstall SecureTunnel.";
    $("f-signin").classList.add("hidden");
    $("si-ms").classList.add("hidden");
    $("si-local-toggle").classList.add("hidden");
    return;
  }
  $("f-signin").classList.remove("hidden");
  if (!st.server) return show("setup");

  switch (st.state) {
    case "signing_in":
    case "connecting":
    case "disconnecting":
      $("busy-title").textContent = { signing_in: "Connecting…", connecting: "Connecting…", disconnecting: "Disconnecting…" }[st.state];
      $("busy-sub").textContent = { signing_in: "Signing in and starting the secure tunnel.", connecting: "Starting the secure tunnel.", disconnecting: "Closing the secure tunnel." }[st.state];
      if (st.state === "signing_in" && st.message && /duo|push|phone/i.test(st.message)) {
        // Only while a Duo Push is actually waiting for the user.
        $("busy-title").textContent = "Check your phone";
        $("busy-sub").textContent = st.message;
      }
      return show("busy");
    case "connected":
    case "reconnecting":
      return renderStatus(st);
    default:
      return renderSignin(st);
  }
}

function renderSignin(st) {
  show("signin");
  $("si-title").textContent = "Not connected";
  $("si-sub").textContent = "Sign in to connect to " + st.server.replace(/^https:\/\//, "") + ".";
  const b = $("si-banner");
  $("si-dot").className = "dot " + (st.on_trusted_network ? "info" : "neutral");
  $("si-dot").querySelector("use").setAttribute("href", st.on_trusted_network ? "#i-building" : "#i-unlock");
  $("si-title").textContent = st.on_trusted_network ? "On the office network" : "Not connected";
  if (st.device_tunnel && !st.on_trusted_network) {
    // Only the pre-logon device tunnel is up (domain controllers etc.).
    $("si-title").textContent = "Device tunnel only";
    $("si-sub").textContent = "This PC can reach the sign-in servers. Sign in to connect fully.";
  }
  loadAuth(false);
  const cfg = auth.config;
  const ms = !!(cfg && cfg.entra);
  const local = !!(cfg && cfg.local);
  const checking = !cfg && !!auth.pending;
  $("si-ms").classList.remove("hidden");
  $("si-ms-ready").classList.toggle("hidden", msWaiting);
  $("si-ms-wait").classList.toggle("hidden", !msWaiting);
  $("si-ms-btn").disabled = busy || checking || (!!cfg && !ms);
  $("si-ms-label").textContent = cfg ? "Sign in with Microsoft" : checking ? "Checking sign-in options…" : "Retry sign-in options";
  $("si-ms-note").textContent = ms ? "Opens your browser to sign in with your work account."
    : cfg ? "Microsoft sign-in is turned off for this server."
      : checking ? "Getting sign-in options from your server." : auth.error;
  // Local accounts are for testing: a small link that opens a compact form.
  $("f-signin").classList.toggle("hidden", !local || !showLocal || msWaiting);
  $("si-local-toggle").classList.toggle("hidden", !local || msWaiting);
  $("si-local-toggle").textContent = showLocal ? "Hide local account" : "Use a local account (testing)";
  if (st.on_trusted_network) $("si-sub").textContent = "Sign in now: traffic goes direct while you're in the office, and through the VPN when you leave.";
  if (st.on_trusted_network) {
    b.textContent = "You're on the office network" + (st.trusted_reason ? " (" + st.trusted_reason + ")" : "") + ", so the VPN stays on standby here.";
    b.className = "banner";
  } else if (st.message) {
    b.textContent = st.message;
    b.className = "banner warn";
  } else {
    b.className = "banner hidden";
  }
  $("si-btn").disabled = busy;
  $("si-ip").textContent = ips && ips.isp_ip ? "Your public IP: " + ips.isp_ip : "";
}

// ---- connection health: plain-English warnings with what to try ----
function healthIssue(st) {
  const n = st.network || {};
  const wifi = n.kind === "Wi-Fi";
  const hist = (st.latency_history || []);
  const ok = hist.filter((v) => v >= 0).sort((a, b) => a - b);
  const median = ok.length ? ok[Math.floor(ok.length / 2)] : 0;
  const local = wifi
    ? "Move closer to your Wi-Fi router, or plug in a network cable if you can."
    : "Check your internet connection, or restart your modem or router.";
  if ((st.drops_recent || 0) >= 3) {
    return { kind: "bad", title: "Your connection keeps dropping",
      text: "It dropped " + st.drops_recent + " times in the last 15 minutes. Calls and downloads may be interrupted. " + local };
  }
  if (wifi && n.signal_pct && n.signal_pct < 40) {
    return { kind: "warn", title: "Weak Wi-Fi signal",
      text: "Your Wi-Fi signal is " + n.signal_pct + "%. Move closer to the router or use a network cable for a steadier connection." };
  }
  if (ok.length >= 10 && median > 150) {
    return { kind: "warn", title: "Your connection is slow to respond",
      text: "It takes about " + median + " ms to reach the VPN (under 80 ms is typical). If others on your network are streaming or uploading, that can cause it. " + local };
  }
  if (ok.length >= 10 && st.jitter_ms >= 30) {
    return { kind: "warn", title: "Your connection is unsteady",
      text: "Response times vary by about " + st.jitter_ms + " ms, which can make Teams calls choppy. " + local };
  }
  return null;
}
function renderHealth(st, rec) {
  const box = $("st-health");
  const issue = rec ? null : healthIssue(st);
  box.classList.toggle("hidden", !issue);
  if (!issue) return;
  box.className = "health " + issue.kind;
  $("st-health-title").textContent = issue.title;
  $("st-health-text").textContent = issue.text;
}

const vpnRecovery = new Map([
  ["checking", ["Checking VPN connection…", "No action needed right now."]],
  ["waiting_for_network", ["Waiting for a network", "Connect to Wi-Fi or Ethernet to continue."]],
  ["repairing", ["Repairing the VPN…", "Restarting the tunnel on the current gateway."]],
  ["switching_gateway", ["Switching VPN gateways…", "Trying another VPN gateway."]],
  ["starting_tunnel", ["Starting the tunnel…", "Setting up the VPN connection."]],
  ["network_change", ["Connecting…", "Checking the VPN after a network change."]],
]);
const vpnRecoveryMessages = new Map([...vpnRecovery].map(([phase, [title]]) => [title, phase]));

vpnRecoveryMessages.set("Checking the VPN path…", "checking"); // Older agent services.

function recoveryStatus(st) {
  if (!st.office_mode) {
    const phase = vpnRecovery.has(st.vpn_phase) ? st.vpn_phase :
      st.state === "reconnecting" ? vpnRecoveryMessages.get(st.message) : null;
    if (phase) {
      const [title, subtitle] = vpnRecovery.get(phase);
      return { title, subtitle };
    }
  }
  if (st.state !== "reconnecting") return null;
  if (!st.office_mode && (st.message || "").startsWith("Moving to gateway ")) {
    return { title: st.message, subtitle: "The VPN connection may be interrupted while it moves." };
  }
  return { title: "Reconnecting…", subtitle: "Trying to restore the VPN connection." };
}

function renderStatus(st) {
  const t = st.device_trust;
  // Certificates only: join type and compliance are Entra's job (Conditional Access).
  const certs = [];
  if (t && t.device_cert) certs.push("Device certificate " + (t.device_cert.ok ? "OK" : "rejected"));
  if (t && t.user_cert) certs.push("User certificate " + (t.user_cert.ok ? "OK" : "rejected"));
  $("st-trust-wrap").classList.toggle("hidden", !certs.length);
  $("st-trust").textContent = certs.join(" · ");
  show("status");
  const recovery = recoveryStatus(st);
  const rec = !!recovery;
  $("st-dot").className = "dot " + (rec ? "warn spin" : "ok");
  $("st-dot").querySelector("use").setAttribute("href", rec ? "#i-refresh" : "#i-lock");
  $("st-title").textContent = rec ? recovery.title : "Connected";
  $("st-sub").textContent = rec ? recovery.subtitle : "VPN tunnel is active.";
  // Office mode: signed in, but traffic goes straight out the office network.
  const office = !!st.office_mode && !rec;
  $("st-office").classList.toggle("hidden", !office);
  $("st-conn").classList.toggle("hidden", office);
  if (office) {
    $("st-dot").className = "dot info";
    $("st-dot").querySelector("use").setAttribute("href", "#i-building");
    $("st-title").textContent = "Connected · office mode";
    $("st-sub").textContent = "Signed in. The VPN is on standby.";
    $("st-office-text").textContent = "Your traffic goes through the office network" +
      (st.trusted_reason ? " (detected by " + st.trusted_reason + ")" : "") + ".";
  }

  // Another Windows user connected this tunnel (shared PC or user switching).
  const other = owner && !owner.you;
  $("st-owner").classList.toggle("hidden", !other);
  if (other) {
    $("st-owner").textContent = "Connected by " + owner.name + ", another Windows user on this PC." +
      (owner.can_disconnect ? "" : " Only they can disconnect it.");
  }
  $("st-disconnect").classList.toggle("hidden", !!(other && !owner.can_disconnect));

  renderUpdateNotice();

  // Speed
  $("sp-down").textContent = fmtBps(st.rx_bps);
  $("sp-up").textContent = fmtBps(st.tx_bps);
  const rates = st.rate_history || [];
  chartData.rates = { values: rates, timing: chartTiming(st.rate_history_seconds, st.rate_latest_seconds) };
  drawRates(rates);
  renderChartAxis("sp", chartData.rates, true, 2);
  const peakRx = rates.reduce((m, p) => Math.max(m, p.rx), 0);
  const peakTx = rates.reduce((m, p) => Math.max(m, p.tx), 0);
  $("sp-total").title = (peakRx || peakTx ? "Peak shown: receiving " + fmtBps(peakRx) + ", sending " + fmtBps(peakTx) + ". " : "") +
    "Blue: receiving. Green: sending.";

  // Quality
  const latency = st.latency_history || [];
  const lat = latency.filter((v) => v >= 0);
  const serverChecks = latency.length > 0 && st.latency_source === "control";
  const unknownSource = latency.length > 0 && !st.latency_source;
  $("lat-caption").textContent = serverChecks ? "Server latency" : unknownSource ? "Latency" : "VPN latency";
  const latencyDescription = serverChecks ? "Round trip to the control server." : unknownSource
    ? "Round trip for recent connection checks." : "Round trip to your VPN gateway through the tunnel.";
  $("lat-total").title = latencyDescription + " Red marks samples with no reply.";
  $("m-lat-box").title = latencyDescription + " Jitter measures how much response times vary.";
  $("m-lat").textContent = st.latency_ms && !rec ? st.latency_ms + " ms" : "–";
  $("m-jit").textContent = lat.length > 1 ? "±" + st.jitter_ms + " ms jitter" : "";
  const loss = $("m-loss");
  const hasLoss = latency.length > 0 && Number.isFinite(st.loss_pct);
  $("m-loss-label").textContent = serverChecks || unknownSource ? "Missed checks" : "Packet loss";
  $("m-loss-box").title = serverChecks ? "Percentage of recent control server checks that received no reply."
    : unknownSource ? "Percentage of recent connection checks that received no reply."
      : "Percentage of recent pings to the VPN gateway that received no reply.";
  $("m-loss-period").textContent = hasLoss && st.loss_window_seconds > 0 ? "Last " + historyDuration(st.loss_window_seconds) : "";
  loss.textContent = hasLoss ? (st.loss_pct > 0 && st.loss_pct < 10 ? st.loss_pct.toFixed(1) : Math.round(st.loss_pct)) + "%" : "–";
  loss.classList.toggle("loss-warn", hasLoss && st.loss_pct >= 3 && st.loss_pct < 10);
  loss.classList.toggle("loss-bad", hasLoss && st.loss_pct >= 10);
  const q = rec ? ["Checking", "neutral"] : quality(st);
  $("q-pill").textContent = q[0];
  $("q-pill").className = "pill " + q[1];
  chartData.lat = { values: latency, timing: chartTiming(st.latency_history_seconds, st.latency_latest_seconds) };
  drawLatency(latency);
  renderChartAxis("lat", chartData.lat, false, serverChecks ? 35 : 6);
  renderHealth(st, rec);

  // Network
  const n = st.network || {};
  $("net-ic").setAttribute("href", n.kind === "Ethernet" ? "#i-cable" : "#i-wifi");
  $("net-name").textContent = n.kind === "Wi-Fi" && n.ssid ? n.ssid : (n.kind || "Network");
  $("net-sub").textContent = [n.adapter, n.link_mbps ? n.link_mbps + " Mbps link" : "", n.signal_pct ? n.signal_pct + "% signal" : ""].filter(Boolean).join(" · ");
  const bars = $("net-bars");
  bars.classList.toggle("hidden-bars", !n.signal_pct);
  const lit = n.signal_pct >= 80 ? 4 : n.signal_pct >= 55 ? 3 : n.signal_pct >= 30 ? 2 : n.signal_pct > 0 ? 1 : 0;
  [...bars.children].forEach((b, i) => b.classList.toggle("on", i < lit));

  // Session
  $("m-dur").textContent = ts(st.connected_since) ? dur((Date.now() - ts(st.connected_since)) / 1000) : "–";
  $("m-exp").textContent = "in " + timeLeft(st.session_expires);
  $("st-user").textContent = st.user || "–";
  $("st-gw").textContent = st.gateway || "–";
  $("st-gw-ep").textContent = st.gateway_endpoint || "";
  const inUse = (st.server_in_use || st.server || "").replace(/^https:\/\//, "");
  const backup = st.server_in_use && st.server && st.server_in_use !== st.server;
  $("st-server").textContent = inUse ? inUse + (backup ? " (backup)" : "") : "–";
  $("st-server").title = backup ? "The main address (" + st.server.replace(/^https:\/\//, "") + ") can't be reached, so this backup is in use." : "";
  $("st-ip").textContent = st.tunnel_ip || "–";
  $("st-vpnip").textContent = (ips && ips.vpn_ip) || "–";
  $("st-ispip").textContent = (ips && ips.isp_ip) || "–";
  $("conn-down").textContent = st.rx_bytes ? fmtBytes(st.rx_bytes) : "–";
  $("conn-up").textContent = st.tx_bytes ? fmtBytes(st.tx_bytes) : "–";
}

function quality(st) {
  const h = st.latency_history || [];
  if (h.length < 2) return ["Measuring…", "neutral"];
  if (st.loss_pct >= 10 || st.latency_ms > 250) return ["Poor", "bad"];
  if (st.loss_pct >= 3 || st.latency_ms > 120 || st.jitter_ms > 40) return ["Fair", "warn"];
  return ["Good", "ok"];
}

function fmtBps(n) {
  if (!n || n < 1) return "0 bps";
  const u = ["bps", "Kbps", "Mbps", "Gbps"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1000)));
  const v = n / Math.pow(1000, i);
  return (v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)) + " " + u[i];
}
function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  const v = n / Math.pow(1024, i);
  return (v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)) + " " + u[i];
}

const SVGNS = "http://www.w3.org/2000/svg";
function svgEl(tag, attrs) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
  return e;
}
function pathFor(vals, W, H, top) {
  const n = vals.length;
  return vals.map((v, i) => {
    const x = n === 1 ? W : (i / (n - 1)) * W;
    const y = H - (Math.min(v, top) / top) * (H - 2) - 1;
    return (i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1);
  }).join(" ");
}
function drawRates(h) {
  const svg = $("sp-chart"), W = 300, H = 64;
  if (!svg) return;
  svg.replaceChildren(svgEl("line", { x1: 0, x2: W, y1: H - 0.5, y2: H - 0.5, class: "grid" }));
  if (h.length < 2) {
    const t = svgEl("text", { x: 0, y: H / 2, class: "empty" });
    t.textContent = "Collecting…";
    svg.append(t);
    return;
  }
  const top = Math.max(1000, ...h.map((p) => Math.max(p.rx, p.tx))) * 1.1;
  const down = pathFor(h.map((p) => p.rx), W, H, top);
  svg.append(svgEl("path", { d: down + ` L${W} ${H} L0 ${H} Z`, class: "down-a" }));
  svg.append(svgEl("path", { d: down, class: "down" }));
  svg.append(svgEl("path", { d: pathFor(h.map((p) => p.tx), W, H, top), class: "up" }));
}
function drawLatency(h) {
  const svg = $("lat-chart"), W = 300, H = 40;
  if (!svg) return;
  svg.replaceChildren();
  const ok = h.filter((v) => v >= 0);
  if (ok.length < 2) {
    const t = svgEl("text", { x: 0, y: H / 2 + 4, class: "empty" });
    t.textContent = "Measuring…";
    svg.append(t);
    return;
  }
  const top = Math.max(50, ...ok) * 1.2;
  const pts = h.map((v) => (v < 0 ? top : v));
  svg.append(svgEl("path", { d: pathFor(pts, W, H, top), class: "lat" }));
  h.forEach((v, i) => {
    if (v < 0) svg.append(svgEl("circle", { cx: (i / Math.max(1, h.length - 1)) * W, cy: 4, r: 2.5, class: "fail" }));
  });
}

function renderAbout() {
  show("about");
  const st = status || {};
  $("ab-server").textContent = st.server ? st.server.replace(/^https:\/\//, "") : "Not set";
  $("ab-trust").textContent = {
    "system": "Trusted", "pinned": "Saved on first connect", "first-use": "Saved on first connect",
  }[st.trust_mode] || "Not checked yet";
  const canChange = !st.server_locked && (st.state === "disconnected" || !st.state);
  $("f-server").classList.toggle("hidden", !!st.server_locked);
  $("ab-new").disabled = !canChange;
  $("ab-save").disabled = !canChange;
  $("ab-note").classList.toggle("hidden", canChange);
  renderUpdate();
  if (!certsLoading && Date.now() - certsAt > 30000) loadCerts();
}

// ---- Settings → Certificates: automatic by default, or pin one ----
let certs = null, certsAt = 0, certsLoading = false;
async function loadCerts() {
  if (!window.stCerts) { $("cert-card").classList.add("hidden"); return; }
  certsLoading = true;
  if (!certs) $("cert-need").textContent = "Loading…";
  try { drawCerts(JSON.parse(await window.stCerts())); } catch (e) { $("cert-error").textContent = String(e); }
  certsLoading = false;
  certsAt = Date.now();
}
const shortDate = (iso) => new Date(iso).toLocaleDateString(undefined, { year: "numeric", month: "short", day: "numeric" });
function drawCerts(r) {
  if (!r.ok) { $("cert-error").textContent = r.error || "Couldn't read certificates."; return; }
  certs = r;
  $("cert-error").textContent = "";
  const need = !r.known ? "" : r.wants_device && r.wants_user ? "Required: device or user" : r.wants_device ? "Required: device" : r.wants_user ? "Required: user" : "Not required";
  $("cert-need").textContent = need;
  // "either" and "both" both set the two flags; the label stays general.
  for (const kind of ["device", "user"]) {
    const list = r[kind], sel = $("cert-" + kind), detail = $("cert-" + kind + "-detail");
    const err = r[kind + "_error"];
    sel.replaceChildren();
    if (!list) { sel.append(new Option("Automatic", "")); sel.disabled = true; detail.textContent = err || ""; continue; }
    sel.disabled = false;
    const byThumb = {};
    for (const c of list.certs || []) byThumb[c.thumb] = c;
    const auto = (list.auto || []).map((t) => byThumb[t]).filter(Boolean);
    sel.append(new Option(auto.length ? "Automatic (" + auto[0].name + ")" : "Automatic (none found)", ""));
    for (const c of list.certs || []) {
      const o = new Option(c.name + " · " + (c.usable ? "expires " + shortDate(c.not_after) : c.why), c.thumb);
      o.disabled = !c.usable && c.thumb !== list.pinned;
      sel.append(o);
    }
    const pinned = list.pinned && byThumb[list.pinned];
    if (list.pinned && !pinned) sel.append(new Option("Chosen certificate (no longer on this PC)", list.pinned));
    sel.value = list.pinned || "";
    const show = pinned || (!list.pinned && auto[0]);
    let text = !(list.certs || []).length ? "No " + kind + " certificates on this PC."
      : show ? "Issued by " + show.issuer + " · expires " + shortDate(show.not_after) + " · " + show.thumb.slice(0, 8).toLowerCase() + "…" : "";
    if (!list.pinned && auto.length > 1) text += " If it's turned down, the next " + (auto.length - 1 === 1 ? "one is" : auto.length - 1 + " are") + " tried too.";
    if (list.pinned && !pinned) text = "The certificate you chose is gone or expired, so one is picked automatically.";
    detail.textContent = text;
  }
}
for (const kind of ["device", "user"]) {
  $("cert-" + kind).addEventListener("change", async (ev) => {
    $("cert-error").textContent = "";
    ev.target.disabled = true;
    try {
      const r = JSON.parse(await window.stSetCert(kind, ev.target.value));
      if (!r.ok) { $("cert-error").textContent = r.error || "Couldn't save."; loadCerts(); return; }
      drawCerts(r);
      $("cert-" + kind + "-detail").textContent += " Saved; used the next time you connect.";
    } catch (e) { $("cert-error").textContent = String(e); }
    ev.target.disabled = false;
  });
}

// ---- updates ----
const whenText = (iso) => {
  const d = new Date(iso), now = new Date();
  const day = d.toDateString() === now.toDateString() ? "today" :
    d.toDateString() === new Date(now.getTime() + 864e5).toDateString() ? "tomorrow" :
    d.toLocaleDateString(undefined, { weekday: "short", month: "short", day: "numeric" });
  return day + " at " + d.toLocaleTimeString(undefined, { hour: "numeric", minute: "2-digit" });
};
const real = (iso) => iso && ts(iso) > 0 && !String(iso).startsWith("0001");
// When a waiting update installs, in words.
function updatePlanText(u) {
  if (real(u.install_at)) return "It's scheduled for " + whenText(u.install_at) + ".";
  let s = "It installs the next time you disconnect";
  if (u.install_when === "window" && u.window) s += ", or during the maintenance window (" + u.window + ")";
  if (u.install_when === "anytime") s = "It installs shortly";
  if (real(u.deadline)) s += ", and by " + whenText(u.deadline) + " at the latest";
  return s + ".";
}
const DROP = "You'll be disconnected for about 20 seconds, then SecureTunnel reconnects by itself.";

// The notice on the Status tab: a countdown before an update interrupts the
// connection, a scheduled update, or (if IT wants users told) a waiting one.
function renderUpdateNotice() {
  const box = $("st-update"), u = update || {};
  const countdown = u.state === "ready" && real(u.countdown);
  const show = u.state === "installing" || (u.state === "ready" && (countdown || real(u.install_at) || u.notify));
  box.classList.toggle("hidden", !show);
  if (!show) return;
  box.classList.toggle("warn", countdown || u.state === "installing");
  $("upd-later").classList.toggle("hidden", !(u.can_postpone && (countdown || real(u.install_at))));
  $("upd-now").classList.toggle("hidden", u.state !== "ready");
  if (u.state === "installing") {
    $("upd-title").textContent = "Updating SecureTunnel…";
    $("upd-sub").textContent = "It reconnects by itself in a moment.";
  } else if (countdown) {
    const left = Math.max(0, Math.round((ts(u.countdown) - Date.now()) / 1000));
    $("upd-title").textContent = "Updating in " + Math.floor(left / 60) + ":" + String(left % 60).padStart(2, "0");
    $("upd-sub").textContent = "Version " + u.latest + (u.why ? " (" + u.why + ")" : "") + ". " + DROP;
  } else if (real(u.install_at)) {
    $("upd-title").textContent = "Update scheduled for " + whenText(u.install_at);
    $("upd-sub").textContent = "Version " + u.latest + ". " + DROP;
  } else {
    $("upd-title").textContent = "Version " + u.latest + " is ready";
    $("upd-sub").textContent = updatePlanText(u);
  }
}
// Keep the countdown ticking between status refreshes.
setInterval(() => { if (update && real(update.countdown) && tab === "home") renderUpdateNotice(); }, 1000);
$("upd-now").addEventListener("click", async () => {
  $("upd-now").disabled = true;
  await call({ cmd: "install_update" });
  $("upd-now").disabled = false;
  render();
});
$("upd-later").addEventListener("click", async () => {
  const r = await call({ cmd: "postpone_update" });
  render();
  if (!r.ok && r.error) $("upd-sub").textContent = r.error;
});

function renderUpdate() {
  const u = update || {};
  const t = ts(u.checked_at);
  $("up-checked").textContent = t ? "Checked " + dur((Date.now() - t) / 1000) + " ago" : "";
  const text = {
    checking: "Checking…",
    up_to_date: "You have the latest version" + (u.current ? " (" + u.current + ")." : "."),
    held: u.held === "paused" ? "Version " + u.latest + " is available, but your IT team has paused updates."
      : "Version " + u.latest + " is being rolled out gradually; this PC gets it soon.",
    downloading: "Downloading version " + (u.latest || "") + "…",
    ready: "Version " + u.latest + " is ready. " + updatePlanText(u),
    installing: "Installing the update. SecureTunnel will reopen in a moment.",
    error: u.message || "Couldn't check for updates.",
  }[u.state] || "Checks automatically every 6 hours.";
  $("up-text").textContent = text;
  $("up-install").classList.toggle("hidden", u.state !== "ready");
  const connected = status && status.state !== "disconnected";
  $("up-install").textContent = "Update now";
  $("up-install").title = connected ? DROP : "";
  $("up-check").disabled = u.state === "checking" || u.state === "downloading" || u.state === "installing";
}

$("up-check").addEventListener("click", async () => {
  update = Object.assign({}, update || {}, { state: "checking" });
  renderUpdate();
  await call({ cmd: "check_update" });
  render();
});
$("up-install").addEventListener("click", async () => {
  await call({ cmd: "install_update" });
  render();
});

// ---- actions ----
$("f-setup").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("setup-error").textContent = "";
  const r = await call({ cmd: "set_server", server: $("setup-server").value });
  if (!r.ok) $("setup-error").textContent = r.error || "Couldn't save the server.";
  render();
});

$("f-signin").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  if (busy) return;
  busy = true;
  $("si-error").textContent = "";
  $("si-btn").disabled = true;
  $("si-btn").textContent = "Connecting…";
  status = Object.assign({}, status || {}, { state: "signing_in", message: "" }); // drop the last status message
  render();
  const r = await call({ cmd: "connect", username: $("si-user").value, password: $("si-pass").value, code: $("si-code").value });
  busy = false;
  $("si-btn").textContent = "Connect";
  if (r.ok) {
    $("si-pass").value = "";
    $("si-code").value = "";
    $("si-code-wrap").classList.add("hidden");
  } else if (r.error_code === "code_required") {
    $("si-code-wrap").classList.remove("hidden");
    $("si-code").focus();
    $("si-error").textContent = r.error;
  } else {
    showError("si-error", r.error || "Couldn't connect.");
    if (r.error_code === "bad_code") $("si-code").value = "";
  }
  render();
});

// ---- Sign in with Microsoft (the Go host opens the browser) ----
$("si-local-toggle").addEventListener("click", () => {
  showLocal = !showLocal;
  render();
  if (showLocal) $("si-user").focus();
});
function startMicrosoft() {
  if (!auth.config) {
    loadAuth(true);
    render();
    return;
  }
  if (!auth.config.entra) return;
  if (!window.stEntra) { $("si-ms-error").textContent = "Not running inside the SecureTunnel app."; return; }
  $("si-ms-error").textContent = "";
  $("si-error").textContent = "";
  msWaiting = true;
  busy = true;
  render();
  window.stEntra(++msSeq);
}
let msSeq = 0;
window.stEntraDone = (r, seq) => {
  if (seq !== msSeq) return; // an earlier attempt that was replaced
  msWaiting = false;
  busy = false;
  if (r && r.status) status = r.status;
  if (r && r.service_down) serviceDown = true;
  if (!r || !r.ok) {
    const msg = (r && r.error) || "Couldn't sign in.";
    if (r && r.error_code === "auth_config_unavailable") {
      auth.config = null;
      auth.error = msg;
      auth.checkedAt = Date.now();
    } else if (r && r.auth) {
      auth.config = r.auth;
      auth.error = "";
      auth.checkedAt = Date.now();
    } else {
      showError("si-ms-error", /cancelled/i.test(msg) ? "" : msg);
    }
  }
  render();
};
$("si-ms-btn").addEventListener("click", startMicrosoft);
$("si-ms-reopen").addEventListener("click", startMicrosoft); // a new attempt replaces the waiting one
$("si-ms-cancel").addEventListener("click", () => { if (window.stEntraCancel) window.stEntraCancel(); });

$("st-disconnect").addEventListener("click", async () => {
  // Show "Disconnecting…" straight away; the service finishes in the background.
  busy = true;
  status = Object.assign({}, status || {}, { state: "disconnecting" });
  render();
  const r = await call({ cmd: "disconnect" });
  busy = false;
  render();
  if (!r.ok && r.error_code === "in_use") { // another Windows user's tunnel
    $("st-owner").textContent = r.error;
    $("st-owner").classList.remove("hidden");
  }
});

let diagText = "";
$("dg-run").addEventListener("click", async () => {
  $("dg-run").disabled = true;
  $("dg-run").textContent = "Checking…";
  const r = await call({ cmd: "diagnose" });
  $("dg-run").disabled = false;
  $("dg-run").textContent = "Run checks";
  const list = $("dg-list");
  list.replaceChildren();
  const lines = ["SecureTunnel diagnostics " + new Date().toLocaleString()];
  for (const d of r.diag || []) {
    const row = document.createElement("div");
    row.className = "diag";
    const ic = document.createElement("div");
    ic.className = "ic " + (d.ok ? "ok" : "bad");
    ic.textContent = d.ok ? "✓" : "✕";
    const body = document.createElement("div");
    const t = document.createElement("div"); t.className = "t"; t.textContent = d.name;
    const de = document.createElement("div"); de.className = "d"; de.textContent = d.detail;
    body.append(t, de);
    row.append(ic, body);
    list.append(row);
    lines.push((d.ok ? "[ok]   " : "[fail] ") + d.name + ": " + d.detail);
  }
  if (!r.diag) {
    const p = document.createElement("p");
    p.className = "error";
    p.textContent = r.error || "Couldn't run the checks.";
    list.append(p);
  }
  diagText = lines.join("\n");
});
$("dg-copy").addEventListener("click", async () => {
  if (!diagText) return;
  try { await navigator.clipboard.writeText(diagText); $("dg-copy").textContent = "Copied"; } catch (e) { $("dg-copy").textContent = "Couldn't copy"; }
  setTimeout(() => { $("dg-copy").textContent = "Copy results"; }, 1500);
});

$("f-server").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("ab-error").textContent = "";
  const r = await call({ cmd: "set_server", server: $("ab-new").value });
  if (!r.ok) $("ab-error").textContent = r.error || "Couldn't save.";
  else $("ab-new").value = "";
  render();
});

document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => { tab = b.dataset.tab; render(); }));

async function poll() {
  if (!busy) {
    await call({ cmd: "status" });
    render();
  }
  setTimeout(poll, 1000);
}
poll();

$("st-health-check").addEventListener("click", () => {
  const b = document.querySelector('.tabs button[data-tab="diag"]');
  if (b) b.click();
  setTimeout(() => { const run = $("dg-run"); if (run) run.click(); }, 50);
});

$("lg-send").addEventListener("click", async () => {
  const btn = $("lg-send"), out = $("lg-result");
  btn.disabled = true;
  btn.textContent = "Sending…";
  out.className = "lg-result hidden";
  const r = await call({ cmd: "send_logs" });
  btn.disabled = false;
  btn.textContent = "Send logs to IT";
  out.replaceChildren();
  if (r.ok && r.log_ref) {
    const code = document.createElement("span");
    code.className = "mono strong";
    code.textContent = r.log_ref;
    out.append("Sent. Give IT this reference: ", code);
    out.className = "lg-result ok";
  } else {
    out.textContent = r.error || "Couldn't send the logs.";
    out.className = "lg-result bad";
  }
});

// Size the window to the content (Windows app): it grows when a notice or
// warning appears and shrinks when it goes, so there's no empty space and no
// scrolling. The host keeps it above the tray and within the screen.
let lastFit = 0;
function fitWindow() {
  if (!window.stResize) return;
  const main = document.querySelector("main");
  const top = document.querySelector(".top"), tabs = document.querySelector(".tabs");
  if (!main || !top || !tabs) return;
  const cs = getComputedStyle(main);
  let h = parseFloat(cs.paddingTop) + parseFloat(cs.paddingBottom);
  for (const c of main.children) {
    if (c.offsetParent === null) continue; // hidden
    h += c.getBoundingClientRect().height + (parseFloat(getComputedStyle(c).marginBottom) || 0);
  }
  h = Math.ceil(h + top.offsetHeight + tabs.offsetHeight) + 2;
  if (Math.abs(h - lastFit) > 6) {
    lastFit = h;
    window.stResize(h);
  }
}
setInterval(fitWindow, 400);

// ---- hover readouts on the small graphs ----
const chartData = { rates: { values: [] }, lat: { values: [] } };
function historyDuration(seconds, preferSeconds = false) {
  if (seconds < 60 || (preferSeconds && seconds < 90)) return Math.round(seconds) + " sec";
  return Math.round(seconds / 60) + " min";
}
function chartTiming(oldest, latest) {
  if (!Number.isFinite(oldest) || !Number.isFinite(latest) || oldest <= latest || latest < 0) return null;
  return { oldest, latest };
}
function renderChartAxis(id, chart, preferSeconds, freshSeconds) {
  const timing = chart.values.length >= 2 ? chart.timing : null;
  $(id + "-oldest").textContent = timing ? historyDuration(timing.oldest, preferSeconds) + " ago" : "";
  $(id + "-latest").textContent = !timing ? "" : timing.latest <= freshSeconds
    ? "Now" : historyDuration(timing.latest, preferSeconds) + " ago";
}
function chartAge(chart, i) {
  if (!chart.timing) return "";
  const { oldest, latest } = chart.timing;
  const offset = oldest - (oldest - latest) * i / Math.max(1, chart.values.length - 1);
  return offset < 2 ? "Now · " : "About " + historyDuration(offset, true) + " ago · ";
}
function chartTip(svgId, read) {
  const svg = $(svgId);
  if (!svg) return;
  const wrap = svg.parentElement;
  wrap.classList.add("tip-host");
  const tip = document.createElement("div");
  tip.className = "chart-tip hidden";
  const line = document.createElement("div");
  line.className = "chart-line hidden";
  wrap.append(tip, line);
  const hide = () => { tip.classList.add("hidden"); line.classList.add("hidden"); };
  svg.addEventListener("mouseleave", hide);
  svg.addEventListener("mousemove", (ev) => {
    const r = svg.getBoundingClientRect();
    const frac = Math.min(1, Math.max(0, (ev.clientX - r.left) / r.width));
    const out = read(frac);
    if (!out) { hide(); return; }
    tip.textContent = out;
    const wr = wrap.getBoundingClientRect();
    const x = ev.clientX - wr.left;
    line.style.left = x + "px";
    line.style.top = (r.top - wr.top) + "px";
    line.style.height = r.height + "px";
    tip.classList.remove("hidden");
    line.classList.remove("hidden");
    const tw = tip.offsetWidth;
    tip.style.left = Math.min(Math.max(0, x - tw / 2), wr.width - tw) + "px";
  });
}
chartTip("sp-chart", (frac) => {
  const chart = chartData.rates, h = chart.values;
  if (!h.length) return "";
  const i = Math.round(frac * (h.length - 1));
  const p = h[i];
  return chartAge(chart, i) + "↓ " + fmtBps(p.rx) + "  ↑ " + fmtBps(p.tx);
});
chartTip("lat-chart", (frac) => {
  const chart = chartData.lat, h = chart.values;
  if (!h.length) return "";
  const i = Math.round(frac * (h.length - 1));
  const v = h[i];
  return chartAge(chart, i) + (v < 0 ? "check failed" : v + " ms");
});

// showError shows a sign-in error; certificate problems get a link to the
// picker in Settings.
function showError(id, msg) {
  const box = $(id);
  box.replaceChildren(msg);
  if (/certificate/i.test(msg)) {
    const a = document.createElement("a");
    a.href = "#";
    a.className = "link";
    a.textContent = " Choose a certificate in Settings";
    a.addEventListener("click", (ev) => {
      ev.preventDefault();
      const b = document.querySelector('.tabs button[data-tab="about"]');
      if (b) b.click();
      setTimeout(() => { certsAt = 0; loadCerts(); $("cert-card").scrollIntoView({ behavior: "smooth" }); }, 50);
    });
    box.append(a);
  }
}
