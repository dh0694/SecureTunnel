"use strict";
// Preview only: loads the real index.html/app.css/app.js into an iframe sized
// like the app window and fakes window.stCall with canned service responses.
(async function () {
  const state = new URLSearchParams(location.search).get("state") || "connected";
  const [html, css, js] = await Promise.all(["index.html", "app.css", "app.js"].map((f) => fetch(f, { cache: "reload" }).then((r) => r.text())));
  const now = Date.now();
  const iso = (ms) => new Date(now - ms).toISOString();

  let t = 0;
  const rates = () => Array.from({ length: 60 }, (_, i) => ({ rx: 18e6 + Math.sin((i + t) / 5) * 9e6 + Math.random() * 6e6, tx: 3e6 + Math.random() * 2e6 }));
  const lat = () => Array.from({ length: 40 }, (_, i) => (i === 22 ? -1 : 24 + Math.round(Math.random() * 12)));
  const base = {
    server: "https://vpn.cott1nghambutler.com", server_locked: false, user: "dan", version: "1.326.600", trust_mode: "system",
    network: { adapter: "Wi-Fi", kind: "Wi-Fi", ssid: "HomeNet-5G", signal_pct: 82, link_mbps: 866 },
  };
  const status = () => {
    t++;
    const s = Object.assign({}, base);
    if (state === "connected" || state === "reconnecting" || state === "message" || state === "officemode") {
      Object.assign(s, {
        state: state === "message" || state === "officemode" ? "connected" : state, gateway: "lab-gw", gateway_endpoint: "172.234.204.252:51820", tunnel_ip: "10.200.0.2",
        connected_since: iso(2.3 * 3600e3), last_heartbeat: iso(8e3), latency_ms: 28, jitter_ms: 4, loss_pct: 2.5,
        session_expires: new Date(now + 9.7 * 3600e3).toISOString(), grace_left_sec: state === "reconnecting" ? 742 : 0,
        device_trust: { join_type: "Hybrid joined", compliant: true, entra_proven: true, entra_device_id: "6f1c2e8a-93b4-4d7e-8a21-0c5b9e3f7d14", device_cert: { ok: true }, passed: true },
        latency_history: lat(), rate_history: rates(), latency_source: "gateway",
        latency_history_seconds: 1800, latency_latest_seconds: 0, loss_window_seconds: 300, rate_history_seconds: 60, rate_latest_seconds: 0, rx_bps: 24.6e6, tx_bps: 3.9e6, rx_bytes: 1.87e9, tx_bytes: 312e6,
      });
      if (state === "officemode") Object.assign(s, { office_mode: true, on_trusted_network: true, trusted_reason: "DNS suffix hq.cb-sisco.com", latency_ms: 0, rx_bps: 0, tx_bps: 0 });
    } else if (state === "office") {
      Object.assign(s, { state: "disconnected", on_trusted_network: true, trusted_reason: "DNS suffix cb-sisco.com", user: "" });
    } else if (state === "unstable") {
      Object.assign(s, {
        state: "connected", gateway: "lab-gw", gateway_endpoint: "172.234.204.252:51820", tunnel_ip: "10.200.0.2", drops_recent: 4,
        connected_since: iso(40 * 60e3), last_heartbeat: iso(8e3), latency_ms: 96, jitter_ms: 41, loss_pct: 7.5,
        session_expires: new Date(now + 11 * 3600e3).toISOString(), latency_history: lat(), rate_history: rates(), latency_source: "gateway",
        latency_history_seconds: 1800, latency_latest_seconds: 0, loss_window_seconds: 300, rate_history_seconds: 60, rate_latest_seconds: 0, rx_bps: 2.1e6, tx_bps: 0.4e6,
        network: { adapter: "Wi-Fi", kind: "Wi-Fi", ssid: "HomeNet-5G", signal_pct: 34, link_mbps: 144 },
      });
    } else if (state === "duo") {
      Object.assign(s, { state: "signing_in", user: "", message: "Approve the Duo Push on your phone to finish connecting." });
    } else if (state === "untrusted") {
      Object.assign(s, { state: "disconnected", user: "", message: "This PC isn't compliant with your organization's policies. Open Company Portal to see what needs fixing." });
    } else if (state === "pending") {
      Object.assign(s, { state: "disconnected", user: "", message: "This PC (LT-5012) is new and waiting for IT to approve it. Ask IT to approve it, then connect again." });
    } else if (state === "setup") {
      Object.assign(s, { state: "disconnected", server: "", user: "" });
    } else {
      Object.assign(s, { state: "disconnected", user: "", message: "" });
    }
    return s;
  };
  const speed = { interval_hours: 24, internet: { down_bps: 212e6, up_bps: 41e6, latency_ms: 12, at: iso(40 * 60e3) }, vpn: { down_bps: 146e6, up_bps: 37e6, latency_ms: 31, at: iso(40 * 60e3) } };
  const ips = { vpn_ip: "172.234.204.252", isp_ip: "47.32.2.7", checked_at: iso(20e3) };
  const update = { current: "1.326.600", latest: "1.326.612", state: state === "connected" ? "ready" : "up_to_date", checked_at: iso(3 * 3600e3) };
  const diag = [
    { name: "Server", ok: true, detail: "https://vpn.cott1nghambutler.com (set in the app)" },
    { name: "DNS", ok: true, detail: "vpn.cott1nghambutler.com → 104.21.32.7 (14 ms)" },
    { name: "Control server", ok: true, detail: "Reachable in 88 ms, trusted certificate" },
    { name: "Gateway", ok: true, detail: "lab-gw at 172.234.204.252:51820" },
    { name: "WireGuard driver", ok: true, detail: "Installed" },
    { name: "Tunnel", ok: true, detail: "Running" },
  ];

  let dismissed = false;
  const frame = document.getElementById("win");
  frame.addEventListener("load", () => {
    const w = frame.contentWindow;
    w.stCall = async (reqJSON) => {
      const req = JSON.parse(reqJSON);
      await new Promise((r) => setTimeout(r, 60));
      const resp = { ok: true, status: status(), update, speed, ips };
      if (state === "message" && !dismissed) resp.notice = { id: "n1", text: "Hi Dan, this is Sam from IT. We're looking at the slow connection you reported. Please stay connected for the next 10 minutes.", from: "helpdesk1", at: new Date(now - 60e3).toISOString() };
      if (req.cmd === "dismiss_notice") dismissed = true;
      if (req.cmd === "diagnose") resp.diag = diag;
      if (req.cmd === "send_logs") resp.log_ref = "K7Q-4P2";
      if (req.cmd === "auth_config") resp.auth = state === "signin-local" || state === "signin" ? { local: true } : { local: true, entra: { tenant_id: "t", client_id: "c", scope: "api://c/access_as_user", authority: "https://login.microsoftonline.com/t", prompt_login: true } };
      return JSON.stringify(resp);
    };
    w.stEntra = async () => true; // preview: stays on "finish signing in in your browser"
    const day = 864e5;
    const pins = { device: "", user: "" };
    const certList = (kind) => {
      const certs = kind === "device"
        ? [
            { thumb: "A1B2C3D4E5F60718293A4B5C6D7E8F9012345678", name: "LAPTOP-7Q2.corp.example.com", issuer: "Example Issuing CA", not_after: new Date(now + 300 * day).toISOString(), usable: true },
            { thumb: "B1B2C3D4E5F60718293A4B5C6D7E8F9012345678", name: "LAPTOP-7Q2.corp.example.com", issuer: "Example Issuing CA", not_after: new Date(now + 20 * day).toISOString(), usable: true },
            { thumb: "C1B2C3D4E5F60718293A4B5C6D7E8F9012345678", name: "LAPTOP-7Q2", issuer: "Old Lab CA", not_after: new Date(now - 40 * day).toISOString(), usable: false, why: "Expired" },
          ]
        : [{ thumb: "D1B2C3D4E5F60718293A4B5C6D7E8F9012345678", name: "dan@example.com", issuer: "Example User CA", not_after: new Date(now + 200 * day).toISOString(), usable: true }];
      return { certs, pinned: pins[kind], auto: certs.filter((c) => c.usable).map((c) => c.thumb) };
    };
    const certsJSON = () => JSON.stringify({ ok: true, known: true, wants_device: true, wants_user: false, device: certList("device"), user: certList("user") });
    w.stCerts = async () => { await new Promise((r) => setTimeout(r, 150)); return certsJSON(); };
    w.stSetCert = async (kind, thumb) => { pins[kind] = thumb; return certsJSON(); };
    w.stEntraCancel = async () => { w.stEntraDone({ ok: false, error: "sign-in cancelled" }, 1); return true; };
    const s = w.document.createElement("script");
    s.textContent = js;
    w.document.body.appendChild(s);
  });
  frame.srcdoc = html.replace("<!--CSS-->", "<style>" + css + "</style>").replace("<!--JS-->", "").replace("{{VERSION}}", "1.326.600");
})();
