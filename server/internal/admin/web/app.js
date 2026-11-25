"use strict";

// Demo mode only for UI design work: opened from disk, or from localhost with ?demo.
const DEMO = !!window.STDemo;

const $ = (id) => document.getElementById(id);
const state = { me: null, timer: null, lastLoad: 0, sessionsState: "live", users: [], audit: [], drawerSession: null };

// ---------------------------------------------------------------- API
async function api(method, path, body) {
  if (DEMO) return window.STDemo.api(method, path, body);
  const opts = { method, headers: { "X-ST-Admin": "1" }, credentials: "same-origin" };
  if (body !== undefined) {
    opts.headers["Content-Type"] = "application/json";
    opts.body = JSON.stringify(body);
  }
  const res = await fetch("/admin/api" + path, opts);
  if (res.status === 401 && path !== "/login") {
    showLogin();
    throw new Error("signed_out");
  }
  if (res.status === 204) return null;
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    const err = new Error(data.message || "Request failed (" + res.status + ")");
    err.code = data.error;
    throw err;
  }
  return data;
}

// ---------------------------------------------------------------- DOM helpers
// All data goes through textContent / attributes, never innerHTML.
function el(tag, attrs, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") e.className = v;
    else if (k.startsWith("on")) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid === null || kid === undefined || kid === false || kid === "") continue;
    e.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
  }
  return e;
}
const SVGNS = "http://www.w3.org/2000/svg";
function icon(name, cls) {
  const s = document.createElementNS(SVGNS, "svg");
  s.setAttribute("class", "i" + (cls ? " " + cls : ""));
  const u = document.createElementNS(SVGNS, "use");
  u.setAttribute("href", "#i-" + name);
  s.append(u);
  return s;
}
function svg(tag, attrs) {
  const e = document.createElementNS(SVGNS, tag);
  for (const [k, v] of Object.entries(attrs || {})) e.setAttribute(k, v);
  return e;
}
const badge = (text, kind) => el("span", { class: "badge " + kind }, text);

const AV_COLORS = ["#2557d6", "#0f8a5f", "#b4419a", "#c25a12", "#6a4cd6", "#0f7a99", "#a8323e", "#4d6b0f"];
function avatar(name, cls) {
  const n = (name || "?").replace(/@.*/, "");
  const parts = n.split(/[^A-Za-z0-9]+/).filter(Boolean);
  const initials = (parts.length > 1 ? parts[0][0] + parts[1][0] : n.slice(0, 2)) || "?";
  let h = 0;
  for (const c of n) h = (h * 31 + c.charCodeAt(0)) >>> 0;
  const a = el("span", { class: "avatar" + (cls ? " " + cls : ""), "aria-hidden": "true" }, initials);
  a.style.background = AV_COLORS[h % AV_COLORS.length];
  return a;
}
function setAvatar(target, name) {
  const a = avatar(name);
  target.textContent = a.textContent;
  target.style.background = a.style.background;
}

function emptyRow(cols, text, iconName) {
  return el("tr", {}, el("td", { class: "empty", colspan: cols }, icon(iconName || "search"), text));
}
function skeletonRows(tbody, cols, n) {
  tbody.replaceChildren(...Array.from({ length: n || 5 }, () =>
    el("tr", {}, ...Array.from({ length: cols }, () => el("td", {}, el("div", { class: "skeleton" }))))));
}

// ---------------------------------------------------------------- time
const EPOCH = Date.UTC(1971, 0, 1);
const ts = (iso) => { const t = Date.parse(iso); return t && t >= EPOCH ? t : 0; };
function dur(s) {
  s = Math.max(0, Math.round(s));
  if (s < 60) return s + "s";
  const m = Math.floor(s / 60);
  if (m < 60) return m + "m";
  const h = Math.floor(m / 60);
  if (h < 48) return h + "h " + (m % 60) + "m";
  return Math.floor(h / 24) + "d " + (h % 24) + "h";
}
function ago(iso) {
  const t = ts(iso);
  if (!t) return "never";
  const s = (Date.now() - t) / 1000;
  if (s < 0) return "in " + dur(-s);
  if (s < 10) return "just now";
  return dur(s) + " ago";
}
const fullTime = (iso) => { const t = ts(iso); return t ? new Date(t).toLocaleString() : "–"; };
const shortTime = (iso) => {
  const t = ts(iso);
  if (!t) return "–";
  const d = new Date(t);
  const today = new Date().toDateString() === d.toDateString();
  return today ? d.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })
    : d.toLocaleString([], { month: "short", day: "numeric", hour: "2-digit", minute: "2-digit" });
};

// ---------------------------------------------------------------- toasts, confirm
function toast(msg, bad) {
  const t = el("div", { class: "toast" + (bad ? " bad" : "") }, icon(bad ? "alert" : "check"), msg);
  $("toasts").append(t);
  setTimeout(() => t.remove(), bad ? 6000 : 3500);
}
function failed(e) {
  if (e && e.message !== "signed_out") toast(e.message || String(e), true);
}

function confirmDialog(title, body, okLabel) {
  return new Promise((resolve) => {
    const d = $("dlg-confirm");
    $("c-title").textContent = title;
    $("c-body").textContent = body;
    $("c-ok").textContent = okLabel || "Confirm";
    d.returnValue = "";
    d.addEventListener("close", () => resolve(d.returnValue === "ok"), { once: true });
    d.showModal();
  });
}
document.querySelectorAll("dialog [data-close]").forEach((b) => b.addEventListener("click", () => b.closest("dialog").close()));

// ---------------------------------------------------------------- labels
const isAdmin = () => state.me && state.me.role === "admin";
const STATE = {
  active: ["Connected", "ok"], suspended: ["Reconnecting", "warn"],
  expired: ["Expired", "neutral"], terminated: ["Ended", "neutral"],
};
const REASON = {
  user_disconnect: "User disconnected", grace_expired: "Grace window ran out", reboot: "Device rebooted",
  max_lifetime: "12-hour limit reached", replaced: "Replaced by a new connect", admin_disconnect: "Disconnected by an admin",
  device_tunnel_off: "Device tunnel turned off or device no longer approved",
};
const ROLE = { admin: ["Admin", "info"], helpdesk: ["Helpdesk", "warn"], user: ["VPN user", "neutral"] };
const ACTION = {
  "session.connect": ["Connected", "zap", "ok"],
  "session.disconnect": ["Disconnected", "power", ""],
  "session.reboot": ["Session ended by reboot", "power", ""],
  "session.failover": ["Failed over", "refresh", "warn"],
  "admin.disconnect": ["Disconnected a user", "user-x", "warn"],
  "admin.login": ["Signed in to admin", "lock", "info"],
  "admin.login_failed": ["Failed admin sign-in", "alert", "bad"],
  "vpn.login_failed": ["Failed VPN sign-in", "alert", "bad"],
  "gateway.enable": ["Enabled a gateway", "server", "ok"],
  "gateway.disable": ["Disabled a gateway", "server", "warn"],
  "user.create": ["Added a user", "users", "info"],
  "user.update": ["Updated a user", "edit", "info"],
  "user.delete": ["Deleted a user", "trash", "bad"],
  "user.mfa_enroll": ["Set up MFA", "key", "info"],
  "user.mfa_remove": ["Removed MFA", "key", "warn"],
  "vpn.country_blocked": ["Blocked by country", "globe", "bad"],
  "admin.command": ["Sent a remote action", "zap", "info"],
  "admin.move": ["Moved a user to another gateway", "server", "warn"],
  "device.logs": ["Logs received", "download", "info"],
  "device.logs_download": ["Downloaded logs", "download", ""],
  "gateway.drain": ["Drained a gateway", "server", "warn"],
  "settings.office_networks": ["Changed office networks", "shield", "info"],
  "settings.countries": ["Changed country access", "globe", "info"],
  "settings.placement": ["Changed placement rules", "server", "info"],
  "settings.speedtest": ["Changed speed test settings", "activity", "info"],
  "settings.updates": ["Changed the update policy", "download", "info"],
  "updates.push": ["Pushed an app update", "download", "warn"],
  "settings.devices": ["Changed device approval", "monitor", "info"],
  "settings.signin": ["Changed sign-in settings", "lock", "info"],
  "settings.servers": ["Changed server addresses", "server", "info"],
  "settings.device_trust": ["Changed device trust", "shield", "info"],
  "settings.duo": ["Changed Duo settings", "key", "info"],
  "settings.policy_groups": ["Changed policy groups", "users", "info"],
  "settings.policies": ["Changed groups or policies", "shield", "info"],
  "device.new_pending": ["New device waiting", "monitor", "warn"],
  "device.approve": ["Approved a device", "check", "ok"],
  "device.approve_all": ["Approved all pending devices", "check", "ok"],
  "device.reset": ["Reset a device to pending", "monitor", "warn"],
  "device.block": ["Blocked a device", "monitor", "bad"],
  "device.remove": ["Removed a device", "trash", "warn"],
  "vpn.device_blocked": ["Blocked device tried to connect", "alert", "bad"],
  "vpn.device_untrusted": ["Blocked by device trust", "shield", "bad"],
  "vpn.signin_method_blocked": ["Sign-in method not allowed", "lock", "bad"],
  "vpn.policy_error": ["Policy check failed", "alert", "bad"],
  "vpn.duo_approved": ["Duo approved", "check", "ok"],
  "vpn.duo_denied": ["Duo denied", "alert", "bad"],
  "vpn.windows_user_mismatch": ["Windows user differs", "alert", "warn"],
  "vpn.windows_user_blocked": ["Blocked: Windows user differs", "user-x", "bad"],
  "device_tunnel.connect": ["Device tunnel connected (before sign-in)", "monitor", "ok"],
  "device_tunnel.disconnect": ["Device tunnel closed", "power", ""],
  "device_tunnel.handover": ["User took over from device tunnel", "refresh", "info"],
  "device_tunnel.end": ["Device tunnel ended by policy", "power", "warn"],
  "device_tunnel.refused": ["Device tunnel refused", "alert", "bad"],
  "settings.device_tunnel": ["Changed device tunnel", "monitor", "info"],
};
const actionInfo = (a) => ACTION[a] || [a, "file", ""];
const platformIcon = (p) => (/mac|ios|android/i.test(p || "") ? "phone" : "monitor");

// ---------------------------------------------------------------- sign-in
function showLogin() {
  clearInterval(state.timer);
  state.me = null;
  $("app-view").classList.add("hidden");
  $("login-view").classList.remove("hidden");
  const params = new URLSearchParams(location.search);
  const ssoErr = params.get("sso_error");
  $("login-sso-error").textContent = ssoErr || "";
  if (ssoErr) history.replaceState(null, "", location.pathname + location.hash);
  api("GET", "/auth-config").catch(() => ({ local: true })).then((cfg) => {
    const ms = !!(cfg && cfg.entra);
    $("login-ms").classList.toggle("hidden", !ms);
    $("login-local").classList.toggle("hidden", ms && !ssoErr && !state.showLocal);
    $("login-local-toggle").classList.toggle("hidden", !$("login-local").classList.contains("hidden"));
    if (!$("login-local").classList.contains("hidden")) $("login-user").focus();
  });
}
$("login-local-toggle").addEventListener("click", () => {
  state.showLocal = true;
  $("login-local").classList.remove("hidden");
  $("login-local-toggle").classList.add("hidden");
  $("login-user").focus();
});

$("login-form").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("login-error").textContent = "";
  const btn = ev.submitter;
  if (btn) btn.disabled = true;
  try {
    state.me = await api("POST", "/login", {
      username: $("login-user").value, password: $("login-pass").value, code: $("login-code").value,
    });
    $("login-pass").value = "";
    $("login-code").value = "";
    $("login-code-wrap").classList.add("hidden");
    startApp();
  } catch (e) {
    if (e.code === "code_required") {
      $("login-code-wrap").classList.remove("hidden");
      $("login-code").focus();
      $("login-error").textContent = "Enter the 6-digit code from your authenticator app.";
    } else {
      $("login-error").textContent = e.message;
    }
  } finally {
    if (btn) btn.disabled = false;
  }
});

$("logout").addEventListener("click", async () => {
  await api("POST", "/logout").catch(() => {});
  showLogin();
});

// ---------------------------------------------------------------- navigation
const VIEWS = {
  overview: ["Overview", "Live status of the VPN"],
  sessions: ["Sessions", "Who is connected, and recent sessions"],
  servers: ["Servers", "Gateways, control servers and their health"],
  groups: ["Groups", "Users and devices that policies are assigned to"],
  policies: ["Policies", "Settings assigned to groups: sign-in, Windows sessions and app updates"],
  settings: ["Settings", "Server addresses, sign-in setup, certificates, Duo, device tunnel"],
  devices: ["Devices", "PCs that have connected, and approval for new ones"],
  users: ["Users", "Local accounts, and settings for Entra users"],
  updates: ["App updates", "Which version the PCs run, how they update, and pushing an update"],
  audit: ["Audit log", "Every sign-in, connection and admin action"],
};
// Older links: Gateways and System are now one Servers page.
const VIEW_ALIASES = { gateways: "servers", system: "servers" };
const currentView = () => {
  const h = location.hash.slice(1);
  return VIEWS[h] ? h : VIEW_ALIASES[h] || "overview";
};

async function render(opts) {
  const v = currentView();
  for (const name of Object.keys(VIEWS)) $("view-" + name).classList.toggle("hidden", name !== v);
  document.querySelectorAll(".nav a").forEach((a) => a.classList.toggle("active", a.dataset.view === v));
  $("page-title").textContent = VIEWS[v][0];
  $("page-sub").textContent = VIEWS[v][1];
  $("side").classList.remove("open");
  const btn = $("refresh");
  btn.classList.add("spin");
  try {
    await loaders[v](opts || {});
    state.lastLoad = Date.now();
    tickUpdated();
  } catch (e) {
    failed(e);
  } finally {
    btn.classList.remove("spin");
  }
}
window.addEventListener("hashchange", () => render({ first: true }));
$("refresh").addEventListener("click", () => render());
$("menu-btn").addEventListener("click", () => $("side").classList.toggle("open"));

function tickUpdated() {
  $("updated").textContent = state.lastLoad ? "Updated " + ago(new Date(state.lastLoad).toISOString()) : "";
}

function startApp() {
  $("login-view").classList.add("hidden");
  $("app-view").classList.remove("hidden");
  $("demo-badge").classList.toggle("hidden", !DEMO);
  $("me-name").textContent = state.me.display_name || state.me.username;
  $("me-role").textContent = (ROLE[state.me.role] || [state.me.role])[0];
  setAvatar($("me-avatar"), state.me.display_name || state.me.username);
  $("u-add").classList.toggle("hidden", !isAdmin());
  render({ first: true });
  clearInterval(state.timer);
  state.timer = setInterval(() => {
    tickUpdated();
    const v = currentView();
    const busy = document.querySelector("dialog[open]") || !$("menu").classList.contains("hidden");
    if (!busy && ["overview", "sessions", "servers"].includes(v) && Date.now() - state.lastLoad > 10000) render();
  }, 1000);
}

// ---------------------------------------------------------------- views
const loaders = {
  async overview() {
    const [sum, gws, audit] = await Promise.all([api("GET", "/summary"), api("GET", "/gateways"), api("GET", "/audit?limit=12")]);
    $("m-active").textContent = sum.active;
    $("m-suspended").textContent = sum.suspended;
    $("m-day").textContent = sum.connects_24h;
    $("m-gw").textContent = sum.gateways_healthy + " / " + sum.gateways;
    $("m-gw-icon").className = "kpi-icon " + (sum.gateways && sum.gateways_healthy === sum.gateways ? "ok" : "bad");
    $("nav-live").textContent = sum.active + sum.suspended || "";
    setPendingCount(sum.pending_devices || 0);
    drawChart(sum.hourly || [], sum.hourly_end);
    $("chart-total").textContent = sum.connects_24h + " connects";

    const totalSessions = gws.reduce((n, g) => n + g.sessions, 0);
    $("ov-gateways").replaceChildren(...(gws.length ? gws.map((g) => {
      const share = totalSessions ? Math.round((g.sessions / totalSessions) * 100) : 0;
      const bar = el("div");
      bar.style.width = Math.max(share, 1) + "%";
      return el("div", { class: "gw-row" },
        el("div", { class: "top" }, el("span", { class: "strong" }, g.id), g.enabled && g.healthy && g.over_limits ? badge("Paused", "warn") : gwBadge(g)),
        el("div", { class: "sub" }, g.site + " · " + g.endpoint),
        el("div", { class: "meter" }, bar),
        el("div", { class: "sub" }, g.sessions + " sessions (" + share + "% of users) · reported " + ago(g.last_health)),
        g.metrics ? resLine(g.metrics) : null);
    }) : [el("p", { class: "muted" }, "No gateways configured yet.")]));
    setSysDot(gws.filter((g) => g.enabled).map((g) => ({ online: g.healthy, current: g.metrics })));

    drawClientVersions(sum.client_versions || {}, sum.latest_client || "");
    $("ov-activity").replaceChildren(...(audit.length ? audit.map(activityItem) : [el("li", { class: "muted" }, "No activity yet.")]));
  },

  async sessions(opts) {
    if (opts.first) skeletonRows($("s-rows"), 10);
    const q = encodeURIComponent($("s-q").value.trim());
    const list = await api("GET", "/sessions?state=" + encodeURIComponent(state.sessionsState) + "&q=" + q);
    const rows = list.map((s) => {
      const [label, kind] = STATE[s.state] || [s.state, "neutral"];
      const live = s.state === "active" || s.state === "suspended";
      const end = live ? Date.now() : ts(s.ended_at) || ts(s.last_seen);
      return el("tr", { onclick: () => openDrawer(s) },
        el("td", {}, el("div", { class: "who" }, avatar(s.upn, "sm"), el("div", { class: "who-text" },
          el("div", { class: "strong" }, s.kind === "device" ? (s.device_name || s.device_id) : s.upn),
          s.kind === "device" ? el("div", { class: "sub" }, badge("Device tunnel · before sign-in", "info")) : null,
          s.kind !== "device" && s.diag && winUserDiffers(s.diag.windows_user, s.upn)
            ? el("div", { class: "sub", title: "The Windows account on the PC isn't the VPN user" }, badge("Windows: " + s.diag.windows_user, "warn plain")) : null))),
        el("td", {}, badge(label, kind), live && s.diag && s.diag.office_mode ? el("div", {}, badge("Office mode", "info plain")) : null, !live && s.end_reason ? el("div", { class: "sub" }, REASON[s.end_reason] || s.end_reason) : null),
        el("td", {}, el("div", { class: "who" }, icon(platformIcon(s.platform)), el("div", { class: "who-text" },
          el("div", {}, s.device_name || s.device_id),
          el("div", { class: "sub" }, s.platform + (s.client_version ? " · v" + s.client_version : "")),
          s.outdated && (s.state === "active" || s.state === "suspended") ? badge("Update pending", "warn plain") : null))),
        el("td", { class: "nowrap" }, netCell(s.diag)),
        el("td", { class: "nowrap" }, s.gateway_id),
        el("td", { class: "mono nowrap" }, s.tunnel_ip),
        el("td", { class: "nowrap" }, el("span", { class: "mono" }, s.client_ip),
          s.country ? el("div", { class: "sub", title: s.country }, countryName(s.country)) : null),
        el("td", { class: "nowrap" }, s.diag && (s.diag.rx_bytes || s.diag.tx_bytes)
          ? el("div", {}, "↓ " + fmtBytes(s.diag.rx_bytes), el("div", { class: "sub" }, "↑ " + fmtBytes(s.diag.tx_bytes))) : "–"),
        el("td", { class: "nowrap" }, dur((end - ts(s.created_at)) / 1000)),
        el("td", { class: "nowrap", title: "Last check-in " + fullTime(s.last_seen) },
          s.state === "active" ? el("span", { class: "now" }, "Now") : ago(s.last_seen)));
    });
    $("s-rows").replaceChildren(...(rows.length ? rows : [emptyRow(10, $("s-q").value ? "No sessions match your search." : "No sessions here yet.", "activity")]));
    if (state.drawerSession) {
      const fresh = list.find((s) => s.id === state.drawerSession.id);
      if (fresh) fillDrawer(fresh);
    }
  },

  // Servers: gateways (with their host metrics) first, then the control
  // servers, load balancer and database.
  async servers() {
    const [gws, pol, sys] = await Promise.all([api("GET", "/gateways"), api("GET", "/settings/placement"), api("GET", "/system")]);
    drawPolicy(pol);
    const hosts = sys.hosts || [];
    setSysDot(hosts);
    const hostOf = {};
    for (const h of hosts) if (h.kind === "gateway") hostOf[h.id] = h;
    const up = hosts.filter((h) => h.online).length;
    const worst = hosts.filter((h) => h.current).map((h) => Math.max(h.current.cpu_percent, ratio(h.current.mem_used, h.current.mem_total), ratio(h.current.disk_used, h.current.disk_total)));
    const peak = worst.length ? Math.max(...worst) : 0;
    const users = gws.reduce((n, g) => n + (g.sessions || 0), 0);
    const tunnels = gws.reduce((n, g) => n + ((g.metrics && g.metrics.handshakes) || 0), 0);
    const kpi = (ic, kind, v, k) => el("div", { class: "kpi" }, el("div", { class: "kpi-icon " + kind }, icon(ic)), el("div", {}, el("div", { class: "kpi-v" }, v), el("div", { class: "kpi-k" }, k)));
    $("sys-summary").replaceChildren(
      kpi("server", up === hosts.length ? "ok" : "bad", up + " / " + hosts.length, "Servers healthy"),
      kpi("users", "info", users.toLocaleString(), "Users on gateways"),
      kpi("activity", "info", tunnels.toLocaleString(), "Active tunnels"),
      kpi("cpu", level(peak) || "ok", Math.round(peak) + "%", "Busiest server (CPU, memory or disk)"));
    $("gw-count").textContent = gws.length;
    $("g-cards").replaceChildren(...(gws.length ? gws.map((g) => gatewayCard(g, hostOf[g.id])) : [el("div", { class: "card empty" }, icon("server"), "No gateways configured. Add one to gateways.json and restart the control server.")]));
    drawSystem(sys);
  },

  async devices(opts) {
    if (opts.first) skeletonRows($("dev-rows"), 8, 4);
    // One list of every device; tabs filter it here and show their counts.
    const [all, pol] = await Promise.all([api("GET", "/devices"), api("GET", "/settings/devices")]);
    state.allDevices = all;
    const count = (st) => all.filter((d) => d.status === st).length;
    const pendingN = count("pending");
    for (const st of ["approved", "blocked"]) $("dev-count-" + st).textContent = "(" + count(st).toLocaleString() + ")";
    $("dev-count-all").textContent = "(" + all.length.toLocaleString() + ")";
    state.devices = state.devStatus ? all.filter((d) => d.status === state.devStatus) : all;
    setPendingCount(pendingN);
    $("dev-require").checked = pol.require_approval;
    $("dev-require-label").textContent = pol.require_approval ? "On" : "Off";
    $("dev-require").disabled = !isAdmin();
    $("dev-approve-all").classList.toggle("hidden", !isAdmin() || pendingN === 0);
    drawDevices();
  },

  async updates() {
    drawUpdates(await api("GET", "/updates"));
  },

  async settings(opts) {
    api("GET", "/settings/speedtest").then(drawSpeedPolicy).catch(() => {});
    const srv = await api("GET", "/settings/servers").catch(() => null);
    $("f-servers").classList.toggle("hidden", !srv);
    if (srv && !$("f-servers").contains(document.activeElement)) {
      $("srv-primary").value = srv.primary;
      $("srv-backups").value = (srv.backups || []).join("\n");
    }
    $("srv-save").classList.toggle("hidden", !isAdmin());
    const [office, countries, si, dt] = await Promise.all([api("GET", "/settings/office"), api("GET", "/settings/countries"),
      api("GET", "/settings/signin").catch(() => null), api("GET", "/settings/devicetrust" + (opts && opts.recheck ? "?recheck=1" : "")).catch(() => null)]);
    const duo = await api("GET", "/settings/duo").catch(() => null);
    $("f-duo").classList.toggle("hidden", !duo);
    if (duo) fillDuo(duo, !$("f-duo").contains(document.activeElement));
    $("f-trust").classList.toggle("hidden", !dt);
    if (dt) fillTrust(dt, !$("f-trust").contains(document.activeElement));
    $("f-signin").classList.toggle("hidden", !si);
    if (si && !$("f-signin").contains(document.activeElement)) {
      $("si-entra").checked = si.entra_enabled;
      $("si-local").checked = si.local_enabled;
      $("si-tenant").value = si.tenant_id || "";
      $("si-client").value = si.client_id || "";
      $("si-secret").value = "";
      $("si-secret-hint").textContent = si.has_secret ? "A secret is saved. Paste a new one to replace it." : "Needed for Microsoft sign-in on this console.";
      $("si-prompt").checked = si.prompt_login;
      $("si-admin-uri").textContent = si.admin_redirect_uri;
      $("si-agent-uri").textContent = si.agent_redirect_uri;
      $("si-scope").textContent = si.scope || "api://<client ID>/access_as_user";
      $("si-roles").textContent = (si.roles || []).join(", ");
      const on = [si.entra_enabled ? "Microsoft" : "", si.local_enabled ? "Local accounts" : ""].filter(Boolean);
      $("si-status").textContent = on.join(" + ") || "Off";
      $("si-status").className = "badge plain " + (si.entra_enabled ? "ok" : "neutral");
    }
    const dtun = await api("GET", "/settings/device-tunnel").catch(() => null);
    $("f-devtun").classList.toggle("hidden", !dtun);
    $("dtun-save").classList.toggle("hidden", !isAdmin());
    if (dtun && !$("f-devtun").contains(document.activeElement)) {
      $("dtun-enabled").checked = dtun.enabled;
      $("dtun-subnets").value = (dtun.subnets || []).join("\n");
      $("dtun-dns").value = (dtun.dns || []).join("\n");
    }
    if (!$("f-office").contains(document.activeElement)) {
      $("of-enabled").checked = office.enabled;
      $("of-dns").value = (office.dns_suffixes || []).join("\n");
      $("of-subnets").value = (office.local_subnets || []).join("\n");
      $("of-public").value = (office.public_ips || []).join("\n");
    }
    if (!$("f-countries").contains(document.activeElement)) {
      $("co-enabled").checked = countries.enabled;
      $("co-default").value = (countries.default || []).join(", ");
      $("co-unknown").checked = countries.block_unknown;
      namesHint($("co-default"), $("co-default-names"));
    }
    const ro = !isAdmin();
    document.querySelectorAll("#view-policies input, #view-policies textarea").forEach((i) => { i.disabled = ro; });
    $("of-save").classList.toggle("hidden", ro);
    $("co-save").classList.toggle("hidden", ro);
    $("si-save").classList.toggle("hidden", ro);
    $("dt-save").classList.toggle("hidden", ro);
    $("duo-save").classList.toggle("hidden", ro);
    $("duo-test").classList.toggle("hidden", ro);
    document.querySelectorAll("#view-policies select").forEach((i) => { i.disabled = ro; });
  },

  // Groups and Policies pages (policies.js).
  async groups() {
    state.pol = await api("GET", "/policies");
    drawGroupsPage();
  },

  async policies() {
    state.pol = await api("GET", "/policies");
    drawPoliciesPage();
  },

  async users(opts) {
    if (opts.first || !state.users.length) skeletonRows($("u-rows"), 7, 4);
    if (!state.pol || opts.first) state.pol = await api("GET", "/policies").catch(() => state.pol || null);
    state.users = await api("GET", "/users");
    drawUsers();
  },

  async audit(opts) {
    if (opts.first || !state.audit.length) skeletonRows($("a-rows"), 4, 8);
    state.audit = await api("GET", "/audit?limit=1000");
    drawAudit();
  },
};

// ---------------------------------------------------------------- overview pieces
function drawChart(hourly, endIso) {
  const box = $("chart");
  const W = 600, H = 190, padL = 28, padB = 22, padT = 8;
  const max = Math.max(4, ...hourly);
  const step = Math.ceil(max / 4);
  const top = step * 4;
  const s = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", role: "img", "aria-label": "Connections per hour" });
  for (let i = 0; i <= 4; i++) {
    const y = padT + (H - padT - padB) * (1 - i / 4);
    s.append(svg("line", { x1: padL, x2: W, y1: y, y2: y, class: "grid" }));
    const t = svg("text", { x: padL - 6, y: y + 4, "text-anchor": "end" });
    t.textContent = String(step * i);
    s.append(t);
  }
  const n = hourly.length || 24;
  const bw = (W - padL) / n;
  const end = ts(endIso) || Date.now();
  hourly.forEach((v, i) => {
    const h = v ? Math.max(2, (H - padT - padB) * (v / top)) : 2;
    const r = svg("rect", {
      x: padL + i * bw + bw * 0.18, y: H - padB - h, width: bw * 0.64, height: h, rx: 2,
      class: "bar" + (v ? "" : " zero"),
    });
    const hourStart = new Date(end - (n - i) * 3600e3);
    const tt = svg("title", {});
    tt.textContent = hourStart.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) + ": " + v + " connect" + (v === 1 ? "" : "s");
    r.append(tt);
    s.append(r);
    if (i % 4 === 0 || i === n - 1) {
      const t = svg("text", { x: padL + i * bw + bw / 2, y: H - 6, "text-anchor": "middle" });
      t.textContent = i === n - 1 ? "now" : hourStart.toLocaleTimeString([], { hour: "numeric" });
      s.append(t);
    }
  });
  box.replaceChildren(s);
}

// Compare "1.326.469"-style versions; non-numeric (e.g. "stclient") sort last.
function cmpVersion(a, b) {
  const pa = a.split(".").map(Number), pb = b.split(".").map(Number);
  const na = pa.length === 3 && pa.every((n) => !isNaN(n)), nb = pb.length === 3 && pb.every((n) => !isNaN(n));
  if (na !== nb) return na ? -1 : 1;
  if (!na) return a < b ? -1 : 1;
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pb[i] - pa[i];
  return 0;
}

function drawClientVersions(counts, latest) {
  $("cv-latest").textContent = latest ? "Latest: " + latest : "";
  const total = Object.values(counts).reduce((a, b) => a + b, 0);
  const rows = Object.keys(counts).sort(cmpVersion).map((v) => {
    const n = counts[v];
    const isAgent = /^\d+\.\d+\.\d+$/.test(v);
    const old = isAgent && latest && cmpVersion(v, latest) > 0;
    const bar = el("div");
    bar.style.width = Math.max(2, Math.round((n / total) * 100)) + "%";
    const label = isAgent ? (v === latest ? badge("v" + v + " · latest", "ok plain") : old ? badge("v" + v + " · update pending", "warn plain") : badge("v" + v, "info plain")) : badge(v, "neutral plain");
    return el("div", { class: "cv-row" + (old ? " old" : "") }, el("div", {}, label), el("div", { class: "meter" }, bar),
      el("div", { class: "n" }, n + (n === 1 ? " user" : " users")));
  });
  $("cv-list").replaceChildren(...(rows.length ? rows : [el("p", { class: "muted" }, "No one is connected.")]));
}

function activityItem(a) {
  const [label, ic, kind] = actionInfo(a.action);
  return el("li", {},
    el("span", { class: "act-icon " + kind }, icon(ic)),
    el("div", { class: "act-body" },
      el("div", { class: "line" }, el("span", { class: "strong" }, a.actor), " · ", label),
      a.detail ? el("div", { class: "sub line" }, a.detail) : null),
    el("span", { class: "act-time", title: fullTime(a.at) }, ago(a.at)));
}

function gwBadge(g) {
  if (!g.enabled) return badge("Disabled", "neutral");
  return g.healthy ? badge("Healthy", "ok") : badge("Not reporting", "bad");
}

function copyBtn(text, label) {
  return el("button", {
    class: "icon-btn", title: "Copy " + label, "aria-label": "Copy " + label,
    onclick: (ev) => { ev.stopPropagation(); navigator.clipboard.writeText(text).then(() => toast("Copied " + label)).catch(() => toast("Couldn't copy", true)); },
  }, icon("copy"));
}

function placementStatus(g) {
  if (!g.enabled) return el("div", { class: "gw-status neutral" }, icon("power"), "Disabled: not taking new users");
  if (!g.healthy) return el("div", { class: "gw-status warn" }, icon("alert"), "Not reporting: not taking new users");
  if (g.over_limits) return el("div", { class: "gw-status warn" }, icon("alert"), "Paused for new users: " + g.over_limits);
  if (g.sessions >= g.capacity) return el("div", { class: "gw-status warn" }, icon("alert"), "Full: at its session limit");
  return el("div", { class: "gw-status ok" }, icon("check"), "Taking new users");
}

function drawPolicy(r) {
  const p = r.policy;
  $("pol-cpu").value = p.max_cpu_percent;
  $("pol-mem").value = p.max_mem_percent;
  $("pol-disk").value = p.min_free_disk_gb;
  $("pol-source").textContent = r.custom ? "Custom settings" : "Using defaults";
  state.policyDefaults = r.defaults;
  const ro = !isAdmin();
  for (const id of ["pol-cpu", "pol-mem", "pol-disk"]) $(id).disabled = ro;
  $("g-policy").querySelector(".policy-actions").classList.toggle("hidden", ro);
  $("pol-error").textContent = "";
  // One-line summary above the gateway cards.
  $("place-text").replaceChildren(
    el("b", {}, "Placement: "), "new users go to the least busy healthy gateway. A gateway stops taking new users at ",
    el("b", {}, p.max_cpu_percent + "% CPU"), ", ", el("b", {}, p.max_mem_percent + "% memory"), " or under ",
    el("b", {}, p.min_free_disk_gb + " GB"), " free disk", r.custom ? "." : " (defaults).");
  $("place-edit").textContent = ro ? "View rules" : "Edit rules";
}
$("place-edit").addEventListener("click", () => { $("pol-error").textContent = ""; $("dlg-place").showModal(); });
async function savePolicy(p) {
  $("pol-error").textContent = "";
  try {
    const r = await api("POST", "/settings/placement", p);
    drawPolicy(r);
    $("dlg-place").close();
    toast("Placement rules saved");
    render();
  } catch (e) { $("pol-error").textContent = e.message; }
}
$("g-policy").addEventListener("submit", (ev) => {
  ev.preventDefault();
  savePolicy({ max_cpu_percent: Number($("pol-cpu").value), max_mem_percent: Number($("pol-mem").value), min_free_disk_gb: Number($("pol-disk").value) });
});
$("pol-reset").addEventListener("click", () => { if (state.policyDefaults) savePolicy(state.policyDefaults); });

// gatewayCard is everything about one gateway: whether it takes new users,
// how many it has, its host's health and traffic, its settings and actions.
// h is its entry from /system (history for the traffic chart); may be missing.
function gatewayCard(g, h) {
  const iconKind = !g.enabled ? "" : g.healthy ? "ok" : "bad";
  const keyShort = g.public_key ? g.public_key.slice(0, 10) + "…" + g.public_key.slice(-6) : "–";
  const m = g.metrics || (h && h.current);
  const stat = (k, v, title) => el("div", { class: "gw-stat", title: title || "" }, el("div", { class: "k" }, k), el("div", { class: "v" }, v));
  const users = g.sessions || 0;
  const traffic = m ? (m.net_rx_bps || 0) + (m.net_tx_bps || 0) : 0;
  return el("div", { class: "card gw-card" },
    el("div", { class: "head" },
      el("div", { class: "kpi-icon " + iconKind }, icon("server")),
      el("div", { class: "grow" }, el("div", { class: "strong" }, g.id), el("div", { class: "sub" }, ["Site " + g.site, m && m.hostname].filter(Boolean).join(" · "))),
      gwBadge(g)),
    placementStatus(g),
    el("div", { class: "gw-stats four" },
      stat("Users", users.toLocaleString() + " / " + g.capacity.toLocaleString(), "Sessions placed on this gateway, and its limit"),
      stat("Active tunnels", ((m && m.handshakes) || 0).toLocaleString(), "PCs that passed traffic through it in the last 3 minutes"),
      stat("Traffic", fmtBps(traffic), "In + out through the tunnels right now"),
      stat("Up for", m && m.uptime_sec ? dur(m.uptime_sec) : "–")),
    m ? el("div", { class: "gw-res" }, resMeter("CPU", m.cpu_percent), resMeter("Memory", ratio(m.mem_used, m.mem_total)), resMeter("Disk", ratio(m.disk_used, m.disk_total))) : null,
    h && (h.history || []).length > 1 ? el("div", { class: "gw-spark", title: "Traffic, last 15 minutes" },
      el("div", { class: "k" }, "Traffic, last 15 minutes"),
      sparkline(h.history.map((x) => ({ t: (x.net_rx_bps || 0) + (x.net_tx_bps || 0) })), "t")) : null,
    el("dl", { class: "kv" },
      el("dt", {}, "Endpoint"), el("dd", { class: "mono" }, g.endpoint, copyBtn(g.endpoint, "endpoint")),
      el("dt", {}, "Address range"), el("dd", { class: "mono" }, g.pool,
        isAdmin() ? el("button", { class: "link-btn", type: "button", title: "Change the tunnel IP range", onclick: () => openPool(g) }, "Edit") : null),
      el("dt", {}, "Public key"), el("dd", { class: "mono", title: g.public_key }, keyShort, g.public_key ? copyBtn(g.public_key, "public key") : null),
      el("dt", {}, "Last report"), el("dd", { title: fullTime(g.last_health) }, ago(g.last_health))),
    isAdmin() ? el("div", { class: "foot" },
      g.enabled ? el("button", { class: "btn sm", title: "Stop new sessions here and move everyone to other gateways", onclick: () => drainGateway(g) }, icon("refresh"), "Drain") : null,
      el("button", { class: "btn sm" + (g.enabled ? " danger" : ""), onclick: () => toggleGateway(g) }, icon("power"), g.enabled ? "Disable" : "Enable")) : null);
}

// ---------------------------------------------------------------- system
const ratio = (a, b) => (b ? (a / b) * 100 : 0);
const level = (p) => (p >= 90 ? "bad" : p >= 80 ? "warn" : "");
function fmtBytes(n) {
  if (!n) return "0 B";
  const u = ["B", "KB", "MB", "GB", "TB"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  const v = n / Math.pow(1024, i);
  return (v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)) + " " + u[i];
}
function fmtBps(n) {
  if (!n) return "0 bps";
  const u = ["bps", "Kbps", "Mbps", "Gbps"];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1000)));
  const v = n / Math.pow(1000, i);
  return (v >= 100 || i === 0 ? Math.round(v) : v.toFixed(1)) + " " + u[i];
}

function setSysDot(hosts) {
  let worst = "";
  for (const h of hosts) {
    if (!h.online) { worst = "bad"; break; }
    const c = h.current;
    if (!c) continue;
    const l = level(Math.max(c.cpu_percent, ratio(c.mem_used, c.mem_total), ratio(c.disk_used, c.disk_total)));
    if (l === "bad") { worst = "bad"; break; }
    if (l === "warn") worst = "warn";
  }
  const dot = $("nav-sys");
  dot.className = "nav-dot" + (worst === "warn" ? " warn" : "") + (worst ? "" : " hidden");
  dot.title = worst ? "A server needs attention" : "";
}

function drawSpeedPolicy(r) {
  const f = $("f-speed");
  if (f.contains(document.activeElement)) return; // don't overwrite while editing
  $("spd-interval").value = r.policy.interval_hours;
  $("spd-size").value = r.policy.size_mb;
  $("spd-host").value = r.policy.host;
  $("spd-source").textContent = r.custom ? "Custom settings" : "Using defaults";
  for (const id of ["spd-interval", "spd-size", "spd-host"]) $(id).disabled = !isAdmin();
  $("spd-save").classList.toggle("hidden", !isAdmin());
}
$("f-speed").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("spd-error").textContent = "";
  try {
    const r = await api("POST", "/settings/speedtest", {
      interval_hours: Number($("spd-interval").value), size_mb: Number($("spd-size").value), host: $("spd-host").value,
    });
    document.activeElement.blur();
    drawSpeedPolicy(r);
    toast("Speed test settings saved");
  } catch (e) { $("spd-error").textContent = e.message; }
});

// ---- System page: what each piece does, how it's connected, and its health.
const ROLES = {
  control: ["Control servers", "shield", "Handle sign-in, policy checks and this admin site, and pick a gateway for each user. They don't carry VPN traffic: if both go down, connected users stay connected."],
  lb: ["Load balancer (HAProxy)", "layers", "Sends sign-in, heartbeat and admin traffic to a healthy control server. Control A is active and Control B is on standby; HAProxy switches over within about 4 seconds of A failing its health checks."],
  db: ["Database (PostgreSQL)", "database", "Shared by every control server: users, devices, sessions, settings and the audit log. This is why either control server can serve any user."],
  gateway: ["Gateways", "server", "Carry the actual VPN traffic. Each user's WireGuard tunnel goes straight from their PC to a gateway, which routes it on to the network. Users are spread across healthy gateways."],
};

function drawSystem(sys) {
  const hosts = sys.hosts || [];
  const controls = hosts.filter((h) => h.kind === "control");
  const gws = hosts.filter((h) => h.kind === "gateway");
  const lb = sys.lb, db = sys.db;
  const lbByName = {};
  for (const s of (lb && lb.servers) || []) lbByName[s.name] = s;

  // Health of each piece for the diagram.
  const allOk = (list) => (!list.length ? "" : list.every((h) => h.online) ? "ok" : list.some((h) => h.online) ? "warn" : "bad");
  const lbState = sys.lb_error ? "bad" : !lb ? "" : lb.servers.some((s) => s.serving) ? (lb.servers.every((s) => s.status.startsWith("UP")) ? "ok" : "warn") : "bad";
  const dbState = sys.db_error ? "bad" : db ? "ok" : "";
  const active = lb && lb.servers.find((s) => s.serving);
  const node = (key, title, sub, state) => {
    const n = el("button", { type: "button", class: "flow-node " + (state || "neutral"), title: "Jump to " + title },
      el("span", { class: "fi" }, icon(ROLES[key] ? ROLES[key][1] : key)), el("span", { class: "ft" }, title), el("span", { class: "fs" }, sub));
    n.onclick = () => { const t = document.getElementById(key === "gateway" ? "sys-sec-gateway" : "sys-sec-control"); if (t) t.scrollIntoView({ behavior: "smooth", block: "start" }); };
    return n;
  };
  const ext = (ic, title, sub) => el("div", { class: "flow-node ext" }, el("span", { class: "fi" }, icon(ic)), el("span", { class: "ft" }, title), el("span", { class: "fs" }, sub));
  const arrow = (label) => el("div", { class: "flow-arrow" }, el("span", {}, label || ""));
  const lane = (name, desc, ...kids) => el("div", { class: "flow-lane" },
    el("div", { class: "flow-name" }, el("b", {}, name), el("span", {}, desc)), el("div", { class: "flow-row" }, ...kids));
  const ctrlSub = controls.length ? controls.filter((h) => h.online).length + " of " + controls.length + " online" : "none";
  const gwSub = gws.length ? gws.filter((h) => h.online).length + " of " + gws.length + " online" : "none";
  const lanes = [
    lane("Sign-in & management", "Small, occasional requests",
      ext("users", "Users & admins", "App and admin site"), arrow("HTTPS"),
      ext("globe", "Cloudflare", "Public address"), arrow(),
      ...(lb || sys.lb_error ? [node("lb", "HAProxy", active ? "→ " + active.name : "No server up", lbState), arrow()] : []),
      node("control", "Control servers", ctrlSub, allOk(controls)), arrow(),
      ...(db || sys.db_error ? [node("db", "PostgreSQL", db ? fmtBytes(db.size_bytes) : "Error", dbState)] : [])),
    lane("VPN traffic", "All of the user's traffic",
      ext("monitor", "User's PC", "SecureTunnel app"), arrow("WireGuard UDP"),
      node("gateway", "Gateways", gwSub, allOk(gws)), arrow(),
      ext("globe", "Network / internet", "Routed or NAT")),
  ];
  $("sys-flow").replaceChildren(el("div", { class: "card-head" }, el("h2", {}, "How it fits together"),
    el("span", { class: "muted small" }, "The control side decides who connects and where; the gateways carry the traffic. Click a box for details.")), ...lanes);

  // Below the gateways: the control side, in one compact section.
  const cards = controls.map((h) => controlCard(h, lbByName[h.label]));
  if (lb || sys.lb_error) cards.push(lbCard(lb, sys.lb_error));
  if (db || sys.db_error) cards.push(dbCard(db, sys.db_error, sys.db_size));
  if (!cards.length) cards.push(el("div", { class: "card empty" }, icon("cpu"), "No control server has reported yet."));
  $("sys-body").replaceChildren(el("section", { class: "sys-sec", id: "sys-sec-control" },
    el("div", { class: "sys-sec-head" }, el("div", { class: "kpi-icon" }, icon("shield")),
      el("div", { class: "grow" }, el("h2", {}, "Sign-in and management"),
        el("p", { class: "muted small" }, "Control servers handle sign-in, policy and this admin site, and pick a gateway for each user. HAProxy sends their traffic to whichever is healthy, and they share one database. None of this carries VPN traffic: if it all went down, connected users would stay connected."))),
    el("div", { class: "mini-cards" }, ...cards)));
}

// miniCard is a compact server card: name, role, status and a few facts.
function miniCard(ic, ok, name, role, status, ...facts) {
  return el("div", { class: "card mini" + (ok ? "" : " offline") },
    el("div", { class: "head" }, el("div", { class: "kpi-icon " + (ok ? "ok" : "bad") }, icon(ic)),
      el("div", { class: "grow" }, el("div", { class: "strong" }, name), el("div", { class: "sub" }, role)), status),
    el("ul", { class: "facts" }, ...facts.filter(Boolean).map((f) => el("li", {}, f))));
}

function controlCard(h, lbSrv) {
  const c = h.current;
  let status = !h.online ? badge("Offline", "bad") : badge("Online", "ok");
  if (h.online && lbSrv) status = lbSrv.serving ? badge("Active", "ok") : lbSrv.status.startsWith("UP") ? badge("Standby", "neutral") : badge("Down", "bad");
  return miniCard("shield", h.online, h.label, "Control server" + (h.serving ? " · answered this page" : ""), status,
    c ? resLine(c) : "No metrics yet",
    c ? "Up " + dur(c.uptime_sec) + (c.hostname ? " · " + c.hostname : "") : null,
    lbSrv ? (lbSrv.serving ? "Receiving sign-in and admin traffic" : lbSrv.status.startsWith("UP") ? "Takes over if the active one fails (about 4 s)" : "Failing health checks") : null);
}

function lbCard(lb, err) {
  if (!lb) return miniCard("layers", false, "HAProxy", "Load balancer", badge("Unreachable", "bad"), err || "No data.");
  const to = (lb.servers.find((s) => s.serving) || {}).name;
  const checks = lb.servers.map((s) => s.name + " " + (s.check === "L7OK" ? "OK" : s.check || "?") + (s.check_ms ? " " + s.check_ms + " ms" : "")).join(" · ");
  return miniCard("layers", !!to, "HAProxy", "Load balancer", to ? badge("Online", "ok") : badge("No server up", "bad"),
    to ? "Sending traffic to " + to : "No control server is passing its health checks",
    lb.current.toLocaleString() + " open connections (mostly apps waiting for policy updates)",
    "Health checks every 2 s: " + checks);
}

function dbCard(db, err, size) {
  if (!db) return miniCard("database", false, "PostgreSQL", "Shared database", badge("Error", "bad"), err || "No data.");
  const up = (Date.now() - new Date(db.started_at).getTime()) / 1000;
  return miniCard("database", true, "PostgreSQL " + db.version, "Shared database", badge("Online", "ok"),
    "Responds in " + db.ping_ms.toFixed(1) + " ms · " + db.connections + " of " + db.max_connections + " connections",
    fmtBytes(db.size_bytes || size || 0) + " · " + db.cache_hit_percent.toFixed(1) + "% of reads from memory · up " + dur(up),
    db.users.toLocaleString() + " users · " + db.devices.toLocaleString() + " devices · " + db.active_sessions.toLocaleString() + " live sessions");
}

// resMeter is a small labeled bar for the gateway card.
function resMeter(k, p) {
  return el("div", { class: "res" }, el("div", { class: "top" }, el("span", {}, k), el("b", { class: level(p) }, Math.round(p || 0) + "%")), meterEl(p || 0));
}

function resLine(m) {
  const part = (label, p) => el("span", {}, label + " ", el("b", { class: level(p) }, Math.round(p) + "%"));
  return el("div", { class: "resline" },
    part("CPU", m.cpu_percent), part("Mem", ratio(m.mem_used, m.mem_total)), part("Disk", ratio(m.disk_used, m.disk_total)));
}

function sparkline(history, key, max) {
  const box = el("div", { class: "spark" });
  const W = 300, H = 46;
  const s = svg("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none" });
  const pts = history.map((h) => h[key]);
  if (pts.length < 2) {
    const t = svg("text", { x: 0, y: H / 2 + 4, class: "empty" });
    t.textContent = "Collecting history…";
    s.append(t);
  } else {
    const top = max || Math.max(1, ...pts);
    const xy = pts.map((v, i) => [(i / (pts.length - 1)) * W, H - (Math.min(v, top) / top) * (H - 2) - 1]);
    const d = xy.map(([x, y], i) => (i ? "L" : "M") + x.toFixed(1) + " " + y.toFixed(1)).join(" ");
    s.append(svg("path", { d: d + ` L${W} ${H} L0 ${H} Z`, class: "area" }));
    s.append(svg("path", { d, class: "line" }));
  }
  box.append(s);
  return box;
}

function meterEl(p) {
  const bar = el("div");
  bar.style.width = Math.max(1, Math.min(100, p)) + "%";
  const l = level(p);
  return el("div", { class: "meter" + (l ? " " + l : "") }, bar);
}


// ---------------------------------------------------------------- devices
state.devStatus = "approved"; // the Devices page opens on Approved
state.devices = [];
const DEV = { pending: ["Pending approval", "warn"], approved: ["Approved", "ok"], blocked: ["Blocked", "bad"] };

function setPendingCount(n) {
  $("nav-pending").textContent = n || "";
  $("dev-count-pending").textContent = "(" + (n || 0).toLocaleString() + ")";
}

// ---- device trust ----
// Certificates only: join type and compliance are Entra's job.
function trustBadges(t) {
  const out = [];
  if (t && t.device_cert) out.push(badge("Device cert " + (t.device_cert.ok ? "OK" : "rejected"), (t.device_cert.ok ? "ok" : "bad") + " plain"));
  if (t && t.user_cert) out.push(badge("User cert " + (t.user_cert.ok ? "OK" : "rejected"), (t.user_cert.ok ? "ok" : "bad") + " plain"));
  if (t && !t.passed) out.push(badge("Blocked", "bad"));
  if (!out.length) out.push(el("span", { class: "muted" }, "None"));
  return out;
}
function trustCell(d) {
  return el("button", { class: "trust-cell", title: "Certificate details", onclick: () => showTrust(d) }, ...trustBadges(d.trust));
}
const yesNo = (v) => (v === true ? "Yes" : v === false ? "No" : "Unknown");
function certRows(label, c) {
  if (!c) return [[label, "None sent"]];
  return [[label, c.ok ? "Accepted" : "Rejected: " + (c.error || "unknown reason")], ["Subject", c.subject, "mono"], ["Issuer", c.issuer, "mono"],
    ["Expires", fullTime(c.not_after)], ["Thumbprint", c.thumbprint, "mono"]];
}
function trustRows(t) {
  if (!t) return [["Certificate", "Not checked yet. It's checked the next time this PC connects."]];
  const rows = [
    ["Result", t.passed ? "Allowed" : "Blocked"],
  ];
  if ((t.problems || []).length) rows.push(["Why", el("ul", { class: "problems" }, ...t.problems.map((p) => el("li", {}, p)))]);
  rows.push(["Checked", fullTime(t.checked_at) + (t.user ? " for " + t.user : "")], ["Sign-in policy", t.group]);
  rows.push(["sep"], ...certRows("Device certificate", t.device_cert), ["sep"], ...certRows("User certificate", t.user_cert));
  return rows;
}
function dlRows(rows) {
  return rows.flatMap(([k, v, cls]) => k === "sep" ? [el("div", { class: "sep" })]
    : [el("dt", {}, k), el("dd", { class: cls }, v || "–")]);
}
function showTrust(d) {
  $("dlg-trust-title").textContent = "Certificates: " + (d.name || d.id);
  $("dlg-trust-sub").textContent = "The latest check, made when this PC last connected. Join type and compliance are checked by Entra (Conditional Access), not here.";
  $("dlg-trust-list").replaceChildren(...dlRows(trustRows(d.trust)));
  $("dlg-trust").showModal();
}

function drawDevices() {
  const q = $("dev-q").value.trim().toLowerCase();
  const list = state.devices.filter((d) => !q || [d.name, d.id, d.last_user].join(" ").toLowerCase().includes(q));
  const rows = list.map((d) => {
    const [label, kind] = DEV[d.status] || [d.status, "neutral"];
    const acts = el("td", { class: "actions" });
    if (d.status === "pending" || (d.status === "blocked" && isAdmin())) acts.append(el("button", { class: "btn sm", onclick: () => setDevice(d, "approved") }, icon("check"), d.status === "blocked" ? "Unblock" : "Approve"));
    if (isAdmin() && d.status !== "blocked") acts.append(el("button", { class: "btn sm danger", onclick: () => setDevice(d, "blocked") }, "Block"));
    acts.append(el("button", { class: "icon-btn", title: "Logs from this device", "aria-label": "Logs from " + d.name, onclick: () => showDeviceLogs(d) }, icon("download")));
    if (isAdmin()) acts.append(el("button", { class: "icon-btn", title: "Remove", "aria-label": "Remove " + d.name, onclick: () => removeDevice(d) }, icon("trash")));
    return el("tr", {},
      el("td", {}, el("div", { class: "who" }, icon(platformIcon(d.platform)), el("div", { class: "who-text" },
        el("div", { class: "strong" }, d.name || d.id), el("div", { class: "sub mono", title: d.id }, d.id.length > 20 ? d.id.slice(0, 8) + "…" + d.id.slice(-4) : d.id)))),
      el("td", {}, badge(label, kind)),
      el("td", {}, trustCell(d)),
      el("td", {}, d.last_user || "–"),
      el("td", {}, d.platform || "–", d.agent_version ? el("div", { class: "sub" }, "v" + d.agent_version) : null),
      el("td", { class: "nowrap", title: d.connected ? "Connected to the VPN right now" : "Last seen " + fullTime(d.last_seen) },
        d.connected ? el("span", { class: "now" }, "Connected now") : ago(d.last_seen),
        el("div", { class: "sub", title: fullTime(d.first_seen) }, "first " + ago(d.first_seen))),
      el("td", { class: "nowrap" }, d.decided_by ? el("div", {}, d.decided_by, el("div", { class: "sub" }, ago(d.decided_at))) : "–"),
      acts);
  });
  const empty = state.devStatus === "pending" ? "No devices are waiting for approval." : "No devices here.";
  $("dev-rows").replaceChildren(...(rows.length ? rows : [emptyRow(8, q ? "No devices match your search." : empty, "monitor")]));
}

async function setDevice(d, status) {
  if (status === "blocked" && !(await confirmDialog("Block " + (d.name || d.id) + "?", "This PC won't be able to connect, and any session it has now ends.", "Block"))) return;
  try {
    await api("POST", "/devices/" + encodeURIComponent(d.id) + "/status", { status });
    toast((status === "approved" ? "Approved " : "Blocked ") + (d.name || d.id));
    render();
  } catch (e) { failed(e); }
}

async function removeDevice(d) {
  if (!(await confirmDialog("Remove " + (d.name || d.id) + "?", "It's forgotten. If it connects again it's treated as a new device.", "Remove"))) return;
  try { await api("DELETE", "/devices/" + encodeURIComponent(d.id)); toast("Removed " + (d.name || d.id)); render(); }
  catch (e) { failed(e); }
}

document.querySelectorAll("#dev-seg button").forEach((b) => b.addEventListener("click", () => {
  state.devStatus = b.dataset.status;
  document.querySelectorAll("#dev-seg button").forEach((x) => x.classList.toggle("on", x === b));
  render({ first: true });
}));
$("dev-q").addEventListener("input", drawDevices);
$("dev-require").addEventListener("change", async (ev) => {
  const on = ev.target.checked;
  if (on && !(await confirmDialog("Require approval for new devices?", "PCs that haven't connected before will be held until IT approves them. PCs already known keep working.", "Turn on"))) {
    ev.target.checked = false;
    return;
  }
  try {
    await api("POST", "/settings/devices", { require_approval: on });
    toast(on ? "New devices now need approval" : "New devices are approved automatically");
    render();
  } catch (e) { failed(e); ev.target.checked = !on; }
});
$("dev-approve-all").addEventListener("click", async () => {
  if (!(await confirmDialog("Approve all pending devices?", "Every device waiting for approval will be able to connect.", "Approve all"))) return;
  try { const r = await api("POST", "/devices/approve-pending"); toast("Approved " + r.approved + " devices"); render(); }
  catch (e) { failed(e); }
});

// ---------------------------------------------------------------- countries
const ISO = ("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ " +
  "CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE " +
  "GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP " +
  "KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF " +
  "NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN " +
  "SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW").split(" ");
let regionNames = null;
try { regionNames = new Intl.DisplayNames(["en"], { type: "region" }); } catch (e) { /* older browsers: codes only */ }
const countryName = (c) => { try { return (regionNames && regionNames.of(c)) || c; } catch (e) { return c; } };
// Windows doesn't draw flag emoji, so countries are shown by name and code only.
const flag = () => "";
const parseCodes = (s) => [...new Set(String(s || "").toUpperCase().split(/[\s,;]+/).filter(Boolean))];
function namesHint(input, hint) {
  const codes = parseCodes(input.value);
  const bad = codes.filter((c) => !ISO.includes(c));
  if (input._picker) { // the picker shows the names; the hint only reports problems
    input._picker.refresh();
    hint.textContent = bad.length ? "Unknown code: " + bad.join(", ") : "";
  } else {
    hint.textContent = bad.length ? "Unknown code: " + bad.join(", ") : codes.map((c) => countryName(c)).join(", ");
  }
  hint.style.color = bad.length ? "var(--bad)" : "";
}

// countryPicker turns a "US, CA" text input into chips of the selected
// countries plus a searchable dropdown of all of them. The input stays (hidden)
// and keeps the codes, so loading and saving work as before; changes fire
// "input" on it.
const COUNTRY_SORTED = () => ISO.slice().sort((a, b) => countryName(a).localeCompare(countryName(b)));
function countryPicker(input, placeholder) {
  const wrap = el("div", { class: "cpick" });
  const chips = el("div", { class: "cpick-chips" });
  const search = el("input", { class: "cpick-search", type: "text", placeholder: placeholder || "Add a country…", autocomplete: "off",
    role: "combobox", "aria-expanded": "false", "aria-label": placeholder || "Add a country" });
  const list = el("ul", { class: "cpick-list hidden", role: "listbox" });
  wrap.append(chips, el("div", { class: "cpick-box" }, icon("search"), search), list);
  input.type = "hidden";
  input.after(wrap);
  let active = 0, shown = [];
  const selected = () => parseCodes(input.value).filter((c) => ISO.includes(c));
  const set = (codes) => {
    input.value = codes.join(", ");
    input.dispatchEvent(new Event("input", { bubbles: true }));
  };
  const toggle = (c) => {
    const cur = selected();
    set(cur.includes(c) ? cur.filter((x) => x !== c) : cur.concat(c));
    search.focus();
    drawList();
  };
  const drawChips = () => {
    const cur = selected();
    chips.replaceChildren(...(cur.length ? cur.map((c) => el("span", { class: "chip", title: countryName(c) },
      countryName(c), el("span", { class: "code" }, c),
      el("button", { type: "button", "aria-label": "Remove " + countryName(c), onclick: () => toggle(c), disabled: input.disabled || null }, icon("x"))))
      : [el("span", { class: "muted small" }, "None selected")]));
  };
  const drawList = () => {
    const q = search.value.trim().toLowerCase();
    const cur = selected();
    const all = COUNTRY_SORTED().filter((c) => !q || c.toLowerCase() === q || countryName(c).toLowerCase().includes(q) || c.toLowerCase().startsWith(q));
    // Searching: exact code, then names starting with the text, then the rest.
    // Not searching: the selected countries first. Each group by name.
    const rank = (c) => !q ? (cur.includes(c) ? 0 : 1)
      : c.toLowerCase() === q ? 0 : countryName(c).toLowerCase().startsWith(q) ? 1 : 2;
    all.sort((a, b) => rank(a) - rank(b));
    shown = all.slice(0, 300);
    active = Math.min(active, Math.max(0, shown.length - 1));
    list.replaceChildren(...(shown.length ? shown.map((c, i) => {
      const on = cur.includes(c);
      const li = el("li", { role: "option", "aria-selected": on ? "true" : "false", class: (on ? "on" : "") + (i === active ? " active" : "") },
        el("span", { class: "tick" }, on ? icon("check") : null), el("span", { class: "nm" }, countryName(c)), el("span", { class: "code" }, c));
      li.addEventListener("mousedown", (ev) => { ev.preventDefault(); toggle(c); });
      return li;
    }) : [el("li", { class: "none" }, "No country matches “" + search.value + "”")]));
    const a = list.querySelector(".active");
    if (a) a.scrollIntoView({ block: "nearest" });
  };
  const open = () => { if (input.disabled) return; list.classList.remove("hidden"); search.setAttribute("aria-expanded", "true"); drawList(); };
  const close = () => { list.classList.add("hidden"); search.setAttribute("aria-expanded", "false"); search.value = ""; };
  search.addEventListener("focus", open);
  search.addEventListener("click", open);
  search.addEventListener("input", () => { active = 0; open(); });
  search.addEventListener("blur", () => setTimeout(close, 120));
  search.addEventListener("keydown", (ev) => {
    if (ev.key === "ArrowDown") { ev.preventDefault(); active = Math.min(active + 1, shown.length - 1); drawList(); }
    else if (ev.key === "ArrowUp") { ev.preventDefault(); active = Math.max(active - 1, 0); drawList(); }
    else if (ev.key === "Enter") { ev.preventDefault(); if (shown[active]) toggle(shown[active]); }
    else if (ev.key === "Escape") { if (!list.classList.contains("hidden")) { ev.stopPropagation(); ev.preventDefault(); close(); } }
    else if (ev.key === "Backspace" && !search.value) { const cur = selected(); if (cur.length) set(cur.slice(0, -1)); drawChips(); }
  });
  input._picker = {
    refresh() {
      drawChips();
      search.disabled = input.disabled;
      wrap.classList.toggle("disabled", !!input.disabled);
      if (!list.classList.contains("hidden")) drawList();
    },
  };
  input._picker.refresh();
  return wrap;
}
// Every country field gets the picker.
countryPicker($("co-default"), "Add a country…");
countryPicker($("f-user-allowed"), "Add a country this user can always use…");
countryPicker($("f-user-travel"), "Add a trip country…");
function countryBadges(codes, kind) {
  return (codes || []).map((c) => el("span", { class: "badge " + kind + " plain", title: countryName(c) }, c));
}
function userCountries(u) {
  const parts = countryBadges(u.allowed_countries, "info");
  const until = ts(u.travel_until);
  if ((u.travel_countries || []).length && until > Date.now()) {
    parts.push(...countryBadges(u.travel_countries, "warn"));
    parts.push(el("span", { class: "sub" }, " trip until " + new Date(until).toLocaleDateString()));
  }
  return parts.length ? el("div", { class: "cc" }, ...parts) : el("span", { class: "muted" }, "Default");
}
$("f-user-allowed").addEventListener("input", () => namesHint($("f-user-allowed"), $("f-user-allowed-names")));
$("f-user-travel").addEventListener("input", () => namesHint($("f-user-travel"), $("f-user-travel-names")));

const lines = (s) => String(s || "").split(/[\n,;]+/).map((x) => x.trim()).filter(Boolean);
$("f-office").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("of-error").textContent = "";
  try {
    const p = await api("POST", "/settings/office", {
      enabled: $("of-enabled").checked, dns_suffixes: lines($("of-dns").value),
      local_subnets: lines($("of-subnets").value), public_ips: lines($("of-public").value),
    });
    document.activeElement.blur();
    $("of-dns").value = p.dns_suffixes.join("\n");
    $("of-subnets").value = p.local_subnets.join("\n");
    $("of-public").value = p.public_ips.join("\n");
    toast("Office networks saved. Agents pick them up within a minute.");
  } catch (e) { $("of-error").textContent = e.message; }
});
$("f-devtun").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("dtun-error").textContent = "";
  try {
    const p = await api("POST", "/settings/device-tunnel", {
      enabled: $("dtun-enabled").checked, subnets: lines($("dtun-subnets").value), dns: lines($("dtun-dns").value),
    });
    document.activeElement.blur();
    $("dtun-subnets").value = p.subnets.join("\n");
    $("dtun-dns").value = p.dns.join("\n");
    toast(p.enabled ? "Device tunnel saved. PCs at the sign-in screen connect within a minute." : "Device tunnel turned off. Open device tunnels close at their next check-in.");
  } catch (e) { $("dtun-error").textContent = e.message; }
});
function fillTrust(dt, fields) {
  if (fields) {
    $("dt-match-name").checked = dt.match_device_name;
    $("dt-match-user").checked = dt.match_user;
    $("dt-dev-names").value = (dt.device_name_patterns || []).join("\n");
    $("dt-user-names").value = (dt.user_name_patterns || []).join("\n");
    $("dt-cas").value = dt.trusted_cas || "";
  }
  $("dt-ca-list").replaceChildren(...(dt.cas || []).map((ca) => el("div", { class: "ca-item" },
    badge(ts(ca.not_after) < Date.now() ? "Expired" : "CA", (ts(ca.not_after) < Date.now() ? "bad" : "info") + " plain"),
    el("span", { class: "mono" }, ca.subject), el("span", { class: "muted" }, "expires " + new Date(ts(ca.not_after)).toLocaleDateString()))));
  const g = { ok: ["ok", "Microsoft Graph: connected. Used for Entra group membership in groups."],
    not_set_up: ["warn", "Microsoft Graph: needs Sign in with Microsoft (with a client secret) set up above. Until then, only what the PC reports is shown."],
    error: ["bad", "Microsoft Graph: " + (dt.graph_error || "error")] }[dt.graph_status] || ["", ""];
  $("dt-graph-dot").className = "dot-s " + g[0];
  $("dt-graph-text").textContent = g[1];
  const n = (dt.cas || []).length;
  $("dt-status").textContent = dt.graph_status === "ok" ? "Graph connected" + (n ? " · " + n + " CA" + (n > 1 ? "s" : "") : "") : n ? n + " CA" + (n > 1 ? "s" : "") : "Not set up";
  $("dt-status").className = "badge plain " + (dt.graph_status === "ok" ? "ok" : "neutral");
}
$("dt-graph-recheck").addEventListener("click", () => render({ recheck: true }));
$("f-trust").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("dt-error").textContent = "";
  try {
    const dt = await api("POST", "/settings/devicetrust", {
      trusted_cas: $("dt-cas").value, match_device_name: $("dt-match-name").checked, match_user: $("dt-match-user").checked,
      device_name_patterns: lines($("dt-dev-names").value), user_name_patterns: lines($("dt-user-names").value),
    });
    document.activeElement.blur();
    fillTrust(dt, true);
    toast("Device trust saved");
  } catch (e) { $("dt-error").textContent = e.message; }
});

function fillDuo(d, fields) {
  if (fields) {
    $("duo-host").value = d.api_host || "";
    $("duo-ikey").value = d.integration_key || "";
    $("duo-skey").value = "";
    $("duo-format").value = d.username_format || "upn";
  }
  $("duo-skey-hint").textContent = d.has_secret ? "A secret key is saved. Paste a new one to replace it." : "";
  $("duo-status").textContent = d.ready ? "Set up" : "Not set up";
  $("duo-status").className = "badge plain " + (d.ready ? "ok" : "neutral");
}
$("f-duo").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("duo-error").textContent = "";
  try {
    const d = await api("POST", "/settings/duo", { api_host: $("duo-host").value, integration_key: $("duo-ikey").value,
      secret_key: $("duo-skey").value, username_format: $("duo-format").value });
    document.activeElement.blur();
    fillDuo(d, true);
    toast("Duo saved");
  } catch (e) { $("duo-error").textContent = e.message; }
});
$("duo-test").addEventListener("click", async () => {
  $("duo-error").textContent = "";
  try { await api("POST", "/settings/duo/test"); toast("Duo answered: the keys work"); }
  catch (e) { $("duo-error").textContent = e.message; }
});
$("f-servers").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("srv-error").textContent = "";
  try {
    const r = await api("POST", "/settings/servers", { backups: lines($("srv-backups").value) });
    document.activeElement.blur();
    $("srv-backups").value = r.backups.join("\n");
    toast("Server addresses saved. Apps pick them up within a minute.");
  } catch (e) { $("srv-error").textContent = e.message; }
});

$("f-signin").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("si-error").textContent = "";
  try {
    await api("POST", "/settings/signin", {
      local_enabled: $("si-local").checked, entra_enabled: $("si-entra").checked,
      tenant_id: $("si-tenant").value, client_id: $("si-client").value,
      client_secret: $("si-secret").value, prompt_login: $("si-prompt").checked,
    });
    document.activeElement.blur();
    toast("Sign-in settings saved");
    render();
  } catch (e) { $("si-error").textContent = e.message; }
});
document.querySelectorAll("[data-copy]").forEach((b) => b.addEventListener("click", () => {
  navigator.clipboard.writeText($(b.dataset.copy).textContent).then(() => toast("Copied")).catch(() => toast("Couldn't copy", true));
}));
$("co-default").addEventListener("input", () => namesHint($("co-default"), $("co-default-names")));
$("f-countries").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("co-error").textContent = "";
  try {
    const p = await api("POST", "/settings/countries", {
      enabled: $("co-enabled").checked, default: parseCodes($("co-default").value), block_unknown: $("co-unknown").checked,
    });
    document.activeElement.blur();
    $("co-default").value = p.default.join(", ");
    namesHint($("co-default"), $("co-default-names"));
    toast("Country access saved");
  } catch (e) { $("co-error").textContent = e.message; }
});

// ---------------------------------------------------------------- diagnostics
function netLabel(d) {
  if (!d || !d.net_kind) return "";
  return d.net_kind === "Wi-Fi" && d.ssid ? d.ssid : d.net_kind;
}
function netCell(d) {
  if (!d || !d.net_kind) return "–";
  const sub = [d.net_kind === "Wi-Fi" ? "Wi-Fi" : "", d.signal_pct ? d.signal_pct + "% signal" : "", d.latency_ms ? d.latency_ms + " ms" : ""].filter(Boolean).join(" · ");
  return el("div", {}, netLabel(d), sub ? el("div", { class: "sub" }, sub) : null);
}
// winUserDiffers mirrors the server's check: DOMAIN\jsmith matches jsmith@...
function winUserDiffers(win, upn) {
  if (!win || !upn) return false;
  let w = win.toLowerCase(), v = upn.toLowerCase();
  if (w === v) return false;
  if (w.includes("\\")) { w = w.slice(w.lastIndexOf("\\") + 1); v = v.split("@")[0]; return w !== v; }
  return true;
}
function diagRows(s) {
  const d = s.diag;
  if (!d) return [["sep"], ["Diagnostics", "No report from this device yet (older agent or not connected)."]];
  const q = (v, unit) => (v || v === 0 ? v + unit : "–");
  return [
    ["sep"], ["head", "Device"],
    ["Computer", d.hostname], ["Operating system", d.os], ["Agent", d.agent_version ? "v" + d.agent_version : ""],
    ["Windows user", d.windows_user ? d.windows_user + (winUserDiffers(d.windows_user, s.upn) ? " · not the VPN user" : "") : ""],
    ["PC up for", d.uptime_sec ? dur(d.uptime_sec) : ""],
    ["sep"], ["head", "Network"],
    ["Connection", [d.net_kind, d.adapter && d.adapter !== d.net_kind ? "(" + d.adapter + ")" : ""].filter(Boolean).join(" ")],
    ["Wi-Fi network", d.ssid], ["Signal", d.signal_pct ? d.signal_pct + "%" : ""], ["Link speed", d.link_mbps ? d.link_mbps + " Mbps" : ""],
    ["Local IP", d.local_ip, "mono"], ["ISP public IP", d.isp_ip, "mono"], ["VPN public IP", d.vpn_ip, "mono"],
    ["sep"], ["head", "Quality"],
    ["Latency", q(d.latency_ms, " ms") + (d.latency_source === "gateway" ? " to the gateway" : d.latency_ms ? " to the control server (older app)" : "")],
    ["Jitter", q(d.jitter_ms, " ms")], ["Packet loss", q(Math.round(d.loss_pct || 0), "%")],
    ...(d.control_ms ? [["Control server response", d.control_ms + " ms (via Cloudflare, includes server work)"]] : []),
    ["Drops (15 min)", d.drops_15m ? d.drops_15m + (d.drops_15m >= 3 ? " · unstable connection" : "") : "None"],
    ["Current usage", "↓ " + fmtBps(d.rx_bps) + "  ↑ " + fmtBps(d.tx_bps) + " (right now, not top speed)"],
    ["sep"], ["head", "Data this session"],
    ["Downloaded", fmtBytes(d.rx_bytes)], ["Uploaded", fmtBytes(d.tx_bytes)],
    ["Last report", ago(s.diag_at)],
  ];
}

// ---------------------------------------------------------------- sessions drawer
// ---- log uploads ----
function logRows(list) {
  if (!list.length) return [el("div", { class: "muted small" }, "None yet. Use Collect logs, or ask the user to choose Diagnose → Send logs to IT in the app.")];
  return list.map((l) => el("div", { class: "log-row" },
    el("div", { class: "grow" },
      el("div", {}, el("span", { class: "mono strong" }, l.ref), " ", badge(l.reason === "admin" ? "Collected by IT" : "Sent by user", (l.reason === "admin" ? "info" : "neutral") + " plain"),
        l.verified ? null : badge("Not signed in", "warn plain")),
      el("div", { class: "sub" }, fullTime(l.at) + " · " + fmtBytes(l.size) + (l.upn ? " · " + l.upn : ""))),
    el("a", { class: "btn sm", href: "/admin/api/logs/" + encodeURIComponent(l.id) + "/download", download: "" }, icon("download"), "Download")));
}
async function loadLogs(device, box) {
  box.replaceChildren(el("div", { class: "muted small" }, "Loading…"));
  try {
    const list = await api("GET", "/logs?device=" + encodeURIComponent(device));
    box.replaceChildren(...logRows(list));
  } catch (e) { box.replaceChildren(el("div", { class: "muted small" }, "Couldn't load logs.")); }
}
function showDeviceLogs(d) {
  $("dlg-logs-title").textContent = "Logs from " + (d.name || d.id);
  loadLogs(d.id, $("dlg-logs-list"));
  $("dlg-logs").showModal();
}

async function loadDrawerSpeed(device) {
  const box = $("d-speed");
  box.replaceChildren(el("div", { class: "muted small" }, "Loading…"));
  try {
    const list = await api("GET", "/speedtests?device=" + encodeURIComponent(device) + "&limit=8");
    if (!state.drawerSession || state.drawerSession.device_id !== device) return;
    box.replaceChildren(...(list.length ? list.map((t) => el("div", { class: "spd-row" },
      badge(t.kind === "vpn" ? "VPN" : "Internet", (t.kind === "vpn" ? "info" : "neutral") + " plain"),
      el("div", {}, el("span", { class: "rate" }, "↓ " + fmtBps(t.down_bps) + "  ↑ " + fmtBps(t.up_bps)),
        el("div", { class: "sub" }, t.latency_ms + " ms" + (t.network ? " · " + t.network : "") + (t.auto ? " · automatic" : ""))),
      el("span", { class: "sub", title: fullTime(t.at) }, ago(t.at)))) : [el("div", { class: "muted small" }, "No speed tests reported yet.")]));
  } catch (e) {
    box.replaceChildren(el("div", { class: "muted small" }, "Couldn't load speed tests."));
  }
}

function openDrawer(s) {
  state.drawerSession = s;
  fillDrawer(s);
  loadDrawerSpeed(s.device_id);
  loadLogs(s.device_id, $("d-logs"));
  $("drawer").classList.add("open");
  $("drawer").setAttribute("aria-hidden", "false");
  $("drawer-backdrop").classList.remove("hidden");
}
function closeDrawer() {
  state.drawerSession = null;
  $("drawer").classList.remove("open");
  $("drawer").setAttribute("aria-hidden", "true");
  $("drawer-backdrop").classList.add("hidden");
}
$("d-close").addEventListener("click", closeDrawer);
$("drawer-backdrop").addEventListener("click", closeDrawer);
document.addEventListener("keydown", (e) => { if (e.key === "Escape") { closeDrawer(); hideMenu(); } });

function fillDrawer(s) {
  state.drawerSession = s;
  const [label, kind] = STATE[s.state] || [s.state, "neutral"];
  const live = s.state === "active" || s.state === "suspended";
  setAvatar($("d-avatar"), s.upn);
  $("d-user").textContent = s.upn;
  $("d-state").replaceChildren(badge(label, kind));
  const end = live ? Date.now() : ts(s.ended_at) || ts(s.last_seen);
  const rows = [
    ["Device", s.device_name || s.device_id], ["Device ID", s.device_name && s.device_name !== s.device_id ? s.device_id : "", "mono"], ["Platform", s.platform],
    ["Client version", s.client_version ? "v" + s.client_version + (s.outdated ? " (update pending)" : "") : "–"], ["sep"],
    ["Gateway", s.gateway_id], ["Tunnel IP", s.tunnel_ip, "mono"], ["Connected from", s.client_ip, "mono"],
    ["Country", s.country ? countryName(s.country) + " (" + s.country + ")" : "Unknown"], ["sep"],
    ["Connected", fullTime(s.created_at)], ["Duration", dur((end - ts(s.created_at)) / 1000)],
    ["Last heartbeat", ago(s.last_seen)], [live ? "Session limit" : "Ended", live ? fullTime(s.expires_at) : fullTime(s.ended_at)],
  ];
  if (!live && s.end_reason) rows.push(["Reason", REASON[s.end_reason] || s.end_reason]);
  if (s.kind === "device") rows.unshift(["Type", "Device tunnel (before sign-in): device certificate only, limited to the device tunnel's subnets"], ["sep"]);
  if (s.state === "suspended") rows.push(["Note", "Network dropped. The session resumes with no sign-in if the device is back within 15 minutes."]);
  if (live && s.diag && s.diag.office_mode) rows.push(["Note", "Office mode: the PC is on the office network, so its traffic goes direct. It stays signed in and goes back through the tunnel when it leaves."]);
  rows.push(...diagRows(s));
  const dev = (state.devices || []).find((x) => x.id === s.device_id);
  if (dev) rows.push(["sep"], ["head", "Certificates"], ["Summary", el("div", { class: "cc" }, ...trustBadges(dev.trust))], ...trustRows(dev.trust).filter(([k]) => ["Why", "Sign-in policy", "Device certificate", "User certificate"].includes(k)));
  else if (!state.devicesLoading) {
    state.devicesLoading = true;
    api("GET", "/devices").then((list) => { state.devices = list; if (state.drawerSession === s) fillDrawer(s); }).catch(() => {}).finally(() => { state.devicesLoading = false; });
  }
  rows.push(["sep"], ["Session ID", s.id, "mono"]);
  $("d-list").replaceChildren(...rows.flatMap(([k, v, cls]) =>
    k === "sep" ? [el("div", { class: "sep" })]
      : k === "head" ? [el("div", { class: "dl-head" }, v)]
        : [el("dt", {}, k), el("dd", { class: cls }, v || "–")]));
  $("d-disconnect").classList.toggle("hidden", !live);
  // Remote actions need the SecureTunnel agent on a live session (not the test client).
  $("d-actions").classList.toggle("hidden", !live || !s.client_version);
  $("d-act-update").classList.toggle("hidden", s.platform !== "windows" || !isAdmin()); // pushes are Windows-only, admins only
}
$("d-disconnect").addEventListener("click", () => state.drawerSession && disconnect(state.drawerSession));

// Remote helpdesk actions on the open session.
async function sendCommand(type, text, okMsg) {
  const s = state.drawerSession;
  if (!s) return;
  try {
    await api("POST", "/sessions/" + encodeURIComponent(s.id) + "/command", { type, text });
    toast(okMsg);
    return true;
  } catch (e) { failed(e); return false; }
}
$("d-act-speed").addEventListener("click", async () => {
  if (await sendCommand("speedtest", "", "Speed test started on " + state.drawerSession.device_id + ". Results appear here in about a minute.")) {
    const dev = state.drawerSession.device_id;
    setTimeout(() => { if (state.drawerSession && state.drawerSession.device_id === dev) loadDrawerSpeed(dev); }, 60000);
  }
});
$("d-act-diag").addEventListener("click", async () => {
  if (await sendCommand("diagnostics", "", "Asked " + state.drawerSession.device_id + " for fresh diagnostics")) {
    setTimeout(() => render(), 5000);
  }
});
$("d-act-msg").addEventListener("click", () => {
  const s = state.drawerSession;
  $("f-msg-who").textContent = "To " + s.upn + " on " + s.device_id;
  $("f-msg-text").value = "";
  $("f-msg-error").textContent = "";
  $("dlg-msg").showModal();
  $("f-msg-text").focus();
});
$("d-act-logs").addEventListener("click", async () => {
  const s = state.drawerSession;
  if (await sendCommand("logs", "", "Asked " + (s.device_name || s.device_id) + " for its logs. They appear here within a minute.")) {
    [15000, 40000].forEach((t) => setTimeout(() => { if (state.drawerSession && state.drawerSession.id === s.id) loadLogs(s.device_id, $("d-logs")); }, t));
  }
});
$("d-act-move").addEventListener("click", async () => {
  const s = state.drawerSession;
  $("f-move-who").textContent = s.upn + " is on " + s.gateway_id + ".";
  $("f-move-error").textContent = "";
  const sel = $("f-move-target");
  sel.replaceChildren(el("option", { value: "" }, "Best available gateway"));
  try {
    const gws = await api("GET", "/gateways");
    (gws || []).filter((g) => g.enabled && g.id !== s.gateway_id).forEach((g) => sel.append(el("option", { value: g.id }, g.id + (g.site ? " (" + g.site + ")" : ""))));
  } catch (e) { /* the default option still works */ }
  $("dlg-move").showModal();
});
$("f-move").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const s = state.drawerSession;
  try {
    await api("POST", "/sessions/" + encodeURIComponent(s.id) + "/move", { target: $("f-move-target").value });
    $("dlg-move").close();
    toast("Moving " + s.upn + ". It takes a few seconds.");
    setTimeout(() => render(), 6000);
  } catch (e) { $("f-move-error").textContent = e.message; }
});
$("f-msg").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const text = $("f-msg-text").value.trim();
  if (!text) { $("f-msg-error").textContent = "Write a message first."; return; }
  if (await sendCommand("message", text, "Message sent to " + state.drawerSession.upn)) $("dlg-msg").close();
});
$("d-history").addEventListener("click", () => {
  const s = state.drawerSession;
  closeDrawer();
  $("s-q").value = s.upn;
  setSessionsState("");
  if (currentView() !== "sessions") location.hash = "#sessions"; else render();
});

function setSessionsState(st) {
  state.sessionsState = st;
  document.querySelectorAll("#s-seg button").forEach((b) => b.classList.toggle("on", b.dataset.state === st));
}
document.querySelectorAll("#s-seg button").forEach((b) => b.addEventListener("click", () => { setSessionsState(b.dataset.state); render({ first: true }); }));
let sTimer;
$("s-q").addEventListener("input", () => { clearTimeout(sTimer); sTimer = setTimeout(() => render(), 250); });

// ---------------------------------------------------------------- users
function drawUsers() {
  const q = $("u-q").value.trim().toLowerCase();
  const list = state.users.filter((u) => !q || u.username.includes(q) || (u.display_name || "").toLowerCase().includes(q));
  const rows = list.map((u) => {
    const [rl, rk] = ROLE[u.role] || [u.role, "neutral"];
    const isMe = state.me && u.username === state.me.username;
    return el("tr", {},
      el("td", {}, el("div", { class: "who" }, avatar(u.display_name || u.username),
        el("div", { class: "who-text" }, el("div", { class: "strong" }, u.display_name || u.username, isMe ? el("span", { class: "sub" }, "  (you)") : null), el("div", { class: "sub" }, u.username)))),
      el("td", {}, u.source === "entra" ? badge("Entra user", "info plain") : badge(rl, rk + " plain")),
      el("td", {}, u.source === "entra" ? badge("Microsoft", "ok") : u.mfa ? badge("Authenticator", "ok") : badge("Password only", "neutral")),
      el("td", {}, ...userGroupBadges(u)),
      el("td", {}, userCountries(u)),
      el("td", {}, u.disabled ? badge("Disabled", "bad") : badge("Active", "ok")),
      el("td", { class: "nowrap", title: fullTime(u.last_login) }, ago(u.last_login)),
      el("td", { class: "actions" }, isAdmin() ? el("button", { class: "icon-btn", "aria-label": "Actions for " + u.username, onclick: (ev) => userMenu(ev, u) }, icon("more")) : null));
  });
  $("u-rows").replaceChildren(...(rows.length ? rows : [emptyRow(8, q ? "No users match your search." : "No users yet.", "users")]));
}
$("u-q").addEventListener("input", drawUsers);

function hideMenu() { $("menu").classList.add("hidden"); }
document.addEventListener("click", (e) => { if (!e.target.closest("#menu")) hideMenu(); });
function userMenu(ev, u) {
  ev.stopPropagation();
  const m = $("menu");
  const isMe = u.username === state.me.username;
  const item = (ic, label, fn, danger) => el("button", { class: danger ? "danger" : "", role: "menuitem", onclick: () => { hideMenu(); fn(); } }, icon(ic), label);
  m.replaceChildren(
    item("edit", "Edit details", () => editUser(u)),
    u.source === "entra" ? null : item("key", "Reset password", () => resetPassword(u)),
    u.source === "entra" ? null : u.mfa ? item("shield", "Remove authenticator", () => removeMFA(u)) : item("shield", "Set up authenticator", () => enrollMFA(u)),
    el("hr"),
    isMe ? null : item("power", u.disabled ? "Enable account" : "Disable account", () => setDisabled(u, !u.disabled), !u.disabled),
    isMe ? null : item("trash", "Delete user", () => deleteUser(u), true));
  m.classList.remove("hidden");
  const r = ev.currentTarget.getBoundingClientRect();
  const mw = m.offsetWidth, mh = m.offsetHeight;
  m.style.left = Math.max(8, Math.min(window.innerWidth - mw - 8, r.right - mw)) + "px";
  m.style.top = (r.bottom + mh + 8 > window.innerHeight ? r.top - mh - 4 : r.bottom + 4) + "px";
}

let userDialogMode = null;
let userKind = "local";
function setUserKind(kind) {
  userKind = kind;
  document.querySelectorAll("#f-user-kind button").forEach((b) => b.classList.toggle("on", b.dataset.kind === kind));
  const entra = kind === "entra";
  $("f-user-kind-hint").textContent = entra
    ? "Settings for someone who signs in with Microsoft: countries, or disable. Users are also added here automatically the first time they connect."
    : "A password account for testing, or the break-glass admin.";
  $("f-user-name-label").textContent = entra ? "Entra sign-in name (UPN)" : "Username";
  $("f-user-name").placeholder = entra ? "jsmith@contoso.com" : "jsmith";
  $("f-user-role-wrap").classList.toggle("hidden", entra);
  const newLocal = !userDialogMode && !entra;
  $("f-user-pass-wrap").classList.toggle("hidden", !newLocal);
  $("f-user-pass").required = newLocal;
}
document.querySelectorAll("#f-user-kind button").forEach((b) => b.addEventListener("click", () => setUserKind(b.dataset.kind)));
function openUserDialog(u) {
  userDialogMode = u ? u.username : null;
  $("f-user-title").textContent = u ? "Edit " + u.username : "Add user";
  $("f-user-submit").textContent = u ? "Save" : "Add user";
  $("f-user-name").value = u ? u.username : "";
  $("f-user-name").disabled = !!u;
  $("f-user-display").value = u ? u.display_name || "" : "";
  $("f-user-role").value = u ? u.role : "user";
  $("f-user-pass").value = "";
  $("f-user-pass").required = !u;
  $("f-user-pass-wrap").classList.toggle("hidden", !!u);
  $("f-user-disabled-wrap").classList.toggle("hidden", !u || u.username === state.me.username);
  $("f-user-countries").classList.toggle("hidden", !u);
  $("f-user-allowed").value = u ? (u.allowed_countries || []).join(", ") : "";
  $("f-user-travel").value = u ? (u.travel_countries || []).join(", ") : "";
  const until = u && ts(u.travel_until) ? new Date(ts(u.travel_until)) : null;
  $("f-user-until").value = until ? until.toISOString().slice(0, 10) : "";
  namesHint($("f-user-allowed"), $("f-user-allowed-names"));
  namesHint($("f-user-travel"), $("f-user-travel-names"));
  $("f-user-disabled").checked = !!(u && u.disabled);
  $("f-user-error").textContent = "";
  $("f-user-kind-wrap").classList.toggle("hidden", !!u);
  drawUserPolicies(u); // which groups and policies apply (policies.js)
  setUserKind(u ? (u.source === "entra" ? "entra" : "local") : "local");
  if (u && u.source === "entra") $("f-user-kind-wrap").classList.remove("hidden");
  document.querySelectorAll("#f-user-kind button").forEach((b) => { b.disabled = !!u; });
  $("dlg-user").showModal();
  (u ? $("f-user-display") : $("f-user-name")).focus();
}
$("u-add").addEventListener("click", () => openUserDialog(null));
const editUser = (u) => openUserDialog(u);

$("f-user").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("f-user-error").textContent = "";
  try {
    if (userDialogMode) {
      const body = {
        display_name: $("f-user-display").value, role: userKind === "entra" ? undefined : $("f-user-role").value,
        allowed_countries: parseCodes($("f-user-allowed").value), travel_countries: parseCodes($("f-user-travel").value),
        travel_until: $("f-user-until").value,
      };
      if (body.travel_countries.length && !body.travel_until) throw new Error("Set when the trip ends, or clear the trip countries.");
      if (userDialogMode !== state.me.username) body.disabled = $("f-user-disabled").checked;
      await api("POST", "/users/" + encodeURIComponent(userDialogMode), body);
      toast("Saved " + userDialogMode);
    } else {
      const name = $("f-user-name").value.trim().toLowerCase();
      await api("POST", "/users", userKind === "entra"
        ? { username: name, display_name: $("f-user-display").value, source: "entra" }
        : { username: name, display_name: $("f-user-display").value, role: $("f-user-role").value, password: $("f-user-pass").value });
      toast("Added " + name);
    }
    $("dlg-user").close();
    render();
  } catch (e) {
    $("f-user-error").textContent = e.message;
  }
});

let passUser = null;
function resetPassword(u) {
  passUser = u.username;
  $("f-pass-who").textContent = "Set a new password for " + u.username + ". Share it with them securely.";
  $("f-pass-new").value = "";
  $("f-pass-new").type = "password";
  $("f-pass-show").textContent = "";
  $("f-pass-error").textContent = "";
  $("dlg-pass").showModal();
  $("f-pass-new").focus();
}
$("f-pass-gen").addEventListener("click", () => {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789";
  const buf = new Uint32Array(16);
  crypto.getRandomValues(buf);
  const pw = Array.from(buf, (n) => chars[n % chars.length]).join("");
  $("f-pass-new").value = pw;
  $("f-pass-new").type = "text";
  $("f-pass-show").textContent = "";
});
$("f-pass").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    await api("POST", "/users/" + encodeURIComponent(passUser), { password: $("f-pass-new").value });
    $("dlg-pass").close();
    toast("Password updated for " + passUser);
  } catch (e) {
    $("f-pass-error").textContent = e.message;
  }
});

async function enrollMFA(u) {
  if (u.mfa && !(await confirmDialog("Replace authenticator?", "The current authenticator for " + u.username + " stops working.", "Replace"))) return;
  try {
    const r = await api("POST", "/users/" + encodeURIComponent(u.username) + "/totp");
    $("mfa-who").textContent = "For " + (u.display_name || u.username) + " (" + u.username + ")";
    $("mfa-secret").textContent = r.secret.replace(/(.{4})/g, "$1 ").trim();
    const img = $("mfa-qr");
    img.classList.toggle("hidden", !r.qr);
    if (r.qr) img.src = r.qr;
    $("mfa-copy").onclick = () => navigator.clipboard.writeText(r.secret).then(() => toast("Key copied")).catch(() => toast("Couldn't copy", true));
    $("dlg-mfa").showModal();
    render();
  } catch (e) { failed(e); }
}

async function removeMFA(u) {
  if (!(await confirmDialog("Remove authenticator?", u.username + " will sign in with just a password until a new authenticator is set up.", "Remove"))) return;
  try { await api("DELETE", "/users/" + encodeURIComponent(u.username) + "/totp"); toast("Authenticator removed"); render(); }
  catch (e) { failed(e); }
}

async function setDisabled(u, disabled) {
  if (disabled && !(await confirmDialog("Disable " + u.username + "?", "They won't be able to sign in or connect. Active sessions aren't ended; disconnect them on the Sessions page.", "Disable"))) return;
  try { await api("POST", "/users/" + encodeURIComponent(u.username), { disabled }); toast((disabled ? "Disabled " : "Enabled ") + u.username); render(); }
  catch (e) { failed(e); }
}

async function deleteUser(u) {
  if (!(await confirmDialog("Delete " + u.username + "?", "This removes the account permanently. Their session history stays in the audit log.", "Delete"))) return;
  try { await api("DELETE", "/users/" + encodeURIComponent(u.username)); toast("Deleted " + u.username); render(); }
  catch (e) { failed(e); }
}

// ---------------------------------------------------------------- audit
function drawAudit() {
  const q = $("a-q").value.trim().toLowerCase();
  const list = state.audit.filter((a) => !q || [a.actor, a.action, a.detail, a.target, actionInfo(a.action)[0]].join(" ").toLowerCase().includes(q));
  const rows = list.slice(0, 500).map((a) => {
    const [label, ic, kind] = actionInfo(a.action);
    return el("tr", {},
      el("td", { class: "nowrap", title: fullTime(a.at) }, shortTime(a.at)),
      el("td", {}, el("div", { class: "who" }, avatar(a.actor, "sm"), el("span", {}, a.actor))),
      el("td", {}, el("div", { class: "who" }, el("span", { class: "act-icon " + kind }, icon(ic)), el("div", { class: "who-text" }, el("div", {}, label), el("div", { class: "sub mono" }, a.action)))),
      el("td", {}, a.detail || "–", a.target ? el("div", { class: "sub mono" }, a.target) : null));
  });
  $("a-rows").replaceChildren(...(rows.length ? rows : [emptyRow(4, q ? "Nothing matches that filter." : "No entries yet.", "file")]));
}
$("a-q").addEventListener("input", drawAudit);

// ---------------------------------------------------------------- actions
async function disconnect(s) {
  if (!(await confirmDialog("Disconnect " + s.upn + "?", "Their tunnel drops within a few seconds and they'll need to sign in again to reconnect.", "Disconnect"))) return;
  try {
    await api("POST", "/sessions/" + encodeURIComponent(s.id) + "/disconnect");
    toast("Disconnected " + s.upn);
    closeDrawer();
    render();
  } catch (e) { failed(e); }
}

async function drainGateway(g) {
  if (!(await confirmDialog("Drain " + g.id + "?", "New connections stop going to " + g.id + ", and everyone on it is moved to another gateway within a few seconds. Their tunnel IP changes, so open calls and file copies restart. Enable it again when you're done.", "Drain"))) return;
  try {
    const r = await api("POST", "/gateways/" + encodeURIComponent(g.id) + "/drain");
    toast("Draining " + g.id + ": queued " + r.moving + " move(s)" + (r.cannot_move ? ", " + r.cannot_move + " unsupported client(s)" : "") + (r.failed ? ", " + r.failed + " move(s) could not be queued" : ""));
    render();
  } catch (e) { failed(e); }
}

// ---- App updates ----
const radioVal = (name) => (document.querySelector('input[name="' + name + '"]:checked') || {}).value;
const setRadio = (name, v) => { const r = document.querySelector('input[name="' + name + '"][value="' + v + '"]'); if (r) r.checked = true; };
const UPD_STATE = {
  up_to_date: ["Up to date", "ok"], downloading: ["Downloading", "info"], ready: ["Ready, waiting", "info"],
  scheduled: ["Scheduled", "info"], installing_soon: ["Updating in a moment", "warn"], installing: ["Installing", "warn"],
  held: ["Held back", "neutral"], error: ["Update error", "bad"], checking: ["Checking", "neutral"],
};
const realTime = (iso) => iso && !String(iso).startsWith("0001");
function pushWhen(prefix) {
  const when = radioVal(prefix + "-when");
  const body = { when };
  if (when === "at") {
    const v = $(prefix === "push" ? "push-at" : "f-update-at").value;
    if (!v) throw new Error("Pick the date and time to update.");
    body.at = new Date(v).toISOString(); // the browser's local time → UTC
  }
  return body;
}
// The app updates policies, as cards: settings in words, assigned groups, PCs.
function drawUpdatePolicies(r) {
  const pols = r.policies || [];
  $("upd-pol-list").replaceChildren(...(pols.length ? pols.map((p) => {
    const row = el("div", { class: "upd-rule" + (isAdmin() ? " click" : "") },
      el("div", { class: "upd-rule-top" }, el("span", { class: "strong" }, p.name),
        p.updates && p.updates.paused ? badge("Paused", "warn plain") : null,
        el("span", { class: "grow" }), el("span", { class: "sub" }, (p.pcs || 0) + " PC" + (p.pcs === 1 ? "" : "s"))),
      el("div", { class: "sub" }, updateSummary(p.updates)),
      el("div", { class: "sub" }, p.default ? "Everyone else" : (p.group_names || []).join(", ") || "No groups"));
    if (isAdmin()) row.addEventListener("click", () => editPolicyByID(p.id));
    return row;
  }) : [el("div", { class: "muted small" }, "No update rules yet.")]));
}
function drawUpdates(r) {
  state.updates = r;
  drawUpdatePolicies(r);
  const pcs = r.connected || [];
  const outdated = pcs.filter((x) => x.outdated);
  const upToDate = (r.devices || 0) - (r.outdated_devices || 0);
  $("nav-outdated").textContent = outdated.length || "";
  // Rollout header: % of PCs on the current version, and a bar split by version.
  $("upd-latest").textContent = r.latest || "–";
  const devs = r.devices || 0;
  $("upd-pct-v").textContent = devs ? Math.round((upToDate / devs) * 100) + "%" : "–";
  $("upd-pct-k").textContent = devs ? upToDate.toLocaleString() + " of " + devs.toLocaleString() + " PCs up to date" : "No PCs have reported yet";
  const vers = (r.versions || []).slice().sort((a, b) => (b.current ? 1 : 0) - (a.current ? 1 : 0) || b.pcs - a.pcs);
  const total = vers.reduce((n, v) => n + v.pcs, 0) || 1;
  const shade = (v, i) => v.current ? "cur" : "old o" + Math.min(i, 4);
  $("upd-stack").replaceChildren(...vers.map((v, i) => {
    const seg = el("div", { class: shade(v, i), title: v.version + ": " + v.pcs + " PC" + (v.pcs === 1 ? "" : "s") });
    seg.style.width = (v.pcs / total) * 100 + "%";
    return seg;
  }));
  $("upd-versions").replaceChildren(...(vers.length ? vers.map((v, i) => el("span", { class: "upd-key" }, el("i", { class: shade(v, i) }),
    el("span", { class: "mono" }, v.version), el("span", { class: "sub" }, v.pcs.toLocaleString() + (v.current ? " · current" : ""))))
    : [el("span", { class: "muted small" }, "No PCs have reported a version yet.")]));
  $("push-to-outdated").textContent = "Older versions (" + outdated.length + " connected)";
  $("upd-n-all").textContent = pcs.length; $("upd-n-old").textContent = outdated.length;
  const shown = state.updFilter === "old" ? outdated : pcs;
  const ticked = new Set([...document.querySelectorAll("#upd-rows input:checked")].map((c) => c.value));
  $("upd-rows").replaceChildren(...(shown.length ? shown.map((x) => {
    const [label, kind] = UPD_STATE[x.update] || (x.outdated ? ["Not started", "neutral"] : ["Up to date", "ok"]);
    const when = realTime(x.update_at) ? " · " + new Date(x.update_at).toLocaleString([], { weekday: "short", hour: "numeric", minute: "2-digit" }) : "";
    return el("tr", {},
      el("td", { class: "chk" }, el("input", { type: "checkbox", value: x.session_id, checked: ticked.has(x.session_id) || null, "aria-label": "Tick " + x.pc, onchange: drawPushCount })),
      el("td", {}, el("div", { class: "strong" }, x.pc || "–"), el("div", { class: "sub" }, x.user)),
      el("td", {}, el("span", { class: "mono" }, x.version), x.outdated ? el("span", { class: "upd-old" }, " → " + (r.latest || "")) : null),
      el("td", { class: "sub" }, x.policy || "–"),
      el("td", {}, badge(label + when, kind + " plain"), x.postponed ? el("div", { class: "sub" }, "Postponed " + x.postponed + "×") : null));
  }) : [emptyRow(5, state.updFilter === "old" ? "Every connected PC is up to date." : "No Windows PCs are connected right now.", "monitor")]));
  drawPushCount();
  $("upd-push").classList.toggle("hidden", !isAdmin());
}
function drawPushCount() {
  const n = document.querySelectorAll("#upd-rows input:checked").length;
  $("push-to-pcs").textContent = "Selected PCs (" + n + ")";
  const to = radioVal("push-to");
  const count = to === "pcs" ? n : ((state.updates && state.updates.connected) || []).filter((x) => x.outdated).length;
  $("push-go").textContent = count ? "Push to " + count + " PC" + (count === 1 ? "" : "s") : "Push update";
}
document.querySelectorAll('input[name="push-to"]').forEach((r) => r.addEventListener("change", drawPushCount));
$("push-at").addEventListener("focus", () => setRadio("push-when", "at"));
document.querySelectorAll("#upd-seg button").forEach((b) => b.addEventListener("click", () => {
  state.updFilter = b.dataset.f;
  document.querySelectorAll("#upd-seg button").forEach((x) => x.classList.toggle("on", x === b));
  if (state.updates) drawUpdates(state.updates);
}));
$("upd-all").addEventListener("change", (ev) => {
  document.querySelectorAll("#upd-rows input[type=checkbox]").forEach((c) => (c.checked = ev.target.checked));
  drawPushCount();
});
async function sendPush(body, errBox) {
  errBox.textContent = "";
  const r = await api("POST", "/updates/push", body);
  const when = { disconnect: "after they disconnect", now: "now (2-minute warning)", immediate: "immediately (no warning)",
    at: "at " + (body.at ? new Date(body.at).toLocaleString() : "") }[body.when];
  toast(r.sent ? "Update sent to " + r.sent + " PC" + (r.sent === 1 ? "" : "s") + ": installs " + when : "No PCs matched: nothing was sent");
  return r;
}
$("push-go").addEventListener("click", async () => {
  try {
    const to = radioVal("push-to");
    const body = Object.assign({ target: to, sessions: to === "pcs" ? [...document.querySelectorAll("#upd-rows input:checked")].map((c) => c.value) : [] }, pushWhen("push"));
    if (to === "pcs" && !body.sessions.length) throw new Error("Tick at least one PC below.");
    const n = to === "pcs" ? body.sessions.length : (state.updates.connected || []).filter((x) => x.outdated).length;
    const warnText = body.when === "immediate"
      ? "Each one disconnects right away, with no warning, for about 20 seconds while it updates, then reconnects by itself. Users can't postpone it, so calls and file copies in progress will drop."
      : "Each one disconnects for about 20 seconds while it updates, then reconnects by itself. Users get a 2-minute warning and can postpone within the policy's limits.";
    if (body.when !== "disconnect" && !(await confirmDialog("Update " + n + " PC" + (n === 1 ? "" : "s") + (body.when === "immediate" ? " immediately?" : "?"), warnText,
      body.when === "immediate" ? "Update immediately" : "Push update"))) return;
    await sendPush(body, $("push-error"));
    setTimeout(render, 4000);
  } catch (e) { $("push-error").textContent = e.message; }
});
// Session drawer → Update app.
$("d-act-update").addEventListener("click", () => {
  const s = state.drawerSession;
  $("f-update-who").textContent = s.upn + " on " + (s.device_name || s.device_id) + (s.client_version ? " · version " + s.client_version : "");
  $("f-update-error").textContent = "";
  setRadio("f-update-when", "disconnect");
  $("dlg-update").showModal();
});
$("f-update").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  try {
    await sendPush(Object.assign({ target: "pcs", sessions: [state.drawerSession.id] }, pushWhen("f-update")), $("f-update-error"));
    $("dlg-update").close();
  } catch (e) { $("f-update-error").textContent = e.message; }
});

// ---- address range ----
let poolGw = null, poolCheck = null, poolTimer;
function poolSize(cidr) {
  const m = /\/(\d+)$/.exec(cidr || "");
  return m ? Math.max(0, 2 ** (32 - Number(m[1])) - 3) : 0;
}
function openPool(g) {
  poolGw = g;
  poolCheck = null;
  $("f-pool-title").textContent = "Address range for " + g.id;
  $("f-pool-input").value = g.pool;
  $("f-pool-error").textContent = "";
  drawPoolCheck(null);
  $("dlg-pool").showModal();
  $("f-pool-input").select();
}
function drawPoolCheck(c, err) {
  const v = $("f-pool-input").value.trim();
  const changed = poolGw && v && v !== poolGw.pool;
  const n = poolSize(c ? c.pool : v);
  $("f-pool-info").textContent = err ? "" : !v ? "" :
    n.toLocaleString() + " user addresses" + (poolGw && poolGw.capacity ? " · gateway limit " + poolGw.capacity.toLocaleString() : "") +
    (c && c.connected ? " · " + c.connected + " session" + (c.connected === 1 ? "" : "s") + " on this gateway now" : "");
  $("f-pool-warn").replaceChildren(...((c && c.warnings) || []).map((w) => el("li", {}, icon("alert"), w)));
  $("f-pool-error").textContent = err || "";
  const busy = c && c.connected > 0;
  $("f-pool-save").textContent = busy ? "Move users, then change" : "Save range";
  $("f-pool-save").disabled = !changed || !!err;
}
$("f-pool-input").addEventListener("input", () => {
  clearTimeout(poolTimer);
  drawPoolCheck(null);
  const v = $("f-pool-input").value.trim();
  if (!v || v === poolGw.pool) return;
  poolTimer = setTimeout(async () => {
    try {
      poolCheck = await api("POST", "/gateways/" + encodeURIComponent(poolGw.id) + "/pool", { pool: v, check: true });
      if ($("f-pool-input").value.trim() === v) drawPoolCheck(poolCheck);
    } catch (e) { if ($("f-pool-input").value.trim() === v) drawPoolCheck(null, e.message); }
  }, 350);
});
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
$("f-pool").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  const g = poolGw, pool = $("f-pool-input").value.trim();
  const path = "/gateways/" + encodeURIComponent(g.id) + "/pool";
  const btn = $("f-pool-save");
  $("f-pool-error").textContent = "";
  btn.disabled = true;
  try {
    let r;
    try {
      r = await api("POST", path, { pool });
    } catch (e) {
      if (e.code !== "gateway_in_use") throw e;
      // Users have addresses from the old range: move them to other gateways first.
      // One modal at a time: the range dialog steps aside for the question.
      const ask = async (title, body, ok) => {
        $("dlg-pool").close();
        const yes = await confirmDialog(title, body, ok);
        $("dlg-pool").showModal();
        return yes;
      };
      if (!(await ask("Move users off " + g.id + "?",
        "Everyone on " + g.id + " is moved to another gateway (their tunnel IP changes, so calls and file copies restart). Then the range changes and " + g.id + " takes new users again.",
        "Move and change"))) { btn.disabled = false; return; }
      btn.textContent = "Moving users…";
      await api("POST", "/gateways/" + encodeURIComponent(g.id) + "/drain");
      let left = 1;
      for (let i = 0; i < 30 && left > 0; i++) { // up to a minute for the apps to switch
        await sleep(2000);
        left = (await api("POST", path, { pool, check: true })).connected || 0;
      }
      let end = false;
      if (left > 0) {
        end = await ask("End " + left + " remaining session" + (left === 1 ? "" : "s") + "?",
          left + " session" + (left === 1 ? " is" : "s are") + " still on " + g.id + " (offline PCs in their grace window, or older apps that can't move). Ending them lets the change go ahead; those users sign in again.", "End and change");
        if (!end) {
          if (g.enabled) await api("POST", "/gateways/" + encodeURIComponent(g.id) + "/enabled", { enabled: true });
          btn.disabled = false; drawPoolCheck(poolCheck); return;
        }
      }
      r = await api("POST", path, { pool, end_remaining: end });
      if (g.enabled) await api("POST", "/gateways/" + encodeURIComponent(g.id) + "/enabled", { enabled: true });
    }
    $("dlg-pool").close();
    toast(g.id + " now uses " + r.pool + (r.ended ? " (" + r.ended + " session" + (r.ended === 1 ? "" : "s") + " ended)" : "") + ". Update your network's route to it.");
    render();
  } catch (e) {
    $("f-pool-error").textContent = e.message;
    drawPoolCheck(poolCheck, e.message);
  }
});

async function toggleGateway(g) {
  if (g.enabled && !(await confirmDialog("Disable " + g.id + "?", "New connections won't be placed on this gateway. People already connected to it stay connected.", "Disable"))) return;
  try {
    await api("POST", "/gateways/" + encodeURIComponent(g.id) + "/enabled", { enabled: !g.enabled });
    toast((g.enabled ? "Disabled " : "Enabled ") + g.id);
    render();
  } catch (e) { failed(e); }
}

// ---------------------------------------------------------------- boot
api("GET", "/me").then((u) => { state.me = u; startApp(); }).catch((e) => { if (e.message !== "signed_out") showLogin(); });
