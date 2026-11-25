"use strict";
// Fake data for designing the UI without a server. Active only when index.html is
// opened from disk (file://) or from localhost with ?demo; never on a real deployment.
(function () {
  const local = location.hostname === "localhost" || location.hostname === "127.0.0.1";
  if (!(location.protocol === "file:" || (local && new URLSearchParams(location.search).has("demo")))) return;

  const now = Date.now();
  const iso = (msAgo) => new Date(now - msAgo).toISOString();
  const min = 60e3, hr = 3600e3;
  const names = ["jsmith", "mgarcia", "achen", "rpatel", "lnguyen", "dkim", "sbrown", "tjohnson", "ewilson", "kmartin",
    "jlee", "amoore", "ctaylor", "banderson", "hthomas", "pjackson", "nwhite", "oharris", "gclark", "flewis",
    "vrobinson", "iwalker", "yyoung", "zallen", "qking", "uwright", "wscott", "xgreen", "mbaker", "radams",
    "snelson", "thill", "lcampbell", "dmitchell", "eroberts", "fcarter"];
  let seed = 7;
  const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
  const pick = (a) => a[Math.floor(rnd() * a.length)];

  const gateways = [
    { id: "dc-pair", site: "datacenter", endpoint: "vpn-dc.contoso.com:51820", public_key: "kX2c9fQ1mZ8bA7yT3nV6pR4sW0uE5hJ2gL9dK1oI8cM=", pool: "10.200.0.0/21", capacity: 1500, enabled: true, healthy: true, last_health: iso(8e3), active_peers: 0 },
    { id: "site2-pair", site: "onprem-site2", endpoint: "vpn-site2.contoso.com:51820", public_key: "Qm4uV8tY2wE6rT0yU3iO7pA1sD5fG9hJ2kL6zX0cV4b=", pool: "10.200.8.0/21", capacity: 1500, enabled: true, healthy: true, last_health: iso(11e3), active_peers: 0 },
  ];

  const sessions = [];
  names.forEach((n, i) => {
    const gw = i % 3 === 0 ? gateways[1] : gateways[0];
    const live = i < 29;
    const state = !live ? pick(["terminated", "expired", "terminated"]) : i % 11 === 4 ? "suspended" : "active";
    const created = (rnd() * 9 + 0.2) * hr;
    const seen = state === "suspended" ? (2 + rnd() * 9) * min : rnd() * 30e3;
    const s = {
      id: (Math.floor(rnd() * 1e16)).toString(16).padStart(16, "0") + i.toString(16).padStart(16, "0"),
      upn: n + "@contoso.com",
      device_id: (i % 5 === 2 ? "MAC-" : "LT-") + (4100 + i * 7),
      platform: i % 5 === 2 ? "macos" : "windows",
      gateway_id: gw.id,
      tunnel_ip: gw.pool.replace(/\.0\/21$/, "." + (i + 2)),
      client_ip: [Math.floor(rnd() * 180) + 20, Math.floor(rnd() * 255), Math.floor(rnd() * 255), Math.floor(rnd() * 254) + 1].join("."),
      state,
      created_at: iso(created),
      last_seen: iso(live ? seen : created - 2 * hr),
      expires_at: new Date(now - created + 12 * hr).toISOString(),
      ended_at: live ? "0001-01-01T00:00:00Z" : iso(created - 2 * hr),
      end_reason: live ? "" : state === "expired" ? pick(["grace_expired", "reboot"]) : pick(["user_disconnect", "admin_disconnect", "user_disconnect"]),
      client_version: i % 9 === 3 ? "" : i % 4 === 0 ? "1.326.465" : "1.326.469",
    };
    s.country = i === 4 ? "FR" : i === 9 ? "CA" : i % 13 === 7 ? "MX" : "US";
    if (s.client_version === "") s.platform = "stclient";
    s.outdated = s.client_version === "1.326.465";
    if (live && s.client_version) {
      const wifi = i % 3 !== 1;
      s.diag = {
        rx_bytes: Math.round((0.2 + rnd() * 3) * 1073741824), tx_bytes: Math.round((0.05 + rnd() * 0.6) * 1073741824),
        rx_bps: rnd() * 40e6, tx_bps: rnd() * 6e6, latency_ms: 18 + Math.round(rnd() * 40), jitter_ms: Math.round(rnd() * 9), loss_pct: rnd() < 0.8 ? 0 : 3.3,
        adapter: wifi ? "Wi-Fi" : "Ethernet", net_kind: wifi ? "Wi-Fi" : "Ethernet", ssid: wifi ? pick(["HomeNet", "ATT-5G-2291", "Starbucks WiFi", "NETGEAR42"]) : "",
        signal_pct: wifi ? 45 + Math.round(rnd() * 54) : 0, link_mbps: wifi ? pick([173, 400, 866, 1200]) : 1000,
        local_ip: "192.168.1." + (20 + i), isp_ip: s.client_ip, vpn_ip: "172.234.204.252",
        hostname: s.device_id, os: s.platform === "macos" ? "macOS 15.1" : "Windows 11 Pro 24H2 (build 26100.4061)",
        agent_version: s.client_version, uptime_sec: Math.round((1 + rnd() * 120) * 3600),
      };
      s.diag_at = iso(rnd() * 30e3);
    }
    if (live) gw.active_peers++;
    sessions.push(s);
  });

  const users = [
    { username: "admin", display_name: "IT Admin", role: "admin", disabled: false, mfa: true, created_at: iso(20 * 24 * hr), last_login: iso(2 * min) },
    { username: "helpdesk1", display_name: "Sam Rivera", role: "helpdesk", disabled: false, mfa: true, created_at: iso(15 * 24 * hr), last_login: iso(3 * hr) },
    { username: "testuser", policy_group: "default", display_name: "Test User", role: "user", disabled: false, mfa: false, created_at: iso(14 * 24 * hr), last_login: iso(40 * min) },
    { username: "jsmith", display_name: "Jane Smith", role: "user", disabled: false, mfa: true, created_at: iso(9 * 24 * hr), last_login: iso(3 * hr), allowed_countries: ["CA"], travel_countries: ["FR", "IT"], travel_until: new Date(now + 9 * 24 * hr).toISOString() },
    { username: "mgarcia", policy_group: "mac-users", display_name: "Miguel Garcia", role: "user", disabled: false, mfa: true, created_at: iso(9 * 24 * hr), last_login: iso(5 * hr), allowed_countries: ["MX"] },
    { username: "dlee@contoso.com", display_name: "Dana Lee", role: "user", source: "entra", disabled: false, mfa: false, created_at: iso(3 * 24 * hr), last_login: iso(18 * min), allowed_countries: ["GB"] },
    { username: "rpatel@contoso.com", display_name: "Raj Patel", role: "user", source: "entra", disabled: false, mfa: false, created_at: iso(2 * 24 * hr), last_login: iso(2 * hr) },
    { username: "achen", display_name: "Amy Chen", role: "user", disabled: false, mfa: false, created_at: iso(6 * 24 * hr), last_login: iso(26 * hr) },
    { username: "contractor2", display_name: "Contractor (temp)", role: "user", disabled: true, mfa: false, created_at: iso(30 * 24 * hr), last_login: iso(12 * 24 * hr) },
  ];

  const audit = [];
  const add = (msAgo, actor, action, target, detail) => audit.push({ id: audit.length + 1, at: iso(msAgo), actor, action, target, detail });
  add(25e3, "jsmith@contoso.com", "session.connect", sessions[0].id, "device=LT-4100 platform=windows gateway=dc-pair tunnel_ip=10.200.0.2");
  add(3 * min, "admin", "admin.login", "", "from 10.10.4.21");
  add(6 * min, "rpatel@contoso.com", "session.failover", sessions[3].id, "from=site2-pair to=dc-pair tunnel_ip=10.200.0.5");
  add(9 * min, "unknown", "vpn.login_failed", "", "wrong username or password from 203.0.113.50");
  add(12 * min, "rpatel", "vpn.country_blocked", "", "connecting from BR isn't allowed for this user (from 177.92.4.18)");
  add(14 * min, "admin", "admin.disconnect", sessions[30].id, "disconnected oharris@contoso.com");
  add(22 * min, "mgarcia@contoso.com", "session.connect", sessions[1].id, "device=LT-4107 platform=windows gateway=dc-pair tunnel_ip=10.200.0.3");
  add(41 * min, "admin", "user.mfa_enroll", "jsmith", "");
  add(55 * min, "achen@contoso.com", "session.reboot", sessions[2].id, "device rebooted; fresh sign-in required");
  add(70 * min, "admin", "gateway.enable", "site2-pair", "");
  add(2 * hr, "admin", "user.create", "testuser", "role=user");
  add(3 * hr, "helpdesk1", "admin.login", "", "from 10.10.4.30");
  for (let i = 0; i < 25; i++) add((3 + i * 0.4) * hr, pick(names) + "@contoso.com", "session.connect", "", "device=LT-" + (4100 + i) + " platform=windows gateway=dc-pair");
  audit.sort((a, b) => Date.parse(b.at) - Date.parse(a.at));

  // Host metrics: 60 samples, 15 s apart.
  const GB = 1024 ** 3;
  function series(base, swing, rxBase) {
    return Array.from({ length: 60 }, (_, i) => {
      const cpu = Math.max(1, Math.min(99, base + Math.sin(i / 6) * swing + (rnd() - 0.5) * swing));
      const rx = rxBase ? rxBase * (0.7 + rnd() * 0.6) : 0;
      return { at: iso((59 - i) * 15e3), cpu_percent: Math.round(cpu * 10) / 10, net_rx_bps: rx, net_tx_bps: rx * 0.35 };
    });
  }
  function host(id, kind, label, site, hostname, base, swing, rxBase, mem, memTotal, disk, diskTotal, handshakes) {
    const history = series(base, swing, rxBase).map((h) => Object.assign(h, {
      hostname, cpu_cores: 4, load1: 0.4, load5: 0.35, load15: 0.3,
      mem_used: mem * GB, mem_total: memTotal * GB, disk_used: disk * GB, disk_total: diskTotal * GB,
      uptime_sec: 19 * 86400 + 4 * 3600, handshakes,
    }));
    const current = history[history.length - 1];
    current.load1 = current.cpu_percent / 25;
    return { id, kind, label, site, online: true, current, history };
  }
  const hosts = [
    Object.assign(host("control:control-a", "control", "control-a", "", "vpn-lab-01", 6, 3, 0, 2.1, 7.7, 18.4, 97.9, 0), { serving: true }),
    host("control:control-b", "control", "control-b", "", "vpn-lab-01", 6, 2, 0, 2.1, 7.7, 18.4, 97.9, 0),
    host("dc-pair", "gateway", "dc-pair", "datacenter", "gw-dc-a", 22, 10, 180e6, 1.4, 3.8, 9.1, 48.9, 18),
    host("site2-pair", "gateway", "site2-pair", "onprem-site2", "gw-site2-a", 61, 20, 95e6, 3.2, 3.8, 41.7, 48.9, 10),
  ];
  gateways.forEach((g) => { g.metrics = hosts.find((h) => h.id === g.id).current; });
  let policy = { max_cpu_percent: 70, max_mem_percent: 70, min_free_disk_gb: 10 };
  const defaults = Object.assign({}, policy);
  let customPolicy = false;
  const demoUpd = { custom: false, pushed: {}, at: {}, policy: { paused: false, rollout_percent: 100, install_when: "window", window_days: [1, 2, 3, 4, 5], window_start: "01:00", window_end: "05:00", deadline_days: 7, notify_users: true, max_postpones: 3 } };
  function decorate() {
    for (const g of gateways) {
      g.sessions = sessions.filter((s) => s.gateway_id === g.id && (s.state === "active" || s.state === "suspended")).length;
      const m = g.metrics, over = [];
      if (m.cpu_percent >= policy.max_cpu_percent) over.push("CPU " + Math.round(m.cpu_percent) + "% (limit " + policy.max_cpu_percent + "%)");
      const mem = (m.mem_used / m.mem_total) * 100;
      if (mem >= policy.max_mem_percent) over.push("memory " + Math.round(mem) + "% (limit " + policy.max_mem_percent + "%)");
      const free = (m.disk_total - m.disk_used) / GB;
      if (free < policy.min_free_disk_gb) over.push("free disk " + free.toFixed(1) + " GB (minimum " + policy.min_free_disk_gb + " GB)");
      g.over_limits = over.join(", ");
      g.accepting = g.enabled && g.healthy && !g.over_limits;
    }
  }
  decorate();

  const hourly = [3, 1, 0, 0, 0, 1, 2, 9, 34, 61, 48, 37, 29, 33, 41, 38, 30, 22, 14, 9, 6, 5, 4, 7];

  let devicePolicy = { require_approval: true };
  const guid = (i) => ["3f2a9c1e", "b71d4e02", "9e04c5aa", "c3a18f77", "5d6e0b91", "a0f4e3c2", "77b2d1e8"][i % 7] + "-4c1b-4f0e-9a2d-" + (100000000000 + i * 7919).toString(16).slice(0, 12);
  let devices = [
    { id: guid(0), name: "LT-5012", status: "pending", platform: "windows", last_user: "nwhite", agent_version: "1.326.600", first_seen: iso(14 * min), last_seen: iso(14 * min), decided_by: "", decided_at: "1970-01-01T00:00:00Z" },
    { id: guid(1), name: "DESKTOP-H7Q2K", status: "pending", platform: "windows", last_user: "achen", agent_version: "1.326.600", first_seen: iso(2 * hr), last_seen: iso(95 * min), decided_by: "", decided_at: "1970-01-01T00:00:00Z" },
    { id: guid(2), name: "LT-4100", status: "approved", platform: "windows", last_user: "jsmith", agent_version: "1.326.600", first_seen: iso(9 * 24 * hr), last_seen: iso(25e3), decided_by: "admin", decided_at: iso(9 * 24 * hr) },
    { id: guid(3), name: "LT-4107", status: "approved", platform: "windows", last_user: "mgarcia", agent_version: "1.326.600", first_seen: iso(8 * 24 * hr), last_seen: iso(22 * min), decided_by: "helpdesk1", decided_at: iso(8 * 24 * hr) },
    { id: guid(4), name: "MAC-4149", status: "approved", platform: "macos", last_user: "tjohnson", agent_version: "1.326.600", first_seen: iso(6 * 24 * hr), last_seen: iso(3 * hr), decided_by: "admin", decided_at: iso(6 * 24 * hr) },
    { id: guid(5), name: "HOME-PC", status: "blocked", platform: "windows", last_user: "contractor2", agent_version: "1.326.465", first_seen: iso(20 * 24 * hr), last_seen: iso(12 * 24 * hr), decided_by: "admin", decided_at: iso(12 * 24 * hr) },
  ];
  const cert = (cn, ok, err) => ({ subject: "CN=" + cn, issuer: "CN=Contoso Issuing CA 01,DC=contoso,DC=com", thumbprint: "3F2A9C51D07E44B8A1C6E2F90B13D7A58C4E61F2", not_after: new Date(now + 300 * 24 * hr).toISOString(), ok, error: err });
  const trust = (o) => Object.assign({ checked_at: iso(20 * min), entra_device_id: "6f1c2e8a-93b4-4d7e-8a21-0c5b9e3f7d14", entra_proven: true, join_type: "Hybrid joined", join_source: "graph", compliant: true, managed: true, entra_enabled: true, os: "Windows 10.0.26100.2314", passed: true }, o);
  devices[0].trust = trust({ user: "nwhite", compliant: false });
  devices[1].trust = trust({ user: "achen", entra_proven: false, join_type: "Not joined", join_source: "agent", entra_device_id: "", compliant: undefined, managed: undefined, entra_enabled: undefined, os: "" });
  devices[0].trust.group = "Default";
  devices[2].trust = trust({ user: "jsmith", group: "IT staff", ad_domain: "corp.contoso.com", domain_proven: true, device_cert: cert("LT-4100.contoso.com", true) });
  devices[3].trust = trust({ user: "mgarcia", join_type: "Entra joined", device_cert: cert("LT-4107.contoso.com", true) });
  devices[4].trust = trust({ user: "tjohnson", join_type: "Registered", compliant: true, os: "macOS 15.1" });
  let trustPolicy = { cert_mode: "device", match_device_name: true, match_user: false,
    trusted_cas: "-----BEGIN CERTIFICATE-----\nMIIDdzCCAl+gAwIBAgIQK8h…(Contoso Issuing CA 01)\n-----END CERTIFICATE-----" };
  let backupServers = ["https://vpn2.contoso.com"];
  let duoSettings = { api_host: "api-1a2b3c4d.duosecurity.com", integration_key: "DIWJ8X6AEYOR5OMC6TQ1", has_secret: true, username_format: "prefix", ready: true };
  let groups = [
    { id: "it-admins", name: "IT staff", description: "Windows PCs with a device certificate", platforms: ["windows"],
      entra_groups: [{ id: "a1f0c3d2-3333-4c3e-9a7f-2d5e8b1c0f03", name: "VPN - IT" }], allow_microsoft: true, allow_local: false, mfa: "none", cert_mode: "device", domains: ["corp.contoso.com"], domain_proof: "certificate" },
    { id: "mac-users", name: "Mac users", description: "Not domain joined; Duo Push after sign-in", platforms: ["macos"],
      entra_groups: [], allow_microsoft: true, allow_local: false, mfa: "duo", cert_mode: "off" },
    { id: "contractors", name: "Contractors", description: "Own PCs; Duo Push, no device requirements", platforms: [],
      entra_groups: [{ id: "a1f0c3d2-2222-4c3e-9a7f-2d5e8b1c0f02", name: "VPN - Contractors" }], allow_microsoft: true, allow_local: false, mfa: "duo", cert_mode: "off" },
    { id: "default", name: "Default", description: "Everyone not matched by a group above.", platforms: [], entra_groups: [],
      allow_microsoft: true, allow_local: true, mfa: "none", cert_mode: "off" },
  ];
  // Groups and policies, as the migration would make them from the groups above.
  const sw = { on_sign_out: "disconnect", on_switch: "disconnect", same_user_session: "same", lock_minutes: 0, user_match: "allow", disconnect_by: "anyone" };
  const demoPol = { migrated: true,
    groups: [
      { id: "it-admins", name: "IT staff", kind: "users", description: "IT department", entra_groups: [{ id: "a1f0c3d2-3333-4c3e-9a7f-2d5e8b1c0f03", name: "VPN - IT" }], users: ["admin"], platforms: [], name_patterns: [] },
      { id: "mac-users", name: "Macs", kind: "devices", entra_groups: [], users: [], platforms: ["macos"], name_patterns: [] },
      { id: "contractors", name: "Contractors", kind: "users", entra_groups: [{ id: "a1f0c3d2-2222-4c3e-9a7f-2d5e8b1c0f02", name: "VPN - Contractors" }], users: [], platforms: [], name_patterns: [] },
      { id: "pilot", name: "Pilot PCs", kind: "devices", description: "IT laptops that get updates first", entra_groups: [], users: [], platforms: ["windows"], name_patterns: ["lt-41*", "it-lab-*"] },
    ],
    policies: [
      { id: "mac-users-signin", name: "Mac sign-in", type: "signin", groups: ["mac-users"], signin: { allow_microsoft: true, allow_local: false, mfa: "duo", cert_mode: "off" } },
      { id: "it-admins-signin", name: "IT sign-in", type: "signin", groups: ["it-admins"], signin: { allow_microsoft: true, allow_local: false, mfa: "none", cert_mode: "device" } },
      { id: "contractors-signin", name: "Contractor sign-in", type: "signin", groups: ["contractors"], signin: { allow_microsoft: true, allow_local: false, mfa: "duo", cert_mode: "off" } },
      { id: "default-signin", name: "Default sign-in", type: "signin", default: true, groups: ["all-users"], signin: { allow_microsoft: true, allow_local: true, mfa: "none", cert_mode: "off" } },
      { id: "contractors-windows", name: "Shared PCs", type: "windows", groups: ["contractors"], windows: Object.assign({}, sw, { on_switch: "block", lock_minutes: 15 }) },
      { id: "default-windows", name: "Default Windows sessions", type: "windows", default: true, groups: ["all-users"], windows: sw },
      { id: "pilot-updates", name: "Pilot ring", type: "updates", groups: ["pilot"], updates: { paused: false, rollout_percent: 100, install_when: "anytime", window_days: [1, 2, 3, 4, 5], window_start: "01:00", window_end: "05:00", deadline_days: 0, notify_users: true, max_postpones: 1 } },
      { id: "default-updates", name: "Default app updates", type: "updates", default: true, groups: ["all-devices"], updates: { paused: false, rollout_percent: 100, install_when: "window", window_days: [1, 2, 3, 4, 5], window_start: "01:00", window_end: "05:00", deadline_days: 7, notify_users: true, max_postpones: 3 } },
    ] };
  let officePolicy = { enabled: true, dns_suffixes: ["cb-sisco.com"], local_subnets: ["10.20.0.0/16", "10.21.0.0/16"], public_ips: ["203.0.113.10/32"] };
  let countryPolicy = { enabled: true, default: ["US"], block_unknown: false };
  let speedPolicy = { interval_hours: 24, size_mb: 25, host: "speed.cloudflare.com" };
  let speedCustom = false;
  const delay = (v) => new Promise((r) => setTimeout(() => r(JSON.parse(JSON.stringify(v))), 120));
  const fail = (msg) => new Promise((_, rej) => setTimeout(() => rej(new Error(msg)), 120));
  const me = users[0];

  const signIn = { local_enabled: true, entra_enabled: true, tenant_id: "8f2c1a4e-6b1d-4c3e-9a7f-2d5e8b1c0f33",
    client_id: "3b9e7d21-4a6c-4f8b-b2e1-9c7a5d3f1e08", has_secret: true, prompt_login: true };
  window.STDemo = {
    api(method, path, body) {
      const [p, qs] = path.split("?");
      const q = new URLSearchParams(qs || "");
      let m;
      if (p === "/me" || p === "/login") return delay(me);
      if (p === "/logout") return delay(null);
      if (p === "/auth-config") return delay({ local: true, entra: true });
      if (p === "/settings/servers") {
        if (method === "POST") backupServers = body.backups;
        return delay({ primary: "https://vpn.contoso.com", backups: backupServers });
      }
      if (p === "/policies") {
        if (method === "POST") { demoPol.groups = body.groups; demoPol.policies = body.policies; demoPol.migrated = false; }
        const builtIn = [{ id: "all-users", name: "All users", kind: "users", built_in: true, description: "Everyone who signs in." },
          { id: "all-devices", name: "All devices", kind: "devices", built_in: true, description: "Every PC and Mac." }];
        return delay({ groups: builtIn.concat(demoPol.groups), policies: demoPol.policies, migrated: demoPol.migrated, duo_ready: true, cas_ready: true,
          device_counts: { "all-devices": 128, "mac-users": 21, "pilot": 6 } });
      }
      if (p === "/policies/explain") {
        return delay([{ type: "signin", policy: "IT sign-in", policy_id: "it-admins-signin", group: "IT staff" },
          { type: "windows", policy: "Default Windows sessions", policy_id: "default-windows", group: "All users" },
          { type: "updates", policy: "Default app updates", policy_id: "default-updates", group: "All devices" }]);
      }
      if (p === "/entra/groups") {
        const all = [{ id: "a1f0c3d2-1111-4c3e-9a7f-2d5e8b1c0f01", name: "VPN - Mac users", description: "Macs (Duo MFA)" },
          { id: "a1f0c3d2-2222-4c3e-9a7f-2d5e8b1c0f02", name: "VPN - Contractors", description: "External staff" },
          { id: "a1f0c3d2-3333-4c3e-9a7f-2d5e8b1c0f03", name: "VPN - IT", description: "IT department" }];
        const qq = (q.get("q") || "").toLowerCase();
        return delay(all.filter((g) => g.name.toLowerCase().startsWith(qq) || g.name.toLowerCase().includes(qq)));
      }
      if (p === "/settings/duo") {
        if (method === "POST") duoSettings = { api_host: body.api_host, integration_key: body.integration_key, username_format: body.username_format, has_secret: true, ready: true };
        return delay(duoSettings);
      }
      if (p === "/settings/duo/test") return delay({ ok: true });
      if (p === "/settings/devicetrust") {
        if (method === "POST") trustPolicy = Object.assign({}, body);
        return delay(Object.assign({}, trustPolicy, { graph_status: "ok",
          cas: [{ subject: "CN=Contoso Issuing CA 01,DC=contoso,DC=com", not_after: new Date(now + 900 * 24 * hr).toISOString() },
            { subject: "CN=Contoso Root CA", not_after: new Date(now + 3200 * 24 * hr).toISOString() }] }));
      }
      if (p === "/settings/signin") {
        if (method === "POST") Object.assign(signIn, body, { has_secret: signIn.has_secret || !!body.client_secret });
        return delay(Object.assign({}, signIn, { scope: "api://" + signIn.client_id + "/access_as_user",
          admin_redirect_uri: "https://vpn.example.com/admin/auth/entra/callback", agent_redirect_uri: "http://localhost",
          roles: ["SecureTunnel.Admin", "SecureTunnel.Helpdesk"] }));
      }
      if (p === "/summary") {
        const live = sessions.filter((s) => s.state === "active" || s.state === "suspended");
        const client_versions = {};
        for (const s of live) { const v = s.client_version || s.platform; client_versions[v] = (client_versions[v] || 0) + 1; }
        return delay({
          client_versions, latest_client: "1.326.469", pending_devices: devices.filter((d) => d.status === "pending").length,
          active: live.filter((s) => s.state === "active").length, suspended: live.filter((s) => s.state === "suspended").length,
          connects_24h: hourly.reduce((a, b) => a + b, 0), gateways: gateways.length,
          gateways_healthy: gateways.filter((g) => g.enabled && g.healthy).length,
          hourly, hourly_end: new Date(Math.ceil(now / hr) * hr).toISOString(),
        });
      }
      if (p === "/sessions") {
        const st = q.get("state") || "", term = (q.get("q") || "").toLowerCase();
        return delay(sessions.filter((s) => {
          const live = s.state === "active" || s.state === "suspended";
          if ((st === "live" && !live) || (st === "ended" && live)) return false;
          return !term || s.upn.includes(term) || s.device_id.toLowerCase().includes(term) || s.tunnel_ip === term;
        }).sort((a, b) => Date.parse(b.last_seen) - Date.parse(a.last_seen)));
      }
      if ((m = p.match(/^\/sessions\/(.+)\/move$/))) {
        const s = sessions.find((x) => x.id === m[1]);
        if (s) { const others = gateways.filter((g) => g.enabled && g.id !== s.gateway_id); if (others.length) s.gateway_id = body.target || others[0].id; }
        return delay(null);
      }
      if ((m = p.match(/^\/gateways\/(.+)\/pool$/))) {
        // Rough stand-in for the server's checks (the real ones are in gwpool.go).
        const g = gateways.find((x) => x.id === m[1]);
        const pm = /^(\d+)\.(\d+)\.(\d+)\.(\d+)\/(\d+)$/.exec(body.pool || "");
        if (!pm) return Promise.reject(new Error('"' + body.pool + "\" isn't a range; write it like 10.200.0.0/21"));
        const other = gateways.find((x) => x.id !== g.id && x.pool.split(".").slice(0, 2).join(".") === pm[1] + "." + pm[2] && x.pool.split(".")[2] === pm[3]);
        if (other) return Promise.reject(new Error(body.pool + " overlaps " + other.id + "'s range (" + other.pool + "); each gateway needs its own"));
        const warnings = Number(pm[5]) > 21 ? [body.pool + " has room for " + (2 ** (32 - pm[5]) - 3) + " users, fewer than this gateway's limit of " + g.capacity + "; it fills up first."] : [];
        const connected = sessions.filter((s) => s.gateway_id === g.id && (s.state === "active" || s.state === "suspended")).length;
        if (body.check) return delay({ pool: body.pool, warnings, connected });
        if (connected && !body.end_remaining) return Promise.reject(Object.assign(new Error(connected + " sessions on " + g.id + " still use the current range. Drain the gateway first, or end them."), { code: "gateway_in_use" }));
        g.pool = body.pool;
        return delay({ pool: body.pool, warnings, ended: 0 });
      }
      if ((m = p.match(/^\/gateways\/(.+)\/drain$/))) {
        const g = gateways.find((x) => x.id === m[1]);
        g.enabled = false;
        const others = gateways.filter((x) => x.enabled);
        let n = 0;
        sessions.forEach((s) => { if (s.gateway_id === g.id && (s.state === "active" || s.state === "suspended") && others.length) { s.gateway_id = others[0].id; n++; } });
        return delay({ moving: n, cannot_move: 0 });
      }
      if ((m = p.match(/^\/sessions\/(.+)\/command$/))) {
        return delay({ id: "cmd-demo", type: body.type, text: body.text || "", from: me.username, at: new Date().toISOString() });
      }
      if ((m = p.match(/^\/sessions\/(.+)\/disconnect$/))) {
        const s = sessions.find((x) => x.id === m[1]);
        if (!s) return fail("session already ended");
        s.state = "terminated"; s.end_reason = "admin_disconnect"; s.ended_at = new Date().toISOString();
        add(0, me.username, "admin.disconnect", s.id, "disconnected " + s.upn);
        audit.sort((a, b) => Date.parse(b.at) - Date.parse(a.at));
        return delay(null);
      }
      if (p === "/gateways") { decorate(); return delay(gateways); }
      if (p === "/settings/placement") {
        if (method === "POST") {
          if (!(body.max_cpu_percent >= 1 && body.max_cpu_percent <= 100)) return fail("CPU limit must be between 1 and 100%");
          policy = body; customPolicy = true;
        }
        return delay({ policy, defaults, custom: customPolicy });
      }
      if (p === "/system") return delay({
        hosts, db_size: 48.3 * 1024 * 1024,
        lb: { frontend: "control", current: 412, total: 1843120, rate: 9, servers: [
          { name: "control-a", backup: false, status: "UP", check: "L7OK", check_ms: 3, current: 412, total: 1798004, checks_failed: 2, down_sec: 9, changed_sec: 187340, serving: true },
          { name: "control-b", backup: true, status: "UP", check: "L7OK", check_ms: 2, current: 0, total: 45116, checks_failed: 0, down_sec: 0, changed_sec: 187352, serving: false }] },
        db: { version: "16.4", started_at: new Date(Date.now() - 9 * 864e5).toISOString(), size_bytes: 48.3 * 1024 * 1024, connections: 14, max_connections: 100,
          pool_open: 6, pool_busy: 1, pool_max: 8, cache_hit_percent: 99.8, commits: 4812201, rollbacks: 312, deadlocks: 0, ping_ms: 0.4,
          users: 1512, devices: 1688, active_sessions: 1147, audit_rows: 98213 },
      });
      if (p === "/updates") {
        const live = sessions.filter((s) => s.state === "active" && s.client_version);
        const connected = live.map((s, i) => ({ session_id: s.id, user: s.upn, pc: s.device_name || s.device_id, platform: "windows", version: s.client_version,
          outdated: s.client_version !== "1.326.469", update: demoUpd.pushed[s.id] || (s.client_version !== "1.326.469" ? (i % 3 ? "ready" : "downloading") : "up_to_date"),
          update_at: demoUpd.at[s.id] || "", postponed: i === 2 ? 1 : 0 }));
        const names = {}; demoPol.groups.forEach((g) => (names[g.id] = g.name)); names["all-devices"] = "All devices";
        const policies = demoPol.policies.filter((x) => x.type === "updates").map((x) => Object.assign({}, x, { group_names: x.groups.map((g) => names[g]), pcs: x.default ? 122 : 6 }));
        return delay({ latest: "1.326.469", policies, devices: 128, outdated_devices: 31, connected,
          versions: [{ version: "1.326.469", pcs: 97, current: true }, { version: "1.326.465", pcs: 26 }, { version: "1.326.401", pcs: 5 }] });
      }
      if (p === "/updates/push") {
        const ids = body.target === "pcs" ? body.sessions : sessions.filter((s) => s.state === "active" && s.client_version && s.client_version !== "1.326.469").map((s) => s.id);
        ids.forEach((id) => { demoUpd.pushed[id] = body.when === "immediate" ? "installing" : body.when === "now" ? "installing_soon" : body.when === "at" ? "scheduled" : "ready"; if (body.at) demoUpd.at[id] = body.at; });
        return delay({ sent: ids.length, skipped: 0 });
      }
      if (p === "/devices") {
        const st = q.get("status") || "";
        const live = new Set(sessions.filter((s) => s.state === "active").map((s) => s.device_id));
        return delay(devices.filter((d) => !st || d.status === st).map((d) => Object.assign({}, d, { connected: live.has(d.id) || live.has(d.name) }))); // demo sessions use the computer name as their device ID
      }
      if (p === "/settings/devices") {
        if (method === "POST") devicePolicy = Object.assign({}, body);
        return delay(devicePolicy);
      }
      if (p === "/devices/approve-pending") {
        let n = 0;
        devices.forEach((d) => { if (d.status === "pending") { d.status = "approved"; d.decided_by = me.username; d.decided_at = new Date().toISOString(); n++; } });
        return delay({ approved: n });
      }
      if ((m = p.match(/^\/devices\/([^/]+)\/status$/))) {
        const d = devices.find((x) => x.id === decodeURIComponent(m[1]));
        Object.assign(d, { status: body.status, decided_by: me.username, decided_at: new Date().toISOString() });
        return delay(null);
      }
      if ((m = p.match(/^\/devices\/([^/]+)$/)) && method === "DELETE") {
        devices = devices.filter((x) => x.id !== decodeURIComponent(m[1]));
        return delay(null);
      }
      if (p === "/settings/office") {
        if (method === "POST") officePolicy = Object.assign({}, body);
        return delay(officePolicy);
      }
      if (p === "/settings/countries") {
        if (method === "POST") countryPolicy = Object.assign({}, body, { default: body.default.map((c) => c.toUpperCase()) });
        return delay(countryPolicy);
      }
      if (p === "/settings/speedtest") {
        if (method === "POST") { speedPolicy = body; speedCustom = true; }
        return delay({ policy: speedPolicy, defaults: { interval_hours: 24, size_mb: 25, host: "speed.cloudflare.com" }, custom: speedCustom });
      }
      if (p === "/logs") {
        return delay([{ id: "a1", ref: "K7Q-4P2", reason: "user", verified: false, size: 412000, at: iso(12 * min), upn: "nwhite@contoso.com" },
          { id: "a2", ref: "M3D-9XT", reason: "admin", verified: true, size: 388000, at: iso(26 * hr), upn: "nwhite@contoso.com" }]);
      }
      if (p === "/speedtests") {
        return delay([
          { kind: "vpn", down_bps: 142e6, up_bps: 38e6, latency_ms: 31, network: "Wi-Fi HomeNet", auto: false, at: iso(4 * min) },
          { kind: "internet", down_bps: 212e6, up_bps: 41e6, latency_ms: 12, network: "Wi-Fi HomeNet", auto: false, at: iso(4 * min) },
          { kind: "vpn", down_bps: 118e6, up_bps: 35e6, latency_ms: 35, network: "Wi-Fi HomeNet", auto: true, at: iso(26 * hr) },
          { kind: "internet", down_bps: 198e6, up_bps: 40e6, latency_ms: 14, network: "Wi-Fi HomeNet", auto: true, at: iso(26 * hr) },
        ]);
      }
      if ((m = p.match(/^\/gateways\/(.+)\/enabled$/))) {
        const g = gateways.find((x) => x.id === m[1]);
        g.enabled = body.enabled;
        return delay(null);
      }
      if (p === "/audit") return delay(audit.slice(0, Number(q.get("limit")) || 500));
      if (p === "/users" && method === "GET") return delay(users);
      if (p === "/users" && method === "POST") {
        if (users.some((u) => u.username === body.username)) return fail("that username is taken");
        if (body.source === "entra") {
          users.push({ username: body.username, display_name: body.display_name, role: "user", source: "entra", disabled: false, mfa: false, created_at: new Date().toISOString(), last_login: "0001-01-01T00:00:00Z" });
          return delay(null);
        }
        if ((body.password || "").length < 12) return fail("password must be at least 12 characters");
        users.push({ username: body.username, display_name: body.display_name, role: body.role, disabled: false, mfa: false, created_at: new Date().toISOString(), last_login: "0001-01-01T00:00:00Z" });
        return delay(null);
      }
      if ((m = p.match(/^\/users\/([^/]+)\/totp$/))) {
        const u = users.find((x) => x.username === m[1]);
        if (method === "DELETE") { u.mfa = false; return delay(null); }
        u.mfa = true;
        return delay({ secret: "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP", uri: "otpauth://totp/SecureTunnel:" + u.username + "?secret=JBSWY3DPEHPK3PXP&issuer=SecureTunnel" });
      }
      if ((m = p.match(/^\/users\/([^/]+)$/))) {
        const i = users.findIndex((x) => x.username === m[1]);
        if (method === "DELETE") { users.splice(i, 1); return delay(null); }
        if (body.password !== undefined && body.password.length < 12) return fail("password must be at least 12 characters");
        Object.assign(users[i], body.display_name !== undefined ? { display_name: body.display_name } : {},
          body.role ? { role: body.role } : {}, body.disabled !== undefined ? { disabled: body.disabled } : {},
          body.allowed_countries ? { allowed_countries: body.allowed_countries } : {},
          body.travel_countries ? { travel_countries: body.travel_countries } : {},
          body.travel_until !== undefined ? { travel_until: body.travel_until ? body.travel_until + "T23:59:59Z" : "" } : {});
        return delay(null);
      }
      return fail("demo: no handler for " + method + " " + path);
    },
  };
})();

