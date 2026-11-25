// SecureTunnel admin: Groups and Policies pages.
//
// Groups are who or what (users by Entra group or picked by hand; devices by
// computer name or platform). Policies are named settings of one type,
// assigned to groups. Per type, the first policy whose groups include the user
// or PC applies; each type ends with a Default. Everything is saved together
// (POST /policies) and the server checks it.
"use strict";

const PLAT = { windows: "Windows", macos: "Mac" };
const CERT = { off: "", device: "Device certificate", user: "User certificate", either: "Device or user certificate", both: "Device and user certificates" };
const WIN_DEFAULTS = { on_sign_out: "disconnect", on_switch: "disconnect", same_user_session: "same", lock_minutes: 0, user_match: "allow", disconnect_by: "anyone" };
const POLICY_TYPES = {
  signin: { title: "Sign-in", icon: "lock", what: "How people sign in: Microsoft and/or local accounts, an extra Duo step, and whether their PC needs a certificate.", for: "users" },
  windows: { title: "Windows sessions", icon: "monitor", what: "What the Windows app does when users sign out, switch user or lock the screen.", for: "users" },
  countries: { title: "Countries", icon: "globe", what: "Which countries users may connect from.", for: "users" },
  updates: { title: "App updates", icon: "download", what: "When PCs install app updates: pause, staged rollout, maintenance window, deadline. Decided per PC, so use device groups.", for: "devices" },
  approval: { title: "Device approval", icon: "shield", what: "Whether new PCs need an admin's approval before they can connect.", for: "devices" },
  office: { title: "Office networks", icon: "home", what: "How PCs tell they're in the office, where the VPN stays off.", for: "devices" },
  speedtest: { title: "Speed tests", icon: "zap", what: "How often PCs run a speed test, and how big.", for: "devices" },
};
const DAY_NAMES = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"];

const pol = () => state.pol || { groups: [], policies: [] };
const groupByID = (id) => pol().groups.find((g) => g.id === id);
const slug = (s) => (s.toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "").slice(0, 40) || "item");
function uniqueID(base, taken) {
  let id = base, n = 2;
  while (taken.includes(id)) id = base + "-" + n++;
  return id;
}

// ---- summaries ----
function winBadges(w) {
  w = Object.assign({}, WIN_DEFAULTS, w || {});
  const b = [];
  if (w.on_sign_out === "stay") b.push(badge("Stays on after sign-out", "warn plain"));
  if (w.on_sign_out === "device_tunnel") b.push(badge("Device tunnel after sign-out", "info plain"));
  if (w.on_switch === "share") b.push(badge("Shared between users", "warn plain"));
  if (w.on_switch === "block") b.push(badge("Other users blocked", "info plain"));
  if (w.same_user_session === "different") b.push(badge("2nd session = other user", "neutral plain"));
  if (w.lock_minutes > 0) b.push(badge("Off after " + (w.lock_minutes >= 60 ? w.lock_minutes / 60 + " h" : w.lock_minutes + " min") + " locked", "neutral plain"));
  if (w.user_match === "warn") b.push(badge("Flags user mismatch", "neutral plain"));
  if (w.user_match === "block") b.push(badge("Windows user must match", "ok plain"));
  if (w.disconnect_by === "owner") b.push(badge("Owner-only disconnect", "neutral plain"));
  return b.length ? b : [el("span", { class: "muted" }, "Disconnect on sign-out or user switch")];
}
function signinBadges(s) {
  const b = [];
  if (s.allow_microsoft) b.push(badge("Microsoft", "ok plain"));
  if (s.allow_local) b.push(badge("Local account", "neutral plain"));
  if (s.mfa === "duo") b.push(badge("+ Duo Push", pol().duo_ready ? "warn" : "bad"));
  if (s.cert_mode && s.cert_mode !== "off") b.push(badge(CERT[s.cert_mode], "ok plain"));
  return b;
}
function updateSummary(u) {
  if (!u) return "";
  if (u.paused) return "Paused: no new versions offered (pushes still work)";
  const when = { disconnected: "Installs when disconnected", window: "Maintenance window " + u.window_days.map((d) => DAY_NAMES[d]).join(", ") + " " + u.window_start + "–" + u.window_end,
    anytime: "Installs as soon as ready (2-minute warning)" }[u.install_when] || "";
  const bits = [when];
  if (u.rollout_percent < 100) bits.push(u.rollout_percent + "% rollout");
  if (u.deadline_days) bits.push("deadline " + u.deadline_days + " day" + (u.deadline_days === 1 ? "" : "s"));
  bits.push(u.max_postpones ? "up to " + u.max_postpones + " postpone" + (u.max_postpones === 1 ? "" : "s") : "no postponing");
  return bits.join(" · ");
}
function settingsSummary(p) {
  if (p.type === "signin") return el("div", { class: "cc" }, ...signinBadges(p.signin));
  if (p.type === "windows") return el("div", { class: "cc" }, ...winBadges(p.windows));
  const sub = (t) => el("div", { class: "sub" }, t);
  if (p.type === "countries") { const c = p.countries || {}; return sub(!c.enabled ? "Any country" : ((c.default || []).map(countryName).join(", ") || "No countries") + (c.block_unknown ? " · unknown blocked" : "")); }
  if (p.type === "approval") return sub(p.approval && p.approval.require_approval ? "New devices need approval" : "New devices approved automatically");
  if (p.type === "office") { const o = p.office || {}; const n = (o.dns_suffixes || []).length + (o.local_subnets || []).length + (o.public_ips || []).length; return sub(o.enabled ? n + " office network rule" + (n === 1 ? "" : "s") : "Off"); }
  if (p.type === "speedtest") { const s = p.speedtest || {}; return sub((s.interval_hours ? "Every " + s.interval_hours + " h" : "On demand only") + " · " + (s.size_mb || 0) + " MB"); }
  return sub(updateSummary(p.updates));
}
function groupRules(g) {
  const out = [];
  if (g.built_in) out.push(el("span", { class: "muted" }, g.description));
  (g.entra_groups || []).forEach((e) => out.push(badge(e.name || e.id, "info plain")));
  if ((g.users || []).length) out.push(el("span", { class: "sub" }, g.users.length + " user" + (g.users.length === 1 ? "" : "s") + " picked"));
  (g.name_patterns || []).forEach((n) => out.push(el("span", { class: "chip mono plain-chip" }, n)));
  (g.platforms || []).forEach((p) => out.push(badge(PLAT[p] || p, "neutral plain")));
  return out;
}
function usedBy(gid) { return pol().policies.filter((p) => (p.groups || []).includes(gid)); }

// ---- the Groups page ----
function migratedBanner(id) {
  $(id).classList.toggle("hidden", !pol().migrated);
  $(id).textContent = "These groups and policies were made from your earlier policy groups and update settings. Everything works as before until you change something.";
}
function drawGroupsPage() {
  migratedBanner("xg-migrated");
  $("xg-add").classList.toggle("hidden", !isAdmin());
  const counts = pol().device_counts || {};
  $("xg-list").replaceChildren(...pol().groups.map((g) => {
    const uses = usedBy(g.id);
    const devN = counts[g.id];
    return el("div", { class: "card xg-card" },
      el("div", { class: "g-top" },
        el("div", { class: "kpi-icon " + (g.kind === "devices" ? "info" : "") }, icon(g.kind === "devices" ? "monitor" : "users")),
        el("div", { class: "grow" },
          el("div", { class: "strong" }, g.name, " ", badge(g.kind === "devices" ? "Devices" : "Users", "neutral plain"), g.built_in ? badge("Built in", "neutral plain") : null),
          g.description && !g.built_in ? el("div", { class: "sub" }, g.description) : null),
        isAdmin() && !g.built_in ? el("button", { class: "btn sm", onclick: () => openXGroup(g) }, icon("edit"), "Edit") : null),
      el("div", { class: "g-rows" },
        el("span", {}, "Members"), el("div", { class: "cc" }, ...groupRules(g), devN !== undefined ? el("span", { class: "sub" }, "· " + devN + " PC" + (devN === 1 ? "" : "s") + " now") : null),
        el("span", {}, "Policies"), el("div", { class: "cc" }, ...(uses.length ? uses.map((p) => badge(POLICY_TYPES[p.type].title + ": " + p.name, "info plain")) : [el("span", { class: "muted" }, "Not assigned to any policy yet")]))));
  }));
}

// ---- group editor ----
let editingGroup = null, groupChips = [];
function setXgKind(kind) {
  document.querySelectorAll("#xg-kind button").forEach((b) => b.classList.toggle("on", b.dataset.kind === kind));
  $("xg-users").classList.toggle("hidden", kind !== "users");
  $("xg-devices").classList.toggle("hidden", kind !== "devices");
  $("xg-plat-hint").textContent = kind === "users" ? "(only when signing in on these; none ticked = any)" : "(none ticked = any)";
}
document.querySelectorAll("#xg-kind button").forEach((b) => b.addEventListener("click", () => setXgKind(b.dataset.kind)));
const xgKind = () => (document.querySelector("#xg-kind button.on") || {}).dataset.kind || "users";
function drawGroupChips() {
  $("g-chips").replaceChildren(...groupChips.map((e) => el("span", { class: "chip", title: e.id }, e.name || e.id,
    el("button", { type: "button", "aria-label": "Remove " + (e.name || e.id), onclick: () => { groupChips = groupChips.filter((x) => x.id !== e.id); drawGroupChips(); } }, icon("x")))));
}
function openXGroup(g) {
  editingGroup = g;
  $("f-xgroup-title").textContent = g ? "Edit " + g.name : "Add group";
  $("xg-name").value = g ? g.name : "";
  $("xg-desc").value = g ? g.description || "" : "";
  setXgKind(g ? g.kind : "users");
  groupChips = g ? (g.entra_groups || []).slice() : [];
  drawGroupChips();
  $("g-search").value = "";
  $("g-results").classList.add("hidden");
  $("xg-userlist").value = g ? (g.users || []).join("\n") : "";
  $("xg-names").value = g ? (g.name_patterns || []).join("\n") : "";
  $("g-win").checked = !!(g && (g.platforms || []).includes("windows"));
  $("g-mac").checked = !!(g && (g.platforms || []).includes("macos"));
  $("xg-delete").classList.toggle("hidden", !g);
  $("xg-hint").textContent = g && usedBy(g.id).length ? "Used by " + usedBy(g.id).map((p) => p.name).join(", ") + "." : "";
  $("xg-error").textContent = "";
  $("dlg-xgroup").showModal();
  $("xg-name").focus();
}
$("xg-add").addEventListener("click", () => openXGroup(null));
async function savePolicySet(set, okMsg, errBox) {
  try {
    state.pol = await api("POST", "/policies", { groups: set.groups.filter((g) => !g.built_in), policies: set.policies });
    toast(okMsg);
    if (currentView() === "groups") drawGroupsPage();
    if (currentView() === "policies") drawPoliciesPage();
    if (currentView() === "updates") render();
    return true;
  } catch (e) { (errBox || {}).textContent = e.message; if (!errBox) failed(e); return false; }
}
$("f-xgroup").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("xg-error").textContent = "";
  const kind = xgKind();
  const lines = (id) => $(id).value.split(/[\n,;]+/).map((x) => x.trim()).filter(Boolean);
  const g = Object.assign({}, editingGroup || {}, {
    name: $("xg-name").value.trim(), description: $("xg-desc").value.trim(), kind,
    entra_groups: kind === "users" ? groupChips : [], users: kind === "users" ? lines("xg-userlist") : [],
    name_patterns: kind === "devices" ? lines("xg-names") : [],
    platforms: [$("g-win").checked ? "windows" : "", $("g-mac").checked ? "macos" : ""].filter(Boolean),
  });
  const set = JSON.parse(JSON.stringify(pol()));
  if (editingGroup) set.groups[set.groups.findIndex((x) => x.id === editingGroup.id)] = g;
  else { g.id = uniqueID(slug(g.name), set.groups.map((x) => x.id)); set.groups.push(g); }
  if (await savePolicySet(set, "Saved " + g.name, $("xg-error"))) $("dlg-xgroup").close();
});
$("xg-delete").addEventListener("click", async () => {
  const g = editingGroup, uses = usedBy(g.id);
  $("dlg-xgroup").close();
  if (!(await confirmDialog("Delete " + g.name + "?", uses.length
    ? "It's assigned to " + uses.map((p) => p.name).join(", ") + ". Those policies stop applying to its members (they'll get the next matching policy, or the Default)."
    : "Nothing uses it.", "Delete group"))) return;
  const set = JSON.parse(JSON.stringify(pol()));
  set.groups = set.groups.filter((x) => x.id !== g.id);
  set.policies.forEach((p) => { if (!p.default) p.groups = (p.groups || []).filter((x) => x !== g.id); });
  savePolicySet(set, "Deleted " + g.name);
});
// Entra group search (type a name, or paste an object ID).
const GUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
function addGroupChip(e) {
  if (!groupChips.some((x) => x.id === e.id)) groupChips.push(e);
  drawGroupChips();
  $("g-search").value = "";
  $("g-results").classList.add("hidden");
}
let gTimer;
$("g-search").addEventListener("input", () => {
  clearTimeout(gTimer);
  const q = $("g-search").value.trim(), box = $("g-results");
  if (!q) { box.classList.add("hidden"); return; }
  if (GUID.test(q)) {
    box.replaceChildren(el("button", { type: "button", onclick: () => addGroupChip({ id: q.toLowerCase(), name: "" }) }, "Add group ID " + q));
    box.classList.remove("hidden");
    return;
  }
  gTimer = setTimeout(async () => {
    box.replaceChildren(el("div", { class: "msg" }, "Searching…"));
    box.classList.remove("hidden");
    try {
      const list = await api("GET", "/entra/groups?q=" + encodeURIComponent(q));
      box.replaceChildren(...(list.length ? list.map((x) => el("button", { type: "button", onclick: () => addGroupChip({ id: x.id, name: x.name }) },
        x.name, el("div", { class: "sub" }, x.description || x.id))) : [el("div", { class: "msg" }, "No security groups start with \"" + q + "\".")]));
    } catch (e) {
      box.replaceChildren(el("div", { class: "msg" }, "Can't search Entra (" + e.message + "). Paste the group's object ID instead."));
    }
  }, 300);
});
$("g-search").addEventListener("keydown", (e) => { if (e.key === "Enter") e.preventDefault(); });

// ---- the Policies page ----
function drawPoliciesPage() {
  const admin = isAdmin();
  const banner = el("div", { class: "banner" + (pol().migrated ? "" : " hidden") },
    "These groups and policies were made from your earlier policy groups and update settings. Everything works as before until you change something.");
  $("pol-sections").replaceChildren(banner, ...Object.keys(POLICY_TYPES).map((type) => {
    const t = POLICY_TYPES[type];
    const list = pol().policies.filter((p) => p.type === type);
    return el("section", { class: "sys-sec" },
      el("div", { class: "sys-sec-head" }, el("div", { class: "kpi-icon" }, icon(t.icon)),
        el("div", { class: "grow" }, el("h2", {}, t.title + " policies", el("span", { class: "count" }, String(list.length))), el("p", { class: "muted small" }, t.what)),
        admin ? el("button", { class: "btn sm", onclick: () => openPolicy(type, null) }, icon("plus"), "Add") : null),
      el("div", { class: "pol-list" }, ...list.map((p, i) => el("div", { class: "card pol-card" + (p.default ? " default" : "") },
        el("div", { class: "pol-num" }, p.default ? "–" : String(i + 1)),
        el("div", { class: "grow" },
          el("div", { class: "strong" }, p.name, p.default ? el("span", { class: "sub" }, "  applies when nothing above does") : null),
          p.description ? el("div", { class: "sub" }, p.description) : null,
          el("div", { class: "cc pol-assign" }, el("span", { class: "sub" }, "Assigned to"), ...(p.groups || []).map((gid) => {
            const g = groupByID(gid);
            return badge(g ? g.name : gid, (g && g.kind === "devices" ? "neutral" : "info") + " plain");
          }), (p.groups || []).length ? null : badge("No groups: applies to nobody", "warn plain")),
          settingsSummary(p)),
        admin ? el("div", { class: "g-actions" },
          p.default ? null : el("button", { class: "icon-btn", title: "Higher priority", "aria-label": "Move " + p.name + " up", disabled: i === 0 || null, onclick: () => movePolicy(p, -1) }, icon("chevron-up")),
          p.default ? null : el("button", { class: "icon-btn", title: "Lower priority", "aria-label": "Move " + p.name + " down", disabled: i >= list.length - 2 || null, onclick: () => movePolicy(p, 1) }, icon("chevron-down")),
          el("button", { class: "btn sm", onclick: () => openPolicy(type, p) }, icon("edit"), "Edit")) : null))));
  }));
}
function movePolicy(p, dir) {
  const set = JSON.parse(JSON.stringify(pol()));
  const same = set.policies.filter((x) => x.type === p.type && !x.default);
  const i = same.findIndex((x) => x.id === p.id), j = i + dir;
  if (j < 0 || j >= same.length) return;
  [same[i], same[j]] = [same[j], same[i]];
  // Rebuild the list: this type's policies in the new order, others unchanged.
  const def = set.policies.find((x) => x.type === p.type && x.default);
  const out = [];
  for (const t of Object.keys(POLICY_TYPES)) {
    if (t === p.type) out.push(...same, def);
    else out.push(...set.policies.filter((x) => x.type === t));
  }
  set.policies = out.filter(Boolean);
  savePolicySet(set, "Priority changed");
}
function editPolicyByID(id) {
  const p = pol().policies.find((x) => x.id === id);
  const go = () => openPolicy(p.type, pol().policies.find((x) => x.id === id));
  if (p) return go();
  api("GET", "/policies").then((r) => { state.pol = r; const q = r.policies.find((x) => x.id === id); if (q) openPolicy(q.type, q); });
}

// ---- policy editor ----
let editingPolicy = null, editingType = "signin";
(function dayPicks() {
  $("up-days").replaceChildren(...DAY_NAMES.map((d, i) => el("label", { class: "day" }, el("input", { type: "checkbox", value: String(i) }), el("span", {}, d))));
})();
document.querySelectorAll('input[name="up-when"]').forEach((r) => r.addEventListener("change", () => $("up-window").classList.toggle("hidden", radioVal("up-when") !== "window")));
$("up-auto").addEventListener("change", () => { $("up-auto-label").textContent = $("up-auto").checked ? "Automatic updates" : "Paused"; });
function drawWinHint() {
  const notes = [];
  if ($("gw-signout").value === "device_tunnel") notes.push("Switching to the device tunnel needs the device tunnel turned on; until then the VPN disconnects.");
  if ($("gw-switch").value === "share") notes.push("Sharing lets the next Windows user use the first user's VPN identity and access.");
  if ($("gw-match").value === "block") notes.push("Blocking works where Windows accounts match Entra accounts (Entra or hybrid joined PCs).");
  $("gw-hint").textContent = notes.join(" ");
}
for (const id of ["gw-signout", "gw-switch", "gw-match"]) $(id).addEventListener("change", drawWinHint);
const pickOpt = (id, v) => { const s = $(id); if (![...s.options].some((o) => o.value === String(v))) s.append(new Option(String(v), String(v))); s.value = String(v); };

function openPolicy(type, p) {
  editingType = type;
  editingPolicy = p;
  const t = POLICY_TYPES[type];
  $("f-policy-title").textContent = (p ? "Edit " : "Add ") + t.title.toLowerCase() + " policy";
  $("p-name").value = p ? p.name : "";
  $("p-desc").value = p ? p.description || "" : "";
  $("p-name").disabled = false;
  // Assigned groups: users groups first for user policies, device groups for device ones.
  const assigned = new Set(p ? p.groups || [] : []);
  const groups = pol().groups.slice().sort((a, b) => (a.kind === t.for ? 0 : 1) - (b.kind === t.for ? 0 : 1));
  $("p-assign").replaceChildren(...groups.map((g) => el("label", { class: "check assign" + (g.kind !== t.for ? " other" : "") },
    el("input", { type: "checkbox", value: g.id, checked: assigned.has(g.id) || null, disabled: (p && p.default) || null }),
    el("span", {}, g.name), el("span", { class: "sub" }, g.kind === "devices" ? "devices" : "users"))));
  $("p-assign-hint").textContent = p && p.default ? "The Default always applies to " + (t.for === "devices" ? "All devices" : "All users") + " that no policy above matched."
    : t.for === "devices" ? "Decided per PC (even with nobody signed in), so pick device groups; user groups don't apply here."
    : "Device groups work too: they apply when the user signs in on one of those PCs.";
  // Hidden sections' fields are disabled so their "required" checks can't block saving.
  for (const k of Object.keys(POLICY_TYPES)) {
    $("ps-" + k).classList.toggle("hidden", k !== type);
    $("ps-" + k).querySelectorAll("input, select, textarea").forEach((f) => (f.disabled = k !== type));
  }
  const info = pol();
  if (type === "signin") {
    const s = p ? p.signin : { allow_microsoft: true, allow_local: false, mfa: "none", cert_mode: "off" };
    $("g-ms").checked = s.allow_microsoft; $("g-local").checked = s.allow_local;
    $("g-mfa").value = s.mfa || "none"; $("g-cert").value = s.cert_mode || "off";
    $("g-mfa-hint").textContent = info.duo_ready ? "" : "Set up Duo under Settings → Duo before using it.";
    $("g-cert-hint").textContent = info.cas_ready ? "Checked against the CAs under Settings → Certificates." : "Add your issuing CA under Settings → Certificates first.";
  } else if (type === "windows") {
    const w = Object.assign({}, WIN_DEFAULTS, p ? p.windows : {});
    $("gw-signout").value = w.on_sign_out; $("gw-switch").value = w.on_switch; $("gw-same").value = w.same_user_session;
    pickOpt("gw-lock", w.lock_minutes); $("gw-match").value = w.user_match; $("gw-disc").value = w.disconnect_by;
    drawWinHint();
  } else if (type === "countries") {
    const c = (p && p.countries) || { enabled: false, default: ["US"], block_unknown: false };
    $("pc-enabled").checked = c.enabled; $("pc-unknown").checked = c.block_unknown;
    $("pc-list").value = (c.default || []).join(", ");
    namesHint($("pc-list"), $("pc-hint"));
  } else if (type === "approval") {
    $("pa-require").checked = !!(p && p.approval && p.approval.require_approval);
  } else if (type === "office") {
    const o = (p && p.office) || {};
    $("po-enabled").checked = !!o.enabled;
    $("po-dns").value = (o.dns_suffixes || []).join("\n"); $("po-subnets").value = (o.local_subnets || []).join("\n"); $("po-ips").value = (o.public_ips || []).join("\n");
  } else if (type === "speedtest") {
    const s = (p && p.speedtest) || { interval_hours: 0, size_mb: 25, host: "" };
    pickOpt("pt-interval", s.interval_hours); pickOpt("pt-size", s.size_mb); $("pt-host").value = s.host || "";
  } else {
    const u = p ? p.updates : { paused: false, rollout_percent: 100, install_when: "disconnected", window_days: [1, 2, 3, 4, 5], window_start: "01:00", window_end: "05:00", deadline_days: 0, notify_users: true, max_postpones: 3 };
    $("up-auto").checked = !u.paused;
    $("up-auto-label").textContent = u.paused ? "Paused" : "Automatic updates";
    setRadio("up-when", u.install_when);
    document.querySelectorAll("#up-days input").forEach((c) => (c.checked = (u.window_days || []).includes(Number(c.value))));
    $("up-start").value = u.window_start; $("up-end").value = u.window_end;
    pickOpt("up-rollout", u.rollout_percent); pickOpt("up-deadline", u.deadline_days); pickOpt("up-postpones", u.max_postpones);
    $("up-notify").checked = u.notify_users;
    $("up-window").classList.toggle("hidden", u.install_when !== "window");
  }
  $("p-delete").classList.toggle("hidden", !p || p.default);
  $("p-error").textContent = "";
  $("dlg-policy").showModal();
  $("p-name").focus();
}
function readPolicySettings(type) {
  if (type === "signin") return { signin: { allow_microsoft: $("g-ms").checked, allow_local: $("g-local").checked, mfa: $("g-mfa").value, cert_mode: $("g-cert").value } };
  if (type === "windows") return { windows: { on_sign_out: $("gw-signout").value, on_switch: $("gw-switch").value, same_user_session: $("gw-same").value,
    lock_minutes: Number($("gw-lock").value), user_match: $("gw-match").value, disconnect_by: $("gw-disc").value } };
  if (type === "countries") return { countries: { enabled: $("pc-enabled").checked, default: parseCodes($("pc-list").value), block_unknown: $("pc-unknown").checked } };
  if (type === "approval") return { approval: { require_approval: $("pa-require").checked } };
  if (type === "office") return { office: { enabled: $("po-enabled").checked, dns_suffixes: lines($("po-dns").value), local_subnets: lines($("po-subnets").value), public_ips: lines($("po-ips").value) } };
  if (type === "speedtest") return { speedtest: { interval_hours: Number($("pt-interval").value), size_mb: Number($("pt-size").value), host: $("pt-host").value.trim() } };
  return { updates: { paused: !$("up-auto").checked, rollout_percent: Number($("up-rollout").value), install_when: radioVal("up-when"),
    window_days: [...document.querySelectorAll("#up-days input:checked")].map((c) => Number(c.value)),
    window_start: $("up-start").value, window_end: $("up-end").value,
    deadline_days: Number($("up-deadline").value), max_postpones: Number($("up-postpones").value), notify_users: $("up-notify").checked } };
}
$("f-policy").addEventListener("submit", async (ev) => {
  ev.preventDefault();
  $("p-error").textContent = "";
  const type = editingType;
  const p = Object.assign({}, editingPolicy || {}, { type, name: $("p-name").value.trim(), description: $("p-desc").value.trim() }, readPolicySettings(type));
  if (!(editingPolicy && editingPolicy.default)) p.groups = [...document.querySelectorAll("#p-assign input:checked")].map((c) => c.value);
  const set = JSON.parse(JSON.stringify(pol()));
  if (editingPolicy) {
    set.policies[set.policies.findIndex((x) => x.id === editingPolicy.id)] = p;
  } else {
    p.id = uniqueID(slug(p.name), set.policies.map((x) => x.id));
    const at = set.policies.findIndex((x) => x.type === type && x.default); // new ones go just above the Default
    set.policies.splice(at < 0 ? set.policies.length : at, 0, p);
  }
  if (await savePolicySet(set, "Saved " + p.name, $("p-error"))) $("dlg-policy").close();
});
$("p-delete").addEventListener("click", async () => {
  const p = editingPolicy;
  $("dlg-policy").close();
  if (!(await confirmDialog("Delete " + p.name + "?", "Its groups get the next matching " + POLICY_TYPES[p.type].title.toLowerCase() + " policy, or the Default.", "Delete policy"))) return;
  const set = JSON.parse(JSON.stringify(pol()));
  set.policies = set.policies.filter((x) => x.id !== p.id);
  savePolicySet(set, "Deleted " + p.name);
});

// ---- Users page: groups a user was picked for, and their policies ----
function userGroupBadges(u) {
  const picked = pol().groups.filter((g) => (g.users || []).includes(String(u.username).toLowerCase()));
  return picked.length ? picked.map((g) => badge(g.name, "info plain")) : [el("span", { class: "muted" }, "–")];
}
async function drawUserPolicies(u) {
  const box = $("f-user-pols");
  box.classList.toggle("hidden", !u);
  if (!u) return;
  box.replaceChildren(el("div", { class: "dialog-sub" }, "Policies"), el("div", { class: "muted small" }, "Checking…"));
  try {
    const rows = await api("GET", "/policies/explain?user=" + encodeURIComponent(u.username));
    box.replaceChildren(el("div", { class: "dialog-sub" }, "Policies"),
      el("div", { class: "g-rows" }, ...rows.filter((r) => POLICY_TYPES[r.type].for === "users").flatMap((r) => [
        el("span", {}, POLICY_TYPES[r.type].title),
        el("div", {}, r.policy ? el("span", {}, el("b", {}, r.policy), el("span", { class: "sub" }, " via " + r.group)) : el("span", { class: "muted" }, r.note || "–"))])),
      el("em", { class: "hint" }, "Groups by Entra membership are checked at sign-in, so this shows groups the user was picked for, and the Defaults."));
  } catch (e) { box.replaceChildren(); }
}

countryPicker($("pc-list"), "Add a country…");
$("pc-list").addEventListener("input", () => namesHint($("pc-list"), $("pc-hint")));
