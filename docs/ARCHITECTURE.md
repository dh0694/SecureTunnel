# SecureTunnel — Architecture & Decisions

Working name. A full-tunnel remote-access VPN for ~1500 users, built on WireGuard as the
data plane, with our own client, GUI, control server, admin site and gateways.

## Decisions (agreed)

| Topic | Decision |
|---|---|
| Data plane | WireGuard (`wireguard-nt` on Windows, WireGuardKit on macOS, kernel WireGuard on gateways). We do **not** write our own crypto or tunnel protocol. |
| Clients | Windows (Go service + tray GUI) and macOS (Swift Network Extension). |
| Identity | Entra ID. MFA on **every connect**, enforced by a Conditional Access policy (require MFA + sign-in frequency "Every time") on the VPN app registration. The control server also checks the token's freshness and MFA claims. |
| POC sign-in | **Local test accounts** (bcrypt passwords, optional TOTP, roles admin / helpdesk / user) for the proof of concept and as break-glass. A local sign-in returns a 5-minute connect token, so every connect is still a fresh sign-in. Entra is enabled by setting `ST_TENANT_ID` + `ST_API_AUDIENCE`; the two can run side by side. |
| Grace window | **15 minutes.** A network drop shorter than that resumes silently with no prompt. |
| Fresh MFA required when | the user intentionally disconnects, the device reboots, the grace window expires, or the absolute session lifetime is reached. |
| Device join | Hybrid AD-joined. Windows gets a **device tunnel** before logon (AD CS machine certificate, limited to DCs/DNS/PKI/management) plus the **user tunnel** after logon. |
| Tunnel mode | Full tunnel (`0.0.0.0/0, ::/0`) with a WFP kill switch and DNS leak protection. |
| Office detection | Trusted Network Detection: a TLS probe to an internal-only host with a pinned certificate, sent out the physical adapter. On success the tunnel stays down. |
| Hosting | On-premises, two sites (datacenter + second on-prem site). Linux servers. |
| HA | Active-active control servers in both sites. Gateways run as **active/standby pairs per site** sharing a floating IP, WireGuard key and peer set, so a gateway reboot keeps users' tunnel IPs. PostgreSQL with Patroni plus a third-site etcd witness. |
| Traffic path | Hub-and-spoke: laptop → gateway → corporate firewall → servers or internet. Gateways route without NAT; the firewall enforces access. |
| Settings | Bootstrap and machine-level settings from the registry (GPO/Intune ADMX) or a macOS managed profile. Everything else from signed, versioned server policy. Each setting has exactly one source. |
| Upgrades | No user is signed out by an upgrade. Client upgrades hand live state to the new version (1–3 s blip, same tunnel IP); server-side upgrades are rolling. |

## Components

```
clients ──HTTPS──▶ control servers (2, one per site, behind LB/DNS) ──▶ PostgreSQL HA
   │                         ▲
   └──WireGuard UDP/TCP443──▶ gateway pair per site (VIP) ── poll desired peer set ──┘
```

### Control server (`server/`)
Stateless Go service. All state lives in PostgreSQL.

- `POST /v1/sessions` — connect. Body: Entra access token, WireGuard public key, device ID,
  boot ID, platform. Validates the token, picks a gateway, allocates a tunnel IP, creates the
  session, and returns the tunnel config plus a one-time **resume token**.
- `POST /v1/sessions/{id}/heartbeat` — sent every 30s while connected. Uses the resume token.
- `POST /v1/sessions/{id}/resume` — after a network drop. Allowed only if the session is still
  within its grace window and the boot ID matches. Uses the resume token; no MFA.
- `DELETE /v1/sessions/{id}` — intentional disconnect. Ends the session immediately, so the next
  connect needs fresh MFA.
- `GET /v1/gateway/peers` — gateways poll their desired peer set (desired-state reconciliation).
- `POST /v1/gateway/health` — gateway load and health reports.

### Session state machine

```
            connect (fresh MFA)
                   │
                   ▼
   ┌──────────▶ ACTIVE ──── heartbeat missed > 90s ───▶ SUSPENDED
   │               │                                      │
   │  resume (same boot ID, within 15 min of last seen)   │
   └──────────────────────────────────────────────────────┘
                   │                                      │
   user disconnect │                   15 min since last  │
   max lifetime    │                   heartbeat, or new  │
                   ▼                   boot ID            ▼
               TERMINATED ◀───────────────────────────── EXPIRED
```

- **Reboot detection.** The client sends a boot ID (Windows: derived from last boot time;
  macOS: `kern.boottime`). Resume with a different boot ID is rejected. The resume token is
  normally held only in the client service's memory. During an upgrade handover it is written
  to disk encrypted to the machine (DPAPI / keychain) and bound to the boot ID, so it is useless
  after a reboot.
- **Absolute lifetime** (default 12h) forces fresh MFA even on a stable connection.
- While SUSPENDED the peer **stays on the gateway**, so WireGuard can pick up again on its own
  as soon as the network returns. The resume call only keeps the session alive.

### Gateway behaviour if the control plane is down
Gateways keep their last known peer set and remove a peer only at its absolute session expiry.
Existing tunnels keep working during a control-plane outage; only new connects fail.

### Traffic path (hub-and-spoke, not peer-to-peer)

```
laptop ══WireGuard══▶ gateway (DMZ) ──▶ corporate firewall ──▶ internal servers
                                              └──────────────▶ internet
```

- Clients only ever talk to gateways. There is no client-to-client traffic.
- **Gateways do not NAT.** They route, so the firewall sees each user's real tunnel IP
  (for example 10.200.0.42) and can write per-user rules and logs.
- **The firewall is the enforcement point** for internal access and internet egress (URL
  filtering, IPS, SSL inspection). The gateway only does WireGuard and a basic anti-spoofing
  check: a peer may only send from its own tunnel IP.
- **User identity on the firewall:** the control server pushes user ↔ tunnel-IP mappings to
  the firewall on connect, failover and disconnect (Palo Alto User-ID XML API, FortiGate FSSO /
  REST, or syslog). Firewall rules can then use Entra users and groups directly.
- The per-group access rules (tier 2) become optional. They can be enforced on the firewall via
  User-ID, or with one IP pool per access profile so firewall rules can match on subnet.

### Gateway pairs and IP addressing
- Each site runs an **active/standby gateway pair** (keepalived/VRRP). The pair shares one
  floating public IP, one WireGuard private key, one client IP pool (for example `10.200.0.0/21`)
  and the same peer set, which both members pull from the control server.
- To the control server a pair is **one logical gateway**: one `gateways` entry whose `endpoint`
  is the floating IP. The phase 1 code needs no change for this.
- When the floating IP moves (failure or planned reboot), the new active member has the same key
  and peers but no WireGuard session state. Clients re-handshake within about 5–10 seconds and
  keep the **same tunnel IP**, so TCP connections survive.
- The pool is routed statically in the core network to the pair's inside VIP.
- Moving to the **other site** (whole-site failure) still gives the client a new tunnel IP and
  resets connections once. Normal network roaming never changes the tunnel IP.

## Settings and policy delivery

| Source | What | How it changes |
|---|---|---|
| Registry `HKLM\SOFTWARE\Policies\SecureTunnel` (ADMX for GPO/Intune); macOS managed profile `com.contoso.securetunnel` | Bootstrap and machine-level: `ControlUrl`, `TenantId`, `ClientId`, `PolicySigningKey`, `TrustedNetworkProbeUrl`, `TrustedNetworkCertSha256`, `AlwaysOn`, `KillSwitch`, `DeviceTunnelEnabled`, `UpdateRing`, `LogLevel`, `DisableUserDisconnect` | GPO refresh / Intune sync |
| Server policy (admin site) | Everything else: tunnel mode, DNS, bypass rules, network preference, metered rules, posture, UI options, grace/lifetime | Within ~30 s for connected clients |

- **One source per setting.** The server never sends a registry-owned setting, so there is no
  precedence to reason about.
- Server policy is **versioned** (one-click rollback), **signed** by the control server (client
  verifies with `PolicySigningKey`), **targeted** by Entra user group, device group and platform,
  and **rolled out in rings** (pilot → broad → all). Every publish is audit-logged.
- The client reports its policy version on every heartbeat; if the server has a newer one, the
  client fetches and applies it live, with no reconnect. The last good policy is cached on disk
  so offline behaviour (kill switch, office detection, captive portals) keeps working.
- Urgent actions (disconnect user, force reconnect, quarantine) use a live push channel so they
  land within seconds instead of waiting for the next heartbeat.
- The client's Settings tab and diagnostics bundle show each effective setting and its source.

## Upgrades without disconnecting users

### Windows client
- **GUI** is a separate process; updating it never touches the tunnel.
- **Service upgrade handover:**
  1. The old service writes its live state (session ID, resume token, WireGuard keys, tunnel IP,
     policy) to a DPAPI-machine-encrypted file bound to the boot ID.
  2. The WFP kill-switch filters are persistent, so traffic stays blocked (no leaks) while the
     service restarts.
  3. The new service reads the state, recreates the adapter with the same keys and tunnel IP,
     and resumes the session through the normal grace-window path (no MFA).
  4. Expected gap: 1–3 seconds. Apps see a pause, not a disconnect.
- The same handover runs from the MSI, so Intune-pushed upgrades are also non-disruptive.
- **Timing:** never during an active call or screen share (microphone/camera in use, Teams/Zoom
  call state); within policy quiet hours if set; otherwise at the next idle moment or the next
  user disconnect/reboot.
- **wireguard-nt driver updates** are rare and held for the next reboot or user disconnect.

### macOS client
macOS restarts the Network Extension on app update. State is handed over through the keychain
(bound to the boot ID) and the tunnel returns with the same IP in a couple of seconds, no MFA.

### Server side
| Component | Method | User impact |
|---|---|---|
| Control servers | Rolling, one at a time behind the LB | None; tunnels don't pass through them |
| PostgreSQL | Patroni rolling (standby first, then switchover) | None for existing tunnels; new connects pause ~30 s |
| Gateway agent | Restart the agent | None; WireGuard lives in the kernel |
| Gateway OS/kernel | Reboot standby, move VIP, reboot the other | ~5–10 s pause, same tunnel IP |

## Entra configuration (to set up in the tenant)

Step-by-step guide: [ENTRA-SETUP.md](ENTRA-SETUP.md). In short:

1. **One app registration, "SecureTunnel VPN":**
   - It exposes the API scope `access_as_user`.
   - It has a Web redirect for the admin site and a `http://localhost` mobile/desktop redirect for the agent's browser sign-in.
   - It has a client secret, the app roles `SecureTunnel.Admin` and `SecureTunnel.Helpdesk`, and the Graph application permissions `Device.Read.All` and `GroupMember.Read.All`.
2. **Conditional Access is the enforcement point** for MFA, sign-in frequency **Every time**, and device compliance or hybrid join. SecureTunnel only *shows* join and compliance status.
3. **Server-side checks are on top of CA:**
   - Per-group sign-in methods, an optional Duo Push, certificates, and an optional AD domain restriction.
   - The optional token claim checks (`ST_REQUIRE_MFA_CLAIM`, `ST_MAX_AUTH_AGE`) are off by default, because v2 access tokens may not carry `amr` or `auth_time`.

## Feature roadmap (target: NetMotion / Absolute Secure Access parity)

Difficulty: **S** small, **M** medium, **L** large, **XL** very large.

### Tier 1: core VPN (needed to go live)
| Feature | Notes | Size |
|---|---|---|
| Entra MFA on every connect, 15-min grace | done in control server (phase 1) | done |
| Full tunnel + kill switch + DNS leak protection | WFP filters on Windows, NE on macOS | M |
| Seamless roaming (Wi-Fi ↔ Ethernet ↔ cellular), sleep/wake | WireGuard roaming + network-change detection | M |
| Gateway failover across both sites | done in control server; client side to build | M |
| TCP/443 fallback when UDP is blocked | WireGuard wrapped in TLS on the gateway | M |
| Captive portal detection and handling | brief, scoped hole in the kill switch | M |
| Trusted Network Detection (office bypass) | pinned-cert TLS probe out the physical adapter | M |
| Windows device tunnel before logon | AD CS machine cert, restricted routes | L |
| Tray GUI, toasts, MSI for Intune | | M |
| Admin site: live sessions, kick user, gateway health, audit log | | M |

### Tier 2: what makes NetMotion feel different
| Feature | Notes | Size |
|---|---|---|
| **Long-outage session persistence** | WireGuard keeps the tunnel IP, so TCP survives short drops. To keep apps alive through long outages (tunnels, dead zones, minutes offline) like NetMotion does, add a **gateway-side TCP proxy** that holds server connections open while the client is away, plus client-side keepalive spoofing. | XL |
| Policy engine | Rules on app, user/group, network type (Wi-Fi/cellular/wired), SSID, location, time, device posture. Actions: allow, block, bypass tunnel, throttle, require tunnel. | L |
| Per-app split tunnel / bypass | Windows WFP app-ID filters; macOS per-app NE rules (app identity on macOS needs MDM). Example: Teams media direct. | L |
| Interface prioritisation | Prefer wired > Wi-Fi > cellular; cost-aware rules on metered links. | M |
| Network quality insights | Client reports latency, loss, jitter, signal strength, Wi-Fi channel/BSSID, carrier, throughput. Admin dashboards and per-user troubleshooting. | L |
| Device posture checks | Defender running, firewall on, BitLocker/FileVault on, OS patch level, Intune compliance (Graph API). Fail → block or quarantine profile. | L |
| Quarantine / remediation network | Non-compliant devices get only Intune/WSUS/AV-update routes. | M |
| Per-app ZTNA access | Groups map to allowed internal subnets/ports, enforced at the gateway (nftables per peer), not only flat full tunnel. | L |
| User-facing diagnostics | "Run diagnostics" in the GUI: DNS, gateway reachability, MTU, captive portal, speed test; one-click bundle to the helpdesk. | M |

### Tier 3: enterprise and admin
| Feature | Notes | Size |
|---|---|---|
| Admin RBAC via Entra groups | Helpdesk (read and kick), Network admin (policy), Super admin. | M |
| Reporting | Usage per user/site, connection success rate, reconnect counts, top apps by bandwidth. | M |
| SIEM export | Syslog/CEF and Sentinel connector for auth, session and policy events. | M |
| Alerts | Gateway down, pool near full, connect failure spikes, posture failure spikes. Email/Teams webhook. | M |
| Web/DNS filtering | DNS resolver with category blocklists, or hand off to an existing filter. | M |
| Bandwidth controls | Per-user/app rate limits and QoS marking on the gateway. | M |
| Client auto-update | Signed updates delivered by the control server, staged rings. | M |
| Remote client config and support | Push settings, pull logs remotely, force reconnect. | M |
| macOS client parity | Same features via Network Extension; some (per-app rules) need MDM. | XL |

### Probably skip or defer
- **Traffic compression/optimisation.** NetMotion offers it; it matters little now that most traffic is already compressed TLS.
- **Multipath link bonding** (using Wi-Fi and cellular at once). Possible later, but complex.

## Build phases
Status as of the POC: phases 1, 3 and 5 are done. Phases 2 and 4 are partly done.

1. **Done.** Control server: token validation, sessions, IP pools, gateway API.
2. **Partly done.** Gateway agent (Linux): peers, health and metrics are done. Per-peer nftables (ZTNA, bandwidth, quarantine) is still to do.
3. **Done.** Windows client service + tray GUI, installer and auto-update.
4. **Partly done.** Resilience:
   - Done: grace window, failover, office detection.
   - To do: TCP/443 fallback, captive portals.
5. **Done.** Admin website, Entra roles, audit log, policy groups, device trust, Duo.
6. Windows device tunnel (pre-logon).
7. Policy engine, posture checks, quarantine, per-app split tunnel.
8. Network quality insights, diagnostics, reporting, SIEM, alerts.
9. Session persistence proxy for long outages.
10. macOS client.
