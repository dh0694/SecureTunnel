# SecureTunnel

A full-tunnel remote-access VPN built on WireGuard, in the style of NetMotion / Absolute Secure Access.
- **Sign-in:** Microsoft (Entra) on every connect, with MFA and device rules enforced by Conditional Access.
- **Dropped networks:** a 15-minute window to reconnect without signing in again.
- **Office detection:** the VPN steps aside when the PC is on the office network.
- **Management:** an admin site for helpdesk and policy.

- Design and decisions: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
- Entra, certificates, groups, policies and Duo setup: [docs/ENTRA-SETUP.md](docs/ENTRA-SETUP.md)

## What the POC does today

### Signing in and staying connected
- **Sign in with Microsoft** from the Windows app. It uses the browser (Edge), so Conditional Access applies MFA, device compliance and hybrid join. You're asked to sign in again on each connect.
- **Local test accounts** (password, optional authenticator app) for the POC. They can be switched off when you're done.
- **15-minute grace window:** a dropped network resumes without signing in. A reboot, a deliberate disconnect or reaching the 12-hour limit needs a fresh sign-in.
- **Gateway failover** if a gateway stops answering.
- **Instant admin disconnect.**

### Access rules (admin site → Groups, Policies and Settings)
- **Groups:** users (by Entra group or picked by hand) and devices (by computer name or platform).
- **Policies,** assigned to groups, with the first match in each list winning and a Default for everyone:
  - **Sign-in:** which methods are allowed (Microsoft and/or local account), an optional **Duo Push**, and an optional **device or user certificate** from your own CA.
  - **Windows sessions:** what happens on Windows sign-out, user switching and screen lock.
  - **App updates:** update rings for groups of PCs (pause, staged rollout, maintenance window, deadline).
- **Settings** for the whole system: server addresses, Microsoft sign-in, certificates, Duo, device tunnel, office networks, countries, speed tests.
- **Device approval:** new PCs wait for IT to approve them.
- **Per-user allowed countries**, including trips with an end date.
- **Office network detection** (DNS suffix, subnet or public IP). On the office network the VPN disconnects and traffic goes out the local network.
- **Device tunnel (connect before logon):** when nobody is signed in to SecureTunnel, an approved Windows PC connects with its device certificate. That lets the Windows sign-in screen reach the domain controllers, so first logons without cached credentials, password changes and resets, and GPO or Intune at boot all work. The tunnel reaches only the subnets IT lists, and the gateways enforce that. A user's sign-in replaces it with their full tunnel, and it comes back when they sign out. See [docs/ENTRA-SETUP.md](docs/ENTRA-SETUP.md#13-device-tunnel-connect-before-logon).

### Windows app
- **Status:** connection state, current usage (receiving/sending), latency, jitter and loss.
- **Network details:** Wi-Fi name and signal, public IPs and data used.
- **Speed test:** inside and outside the tunnel.
- **Self-check:** a diagnostics tab.
- **Messages from IT.**
- **Updates:** installs with `/SERVER=` and updates itself from the server. The admin site's **App updates** page sets the policy and pushes updates:
  - **Policy:** pause, staged rollout, when to install while connected (never, a maintenance window, or right away), a deadline, how often users may postpone, and whether users are told.
  - **Push:** to all outdated connected PCs or chosen ones, to install after they disconnect, now, or at a set time.
  - **What users see:** a notice in the app, and a 2-minute countdown with Update now and Postpone before anything interrupts them. After updating, the app reconnects by itself without a new sign-in.
- **Settings:** in the registry and pushed from the server.

### Admin site
- **Live data:** overview, live sessions with per-user diagnostics, and gateways with CPU, memory and disk-based placement.
- **Server health:** a page with host metrics for each server.
- **Management pages:** devices, users, groups, policies, app updates, settings, the audit log and downloads.
- **Help-this-user actions:** run a speed test, refresh diagnostics, send a message or disconnect.
- **Sign-in:** with Microsoft, using Entra app roles (Admin / Helpdesk). A local admin account stays as break-glass.

### Not done yet
- **Clients:** no Mac client. The device tunnel connects by itself before Windows logon, but there's no button or status on the Windows sign-in screen (that would need a credential provider).
- **Networks that block WireGuard:** no TCP/443 fallback.
- **High availability:** gateway pairs with a shared IP (keepalived), and an HA database. The POC runs one server.
- **Certificates:** revocation (CRL/OCSP) isn't checked.
- **Access control:** no limited "quarantine" network and no per-app split tunnel.
- **Duo:** a "Cancel" button while waiting for a push (it times out after 90 seconds).
- **Code signing:** the installer and app aren't signed (Windows SmartScreen warns).

## Running the POC (Ubuntu + Docker)

Needs Ubuntu 22.04/24.04 with Docker Engine and the compose plugin. No Go install is needed; the image build compiles and tests everything, including the Windows app and installer.

```bash
cd ~/SecureTunnel/deploy
sudo ./setup.sh <ip-or-dns-name-of-this-machine>
```

`setup.sh` does the following:
- Generates the secrets, a self-signed certificate and the gateway key.
- Starts Postgres, the control server and the gateway.
- Creates `admin` (admin site) and `testuser` (VPN). Their passwords are printed and kept in `deploy/.env`.

These are the addresses:
- **Admin site:** `https://<host>:8443/admin/`. In this POC it's published through Cloudflare Tunnel at https://vpn.cott1nghambutler.com/admin/.
- **Windows app:** download it from `/downloads`. Install with `SecureTunnel-Setup.exe /SERVER=vpn.example.com`, adding `/S` for a silent install. A bare IP means port 8443; a host name means port 443.
- **Ports:** TCP 8443 (control server and admin site) and UDP 51820 (WireGuard).

After changing code, run `deploy/rebuild.sh --up`. It builds a new version number, so installed apps update themselves.

The lab gateway **NATs** tunnel traffic out of the host's default interface. The production design is no NAT: the core network routes the client pool to the gateway so the firewall sees real tunnel IPs. For that, use `setup.sh <host> --no-nat` and add the route.

### HA lab on one machine

`deploy/ha.sh up` adds three things:
- **A second control server**, standby behind HAProxy. It takes over in about 4 seconds with no failed requests.
- **A second gateway** (`lab-gw-b`, UDP 51821, pool 10.200.8.0/21).

Commands:
- `ha.sh status` shows which control server is active.
- `ha.sh down` goes back to a single server.

To try a failure:
- `docker compose stop control`: the admin site and connected users stay up on control-b.
- Drain a gateway on the Servers page: users move to the other gateway in seconds.
- `docker compose stop gateway`: users fail over on their own within about a minute.

The admin site's **Servers** page has everything in one place:
- **A diagram** of how the pieces connect, with each one's health.
- **Gateways:** one card each, with whether it's taking new users, users and active tunnels, CPU, memory, disk, traffic, its address range, and the Drain and Disable buttons. The placement rules are one line above them.
- **Sign-in and management:** the control servers (Active or Standby, from HAProxy), HAProxy itself, and the shared PostgreSQL database.

Moving users is also possible one at a time: on the Sessions page, open a session and choose **Move to another gateway**. **Drain** on the Servers page stops new sessions on a gateway and moves everyone on it. Either way, the user's tunnel IP changes to the new gateway's pool.

In HA mode the control servers listen only on localhost, behind HAProxy. Cloudflare Tunnel and the gateways connect locally.

```bash
docker compose logs -f control gateway   # logs
docker compose ps                        # status
sudo wg show wg0                         # live WireGuard peers
```
