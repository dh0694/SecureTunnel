# Setting up Sign in with Microsoft (Entra ID)

SecureTunnel uses **one app registration** in your tenant for everything:

| Who | How they sign in | What Entra gives us |
|---|---|---|
| VPN users (Windows agent) | The agent opens the browser. Public client, auth code + PKCE, redirect `http://localhost` | An access token for the scope `api://<client ID>/access_as_user` |
| Admins and helpdesk (admin site) | A **Sign in with Microsoft** button. Confidential client with a client secret | An ID token with the app roles `SecureTunnel.Admin` / `SecureTunnel.Helpdesk` |

Local accounts keep working during the POC:
- The `testuser` account can still connect while **Local accounts can connect to the VPN** is on (Settings → Sign-in).
- The local `admin` account always works on the admin site as a break-glass account.

You can do every step in the Entra admin center (entra.microsoft.com). Nothing on the server needs SSH.

---

## 1. Create the app registration

1. Go to **Identity → Applications → App registrations → New registration**.
2. Fill it in:
   - **Name:** `SecureTunnel VPN`
   - **Supported account types:** *Accounts in this organizational directory only* (single tenant)
   - **Redirect URI:** platform **Web**, value `https://vpn.cott1nghambutler.com/admin/auth/entra/callback`
     (The exact value is shown on the admin site under Settings → Sign-in, with a Copy button.)
3. Click **Register**. Note the **Application (client) ID** and **Directory (tenant) ID** on the Overview page.

## 2. Add the agent's redirect URI

1. Go to **Authentication → Add a platform → Mobile and desktop applications**.
2. Under **Custom redirect URIs**, enter `http://localhost` (exactly that: no port, no slash). Then click **Configure**.
   Entra accepts any port on localhost. The agent picks a free port each time it signs in.
3. On the same page, under **Advanced settings**, set **Allow public client flows** to **No**. The agent uses the browser flow, not device code or ROPC.

## 3. Expose the VPN API scope

1. Go to **Expose an API**.
2. Next to **Application ID URI**, click **Add** and accept `api://<client ID>`. Save.
3. Click **Add a scope** and fill it in:
   - **Scope name:** `access_as_user`
   - **Who can consent:** *Admins only*
   - **Admin consent display name:** `Connect to SecureTunnel VPN`
   - **Admin consent description:** `Lets the SecureTunnel agent connect the VPN as the signed-in user.`
   - **State:** Enabled
4. Under **Authorized client applications**, click **Add a client application**:
   - Enter the **same client ID**.
   - Tick the `access_as_user` scope.

   With this, users aren't asked to consent the first time they sign in.

## 4. Use v2 access tokens

1. Go to **Manifest**.
2. Set `"requestedAccessTokenVersion": 2`. In the newer manifest format the setting is `api.requestedAccessTokenVersion`.
3. Save.

The server accepts v1 tokens too. With v2, token issuers and claims are consistent with the ID tokens.

## 5. Create a client secret (admin site only)

1. Go to **Certificates & secrets → Client secrets → New client secret**.
2. Choose an expiry (for example 12 months) and copy the **Value**. Entra shows it only once.

You'll paste it into the admin site in step 9. The agent never sees it.

## 6. Create the app roles (admin site access)

Go to **App roles → Create app role** and create two roles:

| Display name | Allowed member types | Value | Description |
|---|---|---|---|
| SecureTunnel Admin | Users/Groups | `SecureTunnel.Admin` | Full access to the SecureTunnel admin site |
| SecureTunnel Helpdesk | Users/Groups | `SecureTunnel.Helpdesk` | View everything, disconnect sessions, approve devices |

People without either role can still connect to the VPN, but they can't open the admin site.

## 7. Assign users

1. Go to **Identity → Applications → Enterprise applications → SecureTunnel VPN**.
2. Under **Properties**, set **Assignment required?** to **Yes**. Then only assigned users and groups can connect.
3. Under **Users and groups → Add user/group**, assign:
   - Your VPN users group, with the **Default Access** role.
   - Your IT admins, with **SecureTunnel Admin**.
   - Your helpdesk group, with **SecureTunnel Helpdesk**.

## 8. Grant admin consent

1. Back in **App registrations → SecureTunnel VPN → API permissions**, make sure these are listed:
   - **Microsoft Graph:** `openid`, `profile`, `email`, `User.Read` (the defaults)
   - **SecureTunnel VPN:** `access_as_user` (click **Add a permission → My APIs** if it's missing)
2. Click **Grant admin consent for <tenant>**.

## 9. Turn it on in SecureTunnel

1. Sign in to `https://vpn.cott1nghambutler.com/admin/` with the local admin account.
2. Go to **Settings → Sign-in** and fill it in:
   - Tick **Sign in with Microsoft (Entra ID)**.
   - Paste the **Directory (tenant) ID**, **Application (client) ID** and **Client secret**.
   - Keep **Local accounts can connect to the VPN** ticked while you test.
   - **Ask for the password on every connect** adds `prompt=login`, so the user must type their password each time.
3. Click **Save sign-in**. Every control server picks it up within about 5 seconds.

To check it works:
- Open the admin site in a private window. You should see **Sign in with Microsoft**.
- On a PC, open SecureTunnel. Its sign-in screen should show **Sign in with Microsoft**, with **Use a local account** underneath.

## 10. Conditional Access (MFA on every connect)

Create a policy under **Protection → Conditional Access → New policy**:

- **Users:** your VPN users group. Exclude your break-glass accounts.
- **Target resources:** select the app **SecureTunnel VPN**.
- **Grant:** *Require multifactor authentication*. Optionally also require *Microsoft Entra hybrid joined device* or *Require device to be marked as compliant*.
- **Session → Sign-in frequency:** *Every time*.
- **Enable policy:** start in *Report-only*, then switch to *On*.

Sign-in frequency *Every time* plus `prompt=login` means a fresh sign-in and MFA on every connect.

These don't need a new sign-in:
- **Network drop:** the 15-minute grace window resumes with the session's resume token.
- **Gateway failover:** also uses the resume token.

These always need a fresh sign-in:
- A reboot.
- A deliberate disconnect.
- Reaching the 12-hour session limit.

### Optional: check the MFA claim on the server too

Conditional Access is the primary control. The server can also refuse tokens itself, as defence in depth. These checks are off by default, because v2 access tokens may leave out `amr` and `auth_time`. Set them in `deploy/.env` and restart the `control` container:

```
ST_REQUIRE_MFA_CLAIM=true   # refuse tokens whose amr has no "mfa"
ST_REQUIRE_AUTH_TIME=true   # refuse tokens without auth_time
ST_MAX_AUTH_AGE=10m         # refuse sign-ins older than this
```

Test with a real user before you turn these on.

## 11. Certificates (optional)

Join type, Intune compliance and domain membership are checked by **Entra** through Conditional Access, not by SecureTunnel. In the CA policy for the SecureTunnel VPN app, use *Require device to be marked as compliant* and/or *Require Microsoft Entra hybrid joined device*. The app signs in through **Edge**, which passes the device identity, so those policies work.

SecureTunnel can additionally require a **device or user certificate** from your own CA, set per sign-in policy. Paste the CAs on the admin site under **Settings → Certificates**.
Choose **Device certificate**, **User certificate**, **either** or **both**. Then paste your issuing CA and root CA certificates (PEM). These are the rules:
- **Device certificates** are read from the computer store (`LocalMachine\My`), for example from AD CS autoenrollment or Intune SCEP/PKCS.
- **User certificates** are read from the user's store (`CurrentUser\My`). Smart cards and Windows Hello for Business certificates work; the user may see a PIN prompt.
- The certificate must allow **Client Authentication**, be valid, and chain to a CA you pasted.
- **Optional name checks:** the device certificate must name the computer (CN or DNS name), and the user certificate must carry the signed-in user's UPN or email.
- **Private keys stay on the PC.** The agent signs a challenge with Windows CNG, so TPM-backed keys work. Keys stored by legacy CSPs aren't supported; use a KSP template.

Revocation (CRL/OCSP) isn't checked yet. To cut off a lost PC, block it on the Devices page or disable it in Entra.

**Which certificate the app uses:** by default it picks automatically. It sends up to 3 that fit (valid, Client Authentication, from a CA you pasted), newest first, and the server accepts the first one that passes. User certificates are tried silently first, so there's at most one PIN prompt.
- In the app, **Settings → Certificates** lists the PC's device and user certificates, with the reason any can't be used (expired, wrong CA, not for sign-in).
- There the user can stay on **Automatic** or choose a specific certificate.
- The device choice is saved in `HKLM\SOFTWARE\SecureTunnel\DeviceCertThumbprint`, the user choice in `HKCU\Software\SecureTunnel\UserCertThumbprint`.
- If a chosen certificate disappears or expires, the app goes back to picking automatically.

When a connect is blocked for a missing or rejected certificate, the user sees the reason, with a link to the certificate list in Settings. It is recorded in the audit log as *vpn.device_untrusted*.

## 12. Groups, policies and Duo

**Groups** (admin site → Groups) say who or what:
- **User groups:** members of Entra groups, and/or users picked by hand (sign-in name or local account). A user group can also be limited to a platform.
- **Device groups:** PCs by computer name (`LT-*`, `KIOSK-0?`, or exact names) and/or platform (Windows / Mac).
- **Built in:** *All users* and *All devices*. A user or PC can be in several groups.

**Policies** (admin site → Policies) are named settings of one kind, assigned to groups:
- **Sign-in:** Microsoft and/or local account, an extra Duo Push, and whether a device and/or user certificate is required. Join type and compliance are left to Conditional Access.
- **Windows sessions:** what happens on Windows sign-out, user switching and screen lock (section 13 has the device tunnel option).
- **App updates:** pause, staged rollout, maintenance window, deadline and postpones. Decided per PC, even with nobody signed in, so assign these to device groups (update rings).

For each kind, the **first** policy in the list with an assigned group that includes the user or PC applies; move policies up or down to change the order. Each kind ends with a **Default** for everyone, so something always applies. The Users page shows which sign-in and Windows sessions policies apply to a user.

Example sign-in policies:

| # | Policy | Assigned to | Sign-in | Certificate |
|---|---|---|---|---|
| 1 | Mac sign-in | *Macs* (device group: platform Mac) | Microsoft + Duo Push | Not required |
| 2 | IT sign-in | *IT staff* (Entra group *VPN - IT*) | Microsoft | Device certificate |
| 3 | Contractor sign-in | *Contractors* (Entra group *VPN - Contractors*) | Microsoft + Duo Push | Not required |
| ∗ | Default sign-in | All users | Microsoft | Not required |

Example app updates policies: *Pilot ring* (device group *Pilot PCs*, `LT-41*`) installs as soon as ready; *Default app updates* uses a weeknight maintenance window with a 7-day deadline.

Upgrading from policy groups: the earlier policy groups (and users picked for them on the Users page) become groups with matching sign-in and Windows sessions policies, and the earlier update policy becomes the Default app updates policy. Nothing changes until you save.

Device compliance and join requirements go in your Conditional Access policies. For example, the Windows users' CA policy requires a compliant or hybrid-joined device, while the Mac users' policy doesn't.

Group membership is read from Microsoft Graph and includes nested groups. Add the application permission **GroupMember.Read.All** and grant admin consent. If membership can't be read while a group depends on it, the connect is refused rather than guessed.

### Duo

1. In the Duo Admin Panel, go to **Applications → Protect an Application** and add an **Auth API** application.
2. On the admin site, go to **Settings → Duo** and paste the API hostname, integration key and secret key. Click **Test connection**.
3. Under **Duo username**, pick how your users are named in Duo: the full sign-in name, or the part before @.
4. In a sign-in policy (Policies page), set **Extra sign-in step** to **Duo Push after sign-in**.

After the Microsoft or local sign-in, the server sends a Duo Push, or a phone call if that's the user's only device. The app shows "Check your phone" and connects once the push is approved. Denied and timed-out pushes are shown to the user and recorded in the audit log.

Entra's own MFA (through Conditional Access) still applies to Microsoft sign-ins. Duo is an extra step for the groups where you want it. You can also add Duo inside Entra as an external authentication method, in which case set the group to "None".

## 13. Device tunnel (connect before logon)

The device tunnel puts a Windows PC on the corporate network **before anyone signs in**. That covers:
- domain logons by users who have no cached credentials on that PC;
- password changes and resets from the Windows sign-in screen;
- Group Policy and Intune at boot.

It works much like the Microsoft Always On VPN device tunnel. The SecureTunnel service (running as SYSTEM) opens it whenever no user session is up. Nothing needs to be clicked.

**How the PC proves itself:** there's no user, so there's no Entra sign-in and no MFA. The service signs a fresh server challenge with the **device certificate** in `LocalMachine\My`, the same certificate used for device trust (section 11). The server lets the PC connect only when all of these hold:
- The device tunnel is on (admin site → **Settings → Device tunnel**).
- The PC is **approved** on the **Devices** page. So it must have connected once with a user sign-in, and IT must have approved it. Unknown, pending and blocked PCs are refused.
- The certificate chains to a CA pasted under **Settings → Certificates**, allows Client Authentication, and **names the computer** (CN or DNS name) as recorded on the Devices page. This name check always applies to the device tunnel, even when it's off for user connects. A certificate from one PC can't open a tunnel for another.
- The country rules allow the PC's location.

**What the PC can reach:** only the **allowed subnets** on the Policies page, for example the DCs, DNS servers and SCCM/WSUS servers. Those go into the tunnel's AllowedIPs instead of `0.0.0.0/0`, so the PC's internet traffic stays local and there's no kill switch. The gateways enforce the same list: a device-tunnel peer's traffic to anything else is dropped in the gateway's `ST-DEVICE-<interface>` iptables chain (for example `ST-DEVICE-wg0`). So a modified client gains nothing. Optional **DNS servers** (usually the DCs) must be inside those subnets. Subnets broader than /8, and default routes, are refused.

**Handover:**
- When a user signs in to SecureTunnel, their full tunnel **replaces** the device tunnel. The server ends the device session (*Replaced by a new connect*), and the audit log shows *User took over from device tunnel*.
- When the user's session ends (they sign out of SecureTunnel, Windows sign-out disconnects it, an admin disconnects it, or the grace window runs out), the service brings the device tunnel back within about 15 seconds.
- While a user's session is live on the same boot, the server refuses a device tunnel (409). After a reboot, the old user session doesn't block it.
- On the office network (office detection), the device tunnel stays off.

**Turning it off:**
- **Everywhere:** switch off **Connect before logon** on the Policies page. Open device tunnels end at their next check-in (within about 30 seconds).
- **One PC:** block or un-approve it on the Devices page (its device tunnel ends at the next check-in). Or, on the PC, set the string value `DeviceTunnel` = `0` under `HKLM\SOFTWARE\Policies\SecureTunnel` (GPO/Intune; this takes precedence) or under `HKLM\SOFTWARE\SecureTunnel`.

**Where you see it:**
- **Sessions page:** device sessions show the computer name with a *Device tunnel · before sign-in* badge. The user column reads `device:<computer>`.
- **Audit log:** *Device tunnel connected (before sign-in)*, *Device tunnel refused* (with the reason, such as not approved, wrong certificate name or untrusted CA), *User took over from device tunnel*, *Device tunnel ended by policy* and *Changed device tunnel*.
- **The app:** while only the device tunnel is up, it shows *Device tunnel only*, with the normal sign-in underneath. The Diagnose tab lists the subnets.

**Setup checklist:**
1. Issue device certificates with Client Authentication and the computer name in the CN or a DNS SAN (for example, AD CS *Workstation Authentication* autoenrollment, or Intune PKCS/SCEP). Use a KSP template.
2. Paste the issuing and root CAs under **Settings → Certificates**. The certificate mode for user connects can stay *Not required*.
3. Make sure each PC has connected once with a user, and approve it on **Devices**.
4. On **Settings → Device tunnel**, add the DCs, DNS and management subnets, set the DNS servers, turn on **Connect before logon**, and save.
5. Reboot a PC, or sign out of SecureTunnel, and check **Sessions** for the device session.

Revocation (CRL/OCSP) isn't checked yet. To cut off a lost PC, block it on the Devices page.

## Users page

People who sign in with Microsoft are added to **Users** automatically the first time they connect, as *Entra user*. On those rows you can:
- Set extra countries and trips for that user.
- Disable them. A disabled user can't connect even with a valid Microsoft sign-in.

You can also add an Entra user ahead of a trip: **Add user → Entra user** and enter their UPN.

Passwords and admin roles for Entra users are managed in Entra, not here.

## Troubleshooting

| Symptom | Cause |
|---|---|
| `AADSTS50011` redirect URI mismatch (admin site) | The Web redirect URI must match Settings → Sign-in exactly, including `https://` and the path |
| `AADSTS50011` in the agent's browser | `http://localhost` is missing under **Mobile and desktop applications** |
| `AADSTS65001` consent required | Grant admin consent (step 8), or add the authorized client application (step 3) |
| `AADSTS50105` user not assigned | Assignment is required and the user isn't assigned (step 7) |
| `AADSTS7000218` client_assertion or client_secret required (agent) | The `http://localhost` redirect URI is under **Web**. Move it to **Mobile and desktop applications** |
| Admin site says "doesn't have access" | The user has no SecureTunnel Admin or Helpdesk app role |
| Agent says "sign in again" after Microsoft sign-in | Check the control server log for `connect rejected`. The usual causes are a wrong audience (Application ID URI not `api://<client ID>`) or a missing `access_as_user` scope |
