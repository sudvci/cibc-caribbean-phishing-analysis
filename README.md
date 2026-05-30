# cibccaribbeanid.icu Phishing Site Analysis

## What It Is

Phishing site impersonating **CIBC Caribbean Online Banking**. The page title
uses Unicode lookalike characters (`СIВС Саribbеаn - ОnIinе Ваnking`) to
spoof the real brand. Included `noindex, nofollow` meta tag to avoid search
engine indexing. This is is hosted on a DigitalOcean droplet. The same droplet **also exposes the
attacker's own Dokploy deployment-management panel** on port 3000 and **SSH on
port 22**.

The kit harvests, across a multi-step flow: banking credentials, full card
details, PII (name/DOB/address/phone), government-ID photos, live OTP/2FA codes,
and the victim's **email-account password** (via pixel-perfect Gmail / Outlook /
Yahoo / iCloud / AOL clones, including live 2FA interception).

The exfil destination is server-side only and not visible in client JS — but it
almost certainly resolves to a **Telegram bot token / chat ID** (and possibly a
Discord webhook) stored inside the exposed Dokploy instance's PostgreSQL
database and container environment variables. That Dokploy panel + open SSH is
the single highest-value evidence point for takedown and attribution.

## How We Got Here

![initial text I got](/text.png)

### 1. Key Findings

#### 1.1. Domain & Hosting

| Field | Value |
|---|---|
| Domain | `cibccaribbeanid.icu` |
| Title spoof | Unicode homoglyphs in `СIВС Саribbеаn - ОnIinе Ваnking` |
| IP | `188.166.36.41` |
| ASN / Host | AS14061 DigitalOcean (Amsterdam) |
| Registrar | PDR Ltd. / PublicDomainRegistry |
| Registrar abuse | `abuse@publicdomainregistry.com` |
| Host abuse | `abuse@digitalocean.com` |
| Registered | 2026-05-29 (same day as writeup) |
| Registrar abuse | `abuse@publicdomainregistry.com` |
| Host abuse | `abuse@digitalocean.com` |

#### Tech Stack & IDs

| Field | Value |
|---|---|
| reCAPTCHA site key | `6Lew2fkrAAAAAOmRUFxLnGjTwki1ex0MMCvtAqYS` |
| Phishing-kit Next.js build ID | `jS7HLfsNPkrJunzq3p8j-` |
| Server Action ID (exfil endpoint) | `7fbd36e5371f9b7bf4658498f5c0d2e205e3c568fa` |
| Dokploy build ID | `88EvmKYaqpt89OTUtSZnM` |
| Stolen-CSS fingerprint | `[_ngcontent-qea-c664]` (Angular scoped selectors) |
| OPSEC leak | `/api/block` → `https://localhost:3000/not-allowed` |

### 2. Initial fetch

Fetched `/` impersonating Chrome. Got the anti-bot decoy page (here's a snippet):

  ```html
      <body class="ng-scope desktop-view mobile-browser theme--light">
          <main style="padding: 40px; font-family: system-ui">
              <h1>Access not allowed</h1>
              <p>Automated traffic is not permitted on this site.</p>
          </main>
          ...
          <script>
              self.__next_f.push([
                  1,
                  '1:"$Sreact.fragment"\n2:I[5429,["509","static/chunks/509-3e5877b939fd87a8.js","177","static/chunks/app/layout-502b8f3b4c8af488.js"],"default"]...'
              ]);
          </script>
  ```
  
  Seems like a Next.js RSC-rendered page that shows "Access not allowed".
  
  Hidden in the RSC payload was the Next.js build ID `jS7HLfsNPkrJunzq3p8j-` and the current route `not-allowed`:
  
  ```json
  {"b":"jS7HLfsNPkrJunzq3p8j-", "c":["","not-allowed"]}
  ```

### 3. Enumerating Build Manifest

Fetched `/_next/static/jS7HLfsNPkrJunzq3p8j-/_buildManifest.js`. It's a
Pages Router manifest with only `/_app` and `/_error`. The real app uses App Router, so routes aren't exposed here.

### 4. JS chunk download & analysis (`recon.py`)

Downloaded all 8 JS chunks referenced in the HTML.
Key findings from `app/layout-502b8f3b4c8af488.js`:

```bash
sitekey: u.env.NEXT_PUBLIC_RECAPTCHA_SITE_KEY || "6Lew2fkrAAAAAOmRUFxLnGjTwki1ex0MMCvtAqYS",
size: "invisible",
```

- Site wraps the entire app in a `RecaptchaProvider` using **invisible reCAPTCHA** (`size="invisible"`).
- Hardcoded fallback site key: `6Lew2fkrAAAAAOmRUFxLnGjTwki1ex0MMCvtAqYS`
- The token flow: reCAPTCHA fires silently → token sent to server → middleware validates → allow or block.

The largest CSS file (`6ec1c51b335e5fa2.css`, 689 KB) contains Angular
component attribute selectors (`[_ngcontent-qea-c664]`). This is the real
CIBC Caribbean banking app's compiled CSS, **stolen wholesale**. Fonts are
self-hosted at `/fonts/external/googlesans/` and `/fonts/external/yahoo/`.

Discovered the middleware has at least two response branches based on IP reputation/geo:

| IP type | `GET /` | `GET /login` |
|---|---|---|
| Real residential IP | Middleware **rewrites** to `/not-allowed`, serves decoy RSC page | 308 -> `/login` (with bypass) |
| VPN/datacenter IP | 308 redirect to `/login` | 405 "Not Allowed" (all methods, plain text) |

The 405 on `/login` for all methods with no `Allow` header and a custom
`text/plain` body is a second middleware block, not a real Next.js route 405.

#### 4.1. Client-Side Bot Detection (module 8066 in `211-98290cf7eeb904d8.js`)

```js
function o() {
    let e = [];
    true === navigator.webdriver && e.push("webdriver");
    navigator.languages && 0 !== navigator.languages.length || e.push("no-languages");
    let n = /Mobile|iPhone|Android/.test(navigator.userAgent);
    n && 0 === navigator.maxTouchPoints && e.push("touch-mismatch");
    let a = document.createElement("canvas").getContext("webgl");
    if (a) {
        let t = a.getExtension("WEBGL_debug_renderer_info");
        let c = t ? a.getParameter(t.UNMASKED_RENDERER_WEBGL) : "";
        /SwiftShader|llvmpipe|Mesa Offscreen/i.test(c) && e.push("software-gpu");
        n && /NVIDIA|AMD|Intel.*HD/i.test(c) && e.push("desktop-gpu-on-mobile-ua");
    }
    setTimeout(() => {
        if (e.length !== 0 && !interacted)
            window.location.replace("/api/block?r=" + encodeURIComponent(e.join(",")));
    }, 4000); // <-- the 4 second timer
}
```

The site runs a fingerprinter 4 seconds after page load and redirects to
`/api/block` if any of the following are true:
- `navigator.webdriver === true` (Selenium / Playwright)
- No browser languages set
- Mobile UA but zero touch points
- Software GPU renderer (SwiftShader, llvmpipe, Mesa)
- Desktop GPU on mobile UA
- No mouse / touch / keyboard interaction in 4 seconds

#### 4.2. Fake Email Provider Login Pages

After the victim submits their email address on the `/email` step, the site
figures out what email provider they use and serves a pixel-perfect clone of
that provider's login page.

```js
async function detectProvider(domain) {
    const map = {
        gmail: 'gmail', aol: 'aol', yahoo: 'yahoo', ymail: 'yahoo',
        outlook: 'outlook', hotmail: 'outlook', live: 'outlook',
        icloud: 'icloud', me: 'icloud',
    };
    const tld = domain.split('.')[0];
    if (map[tld]) return map[tld];

    // For anything not in the list, fire a real DNS-over-HTTPS MX lookup
    const res = await fetch(
        `https://cloudflare-dns.com/dns-query?name=${domain}&type=MX`,
        { headers: { Accept: 'application/dns-json' } }
    );
    const { Answer = [] } = await res.json();
    if (Answer.some(r => r.data.toLowerCase().includes('google.com')))
        return 'gmail';

    return 'outlook'; // fallback
}

router.push(`/email/${provider}`);
```

The DoH lookup catches custom-domain Gmail users (e.g. `@mycompany.com`
routed through Google Workspace) who wouldn't be caught by the hardcoded map.

---

#### 4.3. Provider pages discovered

| Provider | URL | Chunk size | Notes |
|---|---|---|---|
| Gmail | `/api/email/gmail` | 1.07 MB | Google `quantumWiz` CSS inlined |
| Yahoo | `/api/email/yahoo` | 723 KB | Yahoo Sans fonts from `yimg.com` |
| iCloud | `/api/email/icloud` | 3.3 MB | Full Apple UI + 2FA interception |
| AOL | `/api/email/aol` | 722 KB | Same template as Yahoo |
| Live/Hotmail | `/api/email/live` | 116 KB | Hardcoded Microsoft PPFT token |
| Outlook | `/api/email/outlook` | 404 | Not implemented |
---

### 5. Middleware bypass via `/api/` prefix

The middleware blocks pretty much all URLs (`/login`, `/card`, …), but the App Router dynamic segment `[id]` means **`/api/<page>` passes `"api"` as the `[id]` param and bypasses the middleware entirely**. All pages are reachable this way:

| URL | Size | Notes |
|---|---|---|
| `/api/login` | 18 KB | `username`, `password` |
| `/api/card` | 17 KB | `cardNumber`, `expirationDate`, `cvv` |
| `/api/billing` | 17 KB | `fullname`, `dob`, `phoneNumber`, `address` |
| `/api/email` | 16 KB | `email`, `phoneNumber` |
| `/api/document` | 17 KB | ID photo `front` / `back` |
| `/api/otp` | 641 KB | live OTP/2FA code |
| `/api/confirmation` | 15 KB | final "thank you" page |
| `/api/block` |--- | 308 → `https://localhost:3000/not-allowed` (OPSEC leak) |

All submissions POST to one Next.js Server Action:

```bash
POST /<page>
Next-Action: 7fbd36e5371f9b7bf4658498f5c0d2e205e3c568fa
Content-Type: text/plain;charset=UTF-8

["LOGIN",{"logins":{"1":{...}},"sessionId":"...","recaptchaToken":"..."}]
```

Event strings: `LOGIN`, `CARD`, `EMAIL & MOBILE`, `EMAIL`, `EMAIL OTP`,
`INFO` (tracking), `BILLING`, `DOCUMENT`, `OTP`, `CONFIRMATION`.

**Critical flaw:** the reCAPTCHA token is **never validated server-side**. A
dummy token returns `{"sent":true}`:

```bash
curl -s https://cibccaribbeanid.icu/api/login \
  -H 'Content-Type: text/plain;charset=UTF-8' \
  -H 'Next-Action: 7fbd36e5371f9b7bf4658498f5c0d2e205e3c568fa' \
  -d '["LOGIN",{"logins":{"1":{"username":"test","password":"test"}},"sessionId":"AAAAAAAAAA","recaptchaToken":"anything"}]'
# → 0:{"a":"$@1","f":"","b":"jS7HLfsNPkrJunzq3p8j-"}\n1:{"sent":true}
```

### 6. The Attacker's Dokploy Panel

The same droplet exposes the attacker's **Dokploy** deployment manager at
`http://188.166.36.41:3000/` (HTTP, no TLS, publicly reachable). This is where
the phishing-kit container and its exfil secrets are managed.

#### 6.1 Port scan (17 ports, `probe3_dokploy.py`)

| Port | Status | Service |
|---|---|---|
| **22** | **OPEN** | `SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.16` -> Ubuntu 24.04 LTS |
| **3000** | **OPEN** | Dokploy (Next.js, HTTP) |
| 2375 / 2376 | Closed | Docker API / TLS |
| 5432 / 6379 / 27017 | Closed | PostgreSQL / Redis / MongoDB |
| 25, 53, 587, 3001, 4000, 5000, 8080, 8888, 9000, 9090 | Closed | --- |

**Only 22 and 3000 are externally reachable. All secrets are server-side.**

#### 6.2 Auth surface (Better Auth)
- `POST /api/auth/sign-up/email` → 400 `Admin is already created` (registration blocked).
- Sign-in returns identical `INVALID_EMAIL_OR_PASSWORD` for unknown-user vs.
  wrong-password -> **no email enumeration**. admin email remains unknown.
- **Rate limit ≈ 3 attempts/IP** before HTTP 429 -> online brute-force infeasible from one IP.
- **GitHub OAuth:** present but `client_id=undefined`.
- **Google OAuth:** present but HTTP 500.
- **Admin authenticates with email + password only.**

#### 6.3 tRPC enumeration
- Public: `settings.isCloud` → `{"json":false}` (self-hosted).
- Auth-gated (401 = exist, will return data with a valid session):
  `notification.all`, `notification.one`, `notification.testTelegramConnection`,
  `notification.testDiscordConnection`, `project.all`, `user.all`, `user.get`,
  `user.getPermissions`, `server.all`, `deployment.all`,
  `deployment.allCentralized`, `deployment.queueList`, `docker.getContainers`,
  `registry.all`, `destination.all`, `settings.getDokployVersion`.
- Procedures referenced in chunks (`dokploy_trpc_map.json`):
  `deployment.allCentralized`, `project.homeStats`, `user.getPermissions`,
  `application.cancelDeployment`, `compose.cancelDeployment`,
  `deployment.queueList`, `settings.isCloud`, `user.getMetricsToken`.
- tRPC **batch** returns HTTP 207; per-procedure auth is enforced — batching a
  public + private proc does **not** bypass the private auth check.

#### 6.4 Notification schema (from `_app` bundle)
Confirms exactly what is stored in Dokploy's DB per channel:

```bash
Telegram:   { botToken, chatId, messageThreadId? }
Discord:    { webhookUrl }
Slack:      { webhookUrl, channel }
Email/SMTP: { smtpServer, smtpPort, username, password, fromAddress, toAddress }
Teams / Ntfy / Pushover / Gotify / Mattermost / Resend / Custom: ...
```

`notification.testTelegramConnection` and `…testDiscordConnection` returning
**401 (not 404)** confirm those test procedures are registered server-side.

#### 6.5 Routes & assets (no auth)
Build manifest at `/_next/static/88EvmKYaqpt89OTUtSZnM/_buildManifest.js`
exposes the SPA route map, including the high-value:
```
/dashboard/project/[projectId]/environment/[environmentId]   ← env-var editor
```
This editor is where `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` live for an
authenticated admin. All JS chunks are publicly served. WebSocket log endpoints
(`/api/deploy/logs`, `/api/deployment/logs`, `/api/logs`, `/api/ws`) exist but
drop unauthenticated connections. `robots.txt` = `Disallow: /`. Swagger/OpenAPI
exist but are auth-gated (401).


## Takedown Status Report
**Timestamp:** 2026-05-30 ~00:18 UTC  

### What Happened

Between the end of Dokploy enumeration and this session, the attacker
infrastructure went dark.

| Check | Result |
|---|---|
| `cibccaribbeanid.icu` DNS (DoH) | **NXDOMAIN** (RCODE 3) — domain does not exist |
| `188.166.36.41` TCP port 22 | **TIMEOUT** (no banner) |
| `188.166.36.41` TCP port 3000 | **TIMEOUT** |
| `188.166.36.41` TCP port 80/443 | **TIMEOUT** |
| `ams.smarttechco.ir` DNS | **Resolves to `188.166.36.41`** (TTL=120s) |
| `ams.smarttechco.ir` HTTP | **TIMEOUT** |
| DigitalOcean platform status | All Systems Operational |

Key distinction: ports are **timing out**, not **connection refused**. Connection refused would mean the OS is up but no service is listening. Timeout means packets are being silently dropped, either by a network-level firewall or because the droplet is powered off / suspended.

### Most Likely Interpretation

**The phishing domain was suspended by PDR / the .icu registry**, and
**DigitalOcean has suspended or firewalled the droplet** in response to an abuse report (possibly one filed by someone else, or by automated detection).

Evidence supporting this:
- `cibccaribbeanid.icu` NXDOMAIN — registrar-level action (we did not make this
  change; it happened externally).
- All ports timing out — consistent with a DO "droplet suspension" which pulls the
  VM's network interface without destroying the disk. The evidence on disk is
  **preserved**.
- `ams.smarttechco.ir` A record still points to `188.166.36.41` with TTL=120s —
  the droplet IP hasn't been recycled, so the droplet still exists.

Alternative: the attacker self-destructed (noticed they were being probed and shut everything down). Less likely because:
- They would not delete their own domain's DNS record (that's registrar-level).
- They might firewall port 3000 but would keep port 22 for themselves.
- All ports timing out uniformly is more consistent with a DO-level action.
