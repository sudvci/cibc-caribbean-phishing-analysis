"""
generate_report.py
Converts the phishing-analysis findings into a formatted PDF report.
Usage: python generate_report.py
Output: cibc_caribbean_phishing_report.pdf
"""

import base64
import pathlib

from xhtml2pdf import pisa

here = pathlib.Path(__file__).parent

# ── embed the SMS screenshot ──────────────────────────────────────────────────
img_path = here / "text.png"
img_b64 = base64.b64encode(img_path.read_bytes()).decode() if img_path.exists() else ""
img_tag = (
    f'<img src="data:image/png;base64,{img_b64}" alt="Initial SMS received" '
    f'style="max-width:320px;border:1px solid #cccccc;margin-top:8px;">'
    if img_b64
    else "<p><em>[text.png not found]</em></p>"
)

HTML = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>CIBC Caribbean Phishing Site – Threat Analysis Report</title>
<style>
  @page {{
    size: A4;
    margin: 20mm 18mm 20mm 18mm;
  }}

  body {{
    font-family: Helvetica, Arial, sans-serif;
    font-size: 9.5pt;
    line-height: 1.5;
    color: #1a1a1a;
  }}

  /* ── Cover banner ── */
  .cover {{
    background-color: #003366;
    color: #ffffff;
    padding: 22px 20px 16px 20px;
  }}
  .cover h1 {{
    font-size: 16pt;
    color: #ffffff;
    margin: 0 0 5px 0;
  }}
  .cover p {{
    font-size: 9pt;
    color: #ccddee;
    margin: 0 0 10px 0;
  }}
  .badge {{
    background-color: #c0392b;
    color: #ffffff;
    padding: 2px 7px;
    font-size: 7.5pt;
    font-weight: bold;
  }}
  .badge-blue  {{ background-color: #1a6baa; color: #ffffff; padding: 2px 7px; font-size: 7.5pt; font-weight: bold; }}
  .badge-green {{ background-color: #1a7a4a; color: #ffffff; padding: 2px 7px; font-size: 7.5pt; font-weight: bold; }}

  /* ── Headings ── */
  h2 {{
    font-size: 11.5pt;
    color: #003366;
    border-bottom: 2px solid #003366;
    padding-bottom: 3px;
    margin-top: 20px;
    margin-bottom: 8px;
  }}
  h3 {{
    font-size: 10pt;
    color: #1a4d80;
    margin-top: 14px;
    margin-bottom: 5px;
  }}

  /* ── Callout boxes ── */
  .callout {{
    border-left: 4px solid #003366;
    background-color: #f0f5fb;
    padding: 8px 12px;
    margin: 8px 0 12px 0;
  }}
  .callout-red   {{ border-left: 4px solid #c0392b; background-color: #fdf2f0; padding: 8px 12px; margin: 8px 0 12px 0; }}
  .callout-amber {{ border-left: 4px solid #e67e22; background-color: #fdf8f0; padding: 8px 12px; margin: 8px 0 12px 0; }}
  .callout-green {{ border-left: 4px solid #1a7a4a; background-color: #f0faf4; padding: 8px 12px; margin: 8px 0 12px 0; }}

  /* ── Tables ── */
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: 8.5pt;
    margin: 6px 0 12px 0;
  }}
  th {{
    background-color: #003366;
    color: #ffffff;
    padding: 5px 7px;
    text-align: left;
    font-weight: bold;
  }}
  td {{
    padding: 4px 7px;
    border-bottom: 1px solid #dce4ef;
    vertical-align: top;
  }}
  tr.even  td {{ background-color: #f4f7fc; }}
  tr.hl    td {{ background-color: #fff3cd; font-weight: bold; }}
  tr.crit  td {{ background-color: #fde8e8; font-weight: bold; color: #990000; }}

  /* ── Code ── */
  code {{
    font-family: Courier, monospace;
    font-size: 8pt;
    background-color: #f1f3f5;
    padding: 1px 3px;
  }}
  pre {{
    background-color: #1e2330;
    color: #c9d1d9;
    font-family: Courier, monospace;
    font-size: 7.5pt;
    padding: 10px 12px;
    margin: 5px 0 10px 0;
    white-space: pre-wrap;
    word-wrap: break-word;
  }}

  /* ── Misc ── */
  p  {{ margin: 3px 0 7px 0; }}
  ul {{ margin: 3px 0 8px 0; padding-left: 18px; }}
  li {{ margin-bottom: 2px; }}
  .small {{ font-size: 8pt; color: #555555; }}
  .right {{ text-align: right; }}
  hr {{ border: none; border-top: 1px solid #dce4ef; margin: 14px 0; }}
  .pdf-pagebreak {{ page-break-before: always; }}
</style>
</head>
<body>

<!-- COVER -->
<div class="cover">
  <h1>CIBC Caribbean Phishing Site - Threat Analysis Report</h1>
  <p>Domain: <strong>cibccaribbeanid.icu</strong> &nbsp;|&nbsp;
     IP: <strong>188.166.36.41</strong> &nbsp;|&nbsp;
     Prepared: <strong>2026-05-30</strong></p>
</div>


<!-- ════════════════════════════════════
     1. EXECUTIVE SUMMARY
════════════════════════════════════ -->
<h2>1. Executive Summary</h2>

<div class="callout-red">
  <p> A multi-stage phishing kit was actively harvesting full banking
  credentials, card details, government-issued ID photos, PII, and real-time OTP codes from CIBC Caribbean
  customers via a pixel-perfect brand spoof. The attacker's deployment-management panel was inadvertently
  left internet-exposed, providing a high-value evidence point for attribution and takedown. Both the domain
  and the hosting droplet appear to have been suspended by the time this report was finalised.</p>
</div>

<p><strong>What was found:</strong> A Next.js phishing site hosted on a DigitalOcean droplet (Amsterdam)
impersonating CIBC Caribbean Online Banking. The domain was registered the same day the phishing SMS was
sent. The same server simultaneously exposed the attacker's <strong>Dokploy</strong> container-management
panel on port 3000 , a significant OPSEC mistake that reveals the full exfiltration pipeline (Telegram bot /
Discord webhook credentials stored in the panel's database).</p>

<p><strong>Data at risk per victim session:</strong> Banking username + password &rarr; debit/credit card
number, expiry, CVV &rarr; full name, date of birth, home address, phone number &rarr; government-ID photo
(front &amp; back) &rarr; email account password &rarr; live OTP / 2FA code.</p>

<p><strong>Current status (as of 2026-05-30 ~00:18 UTC):</strong> The phishing domain returns NXDOMAIN
(registry-level suspension); the droplet is unreachable on all ports (consistent with a DigitalOcean
droplet suspension). Evidence on disk is likely preserved.</p>


<!-- ════════════════════════════════════
     2. KEY FACTS AT A GLANCE
════════════════════════════════════ -->
<h2>2. Key Facts at a Glance</h2>

<table>
  <thead><tr><th>Field</th><th>Value</th></tr></thead>
  <tbody>
    <tr><td>Phishing Domain</td><td><code>cibccaribbeanid.icu</code></td></tr>
    <tr class="even"><td>Domain Registered</td><td>2026-05-29 (same day as phishing SMS)</td></tr>
    <tr><td>Registrar</td><td>PDR Ltd. / PublicDomainRegistry</td></tr>
    <tr class="even"><td>Registrar Abuse Contact</td><td><code>abuse@publicdomainregistry.com</code></td></tr>
    <tr><td>Server IP</td><td><code>188.166.36.41</code></td></tr>
    <tr class="even"><td>ASN / Hosting Provider</td><td>AS14061: DigitalOcean (Amsterdam)</td></tr>
    <tr><td>Host Abuse Contact</td><td><code>abuse@digitalocean.com</code></td></tr>
    <tr class="hl"><td>Brand Spoofed</td><td>CIBC Caribbean Online Banking (Unicode homoglyphs in page title)</td></tr>
    <tr class="hl"><td>Attacker Panel Exposed</td><td>Dokploy at <code>http://188.166.36.41:3000/</code> (no TLS, publicly reachable)</td></tr>
    <tr><td>SSH Open</td><td>Port 22: OpenSSH 9.6p1 / Ubuntu 24.04 LTS</td></tr>
    <tr class="even"><td>Exfil Method</td><td>Next.js Server Action (server-side): likely Telegram bot + Discord webhook</td></tr>
    <tr class="crit"><td>Current Domain Status</td><td>NXDOMAIN: suspended at registry level</td></tr>
    <tr class="crit"><td>Current Droplet Status</td><td>All ports timing out, consistent with DigitalOcean suspension</td></tr>
  </tbody>
</table>


<!-- ════════════════════════════════════
     3. HOW THIS WAS DISCOVERED
════════════════════════════════════ -->
<h2>3. How This Was Discovered</h2>

<p>An unsolicited SMS was received on a personal phone number that had <em>not</em> been registered with
CIBC Caribbean. The message contained a link to the phishing site. The SMS was recognised as suspicious and
the site was analysed rather than followed.</p>

<p>The site failed to load on the initial device due to anti-fingerprinting browser extensions and an
always-on VPN (Mullvad), confirming the site's bot-detection logic was active.</p>

{img_tag}
<p class="small">Figure 1: Initial phishing SMS received.</p>


<!-- ════════════════════════════════════
     4. TECHNICAL FINDINGS
════════════════════════════════════ -->
<div class="pdf-pagebreak"></div>
<h2>4. Technical Findings</h2>

<h3>4.1 Domain &amp; Hosting Details</h3>

<table>
  <thead><tr><th>Field</th><th>Value</th></tr></thead>
  <tbody>
    <tr><td>Domain</td><td><code>cibccaribbeanid.icu</code></td></tr>
    <tr class="even"><td>Title spoof technique</td><td>Unicode homoglyphs: Cyrillic characters substituted for Latin in page title; visually identical to "CIBC Caribbean Online Banking"</td></tr>
    <tr><td>Search engine hiding</td><td><code>noindex, nofollow</code> meta tag present</td></tr>
    <tr class="even"><td>IP Address</td><td><code>188.166.36.41</code></td></tr>
    <tr><td>ASN / Host</td><td>AS14061 DigitalOcean LLC (Amsterdam, NL)</td></tr>
    <tr class="even"><td>Registrar</td><td>PDR Ltd. / PublicDomainRegistry</td></tr>
    <tr><td>Registrar Abuse Email</td><td><code>abuse@publicdomainregistry.com</code></td></tr>
    <tr class="even"><td>Host Abuse Email</td><td><code>abuse@digitalocean.com</code></td></tr>
    <tr><td>Date Registered</td><td>2026-05-29</td></tr>
    <tr class="even"><td>Tech Stack</td><td>Next.js (App Router) with React Server Components</td></tr>
    <tr><td>reCAPTCHA site key</td><td><code>6Lew2fkrAAAAAOmRUFxLnGjTwki1ex0MMCvtAqYS</code></td></tr>
    <tr class="even"><td>Next.js build ID</td><td><code>jS7HLfsNPkrJunzq3p8j-</code></td></tr>
    <tr><td>Server Action (exfil endpoint)</td><td><code>7fbd36e5371f9b7bf4658498f5c0d2e205e3c568fa</code></td></tr>
  </tbody>
</table>

<h3>4.2 Data Harvested: Multi-Step Victim Flow</h3>

<p>The kit guides victims through a sequential multi-page flow, collecting a different data type at each step:</p>

<table>
  <thead><tr><th>Step / URL</th><th>Data Collected</th></tr></thead>
  <tbody>
    <tr><td><code>/api/login</code></td><td>Banking username &amp; password</td></tr>
    <tr class="even"><td><code>/api/card</code></td><td>Card number, expiry date, CVV</td></tr>
    <tr><td><code>/api/billing</code></td><td>Full name, date of birth, phone number, home address</td></tr>
    <tr class="even"><td><code>/api/email</code></td><td>Email address, phone number</td></tr>
    <tr class="hl"><td><code>/api/document</code></td><td><strong>Government-issued ID photo, front and back</strong></td></tr>
    <tr class="crit"><td><code>/api/otp</code></td><td><strong>Live OTP / 2FA code (real-time interception)</strong></td></tr>
    <tr><td><code>/api/email/[provider]</code></td><td>Email account password + 2FA code (Gmail / Outlook / Yahoo / iCloud / AOL clones)</td></tr>
    <tr class="even"><td><code>/api/confirmation</code></td><td>Final "thank you" page shown to victim</td></tr>
  </tbody>
</table>

<div class="callout-red">
  <p><strong>Note on OTP interception:</strong> The kit captures the OTP code <em>in real time</em>, relaying
  it to the attacker before the victim is shown any success message. This allows the attacker to complete a
  fraudulent transaction while the victim is still on the page.</p>
</div>

<h3>4.3 Email Provider Cloning</h3>

<p>After the victim submits their email address, the kit performs a DNS-over-HTTPS MX lookup (via Cloudflare's
DoH API) to determine the victim's email provider, then serves a pixel-perfect clone of that provider's login
page including live 2FA interception.</p>

<table>
  <thead><tr><th>Provider</th><th>URL</th><th>Notes</th></tr></thead>
  <tbody>
    <tr><td>Gmail</td><td><code>/api/email/gmail</code></td><td>Google quantumWiz CSS inlined (1.07 MB)</td></tr>
    <tr class="even"><td>Yahoo</td><td><code>/api/email/yahoo</code></td><td>Yahoo Sans fonts from yimg.com (723 KB)</td></tr>
    <tr><td>iCloud</td><td><code>/api/email/icloud</code></td><td>Full Apple UI + 2FA interception (3.3 MB)</td></tr>
    <tr class="even"><td>AOL</td><td><code>/api/email/aol</code></td><td>Same template as Yahoo (722 KB)</td></tr>
    <tr><td>Live / Hotmail</td><td><code>/api/email/live</code></td><td>Hardcoded Microsoft PPFT token (116 KB)</td></tr>
    <tr class="even"><td>Custom-domain Gmail</td><td>(detected via DoH MX)</td><td>Catches Google Workspace users</td></tr>
  </tbody>
</table>

<h3>4.4 Anti-Bot &amp; Evasion Techniques</h3>

<ul>
  <li><strong>Server-side middleware:</strong> Blocks VPN / datacenter IPs. Residential IPs see a decoy
  "Access not allowed" page and are redirected to <code>/login</code> if they pass.</li>
  <li><strong>Client-side fingerprinting (4-second timer):</strong> Checks for <code>navigator.webdriver</code>,
  missing browser languages, touch-point mismatches, software GPU renderers, and lack of human interaction.
  Redirects flagged browsers to <code>/api/block</code>.</li>
  <li><strong>Invisible reCAPTCHA:</strong> Wrapped around the entire app, but the token is <em>never
  validated server-side</em> (a dummy token returns <code>{{"sent":true}}</code>).</li>
  <li><strong>Stolen CIBC Caribbean CSS:</strong> Uses the real bank's compiled Angular CSS
  (<code>[_ngcontent-qea-c664]</code> selectors), making pages visually identical to legitimate banking pages.</li>
  <li><strong>Unicode spoofing:</strong> Page title uses Cyrillic characters visually identical to Latin letters.</li>
  <li><strong>Middleware bypass:</strong> The <code>/api/[page]</code> route bypasses middleware entirely,
  all harvesting pages were directly accessible.</li>
</ul>


<!-- ════════════════════════════════════
     5. ATTACKER'S DOKPLOY PANEL
════════════════════════════════════ -->
<div class="pdf-pagebreak"></div>
<h2>5. Attacker's Exposed Dokploy Panel</h2>

<div class="callout-amber">
  <p><strong>Key OPSEC failure:</strong> The attacker left their <strong>Dokploy</strong>
  deployment-management panel publicly accessible on <code>http://188.166.36.41:3000/</code> (no TLS,
  no IP restriction). This panel manages the phishing-kit container and stores the exfiltration secrets
  (Telegram bot token, Discord webhook URL) in its PostgreSQL database and container environment variables.
  This is the single highest-value artefact for attribution and for identifying where harvested data was sent.</p>
</div>

<h3>5.1 Open Ports (confirmed)</h3>

<table>
  <thead><tr><th>Port</th><th>Status</th><th>Service</th></tr></thead>
  <tbody>
    <tr class="hl"><td>22</td><td>OPEN</td><td>SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.16 - Ubuntu 24.04 LTS</td></tr>
    <tr class="hl"><td>3000</td><td>OPEN</td><td>Dokploy deployment manager (Next.js, HTTP only)</td></tr>
    <tr><td>2375 / 2376</td><td>Closed</td><td>Docker API (unexposed)</td></tr>
    <tr class="even"><td>5432 / 6379 / 27017</td><td>Closed</td><td>PostgreSQL / Redis / MongoDB (unexposed)</td></tr>
  </tbody>
</table>

<h3>5.2 Authentication Surface</h3>
<ul>
  <li>Registration is blocked: <code>Admin is already created</code>.</li>
  <li>Login returns identical errors for unknown-user vs. wrong-password - no email enumeration possible.</li>
  <li>Rate limit: approximately 3 attempts per IP before HTTP 429 online brute-force is infeasible.</li>
  <li>GitHub OAuth present but <code>client_id=undefined</code>; Google OAuth returns HTTP 500.</li>
  <li>Admin authenticates with email + password only.</li>
</ul>

<h3>5.3 Confirmed Exfil Channels (from Dokploy schema)</h3>

<table>
  <thead><tr><th>Channel</th><th>Stored Credentials</th></tr></thead>
  <tbody>
    <tr class="hl"><td>Telegram</td><td><code>botToken</code>, <code>chatId</code>, <code>messageThreadId</code> (optional)</td></tr>
    <tr class="hl"><td>Discord</td><td><code>webhookUrl</code></td></tr>
    <tr><td>Slack</td><td><code>webhookUrl</code>, <code>channel</code></td></tr>
    <tr class="even"><td>Email / SMTP</td><td><code>smtpServer</code>, <code>smtpPort</code>, <code>username</code>, <code>password</code>, <code>fromAddress</code>, <code>toAddress</code></td></tr>
    <tr><td>Other</td><td>Ntfy, Pushover, Gotify, Mattermost, Resend, Teams, Custom</td></tr>
  </tbody>
</table>

<p>The tRPC procedures <code>notification.testTelegramConnection</code> and
<code>notification.testDiscordConnection</code> return <strong>HTTP 401</strong> (not 404), confirming both
channels are configured and active on the server.</p>

<h3>5.4 Additional Artefacts from Dokploy</h3>
<ul>
  <li>Dokploy build ID: <code>88EvmKYaqpt89OTUtSZnM</code></li>
  <li>Self-hosted instance (not cloud): confirmed via <code>settings.isCloud &rarr; false</code></li>
  <li>The environment-variable editor route (<code>/dashboard/project/[id]/environment/[id]</code>) is where
  <code>TELEGRAM_BOT_TOKEN</code> / <code>TELEGRAM_CHAT_ID</code> live for an authenticated admin.</li>
  <li>OPSEC leak: <code>/api/block</code> redirects to <code>https://localhost:3000/not-allowed</code>,
  confirming internal Dokploy port.</li>
</ul>


<!-- ════════════════════════════════════
     6. TAKEDOWN STATUS
════════════════════════════════════ -->
<h2>6. Takedown Status</h2>
<p><strong>Confirmed as of 2026-05-30 ~00:18 UTC</strong></p>

<table>
  <thead><tr><th>Check</th><th>Result</th></tr></thead>
  <tbody>
    <tr class="crit"><td><code>cibccaribbeanid.icu</code> DNS (DoH)</td><td>NXDOMAIN (RCODE 3):  domain does not exist</td></tr>
    <tr class="crit"><td><code>188.166.36.41</code> TCP port 22</td><td>TIMEOUT (no banner)</td></tr>
    <tr class="crit"><td><code>188.166.36.41</code> TCP port 3000</td><td>TIMEOUT</td></tr>
    <tr class="crit"><td><code>188.166.36.41</code> TCP ports 80 / 443</td><td>TIMEOUT</td></tr>
    <tr class="even"><td><code>ams.smarttechco.ir</code> DNS</td><td>Still resolves to <code>188.166.36.41</code> (TTL=120 s): droplet IP not recycled</td></tr>
    <tr><td>DigitalOcean platform status</td><td>All Systems Operational</td></tr>
  </tbody>
</table>

<div class="callout-green">
  <p><strong>Most likely interpretation:</strong> The phishing domain was suspended at registrar / registry
  level (NXDOMAIN), and DigitalOcean has suspended or firewalled the droplet in response to an abuse report.
  Ports are <em>timing out</em> (not connection-refused), consistent with a DigitalOcean droplet suspension,
  the VM's network interface is pulled without destroying the disk.
  <strong>Evidence on disk is likely preserved.</strong></p>
  <p>The <code>ams.smarttechco.ir</code> A record still points to the same IP (TTL=120 s), suggesting the
  droplet IP has not been recycled and the droplet still exists in DigitalOcean's infrastructure.</p>
</div>

<h3>6.1 Alternative Interpretation</h3>
<p>The attacker may have self-destructed after noticing reconnaissance activity. This is considered unlikely because:</p>
<ul>
  <li>An attacker would likely keep port 22 open for their own access.</li>
  <li>All ports timing out uniformly is more consistent with a hosting-provider action.</li>
</ul>


<!-- ════════════════════════════════════
     7. RECOMMENDED ACTIONS
════════════════════════════════════ -->
<div class="pdf-pagebreak"></div>
<h2>7. Recommended Actions for Anti-Fraud Teams</h2>

<table>
  <thead><tr><th>Priority</th><th>Action</th><th>Contact</th></tr></thead>
  <tbody>
    <tr class="crit">
      <td>P1</td>
      <td>Request DigitalOcean <strong>preserve</strong> disk image of droplet <code>188.166.36.41</code> before it is destroyed. Contains exfil credentials, harvested victim data, and Dokploy PostgreSQL database.</td>
      <td><code>abuse@digitalocean.com</code></td>
    </tr>
    <tr class="crit">
      <td>P1</td>
      <td>Confirm domain suspension with PDR / .icu registry. Request WHOIS data including registrant email for attribution.</td>
      <td><code>abuse@publicdomainregistry.com</code></td>
    </tr>
    <tr class="hl">
      <td>P2</td>
      <td>Identify Telegram bot token + chat ID from preserved disk (Dokploy PostgreSQL). Request Telegram account suspension and conversation data via legal process.</td>
      <td>Telegram Trust &amp; Safety</td>
    </tr>
    <tr class="hl">
      <td>P2</td>
      <td>Identify Discord webhook URL from preserved disk. Request Discord account suspension and data preservation.</td>
      <td>Discord Trust &amp; Safety</td>
    </tr>
    <tr>
      <td>P3</td>
      <td>Alert CIBC Caribbean fraud operations. Customers who received the phishing SMS and may have submitted data before takedown should be identified via SMS campaign records and have cards / credentials reset proactively.</td>
      <td>CIBC Caribbean Internal</td>
    </tr>
    <tr class="even">
      <td>P3</td>
      <td>Report reCAPTCHA site key <code>6Lew2fkrAAAAAOmRUFxLnGjTwki1ex0MMCvtAqYS</code> to Google for abuse tracking.</td>
      <td>Google Safe Browsing</td>
    </tr>
    <tr>
      <td>P3</td>
      <td>Investigate <code>ams.smarttechco.ir</code>: A record still points to attacker IP. May be a related domain or pivot point; investigate registrant for attribution.</td>
      <td>Internal / OSINT</td>
    </tr>
  </tbody>
</table>

<hr>

</body>
</html>
"""

output_path = here / "cibc_caribbean_phishing_report.pdf"
print("Rendering PDF…")

with open(output_path, "wb") as pdf_file:
    result = pisa.CreatePDF(HTML, dest=pdf_file)

if result.err:
    print(f"Error generating PDF: {result.err}")
else:
    size_kb = output_path.stat().st_size // 1024
    print(f"Done — {output_path}  ({size_kb} KB)")
