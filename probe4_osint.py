#!/usr/bin/env python3
"""
probe4_osint.py — Tier A: Fully-passive OSINT clustering

Goal: build an infrastructure/attribution cluster around the attacker droplet
without sending a single packet to the target host.

APIs used (all free / no key required unless noted):
  A. crt.sh              — SSL cert history for domain + IP
  B. Shodan InternetDB   — free port/vuln/hostname snapshot (no key)
  C. GreyNoise Community — noise classification + tags (no key, rate-limited)
  D. CIRCL Passive DNS   — passive DNS history for domain + IP (no key)
  E. CIRCL Passive SSL   — passive SSL for IP (no key)
  F. hackertarget        — reverse-IP lookup (other domains on same droplet)
  G. URLhaus             — malware/phishing URL database lookup
  H. urlscan.io          — public scan history for domain + IP (no key)
  I. PhishTank           — community phishing database check (no key)
  J. reCAPTCHA key OSINT — search urlscan.io + crt.sh for kit reuse
  K. GitHub code search  — Server Action ID + reCAPTCHA key reuse in public repos
  L. ipinfo.io           — ASN / org / abuse contact enrichment (no key)

Results saved to:
  recon/phase4_osint.json   — machine-readable
  recon/phase4_osint.md     — human-readable summary
"""

import asyncio
import json
import re
from datetime import datetime, timezone
from typing import Any

import httpx

# ── IOCs ──────────────────────────────────────────────────────────────────────
DROPLET_IP = "188.166.36.41"
DOMAIN = "cibccaribbeanid.icu"
RECAPTCHA_KEY = "6Lew2fkrAAAAAOmRUFxLnGjTwki1ex0MMCvtAqYS"
SERVER_ACTION_ID = "7fbd36e5371f9b7bf4658498f5c0d2e205e3c568fa"
PHISH_BUILD_ID = "jS7HLfsNPkrJunzq3p8j-"
DOKPLOY_BUILD_ID = "88EvmKYaqpt89OTUtSZnM"
PNC_TEMPLATE_STR = "PNC account"

OUTPUT_JSON = "recon/phase4_osint.json"
OUTPUT_MD = "recon/phase4_osint.md"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)

results: dict[str, Any] = {}


# ── helpers ───────────────────────────────────────────────────────────────────
def ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def log(msg: str) -> None:
    print(f"[{ts()}] {msg}", flush=True)


async def fetch_json(
    client: httpx.AsyncClient,
    label: str,
    url: str,
    method: str = "GET",
    body: dict | None = None,
    extra_hdrs: dict | None = None,
    timeout: float = 15.0,
) -> dict:
    hdrs = {
        "User-Agent": UA,
        "Accept": "application/json",
        **(extra_hdrs or {}),
    }
    try:
        if method == "POST":
            r = await client.post(url, json=body, headers=hdrs, timeout=timeout)
        else:
            r = await client.get(url, headers=hdrs, timeout=timeout)
        log(f"[{label}] {method} {url}  ->  HTTP {r.status_code}")
        try:
            return {"status": r.status_code, "data": r.json()}
        except Exception:
            return {"status": r.status_code, "data": r.text[:2000]}
    except Exception as exc:
        log(f"[{label}] ERROR  {exc}")
        return {"status": -1, "error": str(exc)}


# ── A: crt.sh ─────────────────────────────────────────────────────────────────
async def run_crtsh(client: httpx.AsyncClient) -> None:
    log("\n=== A: crt.sh certificate history ===")

    queries = {
        "domain": f"https://crt.sh/?q={DOMAIN}&output=json",
        "ip": f"https://crt.sh/?q={DROPLET_IP}&output=json",
        "wildcard_tld": "https://crt.sh/?q=%.icu&output=json",  # .icu registrations (huge, first 200)
    }

    crtsh: dict[str, Any] = {}
    for key, url in queries.items():
        r = await fetch_json(client, f"crtsh/{key}", url, timeout=30)
        if isinstance(r.get("data"), list):
            certs = r["data"]
            # Deduplicate and summarise
            seen = set()
            summary = []
            for c in certs:
                cn = c.get("common_name", "")
                names = c.get("name_value", "")
                issued = c.get("not_before", "")
                issuer = c.get("issuer_name", "")
                entry_id = c.get("id", "")
                if (cn, names) not in seen:
                    seen.add((cn, names))
                    summary.append(
                        {
                            "id": entry_id,
                            "cn": cn,
                            "san": names,
                            "not_before": issued,
                            "issuer": issuer,
                        }
                    )
            crtsh[key] = {
                "count": len(certs),
                "unique": len(summary),
                "certs": summary[:100],
            }
            log(f"  crt.sh/{key}: {len(certs)} raw / {len(summary)} unique certs")
        else:
            crtsh[key] = r

    # Pivot: look for other domains sharing the same issuer/registrant pattern
    domain_certs = crtsh.get("domain", {}).get("certs", [])
    other_domains = set()
    for c in domain_certs:
        for name in c.get("san", "").split("\n"):
            name = name.strip().lstrip("*.")
            if name and name != DOMAIN:
                other_domains.add(name)
    crtsh["related_domains_in_san"] = sorted(other_domains)
    log(f"  crt.sh: {len(other_domains)} other domains in SANs")

    results["crtsh"] = crtsh


# ── B: Shodan InternetDB ──────────────────────────────────────────────────────
async def run_shodan_internetdb(client: httpx.AsyncClient) -> None:
    log("\n=== B: Shodan InternetDB (no key) ===")
    url = f"https://internetdb.shodan.io/{DROPLET_IP}"
    r = await fetch_json(client, "shodan_internetdb", url)
    results["shodan_internetdb"] = r
    if isinstance(r.get("data"), dict):
        d = r["data"]
        log(f"  ports: {d.get('ports')}")
        log(f"  vulns: {d.get('vulns')}")
        log(f"  hostnames: {d.get('hostnames')}")
        log(f"  tags: {d.get('tags')}")
        log(f"  cpes: {d.get('cpes')}")


# ── C: GreyNoise Community ────────────────────────────────────────────────────
async def run_greynoise(client: httpx.AsyncClient) -> None:
    log("\n=== C: GreyNoise Community ===")
    url = f"https://api.greynoise.io/v3/community/{DROPLET_IP}"
    r = await fetch_json(client, "greynoise", url)
    results["greynoise"] = r
    if isinstance(r.get("data"), dict):
        d = r["data"]
        log(f"  classification: {d.get('classification')}")
        log(f"  name: {d.get('name')}")
        log(f"  last_seen: {d.get('last_seen')}")
        log(f"  tags: {d.get('tags')}")


# ── D: CIRCL Passive DNS ──────────────────────────────────────────────────────
async def run_circl_pdns(client: httpx.AsyncClient) -> None:
    log("\n=== D: CIRCL Passive DNS ===")

    endpoints = {
        "domain": f"https://www.circl.lu/pdns/query/{DOMAIN}",
        "ip": f"https://www.circl.lu/pdns/query/{DROPLET_IP}",
    }
    pdns: dict[str, Any] = {}
    for key, url in endpoints.items():
        # CIRCL PDNS returns newline-delimited JSON objects
        hdrs = {"User-Agent": UA, "Accept": "application/json"}
        try:
            r = await client.get(url, headers=hdrs, timeout=20)
            log(f"[circl_pdns/{key}] HTTP {r.status_code}")
            records = []
            for line in r.text.splitlines():
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except Exception:
                        pass
            pdns[key] = {"count": len(records), "records": records[:200]}
            log(f"  CIRCL PDNS/{key}: {len(records)} records")
        except Exception as exc:
            log(f"[circl_pdns/{key}] ERROR  {exc}")
            pdns[key] = {"error": str(exc)}

    # Extract unique rdata values for pivoting
    all_rdata = set()
    for key, data in pdns.items():
        for rec in data.get("records", []):
            all_rdata.add(rec.get("rdata", ""))
    pdns["unique_rdata"] = sorted(all_rdata - {""})
    log(f"  CIRCL PDNS: {len(pdns['unique_rdata'])} unique rdata values")
    results["circl_pdns"] = pdns


# ── E: CIRCL Passive SSL ──────────────────────────────────────────────────────
async def run_circl_pssl(client: httpx.AsyncClient) -> None:
    log("\n=== E: CIRCL Passive SSL ===")
    url = f"https://www.circl.lu/v2pssl/query/{DROPLET_IP}"
    try:
        hdrs = {"User-Agent": UA, "Accept": "application/json"}
        r = await client.get(url, headers=hdrs, timeout=20)
        log(f"[circl_pssl] HTTP {r.status_code}")
        try:
            data = r.json()
        except Exception:
            data = r.text[:2000]
        results["circl_pssl"] = {"status": r.status_code, "data": data}
        if isinstance(data, dict):
            subjects = data.get("subjects", {})
            log(f"  CIRCL PSSL: {len(subjects)} cert subjects")
    except Exception as exc:
        log(f"[circl_pssl] ERROR  {exc}")
        results["circl_pssl"] = {"error": str(exc)}


# ── F: hackertarget reverse IP ────────────────────────────────────────────────
async def run_hackertarget(client: httpx.AsyncClient) -> None:
    log("\n=== F: hackertarget reverse IP ===")
    url = f"https://api.hackertarget.com/reverseiplookup/?q={DROPLET_IP}"
    hdrs = {"User-Agent": UA}
    try:
        r = await client.get(url, headers=hdrs, timeout=20)
        log(f"[hackertarget] HTTP {r.status_code}")
        text = r.text.strip()
        domains = [d.strip() for d in text.splitlines() if d.strip()]
        results["hackertarget_reverse_ip"] = {
            "status": r.status_code,
            "raw": text[:2000],
            "domains": domains,
            "count": len(domains),
        }
        log(f"  hackertarget: {len(domains)} co-hosted domains")
        for d in domains[:20]:
            log(f"    {d}")
    except Exception as exc:
        log(f"[hackertarget] ERROR  {exc}")
        results["hackertarget_reverse_ip"] = {"error": str(exc)}


# ── G: URLhaus ────────────────────────────────────────────────────────────────
async def run_urlhaus(client: httpx.AsyncClient) -> None:
    log("\n=== G: URLhaus lookup ===")
    base = "https://urlhaus-api.abuse.ch/v1"
    queries = [
        ("host_domain", f"{base}/host/", {"host": DOMAIN}),
        ("host_ip", f"{base}/host/", {"host": DROPLET_IP}),
        ("url_kit", f"{base}/url/", {"url": f"https://{DOMAIN}/api/login"}),
    ]
    urlhaus: dict[str, Any] = {}
    for key, url, body in queries:
        r = await fetch_json(client, f"urlhaus/{key}", url, method="POST", body=body)
        urlhaus[key] = r
        if isinstance(r.get("data"), dict):
            d = r["data"]
            qs = d.get("query_status", "")
            log(f"  URLhaus/{key}: status={qs}  urls={len(d.get('urls', []))}")
    results["urlhaus"] = urlhaus


# ── H: urlscan.io ─────────────────────────────────────────────────────────────
async def run_urlscan(client: httpx.AsyncClient) -> None:
    log("\n=== H: urlscan.io search ===")
    base = "https://urlscan.io/api/v1/search"
    queries = {
        "domain": f"{base}/?q=domain:{DOMAIN}&size=50",
        "ip": f"{base}/?q=ip:{DROPLET_IP}&size=100",
        "recaptcha_key": (f'{base}/?q=page.url:"{RECAPTCHA_KEY}"&size=50'),
        "action_id": (f'{base}/?q="{SERVER_ACTION_ID}"&size=20'),
    }
    urlscan: dict[str, Any] = {}
    for key, url in queries.items():
        r = await fetch_json(client, f"urlscan/{key}", url, timeout=20)
        urlscan[key] = r
        if isinstance(r.get("data"), dict):
            total = r["data"].get("total", 0)
            results_list = r["data"].get("results", [])
            log(f"  urlscan/{key}: {total} total hits, got {len(results_list)}")
            # Summarise unique domains / IPs found
            related = set()
            for item in results_list:
                pg = item.get("page", {})
                related.add(pg.get("domain", ""))
                related.add(pg.get("ip", ""))
            related.discard("")
            urlscan[f"{key}_related"] = sorted(related)
        await asyncio.sleep(1.0)  # urlscan rate-limit: be gentle
    results["urlscan"] = urlscan


# ── I: PhishTank ──────────────────────────────────────────────────────────────
async def run_phishtank(client: httpx.AsyncClient) -> None:
    log("\n=== I: PhishTank URL check ===")
    # PhishTank public API — no key required (rate limited to ~1 req/min per IP)
    import urllib.parse

    target_urls = [
        f"https://{DOMAIN}/",
        f"https://{DOMAIN}/api/login",
        f"http://{DROPLET_IP}:3000/",
    ]
    phishtank: dict[str, Any] = {}
    for target_url in target_urls:
        key = re.sub(r"[^\w]", "_", target_url)[:40]
        encoded = urllib.parse.urlencode(
            {
                "url": target_url,
                "format": "json",
            }
        )
        try:
            r = await client.post(
                "https://checkurl.phishtank.com/checkurl/",
                content=encoded,
                headers={
                    "User-Agent": UA,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
                timeout=20,
            )
            log(f"[phishtank] {target_url}  ->  HTTP {r.status_code}")
            try:
                data = r.json()
            except Exception:
                data = r.text[:500]
            phishtank[key] = {"url": target_url, "status": r.status_code, "data": data}
        except Exception as exc:
            log(f"[phishtank] ERROR  {exc}")
            phishtank[key] = {"url": target_url, "error": str(exc)}
        await asyncio.sleep(2.0)  # PhishTank is aggressive with rate-limits
    results["phishtank"] = phishtank


# ── J: reCAPTCHA key / build-ID OSINT via urlscan.io ─────────────────────────
async def run_recaptcha_osint(client: httpx.AsyncClient) -> None:
    log("\n=== J: reCAPTCHA key & build-ID clustering ===")
    queries = {
        "recaptcha_in_page": (
            f'https://urlscan.io/api/v1/search/?q=page.dom:"{RECAPTCHA_KEY}"&size=50'
        ),
        "phish_build_id": (
            f'https://urlscan.io/api/v1/search/?q="{PHISH_BUILD_ID}"&size=20'
        ),
        "dokploy_build_id": (
            f'https://urlscan.io/api/v1/search/?q="{DOKPLOY_BUILD_ID}"&size=20'
        ),
    }
    recaptcha: dict[str, Any] = {}
    for key, url in queries.items():
        r = await fetch_json(client, f"recaptcha/{key}", url, timeout=20)
        recaptcha[key] = r
        if isinstance(r.get("data"), dict):
            total = r["data"].get("total", 0)
            hits = r["data"].get("results", [])
            log(f"  recaptcha/{key}: {total} hits")
            domains = sorted(
                {item.get("page", {}).get("domain", "") for item in hits} - {""}
            )
            recaptcha[f"{key}_domains"] = domains
            if domains:
                log(f"    domains: {domains}")
        await asyncio.sleep(1.0)
    results["recaptcha_osint"] = recaptcha


# ── K: GitHub code search (public kit reuse) ──────────────────────────────────
async def run_github_search(client: httpx.AsyncClient) -> None:
    log("\n=== K: GitHub code search for kit reuse ===")
    # GitHub search API — no key gives 10 req/min; we make 3 queries
    base = "https://api.github.com/search/code"
    queries = {
        "recaptcha_key": f"{base}?q={RECAPTCHA_KEY}&per_page=10",
        "server_action": f"{base}?q={SERVER_ACTION_ID}&per_page=10",
        "pnc_template": f"{base}?q=%22PNC+account%22+%22CIBC%22&per_page=10",
    }
    gh: dict[str, Any] = {}
    for key, url in queries.items():
        r = await fetch_json(
            client,
            f"github/{key}",
            url,
            extra_hdrs={
                "Accept": "application/vnd.github.v3+json",
                "X-GitHub-Api-Version": "2022-11-28",
            },
            timeout=20,
        )
        gh[key] = r
        if isinstance(r.get("data"), dict):
            total = r["data"].get("total_count", 0)
            items = r["data"].get("items", [])
            log(f"  github/{key}: {total} total hits")
            for item in items[:5]:
                log(
                    f"    {item.get('repository', {}).get('full_name')} — {item.get('path')}"
                )
        await asyncio.sleep(7.0)  # GitHub unauthenticated: 10 req/min
    results["github_search"] = gh


# ── L: ipinfo.io enrichment ───────────────────────────────────────────────────
async def run_ipinfo(client: httpx.AsyncClient) -> None:
    log("\n=== L: ipinfo.io enrichment ===")
    url = f"https://ipinfo.io/{DROPLET_IP}/json"
    r = await fetch_json(client, "ipinfo", url)
    results["ipinfo"] = r
    if isinstance(r.get("data"), dict):
        d = r["data"]
        log(f"  org:      {d.get('org')}")
        log(f"  hostname: {d.get('hostname')}")
        log(f"  city:     {d.get('city')}, {d.get('country')}")
        log(f"  abuse:    {d.get('abuse', {})}")


# ── M: Abuse.ch ThreatFox ─────────────────────────────────────────────────────
async def run_threatfox(client: httpx.AsyncClient) -> None:
    log("\n=== M: Abuse.ch ThreatFox IOC search ===")
    base = "https://threatfox-api.abuse.ch/api/v1/"
    queries = [
        ("domain", {"query": "search_ioc", "search_term": DOMAIN}),
        ("ip", {"query": "search_ioc", "search_term": DROPLET_IP}),
    ]
    threatfox: dict[str, Any] = {}
    for key, body in queries:
        r = await fetch_json(client, f"threatfox/{key}", base, method="POST", body=body)
        threatfox[key] = r
        if isinstance(r.get("data"), dict):
            status = r["data"].get("query_status", "")
            iocs = r["data"].get("data", [])
            log(
                f"  ThreatFox/{key}: {status}, {len(iocs) if isinstance(iocs, list) else '?'} IOCs"
            )
        await asyncio.sleep(1.0)
    results["threatfox"] = threatfox


# ── Markdown report ───────────────────────────────────────────────────────────
def write_markdown_report() -> None:
    lines: list[str] = []
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines += [
        f"# Phase 4 — Passive OSINT Report",
        f"",
        f"**Generated:** {now}  ",
        f"**Target:** `{DOMAIN}` / `{DROPLET_IP}`  ",
        f"",
        "---",
        "",
    ]

    # crt.sh
    lines += ["## A. crt.sh — Certificate History", ""]
    crtsh = results.get("crtsh", {})
    domain_certs = crtsh.get("domain", {}).get("certs", [])
    lines.append(
        f"**Domain `{DOMAIN}`:** {crtsh.get('domain', {}).get('count', 0)} certs "
        f"({crtsh.get('domain', {}).get('unique', 0)} unique)"
    )
    lines.append("")
    if domain_certs:
        lines.append("| Issued | CN | SANs | Issuer |")
        lines.append("|---|---|---|---|")
        for c in domain_certs[:20]:
            lines.append(
                f"| {c.get('not_before', '')[:10]} "
                f"| `{c.get('cn', '')}` "
                f"| `{c.get('san', '')[:60]}` "
                f"| {c.get('issuer', '')[:40]} |"
            )
    related = crtsh.get("related_domains_in_san", [])
    if related:
        lines += ["", f"**Related domains in SANs:**"]
        for d in related[:30]:
            lines.append(f"- `{d}`")
    lines.append("")

    # Shodan InternetDB
    lines += ["## B. Shodan InternetDB", ""]
    sid = results.get("shodan_internetdb", {})
    if isinstance(sid.get("data"), dict):
        d = sid["data"]
        lines.append(f"| Field | Value |")
        lines.append(f"|---|---|")
        lines.append(f"| Ports open | `{d.get('ports', [])}` |")
        lines.append(f"| Vulns | `{d.get('vulns', [])}` |")
        lines.append(f"| Hostnames | `{d.get('hostnames', [])}` |")
        lines.append(f"| Tags | `{d.get('tags', [])}` |")
        lines.append(f"| CPEs | `{d.get('cpes', [])}` |")
    else:
        lines.append(f"```\n{sid}\n```")
    lines.append("")

    # GreyNoise
    lines += ["## C. GreyNoise Community", ""]
    gn = results.get("greynoise", {})
    if isinstance(gn.get("data"), dict):
        d = gn["data"]
        lines.append(f"- **Classification:** {d.get('classification')}")
        lines.append(f"- **Name:** {d.get('name')}")
        lines.append(f"- **Last seen:** {d.get('last_seen')}")
        lines.append(f"- **Tags:** {d.get('tags')}")
        lines.append(f"- **Message:** {d.get('message')}")
    else:
        lines.append(f"```\n{gn}\n```")
    lines.append("")

    # CIRCL Passive DNS
    lines += ["## D. CIRCL Passive DNS", ""]
    pdns = results.get("circl_pdns", {})
    for key in ("domain", "ip"):
        recs = pdns.get(key, {}).get("records", [])
        lines.append(f"**{key.upper()}** — {pdns.get(key, {}).get('count', 0)} records")
        if recs:
            lines.append("")
            lines.append("| rrtype | rdata | time_first | time_last |")
            lines.append("|---|---|---|---|")
            for rec in recs[:30]:
                lines.append(
                    f"| {rec.get('rrtype', '')} "
                    f"| `{rec.get('rdata', '')}` "
                    f"| {rec.get('time_first', '')[:10]} "
                    f"| {rec.get('time_last', '')[:10]} |"
                )
        lines.append("")
    rdata_vals = pdns.get("unique_rdata", [])
    if rdata_vals:
        lines.append(f"**Unique rdata pivot values:** {rdata_vals}")
    lines.append("")

    # hackertarget
    lines += ["## F. hackertarget Reverse IP", ""]
    ht = results.get("hackertarget_reverse_ip", {})
    domains = ht.get("domains", [])
    lines.append(f"**Co-hosted domains on `{DROPLET_IP}`:** {ht.get('count', 0)}")
    if domains:
        lines.append("")
        for d in domains[:50]:
            lines.append(f"- `{d}`")
    lines.append("")

    # URLhaus
    lines += ["## G. URLhaus", ""]
    uh = results.get("urlhaus", {})
    for key, val in uh.items():
        data = val.get("data", {}) if isinstance(val, dict) else {}
        qs = data.get("query_status", "N/A") if isinstance(data, dict) else "N/A"
        urls = data.get("urls", []) if isinstance(data, dict) else []
        lines.append(f"**{key}:** `{qs}` — {len(urls)} URLs")
        for u in urls[:5]:
            lines.append(
                f"  - {u.get('url', '')[:80]}  (status: {u.get('url_status', '')})"
            )
    lines.append("")

    # urlscan.io
    lines += ["## H. urlscan.io Search Results", ""]
    us = results.get("urlscan", {})
    for key in ("domain", "ip", "recaptcha_key", "action_id"):
        val = us.get(key, {})
        data = val.get("data", {}) if isinstance(val, dict) else {}
        total = data.get("total", 0) if isinstance(data, dict) else 0
        lines.append(f"**{key}:** {total} total hits")
        rel = us.get(f"{key}_related", [])
        if rel:
            lines.append(f"  Related: {rel[:20]}")
    lines.append("")

    # reCAPTCHA OSINT
    lines += ["## J. reCAPTCHA Key & Build-ID Clustering", ""]
    rc = results.get("recaptcha_osint", {})
    for key in ("recaptcha_in_page", "phish_build_id", "dokploy_build_id"):
        val = rc.get(key, {})
        data = val.get("data", {}) if isinstance(val, dict) else {}
        total = data.get("total", 0) if isinstance(data, dict) else 0
        domains = rc.get(f"{key}_domains", [])
        lines.append(f"**{key}:** {total} hits — domains: {domains[:10] or 'none'}")
    lines.append("")

    # GitHub
    lines += ["## K. GitHub Code Search", ""]
    gh = results.get("github_search", {})
    for key, val in gh.items():
        data = val.get("data", {}) if isinstance(val, dict) else {}
        total = data.get("total_count", 0) if isinstance(data, dict) else 0
        lines.append(f"**{key}:** {total} total hits")
        items = data.get("items", []) if isinstance(data, dict) else []
        for item in items[:5]:
            lines.append(
                f"  - `{item.get('repository', {}).get('full_name')}` — `{item.get('path')}`"
            )
    lines.append("")

    # ThreatFox
    lines += ["## M. ThreatFox IOC Search", ""]
    tf = results.get("threatfox", {})
    for key, val in tf.items():
        data = val.get("data", {}) if isinstance(val, dict) else {}
        qs = data.get("query_status", "N/A") if isinstance(data, dict) else "N/A"
        iocs = data.get("data", []) if isinstance(data, dict) else []
        lines.append(
            f"**{key}:** `{qs}` — {len(iocs) if isinstance(iocs, list) else '?'} IOCs"
        )
        if isinstance(iocs, list):
            for ioc in iocs[:5]:
                lines.append(f"  - {ioc}")
    lines.append("")

    with open(OUTPUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))
    log(f"\nMarkdown report written to {OUTPUT_MD}")


# ── main ──────────────────────────────────────────────────────────────────────
async def main() -> None:
    log(f"=== probe4_osint.py — Tier A Passive OSINT ===")
    log(f"Target: {DOMAIN} / {DROPLET_IP}")
    log("No packets sent to target — all queries go to third-party databases.\n")

    async with httpx.AsyncClient(
        verify=False, follow_redirects=True, timeout=20
    ) as client:
        # Sequential ordering matters: some use outputs of earlier steps
        await run_crtsh(client)
        await asyncio.sleep(1.0)
        await run_shodan_internetdb(client)
        await asyncio.sleep(1.0)
        await run_greynoise(client)
        await asyncio.sleep(1.0)
        await run_circl_pdns(client)
        await asyncio.sleep(1.0)
        await run_circl_pssl(client)
        await asyncio.sleep(1.0)
        await run_hackertarget(client)
        await asyncio.sleep(1.5)
        await run_urlhaus(client)
        await asyncio.sleep(1.0)
        await run_urlscan(client)  # internally rate-limited: ~4 s
        await asyncio.sleep(1.0)
        await run_phishtank(client)  # internally rate-limited: ~6 s
        await asyncio.sleep(1.0)
        await run_recaptcha_osint(client)
        await asyncio.sleep(1.0)
        await run_github_search(client)  # internally rate-limited: ~21 s
        await asyncio.sleep(1.0)
        await run_ipinfo(client)
        await asyncio.sleep(1.0)
        await run_threatfox(client)

    # ── save results ──────────────────────────────────────────────────────────
    with open(OUTPUT_JSON, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2, default=str)
    log(f"\nJSON results saved to {OUTPUT_JSON}")

    write_markdown_report()

    # ── attribution summary ───────────────────────────────────────────────────
    log("\n" + "=" * 60)
    log("ATTRIBUTION SUMMARY")
    log("=" * 60)

    ht_domains = results.get("hackertarget_reverse_ip", {}).get("domains", [])
    log(f"Co-hosted domains on {DROPLET_IP}: {len(ht_domains)}")

    sid = results.get("shodan_internetdb", {}).get("data", {})
    if isinstance(sid, dict):
        log(f"Shodan ports: {sid.get('ports')}")
        log(f"Shodan vulns: {sid.get('vulns')}")
        log(f"Shodan hostnames: {sid.get('hostnames')}")

    rc_domains = results.get("recaptcha_osint", {}).get("recaptcha_in_page_domains", [])
    if rc_domains:
        log(f"Sites reusing same reCAPTCHA key: {rc_domains}")

    log("\nDone. Use recon/phase4_osint.md for the human-readable report.")


if __name__ == "__main__":
    asyncio.run(main())
