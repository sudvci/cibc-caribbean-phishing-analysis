"""
recon.py — Next.js phishing-site reconnaissance tool
=====================================================
Fetches build manifests, JS chunks, and pages from the target site,
then searches the JS for interesting strings (API routes, form actions,
credential-harvesting patterns, external C2 URLs, etc.).

Usage:
    python recon.py

All fetched assets are saved to ./assets/.
A summary is printed to stdout and appended to writeup.md.
"""

from __future__ import annotations

import json
import re
import sys
import textwrap
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse

from curl_cffi import requests

BASE_URL = "https://cibccaribbeanid.icu"
BUILD_ID = "jS7HLfsNPkrJunzq3p8j-"

ASSETS_DIR = Path("assets")
JS_DIR = ASSETS_DIR / "js"
CSS_DIR = ASSETS_DIR / "css"
PAGES_DIR = ASSETS_DIR / "pages"

HEADERS = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
}

JS_HEADERS = {
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
    "Referer": BASE_URL + "/",
}

INTERESTING_PATTERNS: list[tuple[str, str]] = [
    ("API_ROUTE", r'(?:fetch|axios|post|get)\s*\(\s*["\'](\/[^"\']{{2,}})["\']'),
    ("ABSOLUTE_URL", r"https?://[a-zA-Z0-9._/-]{{8,}}"),
    ("FORM_ACTION", r'action\s*[=:]\s*["\']([^"\']+)["\']'),
    ("CREDENTIAL_KW", r'(?:password|passwd|pin|cvv|cardNumber|accountNumber|ssn|dob|token|secret|api[-_]?key)["\']?\s*[=:,]'),
    ("TELEGRAM", r'(?:t\.me|api\.telegram\.org)[^\s"\'.]{0,60}'),
    ("WEBHOOK", r'(?:webhook|discord\.com/api|slack\.com/services)[^\s"\'.]{0,80}'),
    ("EMAIL_HARVEST", r'mailto:[^\s"\'.]{4,}'),
    ("NEXT_ROUTE", r'"(?:/[a-z][a-z0-9/_\-]*)"'),
    ("EXTERNAL_POST", r"(?:XMLHttpRequest|fetch)\b"),
]

KNOWN_CHUNKS: list[str] = [
    "/_next/static/chunks/polyfills-42372ed130431b0a.js",
    "/_next/static/chunks/webpack-b902ad002392232f.js",
    "/_next/static/chunks/4bd1b696-7871aaffd466865a.js",
    "/_next/static/chunks/684-65a873e8c6872c40.js",
    "/_next/static/chunks/main-app-86201a5c7b6d811b.js",
    "/_next/static/chunks/509-3e5877b939fd87a8.js",
    "/_next/static/chunks/app/layout-502b8f3b4c8af488.js",
]

KNOWN_CSS: list[str] = [
    "/_next/static/css/6098925e223603aa.css",
    "/_next/static/css/6ec1c51b335e5fa2.css",
    "/_next/static/css/014d446971dfbef5.css",
]

session = requests.Session()


def get(path, *, base=BASE_URL, headers=None, retries=2):
    url = urljoin(base, path) if not path.startswith("http") else path
    h = {**HEADERS, **(headers or {})}
    for attempt in range(retries):
        try:
            r = session.get(url, impersonate="chrome", headers=h, timeout=30, allow_redirects=True)
            print(f"  GET {url}  ->  {r.status_code}")
            return r
        except Exception as exc:
            print(f"  ERROR fetching {url}: {exc}", file=sys.stderr)
            if attempt < retries - 1:
                time.sleep(1)
    return None


def safe_filename(path):
    return re.sub(r"[^\w.\-]", "_", path.lstrip("/"))


def save(dest, content):
    dest.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(content, str):
        dest.write_text(content, encoding="utf-8")
    else:
        dest.write_bytes(content)


def grep_js(source, filename):
    hits = {}
    for label, pattern in INTERESTING_PATTERNS:
        matches = list(dict.fromkeys(re.findall(pattern, source, re.IGNORECASE)))
        if matches:
            hits[label] = matches
    return hits


def fetch_build_manifests():
    manifest_path = f"/_next/static/{BUILD_ID}/_buildManifest.js"
    ssg_path = f"/_next/static/{BUILD_ID}/_ssgManifest.js"
    extra_chunks, routes = [], []

    for path, label in [(manifest_path, "buildManifest"), (ssg_path, "ssgManifest")]:
        r = get(path, headers=JS_HEADERS)
        if r is None or r.status_code != 200:
            print(f"  [!] Could not fetch {path}")
            continue
        save(ASSETS_DIR / f"{label}.js", r.text)
        if label == "buildManifest":
            pages_m = re.search(r'"sortedPages"\s*:\s*(\[[^\]]+\])', r.text)
            if pages_m:
                try:
                    routes = json.loads(pages_m.group(1))
                except json.JSONDecodeError:
                    routes = re.findall(r'"(/[^"]*)"', pages_m.group(1))
            chunk_matches = re.findall(r'"(static/chunks/[^"]+\.js)"', r.text)
            extra_chunks = [f"/_next/{c}" for c in dict.fromkeys(chunk_matches)]

    return extra_chunks, routes


def fetch_chunks(paths):
    sources = {}
    for path in paths:
        r = get(path, headers=JS_HEADERS)
        if r is None or r.status_code != 200:
            continue
        fname = safe_filename(path)
        save(JS_DIR / fname, r.text)
        sources[path] = r.text
    return sources


def probe_routes(routes):
    results = {}
    for route in routes:
        if route in ("/", "/_error", "/_app", "/_document", "/not-allowed"):
            continue
        r = get(route)
        if r is None:
            continue
        results[route] = r.status_code
        if r.status_code not in (404, 410):
            dest = PAGES_DIR / safe_filename(route + ".html")
            save(dest, r.text)
    return results


def fetch_css(paths):
    for path in paths:
        r = get(path, headers=JS_HEADERS)
        if r and r.status_code == 200:
            save(CSS_DIR / safe_filename(path), r.text)


def analyze_sources(sources):
    all_hits = {}
    for path, src in sources.items():
        hits = grep_js(src, path)
        if hits:
            all_hits[path] = hits
    return all_hits


if __name__ == "__main__":
    print(f"[*] Target: {BASE_URL}")
    print(f"[*] Build ID: {BUILD_ID}")
    ASSETS_DIR.mkdir(exist_ok=True)

    print("\n[1] Fetching build manifests ...")
    extra_chunks, routes = fetch_build_manifests()

    all_chunk_paths = list(dict.fromkeys(KNOWN_CHUNKS + extra_chunks))

    print(f"\n[2] Fetching {len(all_chunk_paths)} JS chunks ...")
    sources = fetch_chunks(all_chunk_paths)

    print("\n[3] Fetching CSS ...")
    fetch_css(KNOWN_CSS)

    print(f"\n[4] Probing {len(routes)} discovered routes ...")
    route_statuses = probe_routes(routes)

    print("\n[5] Analyzing JS sources ...")
    all_hits = analyze_sources(sources)

    print("\n[6] Done. Assets saved to ./assets/")
