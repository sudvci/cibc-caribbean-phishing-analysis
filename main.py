from pathlib import Path
from typing import Final
from urllib.parse import urljoin

from curl_cffi import requests

URL: Final[str] = "https://cibccaribbeanid.icu"
OUT: Final[Path] = Path("index.html")
HEADERS: Final[dict[str, str]] = {
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.9",
    "Upgrade-Insecure-Requests": "1",
}

root = requests.get(
    URL,
    impersonate="chrome",
    headers=HEADERS,
    timeout=30,
    allow_redirects=False,
)

print(f"root_status={root.status_code}")
print(f"root_url={root.url}")
location = root.headers.get("location")
if location:
    print(f"redirect_location={location}")
    target_url = urljoin(str(root.url), location)
    res = requests.get(
        target_url,
        impersonate="chrome",
        headers=HEADERS,
        timeout=30,
        allow_redirects=False,
    )
else:
    res = root

print(f"status={res.status_code}")
print(f"url={res.url}")
server = res.headers.get("server")
if server:
    print(f"server={server}")

OUT.write_text(res.text, encoding="utf-8")
print(f"saved={OUT}")
