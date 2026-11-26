import os
import re
from datetime import datetime, timezone
from urllib.parse import urlparse
import requests

BLOCKLIST_FILE = "webfilter.txt"
WHITELIST_FILE = "whitelist.txt"
CANDIDATES_FILE = "pending_candidates.txt"

SEARCH_QUERIES = [
    "ดูหนังออนไลน์ hd",
    "ดูหนังฟรี ไม่มีโฆษณา",
    "ดูซีรีส์ออนไลน์ พากย์ไทย ซับไทย",
    "ดูอนิเมะออนไลน์ พากย์ไทย",
    "หนังใหม่ชนโรง ออนไลน์",
]

# โดเมนถูกกฎหมายหรือเว็บทั่วไปที่มักติดมาในผลการค้นหา
DEFAULT_EXCLUDED_DOMAINS = {
    "youtube.com",
    "youtu.be",
    "netflix.com",
    "disneyplus.com",
    "primevideo.com",
    "viu.com",
    "iq.com",
    "wetv.vip",
    "trueid.net",
    "aisplay.ais.co.th",
    "monomax.me",
    "bugaboo.tv",
    "ch3plus.com",
    "facebook.com",
    "tiktok.com",
    "instagram.com",
    "x.com",
    "twitter.com",
    "google.com",
    "wikipedia.org",
    "imdb.com",
    "rottentomatoes.com",
    "pantip.com",
    "sanook.com",
    "kapook.com",
    "majorcineplex.com",
    "sfcinemacity.com",
}

DOMAIN_REGEX = re.compile(r"^[a-z0-9-]+(\.[a-z0-9-]+)+$")


def normalize_domain(raw_url: str) -> str | None:
    if not raw_url:
        return None
    if not raw_url.startswith(("http://", "https://")):
        raw_url = "https://" + raw_url
    try:
        parsed = urlparse(raw_url)
        host = (parsed.hostname or "").lower().strip()
        if host.startswith("www."):
            host = host[4:]
        host = host.strip(".")
        if not host or not DOMAIN_REGEX.match(host):
            return None
        return host
    except Exception:
        return None


def load_domains_from_file(filepath: str) -> set[str]:
    found = set()
    if not os.path.exists(filepath):
        return found
    with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("*."):
                line = line[2:]
            norm = normalize_domain(line)
            if norm:
                found.add(norm)
    return found


def search_google(query: str, api_key: str, cx: str, pages: int = 2) -> list[str]:
    urls = []
    for page in range(pages):
        start_index = page * 10 + 1  # 1, 11
        params = {
            "key": api_key,
            "cx": cx,
            "q": query,
            "start": start_index,
            "num": 10,
        }
        resp = requests.get("https://www.googleapis.com/customsearch/v1", params=params, timeout=20)
        resp.raise_for_status()
        data = resp.json()
        items = data.get("items", [])
        if not items:
            break
        for item in items:
            link = item.get("link")
            if link:
                urls.append(link)
    return urls


def main():
    api_key = os.environ.get("SEARCH_API_KEY", "").strip()
    cx = os.environ.get("SEARCH_CX", "").strip()
    if not api_key or not cx:
        raise RuntimeError("Missing SEARCH_API_KEY or SEARCH_CX in environment variables.")

    existing_blocked = load_domains_from_file(BLOCKLIST_FILE)
    existing_candidates = load_domains_from_file(CANDIDATES_FILE)
    whitelisted = load_domains_from_file(WHITELIST_FILE) | DEFAULT_EXCLUDED_DOMAINS

    known_domains = existing_blocked | existing_candidates | whitelisted

    discovered_new = []
    seen_in_run = set()

    for q in SEARCH_QUERIES:
        try:
            links = search_google(q, api_key, cx, pages=2)
        except Exception as e:
            print(f"[WARN] Query '{q}' failed: {e}")
            continue

        for link in links:
            dom = normalize_domain(link)
            if not dom:
                continue
            if dom in known_domains or dom in seen_in_run:
                continue
            # กรองโดเมนย่อยของโดเมนที่รู้จักแล้วออกด้วย
            if any(dom.endswith("." + k) for k in known_domains):
                continue

            seen_in_run.add(dom)
            discovered_new.append((dom, q))

    if not discovered_new:
        print("No new domains discovered.")
        return

    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    lines_to_append = [
        "",
        f"# Discovered on {now_str}",
    ]
    for dom, q in discovered_new:
        lines_to_append.append(f"# Query: {q}")
        lines_to_append.append(dom)
        lines_to_append.append(f"*.{dom}")

    with open(CANDIDATES_FILE, "a", encoding="utf-8") as f:
        f.write("\n".join(lines_to_append) + "\n")

    print(f"Added {len(discovered_new)} new candidate domains to {CANDIDATES_FILE}.")


if __name__ == "__main__":
    main()
