"""
Cheat-intel pulse — website API/asset interceptor (Layer-2, website level)
==========================================================================
Headless Playwright pass over candidate cheat-vendor URLs. Captures what the
page ITSELF requests — no fuzzing, no dir-busting, no auth bypass. Two buckets:

  1. JSON endpoints  (xhr/fetch, application/json, >= min size) + body preview
  2. Interesting asset/file paths the page loads (download / uploads / api /
     .exe / .zip / .dll / .bin / loader) — the filename/filepath layer

Core logic adapted from Brad's Swiss Army Tool bridge (Fun/bridge-server.py),
repackaged as a batch CLI so the monthly pulse can run it unattended over a
list of URLs instead of a live server.

Boundary: this only observes traffic a normal visit triggers. It does NOT
enumerate hidden endpoints. See PULSE-RUNBOOK.md.

Usage:
    python dev/intel/api-intercept.py <url> [<url> ...]
    python dev/intel/api-intercept.py --file urls.txt --out results.json
"""

import argparse
import asyncio
import json
import re
import sys

SKIP_EXT = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
            ".css", ".woff", ".woff2", ".ttf", ".eot",
            ".mp4", ".webm", ".mp3", ".ogg")
SKIP_DOMAINS = ("google-analytics.com", "googletagmanager.com", "fonts.googleapis.com",
                "fonts.gstatic.com", "fontawesome.com", "facebook.net", "doubleclick.net",
                "hotjar.com", "segment.io", "mixpanel.com", "sentry.io")
# Path fragments worth flagging as filename/filepath intel.
INTEREST = re.compile(r"(/download|/dl/|/uploads?/|/files?/|/api/|/cdn/|/loader|/release|"
                      r"\.exe|\.zip|\.dll|\.bin|\.7z|\.rar|\.msi|\.bat|\.ps1)", re.I)


async def scan_one(url, min_size_kb, timeout_ms):
    from playwright.async_api import async_playwright
    json_eps, asset_hits = [], []
    seen = set()

    async def on_response(resp):
        try:
            req = resp.request
            u = req.url
            if u.startswith(("data:", "blob:", "chrome-extension:")):
                return
            if any(d in u for d in SKIP_DOMAINS):
                return
            # asset/file path bucket (any resource type, deduped)
            if INTEREST.search(u) and u not in seen:
                seen.add(u)
                asset_hits.append({"type": req.resource_type, "status": resp.status, "url": u})
            # JSON endpoint bucket
            if req.resource_type not in ("xhr", "fetch"):
                return
            if u.lower().endswith(SKIP_EXT):
                return
            if "application/json" not in resp.headers.get("content-type", ""):
                return
            body = await resp.body()
            size_kb = round(len(body) / 1024, 1)
            if size_kb < min_size_kb:
                return
            json_eps.append({"method": req.method, "url": u, "status": resp.status,
                             "size_kb": size_kb,
                             "preview": body.decode("utf-8", "replace")[:300]})
        except Exception:
            pass

    err = None
    async with async_playwright() as p:
        browser = await p.chromium.launch(headless=True)
        ctx = await browser.new_context(user_agent=(
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
            "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"))
        page = await ctx.new_page()
        page.on("response", on_response)
        try:
            await page.goto(url, wait_until="networkidle", timeout=timeout_ms)
        except Exception as e:
            err = f"nav: {e}"
        try:
            await page.wait_for_timeout(3000)
            for _ in range(3):
                await page.evaluate("window.scrollBy(0, window.innerHeight)")
                await page.wait_for_timeout(1500)
        except Exception:
            pass
        await browser.close()
    return {"target": url, "json_endpoints": json_eps, "asset_paths": asset_hits, "error": err}


async def main_async(urls, min_size_kb, timeout_ms):
    out = []
    for u in urls:
        print(f"[*] scanning {u}", file=sys.stderr)
        r = await scan_one(u, min_size_kb, timeout_ms)
        print(f"    JSON eps: {len(r['json_endpoints'])} | asset/file paths: {len(r['asset_paths'])}"
              + (f" | ERROR {r['error']}" if r['error'] else ""), file=sys.stderr)
        out.append(r)
    return out


def main():
    ap = argparse.ArgumentParser(description="Headless website API/asset interceptor for the cheat-intel pulse.")
    ap.add_argument("urls", nargs="*", help="target URLs")
    ap.add_argument("--file", help="file with one URL per line")
    ap.add_argument("--out", help="write full JSON results here")
    ap.add_argument("--min-size-kb", type=float, default=0.5)
    ap.add_argument("--timeout", type=int, default=45000)
    args = ap.parse_args()

    urls = list(args.urls)
    if args.file:
        with open(args.file, encoding="utf-8") as f:
            urls += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if not urls:
        ap.error("no URLs given")

    results = asyncio.run(main_async(urls, args.min_size_kb, args.timeout))
    text = json.dumps(results, indent=2)
    if args.out:
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(text)
        print(f"[*] wrote {args.out}", file=sys.stderr)
    else:
        print(text)


if __name__ == "__main__":
    main()
