"""
Cheat-intel pulse — feed watcher (RSS/Atom)
===========================================
Polls the feeds in feeds.txt, diffs against the last run, and prints the entries
that are NEW since then. This is the "monitor -> diff -> flag" loop: durable and
bot-friendly, because published feeds have no API key, no 403, and no anti-bot —
so it routes around the walls that block Reddit JSON, WebFetch, and the Chrome
filter. stdlib only (urllib + ElementTree), no dependencies.

State (which entries we've already seen) is kept in feeds-state.json, which is
gitignored — so a first run on any machine establishes a baseline, and later runs
flag only what's new. The pulse reads the flagged entries; tokens still need a
verifiable URL and human review before they touch the engine.

Usage:
    python dev/intel/poll-feeds.py                  # poll feeds.txt, flag new
    python dev/intel/poll-feeds.py --all            # show every entry (ignore state)
    python dev/intel/poll-feeds.py --file F --state S --out report.json
"""

import argparse
import json
import os
import sys
import urllib.request
import xml.etree.ElementTree as ET

UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36")
HERE = os.path.dirname(os.path.abspath(__file__))


def _local(tag):
    return tag.rsplit("}", 1)[-1].lower()


def fetch(url, timeout=20):
    req = urllib.request.Request(url, headers={
        "User-Agent": UA,
        "Accept": "application/atom+xml, application/rss+xml, application/xml;q=0.9, */*;q=0.8",
    })
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read()


def parse_entries(xml_bytes):
    """Return a list of {title, link, id, updated, key} for Atom <entry> or RSS <item>."""
    root = ET.fromstring(xml_bytes)
    out = []
    for el in root.iter():
        if _local(el.tag) not in ("entry", "item"):
            continue
        d = {"title": "", "link": "", "id": "", "updated": ""}
        for ch in el:
            t = _local(ch.tag)
            if t == "title" and not d["title"]:
                d["title"] = (ch.text or "").strip()
            elif t in ("id", "guid") and not d["id"]:
                d["id"] = (ch.text or "").strip()
            elif t == "link" and not d["link"]:
                d["link"] = ch.get("href") or (ch.text or "").strip()
            elif t in ("updated", "published", "pubdate", "date") and not d["updated"]:
                d["updated"] = (ch.text or "").strip()
        d["key"] = d["id"] or d["link"] or d["title"]
        if d["key"]:
            out.append(d)
    return out


def read_feeds(path):
    with open(path, encoding="utf-8") as f:
        return [ln.strip() for ln in f if ln.strip() and not ln.lstrip().startswith("#")]


def main():
    ap = argparse.ArgumentParser(description="Poll RSS/Atom feeds and flag entries new since last run.")
    ap.add_argument("--file", default=os.path.join(HERE, "feeds.txt"))
    ap.add_argument("--state", default=os.path.join(HERE, "feeds-state.json"))
    ap.add_argument("--all", action="store_true", help="show every entry, ignore/keep state")
    ap.add_argument("--out", help="write JSON report of new entries here")
    args = ap.parse_args()

    feeds = read_feeds(args.file)
    if not feeds:
        ap.error("no feeds in " + args.file)

    seen = set()
    baseline = True
    if os.path.exists(args.state):
        try:
            seen = set(json.load(open(args.state, encoding="utf-8")).get("seen", []))
            baseline = not seen
        except Exception:
            pass

    report, new_total = [], 0
    for url in feeds:
        try:
            entries = parse_entries(fetch(url))
        except ET.ParseError:
            print(f"[!] {url} -> parse error (blocked or not a feed?)", file=sys.stderr)
            continue
        except Exception as e:
            print(f"[!] {url} -> {e}", file=sys.stderr)
            continue

        fresh = [e for e in entries if e["key"] not in seen]
        for e in entries:
            seen.add(e["key"])
        shown = entries if args.all else fresh
        new_total += len(fresh)
        report.append({"feed": url, "new": len(fresh), "entries": shown})

        label = f"{len(fresh)} new" + (f" / {len(entries)} total" if args.all else "")
        print(f"\n### {url}  ({label})")
        for e in shown:
            tag = "" if args.all else "NEW "
            print(f"  {tag}- {e['title'][:90]}  [{e['updated'][:10]}]")
            if e["link"]:
                print(f"       {e['link']}")

    # persist state (skip on --all so a peek doesn't silence the next real diff)
    if not args.all:
        json.dump({"seen": sorted(seen)}, open(args.state, "w", encoding="utf-8"), indent=0)

    note = " (baseline run - first poll establishes the seen-set)" if baseline and not args.all else ""
    print(f"\n[*] {new_total} new entr{'y' if new_total == 1 else 'ies'} across {len(feeds)} feed(s){note}", file=sys.stderr)

    if args.out:
        json.dump(report, open(args.out, "w", encoding="utf-8"), indent=2)
        print(f"[*] wrote {args.out}", file=sys.stderr)


if __name__ == "__main__":
    main()
