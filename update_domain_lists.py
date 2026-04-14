"""
Utility script to refresh the trusted/phishing domain lists under DataFiles/.

Usage examples:
  python update_domain_lists.py --legit-source new_legit.txt
  python update_domain_lists.py --phish-source https://example.com/phish.csv
  python update_domain_lists.py --legit-source legit.txt --phish-source phish.csv
"""

from __future__ import annotations

import argparse
import csv
import sys
from pathlib import Path
from typing import Iterable, Set
from urllib.parse import urlparse

try:
    import requests
except ImportError:  # pragma: no cover - requests is in requirements but guard anyway
    requests = None


BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "DataFiles"
LEGIT_FILE = DATA_DIR / "legitimateurls.csv"
PHISH_FILE = DATA_DIR / "phishurls.csv"


def _read_text_from_source(source: str) -> Iterable[str]:
    parsed = urlparse(source)
    if parsed.scheme in {"http", "https"}:
        if not requests:
            raise RuntimeError("requests package is required to download remote sources")
        resp = requests.get(source, timeout=30)
        resp.raise_for_status()
        return resp.text.splitlines()
    return Path(source).read_text(encoding="utf-8").splitlines()


def _normalize_entry(entry: str) -> str | None:
    entry = entry.strip()
    if not entry or entry.startswith("#"):
        return None
    return entry


def load_existing_legit() -> Set[str]:
    entries = set()
    if LEGIT_FILE.exists():
        for line in LEGIT_FILE.read_text(encoding="utf-8").splitlines():
            norm = _normalize_entry(line)
            if norm:
                entries.add(norm.lower())
    return entries


def load_existing_phish() -> Set[str]:
    entries = set()
    if PHISH_FILE.exists():
        lines = PHISH_FILE.read_text(encoding="utf-8").splitlines()
        for line in lines[1:]:  # skip header
            norm = _normalize_entry(line)
            if norm:
                entries.add(norm.lower())
    return entries


def parse_legit_source(source: str) -> Set[str]:
    entries = set()
    for line in _read_text_from_source(source):
        norm = _normalize_entry(line)
        if norm:
            entries.add(norm.lower())
    return entries


def parse_phish_source(source: str) -> Set[str]:
    rows = _read_text_from_source(source)
    reader = csv.reader(rows)
    entries = set()
    for row in reader:
        if not row:
            continue
        norm = _normalize_entry(row[0])
        if norm and norm != "url":
            entries.add(norm.lower())
    return entries


def write_legit(entries: Set[str]) -> int:
    ordered = sorted(entries)
    LEGIT_FILE.write_text("\n".join(ordered) + ("\n" if ordered else ""), encoding="utf-8")
    return len(ordered)


def write_phish(entries: Set[str]) -> int:
    ordered = sorted(entries)
    with PHISH_FILE.open("w", encoding="utf-8", newline="") as fh:
        fh.write("url\n")
        for url in ordered:
            fh.write(f"{url}\n")
    return len(ordered)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--legit-source", help="Path or URL to a trusted-domain list (one per line).")
    parser.add_argument("--phish-source", help="Path or URL to a phishing URL/domain CSV or plain text.")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print the delta without writing files.",
    )
    args = parser.parse_args()

    if not args.legit_source and not args.phish_source:
        parser.error("Provide at least one of --legit-source or --phish-source")

    if args.legit_source:
        existing = load_existing_legit()
        incoming = parse_legit_source(args.legit_source)
        new_entries = incoming - existing
        print(f"[legit] existing={len(existing)} incoming={len(incoming)} new={len(new_entries)}")
        if new_entries and not args.dry_run:
            count = write_legit(existing | incoming)
            print(f"[legit] wrote {count} entries to {LEGIT_FILE}")

    if args.phish_source:
        existing = load_existing_phish()
        incoming = parse_phish_source(args.phish_source)
        new_entries = incoming - existing
        print(f"[phish] existing={len(existing)} incoming={len(incoming)} new={len(new_entries)}")
        if new_entries and not args.dry_run:
            count = write_phish(existing | incoming)
            print(f"[phish] wrote {count} entries to {PHISH_FILE}")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:  # pragma: no cover - surface the error clearly to CLI
        print(f"[update_domain_lists] ERROR: {exc}", file=sys.stderr)
        sys.exit(1)
