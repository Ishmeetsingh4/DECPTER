"""
Entry point for Phase 1: crawl a directory, hash every file (with caching),
and flag basic permission red flags along the way.

This is intentionally still simple - no CVE matching, no secrets, no config
auditing yet. It proves the crawler + hasher pipeline works end to end and
gives you a real incremental-scan cache to build the rest on top of.

Usage:
    python -m scanner.main /path/to/scan
    python -m scanner.main /path/to/scan --cache /path/to/cache.db
"""

from __future__ import annotations

import argparse
import logging
import time

from scanner.modules.crawler import crawl
from scanner.modules.hasher import ScanCache, hash_with_cache

logger = logging.getLogger("scanner.main")


def run_scan(target: str, cache_db: str) -> None:
    cache = ScanCache(cache_db)

    total = 0
    hashed_fresh = 0
    hashed_cached = 0
    flags = []

    start = time.time()

    for record in crawl(target):
        total += 1

        result = hash_with_cache(record.path, record.mtime, record.size, cache)
        if result is None:
            continue  # unreadable file, already logged at debug level

        if result.from_cache:
            hashed_cached += 1
        else:
            hashed_fresh += 1

        if record.is_setuid:
            flags.append(("SETUID", record.path, record.permission_string))
        if record.is_world_writable:
            flags.append(("WORLD_WRITABLE", record.path, record.permission_string))

    elapsed = time.time() - start

    print(f"\nScan complete: {target}")
    print(f"  Files seen:        {total}")
    print(f"  Hashed fresh:      {hashed_fresh}")
    print(f"  Skipped (cached):  {hashed_cached}")
    print(f"  Time:              {elapsed:.2f}s")

    if flags:
        print(f"\nFlags ({len(flags)}):")
        for kind, path, perms in flags:
            print(f"  [{kind}] {perms}  {path}")
    else:
        print("\nNo permission flags found.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Phase 1 local scan: crawl + hash + basic permission flags")
    parser.add_argument("target", help="Directory to scan")
    parser.add_argument("--cache", default="scan_cache.db", help="Path to the SQLite scan cache")
    parser.add_argument("-v", "--verbose", action="store_true")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.WARNING)
    run_scan(args.target, args.cache)


if __name__ == "__main__":
    main()
