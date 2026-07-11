"""
File hashing + incremental scan cache.

Full-disk scans are slow if every file is re-hashed on every run. This module:
  1. Computes SHA-256 for a file (streamed, so large files don't blow up memory)
  2. Maintains a local SQLite cache keyed by path -> (mtime, size, hash)
     so unchanged files can be skipped on subsequent scans.

This is what makes "scan the whole disk" practical to run repeatedly / as a
background service, rather than something you dread running once.
"""

from __future__ import annotations

import hashlib
import sqlite3
import logging
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger("scanner.hasher")

CHUNK_SIZE = 1024 * 1024  # 1 MB read chunks - keeps memory flat for huge files


@dataclass
class HashResult:
    path: str
    sha256: str
    from_cache: bool  # True if we skipped re-hashing because nothing changed


def sha256_of_file(path: str) -> Optional[str]:
    """Stream-hash a file. Returns None on read errors (permission denied, etc)."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                h.update(chunk)
    except (PermissionError, FileNotFoundError, OSError) as e:
        logger.debug("Could not hash %s: %s", path, e)
        return None
    return h.hexdigest()


class ScanCache:
    """
    SQLite-backed cache of file fingerprints from the previous scan.

    Schema is intentionally tiny: one row per path, storing the mtime+size
    we saw last time and the hash we computed then. If mtime and size are
    unchanged, we trust the cached hash instead of re-reading the file.
    """

    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS file_cache (
                    path TEXT PRIMARY KEY,
                    mtime REAL NOT NULL,
                    size INTEGER NOT NULL,
                    sha256 TEXT NOT NULL,
                    last_scanned REAL NOT NULL
                )
                """
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.db_path)
        try:
            yield conn
            conn.commit()
        finally:
            conn.close()

    def get_cached_hash(self, path: str, mtime: float, size: int) -> Optional[str]:
        """Return the cached hash only if mtime+size match what we last saw."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT mtime, size, sha256 FROM file_cache WHERE path = ?",
                (path,),
            ).fetchone()
        if row is None:
            return None
        cached_mtime, cached_size, cached_hash = row
        if cached_mtime == mtime and cached_size == size:
            return cached_hash
        return None

    def update(self, path: str, mtime: float, size: int, sha256: str, scanned_at: float) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO file_cache (path, mtime, size, sha256, last_scanned)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET
                    mtime = excluded.mtime,
                    size = excluded.size,
                    sha256 = excluded.sha256,
                    last_scanned = excluded.last_scanned
                """,
                (path, mtime, size, sha256, scanned_at),
            )


def hash_with_cache(path: str, mtime: float, size: int, cache: ScanCache) -> Optional[HashResult]:
    """Get a file's hash, using the cache when the file hasn't changed since last scan."""
    import time

    cached = cache.get_cached_hash(path, mtime, size)
    if cached is not None:
        return HashResult(path=path, sha256=cached, from_cache=True)

    digest = sha256_of_file(path)
    if digest is None:
        return None

    cache.update(path, mtime, size, digest, time.time())
    return HashResult(path=path, sha256=digest, from_cache=False)


if __name__ == "__main__":
    import sys
    import time

    logging.basicConfig(level=logging.INFO)

    if len(sys.argv) < 2:
        print("Usage: python hasher.py <file_or_dir> [cache_db_path]")
        sys.exit(1)

    target = sys.argv[1]
    cache_path = sys.argv[2] if len(sys.argv) > 2 else "scan_cache.db"
    cache = ScanCache(cache_path)

    p = Path(target)
    if p.is_file():
        st = p.stat()
        result = hash_with_cache(str(p), st.st_mtime, st.st_size, cache)
        if result:
            tag = "(cached)" if result.from_cache else "(computed)"
            print(f"{result.sha256}  {result.path}  {tag}")
    else:
        print(f"{target} is not a file - point this at a single file, "
              f"or use crawler.py + hasher.py together for directories.")
