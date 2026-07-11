"""
File system crawler.

Walks a directory tree and yields metadata for every regular file it finds,
while avoiding common pitfalls:
  - symlink loops (we never follow symlinks into directories)
  - pseudo-filesystems that aren't real files (/proc, /sys, /dev on Linux)
  - permission errors on individual files/dirs (skip and log, don't crash)

This module does NOT decide what is "vulnerable" - it only discovers files
and basic metadata. Downstream modules (hasher, permission auditor, secret
scanner, dependency scanner) consume what this yields.
"""

from __future__ import annotations

import os
import stat
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterator, Optional

logger = logging.getLogger("scanner.crawler")

# Directories that are virtual / not worth scanning on Linux.
# Scanning these wastes time and can even hang (some /proc entries are
# infinite or block on read).
DEFAULT_EXCLUDES = {
    "/proc",
    "/sys",
    "/dev",
    "/run",
    "/snap",
    "/var/lib/docker",  # container layers - noisy, usually out of scope
}


@dataclass
class FileRecord:
    """Metadata for a single discovered file. Cheap to compute - no hashing here."""

    path: str
    size: int
    mode: int  # raw st_mode, callers can decode with `stat` module
    uid: int
    owner_readable_by_others: bool
    is_symlink: bool
    mtime: float
    error: Optional[str] = None  # set if we could not fully stat the file

    @property
    def permission_string(self) -> str:
        """Human readable rwx string, e.g. '-rwxr-xr-x'."""
        return stat.filemode(self.mode)

    @property
    def is_setuid(self) -> bool:
        # Symlinks always report rwxrwxrwx-style bits on Linux regardless of
        # target - meaningless as a signal, so never flag a symlink itself.
        if self.is_symlink:
            return False
        return bool(self.mode & stat.S_ISUID)

    @property
    def is_setgid(self) -> bool:
        if self.is_symlink:
            return False
        return bool(self.mode & stat.S_ISGID)

    @property
    def is_world_writable(self) -> bool:
        if self.is_symlink:
            return False
        return bool(self.mode & stat.S_IWOTH)


def crawl(
    root: str,
    excludes: Optional[set[str]] = None,
    follow_symlinks: bool = False,
) -> Iterator[FileRecord]:
    """
    Walk `root` recursively, yielding a FileRecord for every regular file.

    Directories in `excludes` (or DEFAULT_EXCLUDES if not provided) are
    skipped entirely - os.walk supports pruning by mutating `dirs` in place,
    which we use here so we never even descend into them.
    """
    exclude_set = excludes if excludes is not None else DEFAULT_EXCLUDES
    root_path = os.path.abspath(root)

    for dirpath, dirnames, filenames in os.walk(
        root_path, topdown=True, onerror=_log_walk_error, followlinks=follow_symlinks
    ):
        # Prune excluded directories in-place so os.walk never enters them.
        dirnames[:] = [
            d for d in dirnames if os.path.join(dirpath, d) not in exclude_set
        ]

        for name in filenames:
            full_path = os.path.join(dirpath, name)
            record = _stat_file(full_path)
            if record is not None:
                yield record


def _stat_file(full_path: str) -> Optional[FileRecord]:
    """Stat a single file, handling permission errors and broken symlinks gracefully."""
    try:
        st = os.lstat(full_path)  # lstat: don't follow symlinks, we want to know if it IS one
    except (PermissionError, FileNotFoundError, OSError) as e:
        logger.debug("Could not stat %s: %s", full_path, e)
        return None

    is_link = stat.S_ISLNK(st.st_mode)

    # Only treat regular files (or symlinks pointing at them) as scan targets.
    if not is_link and not stat.S_ISREG(st.st_mode):
        return None

    return FileRecord(
        path=full_path,
        size=st.st_size,
        mode=st.st_mode,
        uid=st.st_uid,
        owner_readable_by_others=bool(st.st_mode & stat.S_IROTH),
        is_symlink=is_link,
        mtime=st.st_mtime,
    )


def _log_walk_error(error: OSError) -> None:
    logger.debug("Walk error: %s", error)


if __name__ == "__main__":
    import sys

    logging.basicConfig(level=logging.INFO)
    target = sys.argv[1] if len(sys.argv) > 1 else "."
    count = 0
    for rec in crawl(target):
        count += 1
        if rec.is_setuid or rec.is_world_writable:
            print(f"[FLAG] {rec.permission_string} {rec.path}")
    print(f"Scanned {count} files under {target}")
