"""Canonical path validation: approved roots only, no symlink/junction escapes, read-only helpers."""
from __future__ import annotations

import os
import stat
from pathlib import Path

REPARSE = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)


class PathDenied(Exception):
    pass


def is_link_like(p: Path) -> bool:
    """True for symlinks and Windows junctions / other reparse points."""
    try:
        if p.is_symlink():
            return True
        st = os.lstat(p)
        attrs = getattr(st, "st_file_attributes", 0)
        return bool(attrs & REPARSE)
    except OSError:
        return True  # unreadable -> treat as unsafe


def _norm(p: Path) -> str:
    return os.path.normcase(str(p))


def within(child: Path, root: Path) -> bool:
    c, r = _norm(child), _norm(root)
    return c == r or c.startswith(r.rstrip(os.sep) + os.sep)


def canonical(raw: str) -> Path:
    if not raw or "\x00" in raw:
        raise PathDenied("invalid path")
    return Path(os.path.realpath(raw))


def validate_under_roots(raw: str, roots: list[Path]) -> Path:
    """Resolve `raw`, require it to be inside an approved root, and require every component
    below the root (walked lexically, as the caller wrote it) to be a plain, non-link entry.
    Returns the canonical path."""
    cand = canonical(raw)
    lex = Path(os.path.abspath(raw))
    for root in roots:
        root_lex = Path(os.path.abspath(root))
        root_real = Path(os.path.realpath(root))
        if not within(cand, root_real):
            continue
        if not within(lex, root_lex):
            raise PathDenied("symlink or junction traversal is not allowed")
        cur = lex
        while _norm(cur) != _norm(root_lex):
            if is_link_like(cur):
                raise PathDenied("symlink or junction traversal is not allowed")
            cur = cur.parent
        return cand
    raise PathDenied("path is outside the approved directories")


def safe_join(base: Path, rel: str) -> Path:
    """Join a user-supplied relative path onto an already-validated base directory."""
    if not rel or "\x00" in rel:
        raise PathDenied("invalid relative path")
    r = rel.replace("\\", "/")
    if r.startswith("/") or (len(r) > 1 and r[1] == ":") or ".." in r.split("/"):
        raise PathDenied("relative path escapes the project")
    cand = Path(os.path.realpath(base / r))
    if not within(cand, Path(os.path.realpath(base))):
        raise PathDenied("relative path escapes the project")
    cur = cand
    base_c = Path(os.path.realpath(base))
    while _norm(cur) != _norm(base_c):
        if is_link_like(cur):
            raise PathDenied("symlink or junction traversal is not allowed")
        cur = cur.parent
    return cand
