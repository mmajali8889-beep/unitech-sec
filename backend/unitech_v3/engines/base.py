from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field, asdict
from typing import Callable

SEVERITIES = ["critical", "high", "medium", "low", "info"]


@dataclass
class Rule:
    id: str
    engine: str
    category: str
    severity: str
    title: str
    pattern: str
    remediation: str
    cwe: str = ""
    exts: tuple[str, ...] = ()          # file extensions (lowercase, with dot); empty = any text file
    names: tuple[str, ...] = ()         # exact file name matches (lowercase), e.g. dockerfile
    verification: str = "heuristic"     # heuristic | deterministic
    flags: int = re.I
    unless: str | None = None           # line is skipped when this matches
    _re: re.Pattern | None = field(default=None, repr=False)
    _un: re.Pattern | None = field(default=None, repr=False)

    def __post_init__(self):
        self._re = re.compile(self.pattern, self.flags)
        self._un = re.compile(self.unless, re.I) if self.unless else None

    def applies(self, name_l: str, ext: str) -> bool:
        if self.names and name_l in self.names:
            return True
        if self.exts:
            return ext in self.exts
        return not self.names


@dataclass
class RawFinding:
    engine: str
    rule_id: str
    category: str
    severity: str
    title: str
    file: str
    line: int
    snippet: str            # already redacted
    remediation: str
    cwe: str = ""
    verification: str = "heuristic"
    col: int = 0
    context_hash: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


def ctx_hash(line: str) -> str:
    return hashlib.sha256(re.sub(r"\s+", " ", line.strip()).encode()).hexdigest()[:24]


@dataclass
class Limits:
    max_file_bytes: int = 1_000_000
    max_files: int = 20_000
    max_total_bytes: int = 500_000_000
    timeout_s: int = 600
    max_findings_per_engine: int = 5_000


@dataclass
class ScanFile:
    rel: str
    name_l: str
    ext: str
    text: str
    lines: list[str]


class Cancelled(Exception):
    pass


class Timeout(Exception):
    pass


ProgressCb = Callable[[float, str], None]
