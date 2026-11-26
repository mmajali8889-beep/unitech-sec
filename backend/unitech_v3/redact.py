"""Secret redaction. Applied before anything is stored, logged, sent to AI or displayed."""
from __future__ import annotations

import math
import re

MARK = "«redacted»"

# (name, regex). Group "v" (if present) is the secret value; otherwise the whole match is replaced.
SECRET_PATTERNS: list[tuple[str, re.Pattern]] = [(n, re.compile(p)) for n, p in [
    ("private-key", r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----"),
    ("aws-access-key", r"\b(?P<v>(?:AKIA|ASIA)[0-9A-Z]{16})\b"),
    ("github-token", r"\b(?P<v>gh[pousr]_[A-Za-z0-9]{30,})\b"),
    ("slack-token", r"\b(?P<v>xox[abprs]-[A-Za-z0-9-]{10,})\b"),
    ("google-api-key", r"\b(?P<v>AIza[0-9A-Za-z_\-]{35})\b"),
    ("stripe-key", r"\b(?P<v>(?:sk|rk)_live_[0-9a-zA-Z]{16,})\b"),
    ("jwt", r"\b(?P<v>eyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,})\b"),
    ("url-credentials", r"[a-zA-Z][a-zA-Z0-9+.\-]*://[^\s:/@'\"]+:(?P<v>[^\s@'\"/]{3,})@"),
    ("bearer", r"(?i)\bbearer\s+(?P<v>[A-Za-z0-9._\-]{20,})"),
    ("assigned-secret", r"""(?ix)\b[\w.\-]*(?:password|passwd|pwd|secret|token|api[_\-]?key|apikey|auth|credential|private[_\-]?key|access[_\-]?key)[\w.\-]*
        ["']?\s*[:=]\s*["'](?P<v>[^"'\s]{6,})["']"""),
    ("env-assigned-secret", r"""(?ix)^\s*[A-Z0-9_]*(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|PRIVATE_?KEY|ACCESS_?KEY)[A-Z0-9_]*\s*=\s*(?P<v>[^\s#"']{6,})"""),
]]


def entropy(s: str) -> float:
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in Counter(s).values())


def redact_text(text: str) -> str:
    out = text
    for _name, pat in SECRET_PATTERNS:
        def sub(m: re.Match, _pat=pat) -> str:
            if "v" in _pat.groupindex and m.group("v") is not None:
                s, e = m.span("v")
                ms = m.start()
                return m.group(0)[: s - ms] + MARK + m.group(0)[e - ms:]
            return MARK
        out = pat.sub(sub, out)
    return out


def redact_line(line: str, max_len: int = 200) -> str:
    line = redact_text(line.strip())
    # long opaque tokens that survived (high-entropy blobs)
    def blob(m: re.Match) -> str:
        t = m.group(0)
        return MARK if len(t) >= 24 and entropy(t) > 3.8 else t
    line = re.sub(r"[A-Za-z0-9+/_\-=]{24,}", blob, line)
    return line if len(line) <= max_len else line[:max_len] + "…"
