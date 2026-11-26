"""Scan worker: runs in a child process so it can be hard-killed on timeout/cancel and resource-limited."""
from __future__ import annotations

import multiprocessing as mp
import queue
import sys
import time
from pathlib import Path


def _limit_resources(mem_mb: int, cpu_s: int):
    try:
        import resource
        resource.setrlimit(resource.RLIMIT_AS, (mem_mb * 1024 * 1024, mem_mb * 1024 * 1024))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu_s, cpu_s + 5))
        resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024 * 1024,) * 2)   # temp output only; sources are opened read-only
    except (ImportError, ValueError, OSError):
        pass   # Windows: bounded by max_file_bytes / max_total_bytes quotas + parent-enforced kill


def _child(q, root, targets, engines, limits_d, ext_cfg, mem_mb):
    from unitech_v3.engines.base import Cancelled, Limits, Timeout
    from unitech_v3.engines.scanner import scan
    _limit_resources(mem_mb, limits_d["timeout_s"] + 30)
    try:
        r = scan(Path(root), targets, engines, Limits(**limits_d), lambda: False,
                 lambda p, m: q.put(("progress", p, m)), ext_cfg)
        q.put(("result", {"findings": [f.to_dict() for f in r["findings"]], "engine_status": r["engine_status"],
                          "files_scanned": r["files_scanned"], "notes": r["notes"]}))
    except Timeout:
        q.put(("error", "timeout"))
    except Cancelled:
        q.put(("error", "cancelled"))
    except MemoryError:
        q.put(("error", "memory limit exceeded"))
    except Exception as ex:
        q.put(("error", f"{type(ex).__name__}: {ex}"[:300]))


class ScanProcess:
    def __init__(self, root: Path, targets, engines, limits_d: dict, ext_cfg: dict, mem_mb: int):
        ctx = mp.get_context("spawn")
        self.q = ctx.Queue()
        self.p = ctx.Process(target=_child, args=(self.q, str(root), targets, engines, limits_d, ext_cfg, mem_mb), daemon=True)
        self.deadline = time.monotonic() + limits_d["timeout_s"] + 5
        self.result = None

    def start(self):
        self.p.start()

    def poll(self):
        """Yield messages; returns when the child finished. Caller checks cancel + deadline."""
        out = []
        while True:
            try:
                out.append(self.q.get_nowait())
            except queue.Empty:
                break
        return out

    def alive(self) -> bool:
        return self.p.is_alive()

    def kill(self):
        if self.p.is_alive():
            self.p.kill()
        self.p.join(5)
