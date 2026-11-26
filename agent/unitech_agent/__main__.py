import argparse
import logging
import sys

from .agent import Agent
from .config import load


def main() -> int:
    ap = argparse.ArgumentParser(description="UNITECH V3 local scanning agent")
    ap.add_argument("--config", default="agent.config.json")
    ns = ap.parse_args()
    cfg = load(ns.config)
    logging.basicConfig(level=logging.INFO, filename=cfg.log_file, format="%(asctime)s %(levelname)s %(message)s")
    a = Agent(cfg)
    logging.getLogger("unitech.agent").info("agent %s starting; approved roots: %s", cfg.name, [str(r) for r in cfg.approved_roots])
    try:
        a.run_forever()
    except KeyboardInterrupt:
        a.stop.set()
    return 0


if __name__ == "__main__":
    sys.exit(main())
