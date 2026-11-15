from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

RUN = Path(r"F:\Codex\runs\fir-1.7.0-release-20261115\generation-7")
SOURCE = Path(
    r"F:\Codex\runs\fir-r2-release-20261115\power_probe.py"
)


def load_probe():
    spec = importlib.util.spec_from_file_location("fir_power_probe_v2", SOURCE)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load power probe")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.RUN = RUN
    module.CANDIDATE = RUN / "full-inspection-repair"
    module.MANIFEST = RUN / "package" / "package-manifest.json"
    module.FREEZE = RUN / "release-build" / "candidate-freeze.json"
    module.POWER = RUN / "power"
    module.TARGET_TEST = module.POWER / "attempt" / "active"
    module.ROLLBACK_TEST = module.POWER / "attempt" / "rollback"
    module.ARM = module.POWER / "arm.json"
    module.MARKER = module.POWER / "MID-SWAP.json"
    module.CUT = module.POWER / "CUT-POWER-NOW.txt"
    module.AUDIT_START = module.POWER / "usn-start.json"
    module.EVIDENCE = module.POWER / "evidence"
    module.__file__ = str(Path(__file__).resolve())
    return module


def main() -> int:
    command = sys.argv[1] if len(sys.argv) > 1 else ""
    if command not in {"arm", "recover"}:
        raise SystemExit("usage: power_probe_wrapper.py arm|recover")
    probe = load_probe()
    return probe.arm() if command == "arm" else probe.recover()


if __name__ == "__main__":
    raise SystemExit(main())
