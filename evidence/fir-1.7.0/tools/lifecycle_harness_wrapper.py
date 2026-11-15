from __future__ import annotations

import importlib.util
import sys
from pathlib import Path


SOURCE = Path(
    r"F:\Codex\runs\fir-r2-release-20261115"
    r"\scope-generation-4\tools\make_lifecycle_harness.py"
)
LOCAL_SOURCE = Path(__file__).with_name("make_lifecycle_harness.py")
if LOCAL_SOURCE.is_file():
    SOURCE = LOCAL_SOURCE


def load_harness():
    spec = importlib.util.spec_from_file_location("fir_lifecycle_harness", SOURCE)
    if spec is None or spec.loader is None:
        raise RuntimeError("cannot load lifecycle harness")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    candidate_index = sys.argv.index("--candidate") + 1
    candidate = Path(sys.argv[candidate_index]).resolve()
    sys.path.insert(0, str(candidate / "scripts"))
    from full_inspection_repair import package as package_module

    original = package_module.build_package_manifest

    def resolve_unique_rollback(path):
        candidate = Path(path)
        if candidate.name == "rollback" and candidate.is_dir():
            children = [
                item
                for item in candidate.iterdir()
                if item.is_dir() and item.name.startswith("rollback-")
            ]
            if len(children) == 1:
                candidate = children[0]
        return original(candidate)

    package_module.build_package_manifest = resolve_unique_rollback
    return module


def main() -> int:
    return load_harness().main()


if __name__ == "__main__":
    raise SystemExit(main())
