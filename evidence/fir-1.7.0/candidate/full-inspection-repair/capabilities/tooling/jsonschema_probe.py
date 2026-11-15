from __future__ import annotations

import json
import sys
from pathlib import Path

import jsonschema


def main() -> int:
    schema = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
    value = json.loads(Path(sys.argv[2]).read_text(encoding="utf-8"))
    try:
        jsonschema.Draft202012Validator(schema).validate(value)
        print(json.dumps({"classification": "VALID"}))
    except jsonschema.ValidationError as exc:
        print(json.dumps({"classification": "INVALID", "path": list(exc.path)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
