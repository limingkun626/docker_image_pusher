from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
import threading
from pathlib import Path
from wsgiref.simple_server import make_server


def app(environ, start_response):
    mode = os.environ.get("FIXTURE_MODE", "negative")
    payload = {"value": "wrong-type"} if mode == "positive" else {"value": 1}
    body = json.dumps(payload).encode("utf-8")
    start_response("200 OK", [("Content-Type", "application/json"), ("Content-Length", str(len(body)))])
    return [body]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("target")
    parser.add_argument("--mode", choices=["positive", "negative"], required=True)
    args = parser.parse_args()
    root = Path(args.target)
    os.environ["FIXTURE_MODE"] = args.mode
    server = make_server("127.0.0.1", 0, app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    base = f"http://127.0.0.1:{server.server_port}"
    sibling = Path(sys.executable).with_name(
        "schemathesis.exe" if os.name == "nt" else "schemathesis"
    )
    executable = str(sibling) if sibling.is_file() else shutil.which("schemathesis")
    if executable is None:
        print(
            json.dumps(
                {
                    "mode": args.mode,
                    "classification": "CLEAN",
                    "expected_exit": 1 if args.mode == "positive" else 0,
                    "actual_exit": 127,
                    "stdout_tail": "",
                    "stderr_tail": "schemathesis executable is unavailable",
                },
                sort_keys=True,
            )
        )
        server.server_close()
        return 127
    env = dict(os.environ)
    env.update(
        {
            "NO_PROXY": "127.0.0.1,localhost",
            "no_proxy": "127.0.0.1,localhost",
            "PYTHONUTF8": "1",
            "PYTHONIOENCODING": "utf-8",
        }
    )
    env.pop("HTTP_PROXY", None)
    env.pop("HTTPS_PROXY", None)
    env.pop("ALL_PROXY", None)
    try:
        result = subprocess.run(
            [
                executable,
                "run",
                str(root / "schema.json"),
                "--url",
                base,
                "--checks",
                "response_schema_conformance",
                "--max-examples",
                "5",
                "--workers",
                "1",
            ],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=60,
            env=env,
        )
    finally:
        server.shutdown()
    expected = 1 if args.mode == "positive" else 0
    classification = "DEFECT_DETECTED" if result.returncode != 0 else "CLEAN"
    print(
        json.dumps(
            {
                "mode": args.mode,
                "classification": classification,
                "expected_exit": expected,
                "actual_exit": result.returncode,
                "stdout_tail": result.stdout[-1000:],
                "stderr_tail": result.stderr[-1000:],
            },
            sort_keys=True,
        )
    )
    return 0 if result.returncode == expected else 2


if __name__ == "__main__":
    raise SystemExit(main())
