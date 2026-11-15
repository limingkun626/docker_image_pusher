from __future__ import annotations

import argparse
import json
import runpy
import sys
from pathlib import Path
from typing import Any


BLOCKED_AUDIT_PREFIXES = (
    "os.system",
    "os.spawn",
    "subprocess.Popen",
    "socket.connect",
    "socket.bind",
    "socket.getaddrinfo",
    "urllib.Request",
    "ctypes.dlopen",
)


def _stable_value(value: Any) -> Any:
    if value is None or isinstance(value, (bool, int, float, str)):
        return value[:256] if isinstance(value, str) else value
    if hasattr(value, "co_name"):
        return {
            "type": "code",
            "name": value.co_name,
            "firstlineno": value.co_firstlineno,
        }
    return {"type": type(value).__name__}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture", required=True)
    parser.add_argument("--call", required=True)
    parser.add_argument("--args-json", default="[]")
    args = parser.parse_args()
    fixture = Path(args.fixture).resolve()
    arguments = json.loads(args.args_json)
    if not isinstance(arguments, list):
        raise SystemExit("--args-json must be a JSON array")
    monitoring = getattr(sys, "monitoring", None)
    if monitoring is None:
        print(json.dumps({"status": "BLOCKED_UNSUPPORTED"}))
        return 2
    events: list[dict[str, Any]] = []

    def on_call(code, _offset, callable_, _arg0):
        if Path(code.co_filename).resolve() != fixture:
            return
        events.append(
            {
                "kind": "call",
                "function": code.co_name,
                "callable": getattr(callable_, "__name__", type(callable_).__name__),
            }
        )

    def on_return(code, _offset, value):
        if Path(code.co_filename).resolve() != fixture:
            return
        events.append(
            {
                "kind": "return",
                "function": code.co_name,
                "value": _stable_value(value),
            }
        )

    def on_raise(code, _offset, exception):
        if Path(code.co_filename).resolve() != fixture:
            return
        events.append(
            {
                "kind": "raise",
                "function": code.co_name,
                "exception": type(exception).__name__,
            }
        )

    def audit(event: str, values: tuple[Any, ...]) -> None:
        if event.startswith(BLOCKED_AUDIT_PREFIXES):
            events.append(
                {
                    "kind": "audit-block",
                    "event": event,
                    "callable": event.rsplit(".", 1)[-1],
                }
            )
            raise PermissionError(f"runtime fixture operation denied: {event}")

    tool_id = None
    try:
        for candidate in (5, 4, 3, 2, 1, 0):
            try:
                monitoring.use_tool_id(candidate, "fir-r2-runtime")
                tool_id = candidate
                break
            except ValueError:
                continue
        if tool_id is None:
            print(json.dumps({"status": "BLOCKED_TOOL_ID"}))
            return 2
        monitoring.register_callback(tool_id, monitoring.events.CALL, on_call)
        monitoring.register_callback(tool_id, monitoring.events.PY_RETURN, on_return)
        monitoring.register_callback(tool_id, monitoring.events.RAISE, on_raise)
        monitoring.set_events(
            tool_id,
            monitoring.events.CALL
            | monitoring.events.PY_RETURN
            | monitoring.events.RAISE,
        )
        sys.addaudithook(audit)
        namespace = runpy.run_path(str(fixture), run_name="fir_runtime_fixture")
        function = namespace[args.call]
        try:
            returned = function(*arguments)
            exception = None
        except Exception as error:
            returned = None
            exception = f"{type(error).__name__}: {error}"
    except (KeyError, SyntaxError, TypeError, ValueError) as error:
        print(
            json.dumps(
                {
                    "status": "BLOCKED_MALFORMED",
                    "error": f"{type(error).__name__}: {error}",
                },
                sort_keys=True,
            )
        )
        return 2
    finally:
        if tool_id is not None:
            monitoring.set_events(tool_id, monitoring.events.NO_EVENTS)
            for event in (
                monitoring.events.CALL,
                monitoring.events.PY_RETURN,
                monitoring.events.RAISE,
            ):
                monitoring.register_callback(tool_id, event, None)
            monitoring.free_tool_id(tool_id)
    print(
        json.dumps(
            {
                "status": "PASS",
                "events": events,
                "return": _stable_value(returned),
                "exception": exception,
            },
            ensure_ascii=False,
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
