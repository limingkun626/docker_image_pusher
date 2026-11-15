from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path


RUN = Path(r"F:\Codex\runs\fir-r2-release-20261115")
CANDIDATE = RUN / "scope-generation-4" / "full-inspection-repair"
MANIFEST = RUN / "scope-generation-4" / "package" / "package-manifest.json"
FREEZE = RUN / "scope-generation-4" / "candidate-freeze.json"
POWER = RUN / "scope-generation-4" / "power-r3"
TARGET_TEST = POWER / "attempt" / "active"
ROLLBACK_TEST = POWER / "attempt" / "rollback"
ARM = POWER / "arm.json"
MARKER = POWER / "MID-SWAP.json"
CUT = POWER / "CUT-POWER-NOW.txt"
AUDIT_START = POWER / "usn-start.json"
EVIDENCE = POWER / "evidence"
ZERO = "0" * 64


def canonical_json(value: object) -> str:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    )


def canonical_digest(value: object) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path: Path) -> dict[str, object]:
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, value: object) -> None:
    payload = (
        json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
    ).encode("utf-8")
    durable_write_bytes(path, payload)


def write_text(path: Path, value: str) -> None:
    durable_write_bytes(path, value.encode("utf-8"))


def durable_write_bytes(path: Path, payload: bytes) -> None:
    scripts = str(CANDIDATE / "scripts")
    if scripts not in sys.path:
        sys.path.insert(0, scripts)
    from full_inspection_repair.strict import _durable_write_bytes

    _durable_write_bytes(path, payload)


def boot_identity() -> dict[str, str]:
    command = subprocess.run(
        [
            r"C:\Windows\System32\reg.exe",
            "query",
            r"HKLM\SOFTWARE\Microsoft\Cryptography",
            "/v",
            "MachineGuid",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if command.returncode != 0:
        raise RuntimeError("cannot read MachineGuid")
    machine_guid = command.stdout.strip().split()[-1]
    powershell = subprocess.run(
        [
            r"C:\Program Files\PowerShell\7\pwsh.exe",
            "-NoProfile",
            "-Command",
            (
                "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime."
                "ToUniversalTime().ToString('o')"
            ),
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if powershell.returncode != 0:
        raise RuntimeError("cannot read LastBootUpTime")
    last_boot = powershell.stdout.strip()
    computer_name = os.environ.get("COMPUTERNAME", "")
    return {
        "machine_guid": machine_guid,
        "computer_name": computer_name,
        "last_boot_utc": last_boot,
        "boot_id": hashlib.sha256(
            f"{machine_guid}\0{computer_name}\0{last_boot}".encode("utf-8")
        ).hexdigest(),
    }


def kernel_power_events(since: str) -> list[dict[str, object]]:
    script = (
        f"$start=[datetime]::Parse('{since}'); "
        "$events=Get-WinEvent -FilterHashtable @{"
        "LogName='System';ProviderName='Microsoft-Windows-Kernel-Power';"
        "Id=41;StartTime=$start} -ErrorAction Stop | "
        "Select-Object Id,ProviderName,TimeCreated,RecordId,MachineName;"
        "ConvertTo-Json -InputObject @($events) -Depth 4"
    )
    completed = subprocess.run(
        [
            r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "-NoProfile",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            "Kernel-Power query failed: " + completed.stderr.strip()
        )
    value = json.loads(completed.stdout or "[]")
    rows = value if isinstance(value, list) else [value]
    return [row for row in rows if isinstance(row, dict)]


def regular_copy(source: Path, destination: Path) -> None:
    def ignore(directory: str, names: list[str]) -> set[str]:
        return {
            name
            for name in names
            if name
            in {
                "__pycache__",
                ".pytest_cache",
                ".ruff_cache",
                ".mypy_cache",
                ".hypothesis",
            }
        }

    shutil.copytree(source, destination, ignore=ignore)


def arm() -> int:
    if POWER.exists():
        raise RuntimeError(f"power probe already exists: {POWER}")
    (POWER / "attempt").mkdir(parents=True)
    sys.path.insert(0, str(CANDIDATE / "scripts"))
    from full_inspection_repair import package as package_module
    from full_inspection_repair.package import (
        build_package_manifest,
        install_package,
        verify_package_manifest,
    )
    from full_inspection_repair.windows_audit import start_filesystem_audit

    manifest = read_json(MANIFEST)
    freeze = read_json(FREEZE)
    verify_package_manifest(CANDIDATE, manifest)
    candidate_digest = str(manifest["tree_digest"])
    if freeze.get("tree_digest") != candidate_digest:
        raise RuntimeError("freeze does not bind the exact candidate")
    installed = Path(
        r"C:\Users\Administrator\.codex\skills\full-inspection-repair"
    )
    regular_copy(installed, TARGET_TEST)
    old_digest = str(build_package_manifest(TARGET_TEST)["tree_digest"])
    usn_start = start_filesystem_audit(POWER)
    write_json(AUDIT_START, usn_start)
    boot = boot_identity()
    armed_at = datetime.now(UTC).replace(microsecond=0).isoformat()
    arm_state: dict[str, object] = {
        "schema_version": 1,
        "status": "ARMED",
        "scope_id": freeze["scope_id"],
        "run_id": freeze["run_id"],
        "scope_digest": freeze["freeze_digest"],
        "candidate_digest": candidate_digest,
        "package_manifest_digest": manifest["manifest_digest"],
        "probe_script": str(Path(__file__).resolve()),
        "probe_script_sha256": sha256(Path(__file__).resolve()),
        "probe_command": (
            f'python -B "{Path(__file__).resolve()}" arm'
        ),
        "installed_target": str(installed),
        "target_test": str(TARGET_TEST),
        "rollback_test": str(ROLLBACK_TEST),
        "old_target_digest": old_digest,
        "armed_at": armed_at,
        "boot": boot,
        "usn_start_path": str(AUDIT_START),
        "usn_start_digest": sha256(AUDIT_START),
        "marker_path": str(MARKER),
    }
    arm_state["arm_digest"] = canonical_digest(arm_state)
    write_json(ARM, arm_state)

    original_replace = package_module._durable_directory_replace
    paused = False

    def controlled_replace(source: str | Path, destination: str | Path) -> None:
        nonlocal paused
        original_replace(source, destination)
        if paused or Path(destination).resolve() != ROLLBACK_TEST.resolve():
            return
        paused = True
        midpoint = {
            "schema_version": 1,
            "status": "MID_SWAP_REACHED",
            "armed_at": armed_at,
            "mid_swap_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
            "candidate_digest": candidate_digest,
            "scope_digest": freeze["freeze_digest"],
            "target_exists": TARGET_TEST.exists(),
            "rollback_exists": ROLLBACK_TEST.exists(),
            "rollback_digest": build_package_manifest(ROLLBACK_TEST)["tree_digest"],
            "staged_candidates": [
                str(item)
                for item in (POWER / "attempt").glob(".active.install-*/active")
            ],
        }
        midpoint["marker_digest"] = canonical_digest(midpoint)
        write_json(MARKER, midpoint)
        write_text(
            CUT,
            "\n".join(
                [
                    "PHYSICAL POWER CUT IS NOW REQUIRED",
                    f"EVENT_ID={midpoint['marker_digest']}",
                    f"MID_SWAP_AT={midpoint['mid_swap_at']}",
                    f"CANDIDATE_DIGEST={candidate_digest}",
                    f"TARGET_EXISTS={TARGET_TEST.exists()}",
                    f"ROLLBACK_EXISTS={ROLLBACK_TEST.exists()}",
                    "",
                ]
            ),
        )
        print("MID_SWAP_REACHED", flush=True)
        print(f"MARKER={MARKER}", flush=True)
        print("CUT_POWER_NOW", flush=True)
        time.sleep(7200)

    package_module._durable_directory_replace = controlled_replace
    package_module.validate_claim_for_install = lambda *_args, **_kwargs: None
    dummy = {
        "claim_digest": ZERO,
        "review_digest": ZERO,
        "subject_digest": ZERO,
        "external_signature": {
            "issuer": "power-probe",
            "trust_root_id": ZERO,
            "trust_anchor_digest": ZERO,
            "history_anchor_key_sha256": ZERO,
            "verification_method": "sigstore-keyless",
            "attestation_sha256": ZERO,
            "signature_sha256": None,
            "receipt_digest": ZERO,
            "bundle_sha256": ZERO,
            "verifier_command_digest": ZERO,
            "trust_config_sha256": ZERO,
            "verifier_closure_digest": ZERO,
        },
    }
    install_package(
        CANDIDATE,
        TARGET_TEST,
        manifest,
        claim=dummy,
        review=dummy,
        verification_method="sigstore-keyless",
        attestation_bytes=b"{}",
        rollback_root=ROLLBACK_TEST,
    )
    raise RuntimeError("installer completed without entering the controlled midpoint")


def recover() -> int:
    if EVIDENCE.exists():
        raise RuntimeError(f"power evidence already exists: {EVIDENCE}")
    sys.path.insert(0, str(CANDIDATE / "scripts"))
    from full_inspection_repair import package as package_module
    from full_inspection_repair.package import (
        build_package_manifest,
        verify_package_manifest,
    )
    from full_inspection_repair.windows_audit import finish_filesystem_audit

    arm_state = read_json(ARM)
    declared = arm_state.pop("arm_digest", None)
    if declared != canonical_digest(arm_state):
        raise RuntimeError("power arm receipt digest mismatch")
    if arm_state.get("probe_script_sha256") != sha256(Path(__file__).resolve()):
        raise RuntimeError("power probe script changed after arming")
    if not MARKER.is_file() or not CUT.is_file():
        raise RuntimeError("mid-swap markers are missing")
    marker = read_json(MARKER)
    marker_declared = marker.pop("marker_digest", None)
    if marker_declared != canonical_digest(marker):
        raise RuntimeError("mid-swap marker digest mismatch")
    if marker.get("candidate_digest") != arm_state["candidate_digest"]:
        raise RuntimeError("mid-swap candidate binding mismatch")
    if marker.get("target_exists") is not False or marker.get("rollback_exists") is not True:
        raise RuntimeError("mid-swap state is not target-absent/rollback-present")
    if TARGET_TEST.exists():
        raise RuntimeError("active target unexpectedly exists after the outage")
    if not ROLLBACK_TEST.is_dir():
        raise RuntimeError("rollback tree is missing after the outage")
    rollback_digest = str(build_package_manifest(ROLLBACK_TEST)["tree_digest"])
    if rollback_digest != arm_state["old_target_digest"]:
        raise RuntimeError("rollback tree does not match the pre-install target")

    candidates = [
        item
        for item in (POWER / "attempt").glob(".active.install-*/active")
        if item.is_dir()
    ]
    staged = next(
        (
            item
            for item in candidates
            if build_package_manifest(item)["tree_digest"]
            == arm_state["candidate_digest"]
        ),
        None,
    )
    if staged is None:
        raise RuntimeError("durable staged candidate tree is missing after the outage")

    boot = boot_identity()
    if boot["boot_id"] == arm_state["boot"]["boot_id"]:
        raise RuntimeError("boot identity did not change after the outage")
    events = kernel_power_events(str(arm_state["armed_at"]))
    if not any(int(event.get("Id", 0)) == 41 for event in events):
        raise RuntimeError("Windows Kernel-Power EventID 41 is missing")
    usn_start = read_json(Path(str(arm_state["usn_start_path"])))
    usn_finish = finish_filesystem_audit(usn_start)
    if usn_finish.get("status") != "COMPLETE":
        raise RuntimeError("USN audit closure is incomplete")

    package_module._durable_directory_replace(staged, TARGET_TEST)
    verify_package_manifest(TARGET_TEST, read_json(MANIFEST))
    target_digest = str(build_package_manifest(TARGET_TEST)["tree_digest"])
    if target_digest != arm_state["candidate_digest"]:
        raise RuntimeError("recovered target digest mismatch")

    EVIDENCE.mkdir(parents=True)
    files: dict[str, Path] = {
        "arm": EVIDENCE / "arm.json",
        "marker": EVIDENCE / "mid-swap.json",
        "cut": EVIDENCE / "kernel-power-41.json",
        "boot": EVIDENCE / "boot-identity.json",
        "usn-start": EVIDENCE / "usn-start.json",
        "usn-finish": EVIDENCE / "usn-finish.json",
        "target-manifest": EVIDENCE / "target-manifest.json",
        "rollback-manifest": EVIDENCE / "rollback-manifest.json",
        "probe-script": EVIDENCE / "power_probe.py",
    }
    arm_payload = {**arm_state, "arm_digest": declared}
    write_json(files["arm"], arm_payload)
    write_json(files["marker"], {**marker, "marker_digest": marker_declared})
    write_json(files["cut"], {"events": events})
    write_json(files["boot"], boot)
    write_json(files["usn-start"], usn_start)
    write_json(files["usn-finish"], usn_finish)
    write_json(files["target-manifest"], build_package_manifest(TARGET_TEST))
    write_json(files["rollback-manifest"], build_package_manifest(ROLLBACK_TEST))
    durable_write_bytes(files["probe-script"], Path(__file__).read_bytes())
    if sha256(files["probe-script"]) != arm_state["probe_script_sha256"]:
        raise RuntimeError("power probe snapshot changed after execution")
    evidence_files = {
        name: {
            "path": path.relative_to(EVIDENCE).as_posix(),
            "bytes": path.stat().st_size,
            "sha256": sha256(path),
        }
        for name, path in files.items()
    }
    evidence: dict[str, object] = {
        "schema_version": 2,
        "status": "VERIFIED",
        "scope_id": arm_state["scope_id"],
        "run_id": arm_state["run_id"],
        "scope_digest": arm_state["scope_digest"],
        "candidate_digest": arm_state["candidate_digest"],
        "probe_script_sha256": arm_state["probe_script_sha256"],
        "probe_command": arm_state["probe_command"],
        "event_id": marker_declared,
        "armed_at": arm_state["armed_at"],
        "mid_swap_at": marker["mid_swap_at"],
        "recovered_at": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "mid_swap_recovered": True,
        "mid_swap_observation": {
            "target_absent": True,
            "rollback_present": True,
            "staged_candidate_present": True,
            "rollback_digest": rollback_digest,
        },
        "recovered_target_digest": target_digest,
        "rollback_digest": rollback_digest,
        "boot_identity_changed": True,
        "pre_cut_boot_id": arm_state["boot"]["boot_id"],
        "post_cut_boot_id": boot["boot_id"],
        "kernel_power_event_id": 41,
        "kernel_power_events": events,
        "usn_status": usn_finish["status"],
        "usn_event_count": usn_finish["event_count"],
        "usn_start_usn": usn_finish["start_usn"],
        "usn_end_usn": usn_finish["end_usn"],
        "evidence_files": evidence_files,
    }
    evidence["evidence_digest"] = canonical_digest(evidence)
    write_json(EVIDENCE / "PHYSICAL-POWER-EVIDENCE.json", evidence)
    print(
        canonical_json(
            {
                "status": "VERIFIED",
                "candidate_digest": target_digest,
                "rollback_digest": rollback_digest,
                "evidence_digest": evidence["evidence_digest"],
                "evidence": str(EVIDENCE / "PHYSICAL-POWER-EVIDENCE.json"),
            }
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("command", choices=("arm", "recover"))
    args = parser.parse_args()
    return arm() if args.command == "arm" else recover()


if __name__ == "__main__":
    raise SystemExit(main())
