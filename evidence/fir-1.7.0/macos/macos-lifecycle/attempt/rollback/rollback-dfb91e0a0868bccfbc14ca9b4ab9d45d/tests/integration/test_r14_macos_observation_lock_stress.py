from __future__ import annotations

import multiprocessing
import stat
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))

from full_inspection_repair.contracts import canonical_digest
from full_inspection_repair.observation import ObservationJournal

_TRIALS = 100
_CHILD_COUNT = 4
_DIGEST = "a" * 64
_VICTIM_BYTES = b"r14-observation-lock-victim\n"


def _observation(trial_number: int, child_number: int) -> dict[str, object]:
    return {
        "source_run_id": f"r14-lock-trial-{trial_number:03d}",
        "source_phase": "CHECK",
        "producer_id": f"child-{child_number}",
        "subject_id": "skill:r14-observation-lock",
        "subject_kind": "SKILL",
        "subject_digest": _DIGEST,
        "invariant_id": "INV-R14-APPEND-SERIALIZATION",
        "defect_class_id": "r14.observation-lock",
        "taxonomy_category_id": "BOUNDARY",
        "fingerprint": f"r14-lock-{trial_number:03d}-{child_number}",
        "fingerprint_version": "1.0.0",
        "message": f"trial {trial_number} child {child_number}",
        "mechanism": "concurrent first observation append",
        "root_cause_hypothesis": None,
        "evidence_refs": ["evidence/r14-observation-lock.json"],
        "evidence_sha256": _DIGEST,
        "redaction_policy_digest": _DIGEST,
        "severity": "Low",
        "analogous_surfaces": [],
        "status": "CONFIRMED",
        "safe_feedback": "serialize observation appends",
        "recorded_at": "2026-11-11T12:00:00Z",
    }


def _append_after_barrier(
    journal_path: str,
    barrier,
    trial_number: int,
    child_number: int,
) -> None:
    barrier.wait()
    ObservationJournal(journal_path).append(_observation(trial_number, child_number))


@pytest.mark.skipif(sys.platform != "darwin", reason="native Darwin lock stress")
def test_macos_observation_lock_stress(tmp_path: Path) -> None:
    for trial_number in range(_TRIALS):
        trial_dir = tmp_path / f"trial-{trial_number:03d}"
        trial_dir.mkdir()
        journal_path = trial_dir / "observations.jsonl"
        lock_path = journal_path.with_name(journal_path.name + ".lock")
        victim_path = trial_dir / "victim"
        victim_path.write_bytes(_VICTIM_BYTES)

        context = multiprocessing.get_context("spawn")
        barrier = context.Barrier(_CHILD_COUNT)
        processes = [
            context.Process(
                target=_append_after_barrier,
                args=(
                    str(journal_path),
                    barrier,
                    trial_number,
                    child_number,
                ),
            )
            for child_number in range(_CHILD_COUNT)
        ]
        try:
            for process in processes:
                process.start()
            for process in processes:
                process.join(30)

            exit_codes = [process.exitcode for process in processes]
            if exit_codes != [0] * _CHILD_COUNT:
                raise AssertionError(f"child exit codes differ: {exit_codes}")

            journal = ObservationJournal(journal_path)
            record_count = journal.verify()
            if record_count != _CHILD_COUNT:
                raise AssertionError(
                    f"record count: expected {_CHILD_COUNT}, got {record_count}"
                )
            records = journal._records(require_nonempty=True)
            previous_digest = None
            for expected_sequence, record in enumerate(records, start=1):
                if record["journal_sequence"] != expected_sequence:
                    raise AssertionError(
                        f"sequence at {expected_sequence}: "
                        f"{record['journal_sequence']}"
                    )
                if record["previous_record_digest"] != previous_digest:
                    raise AssertionError(f"previous digest at {expected_sequence}")
                material = dict(record)
                declared_digest = material.pop("record_digest")
                if canonical_digest(material) != declared_digest:
                    raise AssertionError(f"record digest at {expected_sequence}")
                previous_digest = declared_digest

            if victim_path.read_bytes() != _VICTIM_BYTES:
                raise AssertionError("victim bytes changed")
            if lock_path.is_symlink() or not stat.S_ISREG(lock_path.lstat().st_mode):
                raise AssertionError("lock path is not a regular non-symlink file")
        except Exception as exc:
            exit_codes = [process.exitcode for process in processes]
            raise AssertionError(
                f"{exc}; trial_path={trial_dir}; child_exit_codes={exit_codes}"
            ) from exc
        finally:
            for process in processes:
                if process.pid is not None and process.is_alive():
                    process.terminate()
                if process.pid is not None:
                    process.join()
