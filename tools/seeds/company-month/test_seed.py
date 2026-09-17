#!/usr/bin/env python3
"""Meaningful reproducibility and refusal tests for the company-month seed."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


HERE = Path(__file__).resolve().parent
GENERATOR = HERE / "generate.py"
VALIDATOR = HERE / "validate.py"


def run_generator(output: Path, seed: str = "company-month-v1") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(GENERATOR), "--out", str(output), "--month", "2026-08", "--seed", seed],
        text=True,
        capture_output=True,
        check=False,
    )


def snapshot(root: Path) -> dict[str, bytes]:
    result: dict[str, bytes] = {}
    for path in root.rglob("*"):
        if path.is_file() and ".git" not in path.parts:
            result[path.relative_to(root).as_posix()] = path.read_bytes()
    return result


class CompanyMonthSeedTests(unittest.TestCase):
    def test_same_seed_has_identical_source_and_oracle_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            first = Path(temporary) / "one"
            second = Path(temporary) / "two"
            first_result = run_generator(first)
            second_result = run_generator(second)
            self.assertEqual(first_result.returncode, 0, first_result.stderr)
            self.assertEqual(second_result.returncode, 0, second_result.stderr)
            self.assertEqual(snapshot(first), snapshot(second))
            validation = subprocess.run([sys.executable, str(VALIDATOR), "--seed-dir", str(first)], text=True, capture_output=True, check=False)
            self.assertEqual(validation.returncode, 0, validation.stdout + validation.stderr)

    def test_generator_refuses_populated_directory_without_deleting(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            occupied = Path(temporary) / "occupied"
            occupied.mkdir()
            marker = occupied / "keep.txt"
            marker.write_text("keep", encoding="utf-8")
            result = run_generator(occupied)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(marker.read_text(encoding="utf-8"), "keep")


if __name__ == "__main__":
    unittest.main()
