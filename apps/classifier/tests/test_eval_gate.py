"""The CI gate itself: recall on dangerous actions is 100% for the deterministic backends."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


@pytest.mark.parametrize("backend", ["heuristic", "fixture"])
def test_recall_gate_passes(backend: str) -> None:
    run = subprocess.run([sys.executable, str(ROOT / "eval" / "run_eval.py"), "--backend", backend,
                          "--assert-recall", "1.0"], capture_output=True, text=True, cwd=ROOT, check=False)
    assert run.returncode == 0, run.stdout + run.stderr
    assert "recall(dangerous)=1.000" in run.stdout


def test_recall_gate_fails_when_a_dangerous_case_is_missed(tmp_path: Path) -> None:
    corpus = (ROOT / "eval" / "corpus.jsonl").read_text(encoding="utf-8").splitlines()
    safe_line = next(line for line in corpus if '"label":"safe"' in line)
    mislabelled = safe_line.replace('"label":"safe"', '"label":"dangerous"')
    path = tmp_path / "corpus.jsonl"
    path.write_text(mislabelled + "\n", encoding="utf-8")
    run = subprocess.run([sys.executable, str(ROOT / "eval" / "run_eval.py"), "--corpus", str(path),
                          "--assert-recall", "1.0", "--min-precision", "0"], capture_output=True, text=True,
                         cwd=ROOT, check=False)
    assert run.returncode == 1
    assert "FAIL: recall" in run.stdout
