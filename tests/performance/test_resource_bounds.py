"""재현 도구의 격리 계약과 결정적 입력."""

import argparse
from pathlib import Path

import pytest

from scripts.perf_replay import frames, validate


def arguments(tmp_path):
    return argparse.Namespace(db_name="netwatcher_perf_test", db_host="127.0.0.1",
                              duration_seconds=1, pps=100, alerts_per_second=100,
                              output_dir=tmp_path / "new-run")


def test_corpus_is_reproducible_and_scenario_changes_input():
    assert frames(7, "normal") == frames(7, "normal")
    assert frames(7, "normal") != frames(8, "normal")
    assert frames(7, "normal") != frames(7, "mixed")


def test_replay_rejects_production_database(tmp_path):
    args = arguments(tmp_path)
    args.db_name = "netwatcher_production"
    with pytest.raises(ValueError, match="dedicated"):
        validate(args)


def test_replay_rejects_remote_database(tmp_path):
    args = arguments(tmp_path)
    args.db_host = "192.0.2.235"
    with pytest.raises(ValueError, match="local"):
        validate(args)


def test_replay_cannot_overwrite_results(tmp_path):
    args = arguments(tmp_path)
    args.output_dir.mkdir()
    (args.output_dir / "result.json").write_text("keep")
    with pytest.raises(ValueError, match="already exists"):
        validate(args)
    assert (args.output_dir / "result.json").read_text() == "keep"


@pytest.mark.parametrize("duration", [0, -1, float("inf"), float("nan")])
def test_replay_rejects_invalid_duration(tmp_path, duration):
    args = arguments(tmp_path)
    args.duration_seconds = duration
    with pytest.raises(ValueError, match="duration"):
        validate(args)
