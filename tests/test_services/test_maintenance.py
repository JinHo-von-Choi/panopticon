"""잘못된 갱신 주기가 반복 작업의 대기를 없애지 않도록 검증한다."""

import logging

import pytest

from netwatcher.services.maintenance import _positive_hours


@pytest.mark.parametrize("value", [None, "bad", 0, -1, float("nan"), float("inf"), -float("inf")])
def test_invalid_interval_falls_back_and_warns(value, caplog):
    with caplog.at_level(logging.WARNING):
        assert _positive_hours(value) == 6.0
    assert caplog.records


def test_valid_interval_preserves_hours_and_has_minimum_wait():
    assert _positive_hours(2) == 2
    assert _positive_hours(0.0001) * 3600 == 60
