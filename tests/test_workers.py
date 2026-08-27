import time

import pytest

from configsentinel.workers import run_bounded


def test_worker_results_keep_input_order():
    result = run_bounded([("slow", 2), ("fast", 1)], lambda value: (time.sleep(0.01 * value), value)[1], max_workers=2)
    assert [item.job_id for item in result] == ["slow", "fast"]
    assert [item.value for item in result] == [2, 1]


def test_worker_failure_is_explicit_and_does_not_abort_other_jobs():
    def worker(value: int) -> int:
        if value == 2:
            raise RuntimeError("bad input")
        return value * 2

    result = run_bounded([("ok", 1), ("bad", 2)], worker)
    assert result[0].value == 2 and result[0].error is None
    assert result[1].value is None and "bad input" in result[1].error


def test_worker_bounds_are_validated():
    with pytest.raises(ValueError):
        run_bounded([], lambda value: value, max_workers=0)
    with pytest.raises(ValueError):
        run_bounded([(str(i), i) for i in range(3)], lambda value: value, max_jobs=2)
