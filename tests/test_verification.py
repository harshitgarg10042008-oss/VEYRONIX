from configsentinel.verification import run_benchmark, verify_report


def test_fail_requires_evidence():
    result = verify_report({"audit": {}, "findings": [{"status": "FAIL"}]})
    assert not result.valid
    assert "lacks evidence" in result.violations[0]


def test_benchmark_corpus_passes():
    assert run_benchmark()["passed"] is True
