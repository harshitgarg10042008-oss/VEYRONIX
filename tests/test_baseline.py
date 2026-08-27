import json
from pathlib import Path

import pytest

from configsentinel.baseline import BaselineError, compare_baseline, load_baseline, make_baseline, save_baseline
from configsentinel.client import ConfigSentinelClient
from configsentinel.engine import DeterministicComplianceEngine


def audit(text: str):
    return ConfigSentinelClient(engine=DeterministicComplianceEngine()).audit_text(text, vendor="cisco_ios")


def test_baseline_round_trip_does_not_store_raw_configuration(tmp_path: Path):
    result = audit("version 17.9\nno ip http server\n")
    path = tmp_path / "approved.json"
    snapshot = save_baseline(result, path, label="production-approved")
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert load_baseline(path) == snapshot
    assert payload["input_sha256"] == result.input_sha256
    assert "no ip http server" not in path.read_text(encoding="utf-8")


def test_drift_detects_hash_and_control_status_changes():
    baseline = make_baseline(audit("version 17.9\nno ip http server\n"))
    comparison = compare_baseline(baseline, audit("version 17.9\nline vty 0 4\n transport input telnet\n"))
    assert comparison["drifted"] is True
    assert comparison["hash_changed"] is True
    assert "NET-MGMT-TELNET-001" in comparison["changed_controls"]


def test_unchanged_configuration_is_clean():
    result = audit("version 17.9\nno ip http server\n")
    assert compare_baseline(make_baseline(result), result)["drifted"] is False


def test_invalid_baseline_fails_closed(tmp_path: Path):
    path = tmp_path / "bad.json"
    path.write_text("{}", encoding="utf-8")
    with pytest.raises(BaselineError):
        load_baseline(path)
