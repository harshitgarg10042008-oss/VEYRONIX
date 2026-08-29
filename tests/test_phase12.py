import json
from pathlib import Path

from examples.local_demo import run


def test_offline_demo_produces_three_scenarios_and_safe_outputs(tmp_path: Path):
    manifest = run(tmp_path / "demo")
    assert manifest["mode"] == "offline_local_demo"
    assert manifest["network_calls"] == 0
    assert manifest["llm_enabled"] is False
    assert {item["scenario"] for item in manifest["scenarios"]} == {
        "cisco",
        "junos",
        "firewall",
    }
    for item in manifest["scenarios"]:
        assert Path(item["report"]).exists()
        assert Path(item["json_report"]).exists()
        preview = Path(item["remediation_preview"]).read_text(encoding="utf-8")
        assert "no device connection or execution" in preview.lower()
    saved = json.loads(
        (tmp_path / "demo" / "demo-manifest.json").read_text(encoding="utf-8")
    )
    assert saved["network_calls"] == 0
