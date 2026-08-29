import pytest

from configsentinel.analytics import AnalyticsError, analyze_history


def report(vendor: str, date: str, findings: list[dict[str, str]], failed: int):
    return {
        "recorded_at": date,
        "audit": {"vendor": vendor},
        "summary": {"failed_count": failed, "unknown_count": 0},
        "findings": findings,
    }


def test_history_analytics_aggregates_multiple_dimensions():
    data = analyze_history(
        [
            report(
                "cisco_ios",
                "2026-08-01",
                [{"control_id": "SSH", "status": "PASS", "severity": "LOW"}],
                0,
            ),
            report(
                "junos",
                "2026-08-01",
                [{"control_id": "TELNET", "status": "FAIL", "severity": "HIGH"}],
                1,
            ),
            report(
                "cisco_ios",
                "2026-08-02",
                [{"control_id": "TELNET", "status": "FAIL", "severity": "HIGH"}],
                1,
            ),
        ]
    )
    assert data["report_count"] == 3
    assert data["vendor_counts"] == {"cisco_ios": 2, "junos": 1}
    assert data["severity_counts"]["HIGH"] == 2
    assert data["control_counts"]["TELNET"] == 2
    assert data["timeline"][0]["failed"] == 1
    assert data["timeline"][1]["reports"] == 1


def test_history_analytics_rejects_malformed_entries():
    with pytest.raises(AnalyticsError):
        analyze_history([{"audit": {}, "findings": "not-a-list"}])
