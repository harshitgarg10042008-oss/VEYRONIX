from configsentinel.demo import compare_reports, render_guided_demo


def test_compare_reports_returns_control_status_deltas():
    before = {"audit": {"audit_id": "before"}, "findings": [{"control_id": "SSH", "status": "FAIL"}]}
    after = {"audit": {"audit_id": "after"}, "findings": [{"control_id": "SSH", "status": "PASS"}, {"control_id": "AAA", "status": "UNKNOWN"}]}
    result = compare_reports(before, after)
    assert result["changed_count"] == 2
    assert result["before_audit_id"] == "before"


def test_guided_demo_escapes_report_text_and_has_safety_boundary():
    report = {"audit": {"audit_id": "<audit>", "vendor": "cisco_ios"}, "summary": {"failed_count": 1, "unknown_count": 0}, "findings": [{"control_id": "<control>", "status": "FAIL", "severity": "HIGH"}]}
    rendered = render_guided_demo(report)
    assert "&lt;audit&gt;" in rendered
    assert "&lt;control&gt;" in rendered
    assert "no device connection" in rendered
