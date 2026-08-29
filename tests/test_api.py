from configsentinel.api import AuditApi, AuditPayload, create_app, validate_config_text


def test_api_returns_report_with_evidence_and_summary():
    report = AuditApi().audit(
        AuditPayload(
            config_text="line vty 0 4\n transport input telnet\n",
            vendor="cisco_ios",
            frameworks=["cis", "nist"],
        )
    )
    assert report["audit"]["frameworks"] == ["cis-network", "nist-800-53"]
    assert report["summary"]["failed_count"] >= 1
    finding = next(item for item in report["findings"] if item["status"] == "FAIL")
    assert finding["evidence"]
    assert finding["framework_mappings"]


def test_api_redacts_secret_before_evaluation():
    report = AuditApi().audit(
        AuditPayload(
            config_text="username operator secret 0 super-secret\nline vty 0 4\n transport input telnet\n",
            vendor="cisco_ios",
        )
    )
    assert "super-secret" not in str(report)
    assert report["audit"]["input_sha256"]


def test_api_health_is_explicitly_local_and_non_executing():
    app = create_app()
    route = next(route for route in app.routes if getattr(route, "path", None) == "/api/health")
    payload = route.endpoint()
    assert payload == {"status": "ok", "deterministic": True, "device_connections": False, "llm_enabled": False}


def test_api_exposes_authoritative_control_pack_metadata():
    app = create_app()
    route = next(route for route in app.routes if getattr(route, "path", None) == "/api/control-pack")
    payload = route.endpoint()
    assert payload["version"]
    assert len(payload["controls"]) == 7
    assert {item["control_id"] for item in payload["controls"]} >= {"NET-MGMT-TELNET-001", "NET-MGMT-HTTP-001"}
    assert all(item["applicable_vendors"] for item in payload["controls"])


def test_detect_payload_is_typed_and_bounded():
    from configsentinel.api import DetectPayload

    app = create_app()
    route = next(route for route in app.routes if getattr(route, "path", None) == "/api/detect")
    result = route.endpoint(DetectPayload(config_text="table inet filter\nchain input {}"))
    assert result["selected_vendor"] == "linux_nftables"
    assert {candidate["vendor"] for candidate in result["candidates"]} >= {"arista_eos", "linux_nftables"}


def test_api_validation_rejects_nul_and_oversized_lines():
    import pytest

    with pytest.raises(ValueError, match="NUL"):
        validate_config_text("safe\n\x00unsafe")
    with pytest.raises(ValueError, match="line"):
        validate_config_text("x" * (256 * 1024 + 1))


def test_api_governance_request_decision_and_status(tmp_path, monkeypatch):
    from configsentinel.api import ApprovalRequestPayload, ApprovalDecisionPayload, create_app

    monkeypatch.setenv("CONFIGSENTINEL_GOVERNANCE_LEDGER", str(tmp_path / "events.jsonl"))
    app = create_app()
    request_route = next(route for route in app.routes if getattr(route, "path", None) == "/api/approval/request")
    decision_route = next(route for route in app.routes if getattr(route, "path", None) == "/api/approval/decision")
    status_route = next(route for route in app.routes if getattr(route, "path", None) == "/api/approval/{resource_id}")
    # Route endpoints share the app's ledger; use a fresh app-scoped path via the environment in integration tests.
    request = request_route.endpoint(ApprovalRequestPayload(resource_id="rem_api", actor_id="alice", role="operator", reason="Review preview"))
    assert request["status"] == "PENDING_REVIEW"
    decision = decision_route.endpoint(ApprovalDecisionPayload(resource_id="rem_api", actor_id="bob", role="reviewer", approve=True, reason="Independent review"))
    assert decision["status"] == "APPROVED"
    status = status_route.endpoint("rem_api")
    assert status["status"] == "APPROVED"
    assert [event["action"] for event in status["events"]] == ["REQUEST", "APPROVE"]


def test_api_governance_rejects_same_actor_decision(tmp_path, monkeypatch):
    from fastapi import HTTPException
    from configsentinel.api import ApprovalRequestPayload, ApprovalDecisionPayload, create_app

    monkeypatch.setenv("CONFIGSENTINEL_GOVERNANCE_LEDGER", str(tmp_path / "events.jsonl"))
    app = create_app()
    request_route = next(route for route in app.routes if getattr(route, "path", None) == "/api/approval/request")
    decision_route = next(route for route in app.routes if getattr(route, "path", None) == "/api/approval/decision")
    request_route.endpoint(ApprovalRequestPayload(resource_id="rem_same_actor", actor_id="alice", role="operator"))
    try:
        decision_route.endpoint(ApprovalDecisionPayload(resource_id="rem_same_actor", actor_id="alice", role="reviewer", approve=True))
    except HTTPException as exc:
        assert exc.status_code == 422
        assert "different reviewer" in str(exc.detail)
    else:
        raise AssertionError("same actor must not approve its own request")
