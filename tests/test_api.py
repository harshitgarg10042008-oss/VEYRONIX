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
    assert "posture_score" in report["summary"]
    assert isinstance(report["summary"]["posture_score"], int)
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
    route = next(
        route for route in app.routes if getattr(route, "path", None) == "/api/health"
    )
    payload = route.endpoint()
    assert payload["status"] == "ok"
    assert payload["deterministic"] is True
    assert payload["device_connections"] is False
    assert payload["llm_enabled"] is False
    assert "version" in payload


def test_api_exposes_authoritative_control_pack_metadata():
    app = create_app()
    route = next(
        route
        for route in app.routes
        if getattr(route, "path", None) == "/api/control-pack"
    )
    payload = route.endpoint()
    assert payload["version"]
    assert payload["control_count"] == len(payload["controls"])
    assert payload["vendor_count"] >= 1
    assert len(payload["controls"]) == 7
    assert {item["control_id"] for item in payload["controls"]} >= {
        "NET-MGMT-TELNET-001",
        "NET-MGMT-HTTP-001",
    }
    assert all(item["applicable_vendors"] for item in payload["controls"])


def test_detect_payload_is_typed_and_bounded():
    from configsentinel.api import DetectPayload

    app = create_app()
    route = next(
        route for route in app.routes if getattr(route, "path", None) == "/api/detect"
    )
    result = route.endpoint(
        DetectPayload(config_text="table inet filter\nchain input {}")
    )
    assert result["selected_vendor"] == "linux_nftables"
    assert {candidate["vendor"] for candidate in result["candidates"]} >= {
        "arista_eos",
        "linux_nftables",
    }


def test_api_validation_rejects_nul_and_oversized_lines():
    import pytest

    with pytest.raises(ValueError, match="NUL"):
        validate_config_text("safe\n\x00unsafe")
    with pytest.raises(ValueError, match="line"):
        validate_config_text("x" * (256 * 1024 + 1))


def test_api_governance_request_decision_and_status(tmp_path, monkeypatch):
    from configsentinel.api import create_app
    import uuid
    
    # We need a fresh app instance to use the temp ledger path
    monkeypatch.setenv(
        "CONFIGSENTINEL_GOVERNANCE_LEDGER", str(tmp_path / "events.jsonl")
    )
    app = create_app()
    from starlette.testclient import TestClient
    client = TestClient(app)
    
    # 1. Login as operator
    resp1 = client.post("/api/auth/login", json={"role": "operator"})
    assert resp1.status_code == 200
    cookie_op = resp1.cookies.get("session_token")
    
    resource_id = f"rem_api_{uuid.uuid4().hex}"
    
    # 2. Request
    req_resp = client.post(
        "/api/approval/request",
        json={
            "resource_id": resource_id,
            "reason": "Review preview",
        },
        cookies={"session_token": cookie_op}
    )
    assert req_resp.status_code == 200
    
    # 3. Status check
    status_resp = client.get(f"/api/approval/{resource_id}")
    assert status_resp.status_code == 200
    assert status_resp.json()["status"] == "PENDING_REVIEW"
    
    # 4. Login as reviewer
    resp2 = client.post("/api/auth/login", json={"role": "reviewer"})
    cookie_rev = resp2.cookies.get("session_token")
    
    # 5. Decide
    dec_resp = client.post(
        "/api/approval/decision",
        json={
            "resource_id": resource_id,
            "approve": True,
            "reason": "Looks good",
        },
        cookies={"session_token": cookie_rev}
    )
    assert dec_resp.status_code == 200
    
    status2_resp = client.get(f"/api/approval/{resource_id}")
    assert status2_resp.status_code == 200
    assert status2_resp.json()["status"] == "APPROVED"


def test_api_governance_rejects_same_actor_decision(tmp_path, monkeypatch):
    from configsentinel.api import create_app
    import uuid
    
    monkeypatch.setenv(
        "CONFIGSENTINEL_GOVERNANCE_LEDGER", str(tmp_path / "events.jsonl")
    )
    app = create_app()
    from starlette.testclient import TestClient
    client = TestClient(app)
    
    # Login as operator
    resp1 = client.post("/api/auth/login", json={"role": "operator"})
    cookie_op = resp1.cookies.get("session_token")
    
    resource_id = f"rem_same_actor_{uuid.uuid4().hex}"
    
    req_resp = client.post(
        "/api/approval/request",
        json={"resource_id": resource_id},
        cookies={"session_token": cookie_op}
    )
    assert req_resp.status_code == 200
    
    dec_resp = client.post(
        "/api/approval/decision",
        json={"resource_id": resource_id, "approve": True},
        cookies={"session_token": cookie_op}
    )
    assert dec_resp.status_code == 422
    assert "only reviewers or administrators can decide" in dec_resp.json().get("detail", "")


def test_api_offline_explanation_is_bounded_and_non_authoritative(monkeypatch):
    from configsentinel.api import ExplainPayload, create_app

    monkeypatch.setenv("CONFIGSENTINEL_LLM_PROVIDER", "offline")
    app = create_app()
    route = next(
        route for route in app.routes if getattr(route, "path", None) == "/api/explain"
    )
    response = route.endpoint(
        ExplainPayload(
            config_text="version 17.9\nline vty 0 4\n transport input telnet\n",
            vendor="cisco_ios",
            control_id="NET-MGMT-HTTP-001",
        )
    )
    assert response["llm_assisted"] is True
    assert response["deterministic_status"] == "UNKNOWN"
    assert response["explanation"]["safety_status"] == "REVIEW_REQUIRED"
    assert "NET-MGMT-HTTP-001" in response["explanation"]["explanation"]


def test_strict_identity_mode_derives_governance_actor_from_authenticated_headers(monkeypatch, tmp_path):
    from fastapi.testclient import TestClient
    from configsentinel.api import create_app

    monkeypatch.setenv("CONFIGSENTINEL_GOVERNANCE_LEDGER", str(tmp_path / "strict-events.jsonl"))
    monkeypatch.setenv("CONFIGSENTINEL_AUTH_REQUIRED", "true")
    monkeypatch.setenv("CONFIGSENTINEL_API_TOKEN", "strict-test-token")
    monkeypatch.setenv("CONFIGSENTINEL_IDENTITY_REQUIRED", "true")
    client = TestClient(create_app())
    payload = {"resource_id": "strict-api-rem", "actor_id": "spoofed", "role": "reviewer", "reason": "review"}
    bearer = {"Authorization": "Bearer strict-test-token"}

    assert client.post("/api/approval/request", json=payload, headers=bearer).status_code == 403
    operator = {**bearer, "X-Authenticated-User": "operator-a", "X-Authenticated-Role": "operator", "X-Authenticated-Workspace": "team-a"}
    reviewer = {**bearer, "X-Authenticated-User": "reviewer-b", "X-Authenticated-Role": "reviewer", "X-Authenticated-Workspace": "team-a"}
    requested = client.post("/api/approval/request", json=payload, headers=operator)
    decided = client.post("/api/approval/decision", json={**payload, "approve": True}, headers=reviewer)

    assert requested.status_code == 200
    assert requested.json()["event"]["actor_id"] == "operator-a"
    assert requested.json()["event"]["role"] == "operator"
    assert decided.status_code == 200
    assert decided.json()["event"]["actor_id"] == "reviewer-b"
    assert decided.json()["event"]["role"] == "reviewer"
