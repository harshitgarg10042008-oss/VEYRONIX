"""SIH Master verification tests covering LAN endpoints, shared state, email inspection, and archive audits."""

from __future__ import annotations

import base64
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from configsentinel.api import create_app
from configsentinel.email_inspection import inspect_raw_email


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("CONFIGSENTINEL_DATABASE_URL", str(tmp_path / "sih_test.db"))
    app = create_app()
    return TestClient(app, raise_server_exceptions=False)


def test_version_endpoint_public(client):
    res = client.get("/api/version")
    assert res.status_code == 200
    data = res.json()
    assert data["api_version"] == "0.4.0"
    assert data["compatible"] is True
    assert "deployment_mode" in data
    assert "auth_mode" in data


def test_health_diagnostics_extended(client):
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "ok"
    assert data["storage"] == "healthy"
    assert data["deterministic"] is True
    assert data["device_connections"] is False
    assert "backup_age_hours" in data
    assert "deployment_mode" in data


def test_projects_crud(client):
    res = client.get("/api/projects")
    assert res.status_code == 200
    data = res.json()
    assert data["total"] >= 1
    assert any(p["project_id"] == "local" for p in data["projects"])

    # Create new project
    res_create = client.post("/api/projects", json={
        "project_id": "sih-demo-project",
        "name": "SIH Evaluation Workspace",
        "description": "Multi-client test project",
    })
    assert res_create.status_code == 200
    assert res_create.json()["project_id"] == "sih-demo-project"

    # List again
    res_list = client.get("/api/projects")
    assert any(p["project_id"] == "sih-demo-project" for p in res_list.json()["projects"])


def test_shared_audits_idempotent_and_bulk_delete(client):
    payload = {
        "audit_id": "audit-sih-001",
        "project_id": "sih-demo-project",
        "filename": "cisco_edge.conf",
        "input_sha256": "abcdef1234567890" * 4,
        "vendor": "cisco_ios",
        "format": "cisco_ios",
        "parser_id": "cisco_ios",
        "parser_version": "4.0.0",
        "control_pack_version": "2.0.0",
        "score_state": "SCORE_AVAILABLE",
        "score": 85.0,
        "summary": {"finding_count": 5, "failed_count": 1, "posture_score": 85},
        "created_by": "auditor-a",
        "report_json": {"audit": {"audit_id": "audit-sih-001"}, "findings": []},
    }

    # First insert
    res1 = client.post("/api/audits", json=payload)
    assert res1.status_code == 200
    assert res1.json()["audit_id"] == "audit-sih-001"
    assert res1.json()["score"] == 85.0

    # Second insert with updated score should update idempotently, not crash 409
    payload["score"] = 90.0
    res2 = client.post("/api/audits", json=payload)
    assert res2.status_code == 200
    assert res2.json()["score"] == 90.0

    # Get single audit
    res_get = client.get("/api/audits/audit-sih-001")
    assert res_get.status_code == 200
    assert res_get.json()["filename"] == "cisco_edge.conf"
    assert res_get.json()["finding_counts"]["total"] == 5

    # Bulk delete
    del_res = client.delete("/api/audits")
    assert del_res.status_code == 200
    assert del_res.json()["deleted_count"] >= 1

    # List should be empty now
    res_empty = client.get("/api/audits")
    assert res_empty.json()["total"] == 0


def test_archive_audit_endpoint(client, tmp_path):
    zip_path = tmp_path / "test_bundle.zip"
    cisco_conf = Path("tests/fixtures/cisco.conf").read_text(encoding="utf-8")
    junos_conf = Path("tests/fixtures/junos.conf").read_text(encoding="utf-8")

    with zipfile.ZipFile(zip_path, "w") as bundle:
        bundle.writestr("cisco.conf", cisco_conf)
        bundle.writestr("junos.conf", junos_conf)

    b64_data = base64.b64encode(zip_path.read_bytes()).decode("ascii")
    res = client.post("/api/audit/archive", json={
        "archive_base64": b64_data,
        "filename": "test_bundle.zip",
        "vendor": "auto",
    })
    assert res.status_code == 200
    data = res.json()
    assert data["total_members"] == 2
    assert data["audited_count"] == 2
    filenames = [m["filename"] for m in data["members"]]
    assert "cisco.conf" in filenames
    assert "junos.conf" in filenames
    cisco_member = next(m for m in data["members"] if m["filename"] == "cisco.conf")
    assert cisco_member["status"] in {"PARSED", "PARTIALLY_PARSED"}
    assert "report" in cisco_member


def test_email_inspection_clean():
    raw = (
        "From: security@acme.corp\n"
        "Reply-To: security@acme.corp\n"
        "Return-Path: <security@acme.corp>\n"
        "Subject: Routine Security Notice\n"
        "Authentication-Results: mx.acme.corp; spf=pass; dkim=pass (d=acme.corp)\n"
        "DKIM-Signature: v=1; a=rsa-sha256; d=acme.corp; s=s1;\n"
        "\n"
        "This is an authorized internal security notice.\n"
    )
    result = inspect_raw_email(raw)
    assert result["score"] >= 80
    assert result["finding_counts"]["fail"] == 0
    assert result["headers"]["from_domain"] == "acme.corp"
    assert "Review-only header authentication" in result["boundary_notice"]


def test_email_inspection_mismatched_and_dangerous_attachment():
    raw = (
        "From: ceo@legit-company.com\n"
        "Reply-To: attacker@phishing-drop.xyz\n"
        "Return-Path: <spoof@unrelated.net>\n"
        "Subject: Urgent Wire Transfer\n"
        "Authentication-Results: mx.receiver.com; spf=fail; dkim=none\n"
        "Content-Type: multipart/mixed; boundary=\"BOUNDARY\"\n"
        "\n"
        "--BOUNDARY\n"
        "Content-Type: text/plain\n"
        "\n"
        "Please execute this wire transfer immediately: http://192.168.1.50/login.php\n"
        "--BOUNDARY\n"
        "Content-Type: application/octet-stream; name=\"invoice.exe\"\n"
        "Content-Disposition: attachment; filename=\"invoice.exe\"\n"
        "\n"
        "FAKE_EXE_BINARY_DATA\n"
        "--BOUNDARY--\n"
    )
    result = inspect_raw_email(raw)
    assert result["score"] < 50
    assert result["finding_counts"]["fail"] >= 2
    check_ids = {f["check_id"] for f in result["findings"]}
    assert "EMAIL-AUTH-REPLYTO-001" in check_ids
    assert "EMAIL-ATTACHMENT-001" in check_ids
    assert any(a["dangerous_type"] is True for a in result["attachments"])
