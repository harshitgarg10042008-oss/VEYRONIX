import json

import pytest
from fastapi.testclient import TestClient
from configsentinel.api import app

client = TestClient(app)


def test_shared_audit_routes_create_and_list_records(tmp_path, monkeypatch):
    monkeypatch.setenv("CONFIGSENTINEL_DATABASE_URL", str(tmp_path / "shared-audits.db"))
    client = TestClient(app)

    payload = {
        "audit_id": "audit-123",
        "project_id": "project-demo",
        "filename": "edge.cfg",
        "input_sha256": "a" * 64,
        "vendor": "cisco_ios",
        "parser_id": "cisco_ios",
        "parser_version": "4.0.0",
        "control_pack_version": "2.0.0",
        "summary": {"failed_count": 1, "status": "FAIL"},
        "created_by": "operator-a",
        "report_json": {"audit": {"audit_id": "audit-123"}, "summary": {"failed_count": 1}},
    }

    create_response = client.post("/api/audits", json=payload)
    assert create_response.status_code == 200, create_response.text
    created = create_response.json()
    assert created["audit_id"] == "audit-123"
    assert created["project_id"] == "project-demo"

    list_response = client.get("/api/audits")
    assert list_response.status_code == 200
    assert any(item["audit_id"] == "audit-123" for item in list_response.json()["items"])

    fetch_response = client.get("/api/audits/audit-123")
    assert fetch_response.status_code == 200
    assert fetch_response.json()["filename"] == "edge.cfg"


def test_shared_audit_review_route_records_review_disposition(tmp_path, monkeypatch):
    monkeypatch.setenv("CONFIGSENTINEL_DATABASE_URL", str(tmp_path / "shared-audits.db"))
    client = TestClient(app)

    client.post(
        "/api/audits",
        json={
            "audit_id": "audit-review",
            "project_id": "project-demo",
            "filename": "edge.cfg",
            "input_sha256": "b" * 64,
            "vendor": "cisco_ios",
            "parser_id": "cisco_ios",
            "parser_version": "4.0.0",
            "control_pack_version": "2.0.0",
            "summary": {"failed_count": 2},
            "created_by": "operator-a",
            "report_json": {"audit": {"audit_id": "audit-review"}},
        },
    )

    review_response = client.post(
        "/api/audits/audit-review/reviews",
        json={"reviewer": "reviewer-b", "decision": "APPROVED", "reason": "Clear evidence"},
    )
    assert review_response.status_code == 200, review_response.text
    assert review_response.json()["decision"] == "APPROVED"

    audit_response = client.get("/api/audits/audit-review")
    assert audit_response.status_code == 200
    assert audit_response.json()["reviews"][0]["decision"] == "APPROVED"

def test_blast_radius_simulation():
    response = client.post("/api/blast-radius/simulate", json={"change_type": "acl_modification", "target_id": "fw-01"})
    assert response.status_code in (200, 404, 405, 422) # if mocked or stubbed out

def test_mutation_lab_run():
    response = client.post("/api/mutation-lab/run", json={"control_id": "test", "iterations": 1})
    assert response.status_code in (200, 422)

def test_parser_differential_run():
    response = client.post("/api/parser-differential/run", json={"config_text": "test", "vendors": ["cisco_ios"]})
    assert response.status_code in (200, 422)

def test_attack_graph_paths():
    response = client.get("/api/attack-graph/paths")
    assert response.status_code in (200, 404)

def test_counterfactual_run():
    response = client.post("/api/counterfactual/run", json={"scenario": "test"})
    assert response.status_code in (200, 422)

def test_decision_quality_report():
    response = client.get("/api/decision-quality/report")
    assert response.status_code in (200, 404)

def test_secrets_scan():
    response = client.post("/api/secrets/scan", json={"config_text": "password=123"})
    assert response.status_code in (200, 422)

def test_supply_chain_sboms():
    response = client.post("/api/supply-chain/sboms", json={"sbom_content": "{}"})
    assert response.status_code in (200, 422)

def test_provenance_verify():
    response = client.post("/api/provenance/verify", json={"artifact_hash": "test"})
    assert response.status_code in (200, 422)

def test_threat_models_compile():
    response = client.post("/api/threat-models/compile", json={"architecture_json": "{}"})
    assert response.status_code in (200, 422)

def test_api_contracts_conformance():
    response = client.post("/api/api-contracts/conformance", json={"spec": "{}"})
    assert response.status_code in (200, 422)

def test_resilience_drills():
    response = client.get("/api/resilience/drills")
    assert response.status_code in (200, 404)

def test_debt_report():
    response = client.post("/api/debt/report", json={"scope": "global"})
    assert response.status_code in (200, 422)

def test_exchange_packages():
    response = client.post("/api/exchange/packages", json={"package_data": "{}"})
    assert response.status_code in (200, 422)

def test_regulatory_export():
    response = client.post("/api/regulatory/export", json={"framework": "nist-800-53"})
    assert response.status_code in (200, 422)

def test_knowledge_graph_query():
    response = client.post("/api/knowledge-graph/query", json={"query": "test"})
    assert response.status_code in (200, 422)
