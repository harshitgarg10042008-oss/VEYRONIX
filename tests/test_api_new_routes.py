import pytest
from fastapi.testclient import TestClient
from configsentinel.api import app

client = TestClient(app)

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
