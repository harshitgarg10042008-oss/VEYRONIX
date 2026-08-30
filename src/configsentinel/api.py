"""Local HTTP adapter for the deterministic VEYRONIX audit engine.

The API is intentionally small and local-first. It accepts configuration text,
redacts it through the SDK client, evaluates deterministic controls, and returns
the same report dictionary used by CLI exports. It never connects to devices or
allows the LLM to create verdicts.
"""

from __future__ import annotations

import json
import os
import time
import uuid
import secrets
from collections import defaultdict, deque
from typing import Any

from .client import ConfigSentinelClient
from .controls import CONTROL_PACK, CONTROL_PACK_VERSION
from .detection import detect_vendor
from .engine import DeterministicComplianceEngine
from .frameworks import normalize_frameworks
from .governance import ApprovalLedger, GovernanceError, Role
from .llm import LLMConfig, LLMError, LLMCopilot, OpenAICompatibleProvider
from .reporting import report_dict
from .proof import (
    build_proof_bundle,
    verify_proof_bundle,
    ProofError,
    audit_from_report,
)
from .remediation import generate_bundle, build_diffs, RemediationError
from .website_scanner import WebsiteScanner
from .website_models import WebsiteScanRequest
from .website_http import HTTPClientConfig, TargetSafetyError
from .website_storage import WebsiteScanStorage

try:
    from fastapi import FastAPI, HTTPException, Request, Response, Depends, Cookie
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
except (
    ImportError
) as exc:  # pragma: no cover - exercised only without the optional API extra
    raise RuntimeError("Install the 'api' extra to run the local HTTP adapter") from exc


MAX_CONFIG_CHARS = 5 * 1024 * 1024
MAX_LINE_BYTES = 256 * 1024


def validate_config_text(config_text: str) -> None:
    encoded = config_text.encode("utf-8")
    if b"\x00" in encoded:
        raise ValueError("NUL bytes are not accepted")
    if len(encoded) > MAX_CONFIG_CHARS:
        raise ValueError("configuration exceeds the maximum size")
    if any(
        len(line.encode("utf-8")) > MAX_LINE_BYTES
        for line in config_text.splitlines(keepends=True)
    ):
        raise ValueError("configuration line exceeds the safety limit")


class AuditPayload(BaseModel):
    config_text: str = Field(min_length=1, max_length=MAX_CONFIG_CHARS)
    vendor: str = Field(default="auto", min_length=1, max_length=64)
    frameworks: list[str] = Field(
        default_factory=lambda: ["cis-network", "nist-800-53"], max_length=8
    )
    project_id: str = Field(default="local", min_length=1, max_length=128)


class DetectPayload(BaseModel):
    config_text: str = Field(min_length=1, max_length=MAX_CONFIG_CHARS)


class ApprovalRequestPayload(BaseModel):
    resource_id: str = Field(min_length=1, max_length=256)
    reason: str = Field(default="", max_length=500)
    # The frontend still sends these, so we accept them to avoid 422 but ignore their values
    actor_id: str | None = None
    role: str | None = None


class ApprovalDecisionPayload(ApprovalRequestPayload):
    approve: bool


class LoginPayload(BaseModel):
    role: str = Field(default="operator")


MOCK_SESSIONS: dict[str, dict[str, str]] = {}


def get_current_session(session_token: str | None = Cookie(default=None)):
    if not session_token or session_token not in MOCK_SESSIONS:
        raise HTTPException(status_code=401, detail="Valid session required")
    return MOCK_SESSIONS[session_token]


class ExplainPayload(AuditPayload):
    finding_id: str | None = Field(default=None, max_length=256)
    control_id: str | None = Field(default=None, max_length=128)


class WebsiteScanPayload(BaseModel):
    url: str = Field(min_length=1, max_length=2048)
    authorization_confirmed: bool = True
    workspace_id: str = Field(default="local", max_length=128)


class WebsiteExplainPayload(BaseModel):
    finding_id: str = Field(min_length=1, max_length=256)


class AuditApi:
    def __init__(self) -> None:
        self.client = ConfigSentinelClient(engine=DeterministicComplianceEngine())

    def audit(self, payload: AuditPayload) -> dict[str, Any]:
        try:
            validate_config_text(payload.config_text)
            frameworks = normalize_frameworks(tuple(payload.frameworks))
            result = self.client.audit_text(
                payload.config_text,
                vendor=payload.vendor,
                frameworks=frameworks,
                project_id=payload.project_id,
            )
            return report_dict(result, frameworks)
        except (ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc


def create_app(*, allowed_origins: list[str] | None = None) -> FastAPI:
    app = FastAPI(
        title="ConfigSentinel AI Local Audit API",
        version="0.4.0",
        description="Evidence-backed, deterministic configuration compliance auditing. No device connections or remote mutation.",
        openapi_tags=[
            {
                "name": "audit",
                "description": "Deterministic audit and vendor detection operations.",
            },
            {
                "name": "webhooks",
                "description": "Local event contract; delivery is intentionally external.",
            },
        ],
    )
    origins = allowed_origins or ["http://localhost:3000", "http://127.0.0.1:3000"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
    )
    service = AuditApi()
    ledger = ApprovalLedger(
        os.getenv("CONFIGSENTINEL_GOVERNANCE_LEDGER", ".configsentinel/events.jsonl")
    )
    website_storage = WebsiteScanStorage(
        os.getenv("CONFIGSENTINEL_DATABASE_URL", "sqlite:///./.configsentinel/configsentinel.db")
    )
    api_token = os.getenv("CONFIGSENTINEL_API_TOKEN", "").strip()
    auth_required = os.getenv("CONFIGSENTINEL_AUTH_REQUIRED", "false").lower() == "true"
    if auth_required and not api_token:
        raise RuntimeError(
            "CONFIGSENTINEL_AUTH_REQUIRED is enabled but CONFIGSENTINEL_API_TOKEN is missing"
        )
    rate_limit = max(1, int(os.getenv("CONFIGSENTINEL_RATE_LIMIT_PER_MINUTE", "120")))
    request_windows: dict[str, deque[float]] = defaultdict(deque)

    @app.middleware("http")
    async def security_boundary(request: Request, call_next):
        request_id = request.headers.get("x-request-id", "").strip()[:128] or str(
            uuid.uuid4()
        )
        protected = request.url.path.startswith("/api/") and request.url.path not in {
            "/api/health",
            "/api/v1/health",
        }
        if protected:
            now = time.monotonic()
            client_key = request.client.host if request.client else "unknown"
            window = request_windows[client_key]
            while window and now - window[0] >= 60:
                window.popleft()
            if len(window) >= rate_limit:
                response = JSONResponse(
                    status_code=429,
                    content={"detail": "rate limit exceeded", "request_id": request_id},
                )
                response.headers["Retry-After"] = "60"
                response.headers["X-Request-ID"] = request_id
                return response
            window.append(now)
            if auth_required or api_token:
                supplied = request.headers.get("authorization", "")
                expected = f"Bearer {api_token}"
                if not hmac.compare_digest(supplied, expected):
                    response = JSONResponse(
                        status_code=401,
                        content={
                            "detail": "Bearer authentication required",
                            "request_id": request_id,
                        },
                    )
                    response.headers["X-Request-ID"] = request_id
                    return response
        response = await call_next(request)
        response.headers["X-Request-ID"] = request_id
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/api/health")
    def health() -> dict[str, str | bool]:
        return {
            "status": "ok",
            "version": "0.3.0",
            "deterministic": True,
            "device_connections": False,
            "llm_enabled": False,
        }

    @app.post("/api/audit", tags=["audit"])
    def audit(payload: AuditPayload) -> dict[str, Any]:
        return service.audit(payload)

    @app.post("/api/v1/audit", tags=["audit"])
    def audit_v1(payload: AuditPayload) -> dict[str, Any]:
        return service.audit(payload)

    @app.post("/api/detect", tags=["audit"])
    def detect(payload: DetectPayload | dict[str, str]) -> dict[str, Any]:
        normalized = (
            payload
            if isinstance(payload, DetectPayload)
            else DetectPayload.model_validate(payload)
        )
        validate_config_text(normalized.config_text)
        result = detect_vendor(normalized.config_text)
        return {
            "selected_vendor": result.selected_vendor,
            "confidence": result.confidence,
            "ambiguous": result.ambiguous,
            "reason": result.reason,
            "candidates": [candidate.__dict__ for candidate in result.candidates],
        }

    @app.get("/api/control-pack", tags=["audit"])
    def control_pack() -> dict[str, Any]:
        vendors = set()
        controls = []
        for definition in CONTROL_PACK:
            vendors.update(definition.control.applies_to)
            controls.append(
                {
                    "control_id": definition.control.control_id,
                    "title": definition.control.title,
                    "intent": definition.control.intent,
                    "severity": definition.control.severity.value,
                    "framework_mappings": {
                        key: list(value)
                        for key, value in definition.control.framework_mappings.items()
                    },
                    "applicable_vendors": list(definition.control.applies_to),
                    "remediation": definition.remediation,
                }
            )
        return {
            "version": CONTROL_PACK_VERSION,
            "control_count": len(controls),
            "vendor_count": len(vendors),
            "controls": controls,
        }

    @app.post("/api/explain", tags=["audit"])
    def explain(payload: ExplainPayload) -> dict[str, Any]:
        try:
            validate_config_text(payload.config_text)
            frameworks = normalize_frameworks(tuple(payload.frameworks))
            result = service.client.audit_text(
                payload.config_text,
                vendor=payload.vendor,
                frameworks=frameworks,
                project_id=payload.project_id,
            )
            finding = next(
                (
                    item
                    for item in result.findings
                    if (payload.finding_id and item.finding_id == payload.finding_id)
                    or (payload.control_id and item.control_id == payload.control_id)
                ),
                None,
            )
            if finding is None:
                raise HTTPException(
                    status_code=404,
                    detail="finding was not found in the deterministic audit",
                )
            if finding.status.value not in {"UNKNOWN", "REVIEW_REQUIRED"}:
                raise HTTPException(
                    status_code=422,
                    detail="AI explanations are limited to unresolved findings",
                )
            config = LLMConfig.from_environment()
            if (
                os.getenv("CONFIGSENTINEL_LLM_PROVIDER", "").strip().lower()
                == "offline"
            ):
                copilot = LLMCopilot.offline()
            else:
                copilot = LLMCopilot(
                    provider=OpenAICompatibleProvider(config), config=config
                )
            explanation = copilot.explain_finding(finding, payload.config_text)
            return {
                "deterministic_status": finding.status.value,
                "finding_id": finding.finding_id,
                "llm_assisted": True,
                "explanation": {
                    "finding_id": explanation.finding_id,
                    "explanation": explanation.explanation,
                    "confidence": explanation.confidence,
                    "evidence_needed": list(explanation.evidence_needed),
                    "safety_status": explanation.safety_status,
                    "model_id": explanation.model_id,
                    "prompt_version": explanation.prompt_version,
                },
            }
        except (LLMError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/auth/login", tags=["auth"])
    def login(payload: LoginPayload, response: Response) -> dict[str, Any]:
        session_token = secrets.token_hex(32)
        actor_id = "local-reviewer" if payload.role == "reviewer" else "local-operator"
        MOCK_SESSIONS[session_token] = {
            "actor_id": actor_id,
            "role": payload.role,
            "workspace_id": "local-workspace"
        }
        response.set_cookie(
            key="session_token",
            value=session_token,
            httponly=True,
            samesite="lax",
            path="/"
        )
        return {"status": "ok", "actor_id": actor_id, "role": payload.role}

    @app.post("/api/auth/logout", tags=["auth"])
    def logout(response: Response) -> dict[str, Any]:
        response.delete_cookie(key="session_token", path="/")
        return {"status": "ok"}

    @app.get("/api/auth/me", tags=["auth"])
    def me(session: dict[str, Any] = Depends(get_current_session)) -> dict[str, Any]:
        return session

    @app.post("/api/approval/request", tags=["audit"])
    def approval_request(
        payload: ApprovalRequestPayload,
        session: dict[str, Any] = Depends(get_current_session)
    ) -> dict[str, Any]:
        try:
            event = ledger.request(
                payload.resource_id,
                session["actor_id"],
                role=Role(session["role"]),
                reason=payload.reason,
            )
            return {
                "status": ledger.status(payload.resource_id),
                "event": event.as_dict(),
                "events": [
                    item.as_dict() for item in ledger.events(payload.resource_id)
                ],
            }
        except (GovernanceError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/approval/decision", tags=["audit"])
    def approval_decision(
        payload: ApprovalDecisionPayload,
        session: dict[str, Any] = Depends(get_current_session)
    ) -> dict[str, Any]:
        try:
            event = ledger.decide(
                payload.resource_id,
                session["actor_id"],
                role=Role(session["role"]),
                approve=payload.approve,
                reason=payload.reason,
            )
            return {
                "status": ledger.status(payload.resource_id),
                "event": event.as_dict(),
                "events": [
                    item.as_dict() for item in ledger.events(payload.resource_id)
                ],
            }
        except (GovernanceError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/approval/{resource_id}", tags=["audit"])
    def approval_status(resource_id: str) -> dict[str, Any]:
        return {
            "resource_id": resource_id,
            "status": ledger.status(resource_id),
            "events": [item.as_dict() for item in ledger.events(resource_id)],
        }

    @app.get("/api/v1/control-pack", tags=["audit"])
    def control_pack_v1() -> dict[str, Any]:
        return control_pack()

    @app.get("/api/v1/health", tags=["audit"])
    def health_v1() -> dict[str, str | bool]:
        return health()

    @app.post("/api/remediation", tags=["remediation"])
    def generate_remediation(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            audit = audit_from_report(payload)
            bundle = generate_bundle(audit)
            diffs = build_diffs(audit, bundle)
            return {
                "bundle_id": bundle.bundle_id,
                "vendor": bundle.vendor,
                "input_sha256": bundle.input_sha256,
                "generated_at": bundle.generated_at,
                "warnings": list(bundle.warnings),
                "steps": [
                    {
                        "finding_id": step.finding_id,
                        "control_id": step.control_id,
                        "command": step.command,
                        "rollback": step.rollback,
                        "unified_diff": next(
                            (
                                d.unified_preview
                                for d in diffs
                                if d.finding_id == step.finding_id
                            ),
                            "",
                        ),
                    }
                    for step in bundle.steps
                ],
            }
        except (ValueError, ProofError, RemediationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/remediation/proof", tags=["remediation"])
    def generate_remediation_proof(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            return build_proof_bundle(payload)
        except (ValueError, ProofError, RemediationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/remediation/verify", tags=["remediation"])
    def verify_remediation_proof(payload: dict[str, Any]) -> dict[str, Any]:
        try:
            proof = payload.get("proof")
            report = payload.get("report")
            if not isinstance(proof, dict) or not isinstance(report, dict):
                raise ValueError("Payload must contain 'proof' and 'report' objects.")
            return verify_proof_bundle(proof, report)
        except (ValueError, ProofError, RemediationError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/websites/scans", tags=["websites"])
    def create_website_scan(payload: WebsiteScanPayload) -> dict[str, Any]:
        """Create a new website security scan."""
        try:
            # Create scan request
            request = WebsiteScanRequest(
                url=payload.url,
                authorization_confirmed=payload.authorization_confirmed,
                workspace_id=payload.workspace_id,
            )
            
            # Configure scanner from environment
            http_config = HTTPClientConfig(
                timeout_seconds=float(os.getenv("CONFIGSENTINEL_WEB_SCAN_TIMEOUT_SECONDS", "15")),
                max_response_bytes=int(os.getenv("CONFIGSENTINEL_WEB_SCAN_MAX_RESPONSE_BYTES", "2000000")),
                max_redirects=int(os.getenv("CONFIGSENTINEL_WEB_SCAN_MAX_REDIRECTS", "5")),
                allow_private_targets=os.getenv("CONFIGSENTINEL_WEB_SCAN_ALLOW_PRIVATE_TARGETS", "false").lower() == "true",
                user_agent=os.getenv("CONFIGSENTINEL_WEB_SCAN_USER_AGENT", "ConfigSentinel-Posture-Checker/1.0"),
            )
            
            # Create scanner and perform scan
            scanner = WebsiteScanner(http_config=http_config)
            result = scanner.scan(request)
            
            # Save to storage
            website_storage.save_scan(result)
            
            # Convert to dict for JSON response
            return {
                "scan_id": result.scan_id,
                "target_origin": result.target_origin,
                "final_url": result.final_url,
                "posture_classification": result.posture_classification.value,
                "score": result.score,
                "findings_count": len(result.findings),
                "passed_count": result.passed_count,
                "failed_count": result.failed_count,
                "warning_count": result.warning_count,
                "unknown_count": result.unknown_count,
                "critical_count": result.critical_count,
                "high_count": result.high_count,
                "medium_count": result.medium_count,
                "low_count": result.low_count,
                "rule_pack_version": result.rule_pack_version,
                "scan_timestamp": result.scan_timestamp.isoformat(),
                "limitations": result.limitations,
                "findings": [
                    {
                        "finding_id": f.finding_id,
                        "rule_id": f.rule_id,
                        "title": f.title,
                        "status": f.status.value,
                        "severity": f.severity.value,
                        "evidence": {
                            "check_type": f.evidence.check_type,
                            "observed_value": f.evidence.observed_value,
                            "expected_value": f.evidence.expected_value,
                        },
                        "rationale": f.rationale,
                        "remediation": f.remediation,
                        "observed_at": f.observed_at.isoformat(),
                        "rule_version": f.rule_version,
                        "limitations": f.limitations,
                    }
                    for f in result.findings
                ],
            }
        except (ValueError, TargetSafetyError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(status_code=500, detail=f"Scan failed: {str(exc)}") from exc

    @app.get("/api/websites/scans/{scan_id}", tags=["websites"])
    def get_website_scan(scan_id: str) -> dict[str, Any]:
        """Get a website scan result by ID."""
        scan_data = website_storage.get_scan(scan_id)
        if scan_data is None:
            raise HTTPException(status_code=404, detail="Scan not found")
        
        # Parse findings JSON
        findings = json.loads(scan_data["findings_json"])
        
        return {
            "scan_id": scan_data["scan_id"],
            "target_origin": scan_data["target_origin"],
            "final_url": scan_data["final_url"],
            "posture_classification": scan_data["posture_classification"],
            "score": scan_data["score"],
            "findings_count": scan_data["findings_count"],
            "passed_count": scan_data["passed_count"],
            "failed_count": scan_data["failed_count"],
            "warning_count": scan_data["warning_count"],
            "unknown_count": scan_data["unknown_count"],
            "rule_pack_version": scan_data["rule_pack_version"],
            "scan_timestamp": scan_data["scan_timestamp"],
            "limitations": scan_data["limitations"],
            "findings": findings,
        }

    @app.get("/api/websites/rules", tags=["websites"])
    def get_website_rules() -> dict[str, Any]:
        """Get the website security rule pack."""
        from .website_rules import WEBSITE_RULE_PACK, WEBSITE_RULE_PACK_VERSION
        
        rules = []
        for rule_def in WEBSITE_RULE_PACK:
            rules.append({
                "rule_id": rule_def.rule.rule_id,
                "title": rule_def.rule.title,
                "intent": rule_def.rule.intent,
                "severity": rule_def.rule.severity.value,
                "check_family": rule_def.rule.check_family,
                "version": rule_def.rule.version,
                "remediation": rule_def.remediation,
            })
        
        return {
            "version": WEBSITE_RULE_PACK_VERSION,
            "rule_count": len(rules),
            "rules": rules,
        }

    @app.get("/api/websites/health", tags=["websites"])
    def website_health() -> dict[str, Any]:
        """Health check for website scanner."""
        return {
            "status": "ok",
            "scanner_enabled": os.getenv("CONFIGSENTINEL_WEB_SCAN_ENABLED", "true").lower() == "true",
            "version": "1.0.0",
        }

    @app.delete("/api/websites/scans/{scan_id}", tags=["websites"])
    def delete_website_scan(scan_id: str) -> dict[str, Any]:
        """Delete a website scan result."""
        deleted = website_storage.delete_scan(scan_id)
        if not deleted:
            raise HTTPException(status_code=404, detail="Scan not found")
        return {"status": "deleted", "scan_id": scan_id}

    @app.post("/api/websites/scans/{scan_id}/explanation", tags=["websites"])
    def explain_website_finding_endpoint(scan_id: str, payload: WebsiteExplainPayload) -> dict[str, Any]:
        """Explain a website finding using the LLM copilot."""
        scan_data = website_storage.get_scan(scan_id)
        if scan_data is None:
            raise HTTPException(status_code=404, detail="Scan not found")
            
        findings = json.loads(scan_data["findings_json"])
        
        # Find the specific finding
        finding_dict = next((f for f in findings if f["finding_id"] == payload.finding_id), None)
        if finding_dict is None:
            raise HTTPException(status_code=404, detail="Finding not found in scan")
            
        if finding_dict["status"] == "PASS":
            raise HTTPException(status_code=422, detail="PASS findings do not need explanation")
            
        # Reconstruct WebsiteFinding object roughly
        from .website_models import WebsiteFinding, WebsiteFindingStatus, WebsiteSeverity, WebsiteEvidence
        
        evidence_dict = finding_dict.get("evidence", {})
        evidence_obj = None
        if evidence_dict:
            evidence_obj = WebsiteEvidence(
                check_type=evidence_dict.get("check_type", "unknown"),
                observed_value=evidence_dict.get("observed_value", "unknown"),
                expected_value=evidence_dict.get("expected_value", "unknown"),
            )
            
        finding = WebsiteFinding(
            finding_id=finding_dict["finding_id"],
            scan_id=scan_id,
            rule_id=finding_dict["rule_id"],
            title=finding_dict["title"],
            status=WebsiteFindingStatus(finding_dict["status"]),
            severity=WebsiteSeverity(finding_dict["severity"]),
            evidence=evidence_obj,
            rationale=finding_dict["rationale"],
            remediation=finding_dict["remediation"],
            observed_at=finding_dict["observed_at"], # Keep as string for this passing
            rule_version=finding_dict["rule_version"],
            target_hash="unknown",
            limitations=finding_dict.get("limitations", ""),
        )
        
        config = LLMConfig.from_environment()
        if os.getenv("CONFIGSENTINEL_LLM_PROVIDER", "").strip().lower() == "offline":
            copilot = LLMCopilot.offline()
        else:
            copilot = LLMCopilot(provider=OpenAICompatibleProvider(config), config=config)
            
        try:
            explanation = copilot.explain_website_finding(finding)
            return {
                "finding_id": finding.finding_id,
                "explanation": {
                    "explanation": explanation.explanation,
                    "confidence": explanation.confidence,
                    "evidence_needed": list(explanation.evidence_needed),
                    "safety_status": explanation.safety_status,
                }
            }
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    return app


app = create_app()

__all__ = [
    "AuditPayload",
    "DetectPayload",
    "AuditApi",
    "create_app",
    "app",
    "validate_config_text",
]
