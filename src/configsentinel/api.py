"""Local HTTP adapter for the deterministic VEYRONIX audit engine.

The API is intentionally small and local-first. It accepts configuration text,
redacts it through the SDK client, evaluates deterministic controls, and returns
the same report dictionary used by CLI exports. It never connects to devices or
allows the LLM to create verdicts.
"""

from __future__ import annotations

import hmac
import os
import time
import uuid
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

try:
    from fastapi import FastAPI, HTTPException, Request
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover - exercised only without the optional API extra
    raise RuntimeError("Install the 'api' extra to run the local HTTP adapter") from exc


MAX_CONFIG_CHARS = 5 * 1024 * 1024
MAX_LINE_BYTES = 256 * 1024


def validate_config_text(config_text: str) -> None:
    encoded = config_text.encode("utf-8")
    if b"\x00" in encoded:
        raise ValueError("NUL bytes are not accepted")
    if len(encoded) > MAX_CONFIG_CHARS:
        raise ValueError("configuration exceeds the maximum size")
    if any(len(line.encode("utf-8")) > MAX_LINE_BYTES for line in config_text.splitlines(keepends=True)):
        raise ValueError("configuration line exceeds the safety limit")


class AuditPayload(BaseModel):
    config_text: str = Field(min_length=1, max_length=MAX_CONFIG_CHARS)
    vendor: str = Field(default="auto", min_length=1, max_length=64)
    frameworks: list[str] = Field(default_factory=lambda: ["cis-network", "nist-800-53"], max_length=8)
    project_id: str = Field(default="local", min_length=1, max_length=128)


class DetectPayload(BaseModel):
    config_text: str = Field(min_length=1, max_length=MAX_CONFIG_CHARS)


class ApprovalRequestPayload(BaseModel):
    resource_id: str = Field(min_length=1, max_length=256)
    actor_id: str = Field(min_length=1, max_length=128)
    role: str = Field(default="operator", min_length=1, max_length=32)
    reason: str = Field(default="", max_length=500)


class ApprovalDecisionPayload(ApprovalRequestPayload):
    approve: bool


class ExplainPayload(AuditPayload):
    finding_id: str | None = Field(default=None, max_length=256)
    control_id: str | None = Field(default=None, max_length=128)


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
    app = FastAPI(title="ConfigSentinel AI Local Audit API", version="0.4.0", description="Evidence-backed, deterministic configuration compliance auditing. No device connections or remote mutation.", openapi_tags=[{"name": "audit", "description": "Deterministic audit and vendor detection operations."}, {"name": "webhooks", "description": "Local event contract; delivery is intentionally external."}])
    origins = allowed_origins or ["http://localhost:3000", "http://127.0.0.1:3000"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type", "Authorization", "X-Request-ID"],
    )
    service = AuditApi()
    ledger = ApprovalLedger(os.getenv("CONFIGSENTINEL_GOVERNANCE_LEDGER", ".configsentinel/events.jsonl"))
    api_token = os.getenv("CONFIGSENTINEL_API_TOKEN", "").strip()
    auth_required = os.getenv("CONFIGSENTINEL_AUTH_REQUIRED", "false").lower() == "true"
    if auth_required and not api_token:
        raise RuntimeError("CONFIGSENTINEL_AUTH_REQUIRED is enabled but CONFIGSENTINEL_API_TOKEN is missing")
    rate_limit = max(1, int(os.getenv("CONFIGSENTINEL_RATE_LIMIT_PER_MINUTE", "120")))
    request_windows: dict[str, deque[float]] = defaultdict(deque)

    @app.middleware("http")
    async def security_boundary(request: Request, call_next):
        request_id = request.headers.get("x-request-id", "").strip()[:128] or str(uuid.uuid4())
        protected = request.url.path.startswith("/api/") and request.url.path not in {"/api/health", "/api/v1/health"}
        if protected:
            now = time.monotonic()
            client_key = request.client.host if request.client else "unknown"
            window = request_windows[client_key]
            while window and now - window[0] >= 60:
                window.popleft()
            if len(window) >= rate_limit:
                response = JSONResponse(status_code=429, content={"detail": "rate limit exceeded", "request_id": request_id})
                response.headers["Retry-After"] = "60"
                response.headers["X-Request-ID"] = request_id
                return response
            window.append(now)
            if auth_required or api_token:
                supplied = request.headers.get("authorization", "")
                expected = f"Bearer {api_token}"
                if not hmac.compare_digest(supplied, expected):
                    response = JSONResponse(status_code=401, content={"detail": "Bearer authentication required", "request_id": request_id})
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
        return {"status": "ok", "version": "0.3.0", "deterministic": True, "device_connections": False, "llm_enabled": False}

    @app.post("/api/audit", tags=["audit"])
    def audit(payload: AuditPayload) -> dict[str, Any]:
        return service.audit(payload)

    @app.post("/api/v1/audit", tags=["audit"])
    def audit_v1(payload: AuditPayload) -> dict[str, Any]:
        return service.audit(payload)

    @app.post("/api/detect", tags=["audit"])
    def detect(payload: DetectPayload | dict[str, str]) -> dict[str, Any]:
        normalized = payload if isinstance(payload, DetectPayload) else DetectPayload.model_validate(payload)
        validate_config_text(normalized.config_text)
        result = detect_vendor(normalized.config_text)
        return {"selected_vendor": result.selected_vendor, "confidence": result.confidence, "ambiguous": result.ambiguous, "reason": result.reason, "candidates": [candidate.__dict__ for candidate in result.candidates]}

    @app.get("/api/control-pack", tags=["audit"])
    def control_pack() -> dict[str, Any]:
        return {
            "version": CONTROL_PACK_VERSION,
            "controls": [
                {
                    "control_id": definition.control.control_id,
                    "title": definition.control.title,
                    "intent": definition.control.intent,
                    "severity": definition.control.severity.value,
                    "framework_mappings": {key: list(value) for key, value in definition.control.framework_mappings.items()},
                    "applicable_vendors": list(definition.control.applies_to),
                    "remediation": definition.remediation,
                }
                for definition in CONTROL_PACK
            ],
        }

    @app.post("/api/explain", tags=["audit"])
    def explain(payload: ExplainPayload) -> dict[str, Any]:
        try:
            validate_config_text(payload.config_text)
            frameworks = normalize_frameworks(tuple(payload.frameworks))
            result = service.client.audit_text(payload.config_text, vendor=payload.vendor, frameworks=frameworks, project_id=payload.project_id)
            finding = next((item for item in result.findings if (payload.finding_id and item.finding_id == payload.finding_id) or (payload.control_id and item.control_id == payload.control_id)), None)
            if finding is None:
                raise HTTPException(status_code=404, detail="finding was not found in the deterministic audit")
            if finding.status.value not in {"UNKNOWN", "REVIEW_REQUIRED"}:
                raise HTTPException(status_code=422, detail="AI explanations are limited to unresolved findings")
            config = LLMConfig.from_environment()
            if os.getenv("CONFIGSENTINEL_LLM_PROVIDER", "").strip().lower() == "offline":
                copilot = LLMCopilot.offline()
            else:
                copilot = LLMCopilot(provider=OpenAICompatibleProvider(config), config=config)
            explanation = copilot.explain_finding(finding, payload.config_text)
            return {"deterministic_status": finding.status.value, "finding_id": finding.finding_id, "llm_assisted": True, "explanation": {"finding_id": explanation.finding_id, "explanation": explanation.explanation, "confidence": explanation.confidence, "evidence_needed": list(explanation.evidence_needed), "safety_status": explanation.safety_status, "model_id": explanation.model_id, "prompt_version": explanation.prompt_version}}
        except (LLMError, ValueError, RuntimeError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/approval/request", tags=["audit"])
    def approval_request(payload: ApprovalRequestPayload) -> dict[str, Any]:
        try:
            event = ledger.request(payload.resource_id, payload.actor_id, role=Role(payload.role), reason=payload.reason)
            return {"status": ledger.status(payload.resource_id), "event": event.as_dict(), "events": [item.as_dict() for item in ledger.events(payload.resource_id)]}
        except (GovernanceError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/approval/decision", tags=["audit"])
    def approval_decision(payload: ApprovalDecisionPayload) -> dict[str, Any]:
        try:
            event = ledger.decide(payload.resource_id, payload.actor_id, role=Role(payload.role), approve=payload.approve, reason=payload.reason)
            return {"status": ledger.status(payload.resource_id), "event": event.as_dict(), "events": [item.as_dict() for item in ledger.events(payload.resource_id)]}
        except (GovernanceError, ValueError) as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.get("/api/approval/{resource_id}", tags=["audit"])
    def approval_status(resource_id: str) -> dict[str, Any]:
        return {"resource_id": resource_id, "status": ledger.status(resource_id), "events": [item.as_dict() for item in ledger.events(resource_id)]}

    @app.get("/api/v1/control-pack", tags=["audit"])
    def control_pack_v1() -> dict[str, Any]:
        return control_pack()

    @app.get("/api/v1/health", tags=["audit"])
    def health_v1() -> dict[str, str | bool]:
        return health()

    return app


app = create_app()

__all__ = ["AuditPayload", "DetectPayload", "AuditApi", "create_app", "app", "validate_config_text"]
