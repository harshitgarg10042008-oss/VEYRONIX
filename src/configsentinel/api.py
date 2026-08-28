"""Local HTTP adapter for the deterministic VEYRONIX audit engine.

The API is intentionally small and local-first. It accepts configuration text,
redacts it through the SDK client, evaluates deterministic controls, and returns
the same report dictionary used by CLI exports. It never connects to devices or
allows the LLM to create verdicts.
"""

from __future__ import annotations

import hmac
import os
from typing import Any

from .client import ConfigSentinelClient
from .controls import CONTROL_PACK, CONTROL_PACK_VERSION
from .detection import detect_vendor
from .engine import DeterministicComplianceEngine
from .frameworks import normalize_frameworks
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
        allow_headers=["Content-Type"],
    )
    service = AuditApi()
    api_token = os.getenv("CONFIGSENTINEL_API_TOKEN", "").strip()

    @app.middleware("http")
    async def security_boundary(request: Request, call_next):
        if api_token and request.url.path not in {"/api/health", "/api/v1/health"}:
            supplied = request.headers.get("authorization", "")
            expected = f"Bearer {api_token}"
            if not hmac.compare_digest(supplied, expected):
                return JSONResponse(status_code=401, content={"detail": "Bearer authentication required"})
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response

    @app.get("/api/health")
    def health() -> dict[str, str | bool]:
        return {"status": "ok", "deterministic": True, "device_connections": False, "llm_enabled": False}

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

    @app.get("/api/v1/control-pack", tags=["audit"])
    def control_pack_v1() -> dict[str, Any]:
        return control_pack()

    @app.get("/api/v1/health", tags=["audit"])
    def health_v1() -> dict[str, str | bool]:
        return health()

    return app


app = create_app()

__all__ = ["AuditPayload", "DetectPayload", "AuditApi", "create_app", "app", "validate_config_text"]
