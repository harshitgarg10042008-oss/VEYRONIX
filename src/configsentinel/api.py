"""Local HTTP adapter for the deterministic VEYRONIX audit engine.

The API is intentionally small and local-first. It accepts configuration text,
redacts it through the SDK client, evaluates deterministic controls, and returns
the same report dictionary used by CLI exports. It never connects to devices or
allows the LLM to create verdicts.
"""

from __future__ import annotations

from typing import Any

from .client import ConfigSentinelClient
from .engine import DeterministicComplianceEngine
from .frameworks import normalize_frameworks
from .reporting import report_dict

try:
    from fastapi import FastAPI, HTTPException
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel, Field
except ImportError as exc:  # pragma: no cover - exercised only without the optional API extra
    raise RuntimeError("Install the 'api' extra to run the local HTTP adapter") from exc


class AuditPayload(BaseModel):
    config_text: str = Field(min_length=1, max_length=5 * 1024 * 1024)
    vendor: str = Field(default="auto", min_length=1, max_length=64)
    frameworks: list[str] = Field(default_factory=lambda: ["cis-network", "nist-800-53"], max_length=8)
    project_id: str = Field(default="local", min_length=1, max_length=128)


class AuditApi:
    def __init__(self) -> None:
        self.client = ConfigSentinelClient(engine=DeterministicComplianceEngine())

    def audit(self, payload: AuditPayload) -> dict[str, Any]:
        try:
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
    app = FastAPI(title="VEYRONIX Local Audit API", version="0.3.0")
    origins = allowed_origins or ["http://localhost:3000", "http://127.0.0.1:3000"]
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )
    service = AuditApi()

    @app.get("/api/health")
    def health() -> dict[str, str | bool]:
        return {"status": "ok", "deterministic": True, "device_connections": False, "llm_enabled": False}

    @app.post("/api/audit")
    def audit(payload: AuditPayload) -> dict[str, Any]:
        return service.audit(payload)

    return app


app = create_app()

__all__ = ["AuditPayload", "AuditApi", "create_app", "app"]
