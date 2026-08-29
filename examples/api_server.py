"""Run the local VEYRONIX audit API for the operator dashboard."""

from __future__ import annotations

import os

import uvicorn

from configsentinel.api import app


if __name__ == "__main__":
    uvicorn.run(
        app,
        host=os.getenv("VEYRONIX_API_HOST", "127.0.0.1"),
        port=int(os.getenv("VEYRONIX_API_PORT", "5000")),
        log_level="info",
    )
