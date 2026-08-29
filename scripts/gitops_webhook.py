import json
import logging
import os
import subprocess
from pathlib import Path
from typing import Any

try:
    from fastapi import FastAPI, Header, HTTPException, Request
    import uvicorn
except ImportError:
    raise SystemExit(
        "FastAPI and uvicorn are required for the GitOps webhook. Run: pip install fastapi uvicorn"
    )

app = FastAPI(title="VEYRONIX GitOps Webhook")
logger = logging.getLogger("gitops_webhook")
logging.basicConfig(level=logging.INFO)


@app.post("/webhook/gitops")
async def handle_gitops_webhook(
    request: Request, x_github_event: str | None = Header(None)
) -> dict[str, Any]:
    if x_github_event != "push":
        return {"status": "ignored", "reason": "Not a push event"}

    payload = await request.json()
    repo_name = payload.get("repository", {}).get("name", "unknown")
    after_sha = payload.get("after")
    before_sha = payload.get("before")

    if not after_sha or not before_sha:
        raise HTTPException(status_code=400, detail="Missing before or after SHA")

    logger.info(f"Received push event for {repo_name}: {before_sha} -> {after_sha}")

    # Run gitops gate check locally on the current repo assuming the webhook is running in the repo root
    repo_path = Path.cwd()
    gate_script = repo_path / "scripts" / "gitops_gate.sh"

    if not gate_script.exists():
        logger.error("GitOps gate script not found.")
        raise HTTPException(status_code=500, detail="GitOps script not found.")

    try:
        result = subprocess.run(
            [str(gate_script), before_sha, after_sha, "auto"],
            cwd=repo_path,
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            logger.info("GitOps gate passed.")
            return {
                "status": "passed",
                "details": "Configuration changes meet compliance requirements.",
            }
        else:
            logger.warning("GitOps gate failed.")
            return {
                "status": "failed",
                "details": "Compliance violations detected in the changed files.",
                "logs": result.stdout,
            }
    except Exception as exc:
        logger.error(f"Execution failed: {exc}")
        raise HTTPException(status_code=500, detail="Failed to run GitOps gate check")


if __name__ == "__main__":
    port = int(os.environ.get("WEBHOOK_PORT", "8000"))
    logger.info(f"Starting GitOps webhook on port {port}...")
    uvicorn.run(app, host="0.0.0.0", port=port)
