#!/usr/bin/env bash
set -euo pipefail

BASE_REF="${1:?usage: scripts/gitops_gate.sh BASE_SHA [HEAD_SHA] [VENDOR]}"
HEAD_REF="${2:-HEAD}"
VENDOR="${3:-auto}"

PYTHONPATH="${PYTHONPATH:-src}" python -m configsentinel.cli gitops-check \
  --repo . \
  --base "$BASE_REF" \
  --head "$HEAD_REF" \
  --vendor "$VENDOR" \
  --json-out gitops-report.json
