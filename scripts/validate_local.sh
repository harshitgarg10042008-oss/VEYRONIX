#!/usr/bin/env bash
set -euo pipefail

# VEYRONIX local-first gate: deterministic backend first, then the operator workbench.
root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$root_dir"

python -m pytest
python -m compileall -q src tests examples
python -m pip install build >/dev/null
python -m build

(
  cd frontend
  pnpm install --frozen-lockfile
  pnpm run check
  pnpm run build
)

PYTHONPATH=src python examples/local_demo.py
printf '\nVEYRONIX local delivery gate: PASS\n'
