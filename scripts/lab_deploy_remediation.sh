#!/usr/bin/env bash
set -euo pipefail

# ConfigSentinel Lab Deployment Simulator
# This script simulates applying a ConfigSentinel proof-carrying remediation preview
# to a lab device. It does not actually mutate any remote devices.

echo "=========================================="
echo " VEYRONIX Lab Remediation Simulator "
echo "=========================================="

if [ "$#" -lt 1 ]; then
    echo "Usage: scripts/lab_deploy_remediation.sh <path_to_remediation_preview.conf>"
    exit 1
fi

PREVIEW_FILE="$1"

if [ ! -f "$PREVIEW_FILE" ]; then
    echo "[Error] Remediation preview file not found: $PREVIEW_FILE"
    exit 1
fi

echo "[Info] Loading remediation preview: $PREVIEW_FILE"

# Extract bundle ID and target vendor from the preview headers
BUNDLE_ID=$(grep -m1 "# bundle_id:" "$PREVIEW_FILE" | awk '{print $3}' || echo "UNKNOWN")
VENDOR=$(grep -m1 "# vendor:" "$PREVIEW_FILE" | awk '{print $3}' || echo "UNKNOWN")

echo "[Info] Bundle ID: $BUNDLE_ID"
echo "[Info] Target Vendor: $VENDOR"

echo "[Info] Connecting to simulated lab device..."
sleep 1

# Look for commands in the file (lines that do not start with # and are not empty)
echo "[Info] Applying safe remediation commands:"
grep -v "^#" "$PREVIEW_FILE" | grep -v "^$" | while read -r cmd; do
    echo "  > $cmd"
    sleep 0.5
    echo "  < [Simulated OK]"
done

echo "[Success] Remediation successfully deployed to lab environment for testing."
echo "=========================================="
