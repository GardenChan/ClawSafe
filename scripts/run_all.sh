#!/usr/bin/env bash
# ClawSafe - Run All Security Checks
# Supports: Linux, macOS, containers
#
# This script does NOT assume any hardcoded paths for OpenClaw.
# OpenClaw detection is fully dynamic (CLI, env vars, process inspection).
#
# Usage:
#   bash run_all.sh [target_directory]
#
# Environment variables (all optional):
#   OPENCLAW_STATE_DIR   - Explicit OpenClaw state directory
#   OPENCLAW_CONFIG_PATH - Explicit OpenClaw config file path
#   OPENCLAW_HOME        - Explicit OpenClaw home override
#
# Output: JSON lines from all check modules

set -euo pipefail

TARGET_DIR="${1:-.}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo "=========================================="
echo "  ClawSafe Security Scan"
echo "  Target: ${TARGET_DIR}"
echo "  Time:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "  OS:     $(uname -s) $(uname -r)"
echo "=========================================="
echo ""

# --- Phase 1: OpenClaw Configuration Audit ---
# The check_openclaw.sh script handles its own discovery
# It will auto-detect OpenClaw via CLI, env vars, or process inspection
echo "🔍 Phase 1: OpenClaw Configuration Audit"
echo "   (auto-discovering OpenClaw installation...)"
echo ""
script="${SCRIPT_DIR}/check_openclaw.sh"
if [ -f "$script" ]; then
    bash "$script"
    echo ""
else
    echo "WARNING: check_openclaw.sh not found, skipping OpenClaw audit."
    echo ""
fi

# --- Phase 2: General Security Checks ---
echo "🔍 Phase 2: General Security Checks"
echo "   Target: ${TARGET_DIR}"
echo ""

CHECKS=("check_env" "check_files" "check_network" "check_deps")

for check in "${CHECKS[@]}"; do
    script="${SCRIPT_DIR}/${check}.sh"
    if [ -f "$script" ]; then
        bash "$script" "$TARGET_DIR"
        echo ""
    else
        echo "WARNING: ${script} not found, skipping."
    fi
done

echo "=========================================="
echo "  ClawSafe scan complete."
echo ""
echo "  TIP: Also run 'openclaw security audit'"
echo "  and 'openclaw doctor' for built-in checks."
echo ""
echo "  WARNING: This tool cannot replace"
echo "  a professional security audit."
echo "=========================================="
