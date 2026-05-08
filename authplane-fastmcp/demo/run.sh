#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

# Demo defaults — override by setting the variable in your shell before running.
export ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"
export RESOURCE_URL="${RESOURCE_URL:-http://localhost:8080/mcp}"
if [[ -z "${CLIENT_ID:-}" && -f /tmp/authserver-demo.client-id ]]; then
  export CLIENT_ID="$(cat /tmp/authserver-demo.client-id)"
fi
if [[ -z "${CLIENT_SECRET:-}" && -f /tmp/authserver-demo.key ]]; then
  export CLIENT_SECRET="$(cat /tmp/authserver-demo.key)"
fi

cd "$PROJECT_DIR"

# Keep BASE_URL as a derived compatibility env for mcpserver.
export BASE_URL="${RESOURCE_URL%/mcp}"
if [[ "${BASE_URL}" == "${RESOURCE_URL}" ]]; then
    echo "RESOURCE_URL must end with /mcp (got: ${RESOURCE_URL})" >&2
    exit 1
fi

# Create venv if needed
if [ ! -d .venv ]; then
    python3 -m venv .venv
fi

source .venv/bin/activate
pip install -q -e "$PROJECT_DIR/.."
pip install -q -e ".[dev]"

python "$SCRIPT_DIR/mcpserver.py"
