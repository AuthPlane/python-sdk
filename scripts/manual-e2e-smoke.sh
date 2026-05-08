#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

ADAPTER="mcp"
RUN_SETUP=1
export ISSUER_URL="${ISSUER_URL:-http://localhost:9000}"
export RESOURCE_URL="${RESOURCE_URL:-http://localhost:8080/mcp}"

usage() {
  cat <<'EOF'
Usage:
  manual-e2e-smoke.sh [--adapter mcp|fastmcp] [--skip-setup]
EOF
}

while [ "${#}" -gt 0 ]; do
  case "$1" in
    --adapter)
      ADAPTER="${2:-}"
      shift
      ;;
    --skip-setup)
      RUN_SETUP=0
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
  shift
done

if [ "${ADAPTER}" = "mcp" ]; then
  RUN_CMD="./authplane-mcp/demo/run.sh"
elif [ "${ADAPTER}" = "fastmcp" ]; then
  RUN_CMD="./authplane-fastmcp/demo/run.sh"
else
  echo "Invalid adapter: ${ADAPTER}" >&2
  exit 1
fi

SERVER_LOG="/tmp/python-adapters-manual-e2e-smoke-${ADAPTER}.log"
RESOURCE_BASE="${RESOURCE_URL%/mcp}"
if [ "${RESOURCE_BASE}" = "${RESOURCE_URL}" ]; then
  echo "ERROR: RESOURCE_URL must end with /mcp, got ${RESOURCE_URL}" >&2
  exit 1
fi
PRM_URL="${RESOURCE_BASE}/.well-known/oauth-protected-resource/mcp"
ADMIN_URL="${ADMIN_URL:-http://localhost:9001}"
ADMIN_KEY="${ADMIN_KEY:-b480b9760e730abe43b98d0ba01418961df392de0fc6358c36a9a62a8764a7c1}"

cleanup() {
  if [ -n "${SERVER_PID:-}" ]; then
    pkill -P "${SERVER_PID}" || true
    kill "${SERVER_PID}" || true
  fi
  pkill -f "${REPO_ROOT}/authplane-mcp/demo/mcpserver.py" || true
  pkill -f "${REPO_ROOT}/authplane-fastmcp/demo/mcpserver.py" || true
}
trap cleanup EXIT

register_scope() {
  local scope_name="$1"
  local status
  status="$(
    curl -sS -o /dev/null -w "%{http_code}" \
      -X POST "${ADMIN_URL}/admin/scopes" \
      -H "Authorization: Bearer ${ADMIN_KEY}" \
      -H "Content-Type: application/json" \
      -d "{\"resource\":\"${RESOURCE_URL}\",\"name\":\"${scope_name}\",\"description\":\"Manual E2E smoke scope ${scope_name}\"}" \
      || true
  )"
  if [ "${status}" != "201" ] && [ "${status}" != "409" ]; then
    echo "WARN: could not ensure scope ${scope_name} for ${RESOURCE_URL} (status=${status}); continuing" >&2
  fi
}

if [ "${RUN_SETUP}" -eq 1 ]; then
  bash "${SCRIPT_DIR}/manual-e2e-setup.sh"
fi

if [ ! -x "${REPO_ROOT}/${RUN_CMD#./}" ]; then
  echo "ERROR: adapter run script not found or not executable: ${RUN_CMD}" >&2
  exit 1
fi

echo "==> Starting Python demo (${ADAPTER})"
(
  cd "${REPO_ROOT}"
  ${RUN_CMD} >"${SERVER_LOG}" 2>&1
) &
SERVER_PID=$!

echo "==> Waiting for PRM: ${PRM_URL}"
for _ in $(seq 1 180); do
  status="$(curl -sS -o /dev/null -w "%{http_code}" "${PRM_URL}" || true)"
  if [ "${status}" = "200" ] || [ "${status}" = "401" ]; then
    break
  fi
  sleep 1
done
status="$(curl -sS -o /dev/null -w "%{http_code}" "${PRM_URL}" || true)"
if [ "${status}" != "200" ] && [ "${status}" != "401" ]; then
  echo "ERROR: PRM endpoint not ready (status=${status})" >&2
  echo "Server log: ${SERVER_LOG}" >&2
  exit 1
fi

if [ ! -f /tmp/authserver-demo.client-id ] || [ ! -f /tmp/authserver-demo.key ]; then
  echo "ERROR: missing /tmp/authserver-demo.client-id or /tmp/authserver-demo.key" >&2
  exit 1
fi

echo "==> Ensuring authserver scopes for resource: ${RESOURCE_URL}"
register_scope "tools/add"
register_scope "tools/multiply"

CLIENT_ID="$(cat /tmp/authserver-demo.client-id)"
CLIENT_SECRET="$(cat /tmp/authserver-demo.key)"

echo "==> Minting token (tools/add)"
TOKEN_JSON="$(
  curl -sS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
    -H "Content-Type: application/x-www-form-urlencoded" \
    -d "grant_type=client_credentials" \
    -d "resource=${RESOURCE_URL}" \
    -d "scope=tools/add" \
    "${ISSUER_URL}/oauth/token"
)"

TOKEN_ERROR="$(
  echo "${TOKEN_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("error",""))'
)"
if [ "${TOKEN_ERROR}" = "invalid_scope" ]; then
  echo "==> Scope tools/add not available, retrying token mint without scope"
  TOKEN_JSON="$(
    curl -sS -u "${CLIENT_ID}:${CLIENT_SECRET}" \
      -H "Content-Type: application/x-www-form-urlencoded" \
      -d "grant_type=client_credentials" \
      -d "resource=${RESOURCE_URL}" \
      "${ISSUER_URL}/oauth/token"
  )"
fi

ACCESS_TOKEN="$(
  echo "${TOKEN_JSON}" | python3 -c 'import json,sys; print(json.load(sys.stdin).get("access_token",""))'
)"
if [ -z "${ACCESS_TOKEN}" ]; then
  echo "ERROR: token mint failed" >&2
  echo "${TOKEN_JSON}" >&2
  exit 1
fi

echo "==> Checking unauthenticated /mcp is blocked"
mcp_status="$(
  curl -sS -o /dev/null -w "%{http_code}" -X POST "${RESOURCE_URL}" \
    -H "Content-Type: application/json" \
    -d '{}' || true
)"
if [ "${mcp_status}" = "200" ]; then
  echo "ERROR: unauthenticated /mcp request unexpectedly returned 200" >&2
  exit 1
fi
if [ "${mcp_status}" = "000" ]; then
  echo "ERROR: unauthenticated /mcp check could not reach server" >&2
  exit 1
fi

echo ""
echo "Smoke check passed (python-adapters, adapter=${ADAPTER})"
echo "PRM: ${PRM_URL}"
echo "Server log: ${SERVER_LOG}"
