#!/usr/bin/env bash
set -euo pipefail

# Simple OAuth2 smoke test for Spring Authorization Server with custom password and mfa grants.
# Usage:
#   scripts/auth-smoke.sh [--port 8080]
#
# Requires:
#   - curl
#   - jq (optional but recommended, for JSON parsing)

PORT=8080
if [[ "${1:-}" == "--port" && -n "${2:-}" ]]; then
  PORT="$2"; shift 2
fi

BASE="http://localhost:${PORT}"

echo "[1/6] Probing OIDC discovery at ${BASE}/.well-known/openid-configuration"
code=$(curl -s -o /dev/null -w "%{http_code}" "${BASE}/.well-known/openid-configuration" || true)
if [[ "$code" != "200" ]]; then
  echo "ERROR: Server not responding at ${BASE} (HTTP $code). Is the app running on this port?" >&2
  exit 1
fi

echo "[2/6] Client credentials token"
cc_res=$(curl -s -u client:secret \
  -d grant_type=client_credentials \
  -d scope=read \
  "${BASE}/oauth2/token") || { echo "client_credentials request failed" >&2; exit 1; }
if command -v jq >/dev/null 2>&1; then
  echo "$cc_res" | jq '{flow:"client_credentials", access_token:.access_token, token_type:.token_type, expires_in:.expires_in, scope:.scope}'
else
  echo "$cc_res"
fi

# Password grant (demo only)
echo "[3/6] Password grant (john/pass)"
passwd_res=$(curl -s -u client:secret \
  -d grant_type=password \
  -d username=john \
  -d password=pass \
  -d scope=read \
  "${BASE}/oauth2/token") || { echo "password grant request failed" >&2; exit 1; }
if command -v jq >/dev/null 2>&1; then
  echo "$passwd_res" | jq '{
    flow:"password",
    access_token:.access_token,
    access_len:(.access_token|tostring|length),
    refresh_token:.refresh_token,
    refresh_len:(.refresh_token|tostring|length),
    token_type:.token_type,
    expires_in:.expires_in,
    scope:.scope,
    error:.error,
    error_description:.error_description
  }'
else
  echo "$passwd_res"
fi

# MFA flow (issue then exchange)
echo "[4/6] Issue MFA token/code for user john"
issue_res=$(curl -s "${BASE}/mfa/issue?username=john") || { echo "mfa issue failed" >&2; exit 1; }
if command -v jq >/dev/null 2>&1; then
  mfa_token=$(echo "$issue_res" | jq -r .mfa_token)
  mfa_code=$(echo "$issue_res" | jq -r .code)
else
  # naive parsing if jq missing
  mfa_token=$(echo "$issue_res" | sed -n 's/.*"mfa_token"\s*:\s*"\([^"]*\)".*/\1/p')
  mfa_code=$(echo "$issue_res" | sed -n 's/.*"code"\s*:\s*"\([^"]*\)".*/\1/p')
fi
if [[ -z "${mfa_token:-}" || -z "${mfa_code:-}" ]]; then
  echo "ERROR: Could not parse mfa_token/code from: $issue_res" >&2
  exit 1
fi

echo "[5/6] Exchange MFA token/code for access token"
mfa_res=$(curl -s -u client:secret \
  -d grant_type=mfa \
  -d mfa_token="${mfa_token}" \
  -d code="${mfa_code}" \
  -d scope=read \
  "${BASE}/oauth2/token") || { echo "mfa grant request failed" >&2; exit 1; }
if command -v jq >/dev/null 2>&1; then
  echo "$mfa_res" | jq '{
    flow:"mfa",
    access_token:.access_token,
    access_len:(.access_token|tostring|length),
    refresh_token:.refresh_token,
    refresh_len:(.refresh_token|tostring|length),
    token_type:.token_type,
    expires_in:.expires_in,
    scope:.scope,
    error:.error,
    error_description:.error_description
  }'
else
  echo "$mfa_res"
fi

echo "[6/6] Done"
