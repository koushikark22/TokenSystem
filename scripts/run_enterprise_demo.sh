#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

cleanup() {
  [[ -n "${IDP_PID:-}" ]] && kill "$IDP_PID" 2>/dev/null || true
  [[ -n "${API_PID:-}" ]] && kill "$API_PID" 2>/dev/null || true
}
trap cleanup EXIT

rm -rf .state/enterprise_sim
python3 enterprise_sim/bootstrap.py

python3 internal_api.py > .state/internal_api-enterprise.log 2>&1 &
API_PID=$!
python3 enterprise_sim/idp_server.py > .state/idp-enterprise.log 2>&1 &
IDP_PID=$!

sleep 1

python3 enterprise_sim/cli_client.py login --auto
python3 enterprise_sim/cli_client.py exchange --scopes build.read
python3 enterprise_sim/cli_client.py call-api --path /build/status

echo
echo "--- PIM denial expected ---"
set +e
python3 enterprise_sim/cli_client.py exchange --scopes deploy.prod
DENY_RC=$?
set -e
if [[ "$DENY_RC" -eq 0 ]]; then
  echo "Expected deploy.prod to require PIM but it succeeded."
  exit 1
fi

python3 enterprise_sim/cli_client.py pim-activate --role Production-Admin --justification "automated enterprise lab validation"
python3 enterprise_sim/cli_client.py login --auto
python3 enterprise_sim/cli_client.py exchange --scopes deploy.prod
python3 enterprise_sim/cli_client.py call-api --method POST --path /deploy/prod --body '{"change":"enterprise-lab"}'

python3 enterprise_sim/attack_lab.py
python3 enterprise_sim/detections.py >/dev/null

echo
echo "Enterprise simulation demo passed."
