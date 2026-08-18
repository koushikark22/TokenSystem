#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

python3 enterprise_sim/bootstrap.py

echo
echo "Start these in separate terminals:"
echo "  python3 internal_api.py"
echo "  python3 enterprise_sim/idp_server.py"
echo "  python3 enterprise_sim/browser_client.py"
echo
echo "CLI demo:"
echo "  python3 enterprise_sim/cli_client.py login --auto"
echo "  python3 enterprise_sim/cli_client.py exchange --scopes build.read"
echo "  python3 enterprise_sim/cli_client.py call-api --path /build/status"
