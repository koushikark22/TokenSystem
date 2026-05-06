#!/usr/bin/env bash
set -euo pipefail
python token_service.py >/tmp/token_service.validate.log 2>&1 &
TS_PID=$!
python internal_api.py >/tmp/internal_api.validate.log 2>&1 &
API_PID=$!
trap 'kill $TS_PID $API_PID >/dev/null 2>&1 || true' EXIT
sleep 1
python devctl.py demo-conditional-rotation
python devctl.py demo-jwt-replay-kill-switch
python devctl.py demo-refresh-replay
python devctl.py demo-device-attested-renewal
python devctl.py demo-action-specific-gpu-token
python devctl.py audit-verify
