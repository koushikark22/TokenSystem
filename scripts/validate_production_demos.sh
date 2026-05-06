#!/usr/bin/env bash
set -euo pipefail
python devctl.py demo-conditional-rotation
python devctl.py demo-jwt-replay-kill-switch
python devctl.py demo-refresh-replay
python devctl.py demo-device-attested-renewal
python devctl.py demo-action-specific-gpu-token
python devctl.py audit-verify
