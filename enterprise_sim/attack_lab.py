#!/usr/bin/env python3
"""Safe local identity-control validation scenarios for the simulated lab."""
import json
import sys
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from enterprise_sim.conditional_access import evaluate
    from enterprise_sim.directory import bootstrap_directory, get_user, get_device, set_user_risk
    from enterprise_sim.pim import revoke
else:
    from .conditional_access import evaluate
    from .directory import bootstrap_directory, get_user, get_device, set_user_risk
    from .pim import revoke

def scenario(name, func):
    try:
        result = func()
        print(f"[{name}] {json.dumps(result.to_dict() if hasattr(result, 'to_dict') else result, indent=2)}")
    except Exception as e:
        print(f"[{name}] denied/error: {e}")

def main():
    bootstrap_directory()
    user = get_user("developer01")

    scenario("managed-device-build-read", lambda: evaluate(
        user=user, device=get_device("linux-laptop-001"),
        requested_scopes=["build.read"], mfa=True, risk_level="low"
    ))
    scenario("unmanaged-device-gpu-submit", lambda: evaluate(
        user=user, device=get_device("personal-laptop-001"),
        requested_scopes=["gpu.job.submit"], mfa=True, risk_level="low"
    ))
    scenario("no-mfa", lambda: evaluate(
        user=user, device=get_device("linux-laptop-001"),
        requested_scopes=["build.read"], mfa=False, risk_level="low"
    ))
    scenario("prod-without-pim", lambda: evaluate(
        user=user, device=get_device("linux-laptop-001"),
        requested_scopes=["deploy.prod"], mfa=True, risk_level="low"
    ))
    scenario("high-risk-login", lambda: evaluate(
        user=user, device=get_device("linux-laptop-001"),
        requested_scopes=["build.read"], mfa=True, risk_level="high"
    ))
    print("\nThese scenarios validate defensive identity controls only; they do not target external systems.")

if __name__ == "__main__":
    main()
