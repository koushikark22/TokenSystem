#!/usr/bin/env python3
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from enterprise_sim.settings import ENTERPRISE_AUDIT_FILE, ALERTS_FILE
    from enterprise_sim.storage import load_json, save_json, now
else:
    from .settings import ENTERPRISE_AUDIT_FILE, ALERTS_FILE
    from .storage import load_json, save_json, now

def _read_jsonl(path):
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            out.append(json.loads(line))
        except Exception:
            pass
    return out

def run_detections():
    enterprise = _read_jsonl(ENTERPRISE_AUDIT_FILE)
    try:
        from token_utils import AUDIT_LOG_PATH
        token_events = _read_jsonl(AUDIT_LOG_PATH)
    except Exception:
        token_events = []

    events = enterprise + token_events
    alerts = []

    def add(rule, severity, event, reason):
        alerts.append({
            "alert_id": f"{rule}:{event.get('event_id') or event.get('audit_event_id') or len(alerts)}",
            "timestamp": now(),
            "rule": rule,
            "severity": severity,
            "reason": reason,
            "source_event": event,
        })

    for e in events:
        et = e.get("event_type") or e.get("event")
        reason = str(e.get("reason") or e.get("details", {}).get("reason") or "")
        if et in {"refresh_replay_detected", "jwt_replay_or_revoked_jti_detected"}:
            add("IAM-TOKEN-REPLAY", "high", e, "Replay or reused credential detected")
        if et in {"pkce_validation_failed", "certificate_binding_failed"}:
            add("IAM-PROOF-FAILURE", "high", e, "Proof-of-possession or PKCE validation failed")
        if et in {"idp_authentication_denied", "broker_policy_denied"} and "high" in reason:
            add("IAM-HIGH-RISK-DENY", "high", e, "High-risk authentication/token request denied")
        if et == "pim_role_activated":
            add("IAM-PIM-ACTIVATION", "medium", e, "Privileged role activated")
        if et == "owned_agents_quarantined":
            add("IAM-OWNER-DEPROVISION", "high", e, "Agents quarantined after owner deprovisioning")
        if et in {"broker_scope_denied", "scope_denied"}:
            add("IAM-SCOPE-ESCALATION", "medium", e, "Requested scope exceeded entitlement")

    # Burst detection for repeated denials by user.
    denials = defaultdict(list)
    for e in enterprise:
        if e.get("event_type") in {"idp_authentication_denied", "broker_policy_denied", "broker_scope_denied"}:
            denials[e.get("user") or "unknown"].append(e)
    for user, user_events in denials.items():
        if len(user_events) >= 3:
            add("IAM-DENIAL-BURST", "medium", user_events[-1], f"{len(user_events)} denied identity events for {user}")

    save_json(ALERTS_FILE, alerts)
    return alerts

def main():
    alerts = run_detections()
    print(json.dumps(alerts, indent=2))
    print(f"\nGenerated {len(alerts)} alert(s).")

if __name__ == "__main__":
    main()
