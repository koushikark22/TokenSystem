# SIEM / Splunk-style Detection Exercises

The project remains license-free. `enterprise_sim/detections.py` provides executable local detections. The SPL below is included as study material for how the same telemetry could be represented in Splunk.

## Refresh/JWT replay

```spl
index=identity (event_type=refresh_replay_detected OR event_type=jwt_replay_or_revoked_jti_detected)
| stats count values(user) values(token_id) values(reason) by event_type
```

## Scope escalation

```spl
index=identity (event_type=broker_scope_denied OR event_type=scope_denied)
| stats count values(scopes) values(reason) by user
| where count >= 1
```

## PIM activation

```spl
index=identity event_type=pim_role_activated
| table _time user role device_id justification expires_at
```

## High-risk authentication denial

```spl
index=identity event_type=idp_authentication_denied
| search reason="*high*"
| stats count by user device_id reason
```

## Proof/certificate binding failure

```spl
index=identity (event_type=certificate_binding_failed OR event_type=pkce_validation_failed)
| stats count by user request_path reason
```

## Deprovisioned owner with agent identities

```spl
index=identity event_type=owned_agents_quarantined
| table _time user agent_ids
```

## Repeated identity denials

```spl
index=identity (event_type=idp_authentication_denied OR event_type=broker_policy_denied OR event_type=broker_scope_denied)
| bin _time span=10m
| stats count by _time user
| where count >= 3
```
