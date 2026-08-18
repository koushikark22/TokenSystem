# IC4 / IC5 Study Map

## IC4: operate and troubleshoot

Be able to trace each flow without reading the code:

1. Browser login → authorization code → PKCE → IdP access token → broker → internal token.
2. CLI device flow → user completion → IdP token → broker → internal token.
3. JWKS `kid` selection and RS256 signature validation.
4. `iss`, `aud`, `exp`, `nbf`, MFA and device claims.
5. Group-to-scope mapping.
6. Conditional Access allow/deny reasoning.
7. PIM activation, expiration and privileged token issuance.
8. Sender-constrained `cnf.x5t#S256` proof.
9. SCIM joiner/mover/leaver behavior.
10. Audit and detection events.

Troubleshooting drills:
- wrong audience
- unknown `kid`
- expired token
- bad PKCE verifier
- disabled user
- unmanaged device
- noncompliant device
- high-risk user
- scope not entitled
- missing PIM
- expired PIM activation
- wrong sender certificate
- revoked/replayed token

## IC5: architecture and tradeoffs

For each design decision, be able to answer:

- Why broker tokens instead of forwarding the enterprise access token everywhere?
- When is token exchange preferable to impersonation?
- How do you preserve the original user when an agent acts on their behalf?
- What should be evaluated at authentication time vs token issuance time vs API authorization time?
- How do device posture changes affect existing sessions and refresh behavior?
- How do you prevent stale privilege after a PIM activation expires?
- What happens to service/agent identities when their owner leaves?
- How are signing keys rotated without breaking verifiers?
- What happens if JWKS is unavailable?
- How do you fail safely when the policy engine is unavailable?
- Which decisions should be locally cached?
- How would you move JSON state to a transactional datastore?
- How would you make the token service multi-region and highly available?
- How would you protect signing keys with HSM/KMS?
- How would you export audit events with immutable retention?
- How would you map the simulated controls to Entra, Intune, PIM and a production SIEM?

## Architecture exercise

Whiteboard a migration from:

```text
AD + LDAP/Kerberos + static service accounts
```

to:

```text
Enterprise IdP
  + OIDC/OAuth
  + device trust
  + centralized token broker
  + short-lived workload/agent identities
  + JIT privilege
  + policy-driven authorization
  + centralized identity telemetry
```

Include migration stages, rollback, legacy application compatibility, break-glass access and blast-radius controls.
