# PRODUCTION_HARDENING

## Demo scope

- Local proof of concept for centralized token governance.
- Demonstrates Linux CLI access, JWTs, OBO, refresh rotation, step-up, agent/NHI identity, GPU authorization, PKI-style sender constraint, audit, and dashboard.
- Local files and local HTTP are for demo simplicity only.

## Production requirements

- Replace simulated login with Microsoft Entra ID OIDC/OAuth flows.
- Use MSAL for Linux CLI authentication.
- Use Entra Conditional Access / authentication context for step-up.
- Move JWT signing keys to HSM/KMS, such as Azure Key Vault or Managed HSM.
- Publish JWKS with overlapping key rotation by kid.
- Use TLS/mTLS for all service communication.
- Store refresh tokens as hash/HMAC values, never plaintext.
- Store token state, agent registry, audit events, and GPU quota state in a transactional database.
- Export audit logs to SIEM with immutable retention.
- Disable unsafe dev-mode certificate fallbacks in production.
- Enforce exp, nbf, iss, aud, scope, cnf, and kid validation.
- Integrate GPU enforcement with Kubernetes, Run:ai, NVIDIA GPU Operator, admission control, or scheduler quota controls.

## Architecture talking point

“The prototype proves the control model; production hardening replaces local demo primitives with Entra ID, HSM/KMS, transactional storage, SIEM, TLS/mTLS, and scheduler-native GPU governance.”
