# Enterprise Simulation Upgrade Changelog

## Added

- Simulated enterprise OIDC identity provider with:
  - discovery document
  - JWKS
  - RS256 signing
  - Authorization Code + PKCE
  - Device Authorization-style flow
  - MFA simulation
  - managed-device and risk context
- Hybrid AD → cloud directory simulator.
- Group/role/scope entitlement mapping.
- Conditional Access decision engine.
- PIM/JIT privileged-role activation with:
  - eligibility
  - MFA
  - trusted device
  - justification
  - TTL/expiry
- SCIM provisioning/deprovisioning simulator.
- Owner deprovisioning hook for existing TokenSystem agent identities.
- Enterprise token broker that:
  - validates the external IdP JWT using JWKS
  - intersects requested scopes with entitlements
  - reevaluates Conditional Access
  - checks active PIM roles
  - emits TokenSystem-compatible sender-constrained internal JWTs
- Browser SSO portal.
- Enterprise CLI.
- Protected API helper using existing TokenSystem certificate-bound proof.
- Local SIEM/detection engine.
- Defensive identity attack/control scenarios.
- IC4/IC5 study map.
- Splunk-style SPL study examples.
- CI tests and runnable demo scripts.

## Intentionally unchanged

The existing TokenSystem core files are not rewritten. Existing:
- token service
- OBO
- agent identity
- replay controls
- device registry
- protected internal API
- GPU authorization
- audit chain

continue to work unchanged.

This is deliberate: the enterprise simulation is an integration layer around the current security architecture rather than a competing implementation.

## No paid services required

No Microsoft Entra, Intune, PIM, Active Directory cloud sync, Splunk, SCIM SaaS target or other paid license is required.
