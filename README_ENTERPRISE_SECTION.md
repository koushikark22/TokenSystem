## License-free enterprise identity security lab

An additional `enterprise_sim/` environment extends this proof-of-concept into a fully local enterprise IAM/security lab without requiring Microsoft Entra ID, Intune, PIM, SCIM, Splunk, or other commercial licenses.

It adds:

- simulated OIDC enterprise IdP with JWKS and RS256
- browser Authorization Code + PKCE
- CLI Device Authorization-style authentication
- hybrid AD-to-cloud directory synchronization
- MFA and risk context
- Conditional Access-style policy
- PIM/JIT privileged role activation
- SCIM joiner/leaver lifecycle
- owner-based agent quarantine on deprovisioning
- external-to-internal token brokering
- sender-constrained internal TokenSystem JWTs
- local SIEM-style identity detections
- IC4/IC5 troubleshooting and architecture exercises

See [`docs/ENTERPRISE_SIM_LAB.md`](docs/ENTERPRISE_SIM_LAB.md) for the full walkthrough.

Quick start:

```bash
python3 enterprise_sim/bootstrap.py
python3 internal_api.py
python3 enterprise_sim/idp_server.py
python3 enterprise_sim/cli_client.py login --auto
python3 enterprise_sim/cli_client.py exchange --scopes build.read
python3 enterprise_sim/cli_client.py call-api --path /build/status
```
