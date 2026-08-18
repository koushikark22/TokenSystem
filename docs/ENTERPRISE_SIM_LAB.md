# TokenSystem Enterprise Identity Security Lab

This extension turns the existing TokenSystem proof-of-concept into a fully local enterprise IAM/security lab. It deliberately simulates commercial services so the environment can be studied without Microsoft Entra ID, Intune, PIM, SCIM, Splunk, Active Directory cloud sync, or other paid licenses.

## What is simulated

| Enterprise capability | Local implementation |
|---|---|
| Microsoft Entra-style IdP | `enterprise_sim/idp_server.py` |
| OIDC discovery + JWKS | `/.well-known/openid-configuration`, `/jwks.json` |
| Browser SSO | Authorization Code + PKCE through `browser_client.py` |
| CLI SSO | OAuth Device Authorization-style flow through `cli_client.py` |
| Hybrid AD → cloud sync | `directory.py` |
| MFA | Local OTP validation |
| Conditional Access | `conditional_access.py` |
| Device compliance/attestation | Local managed/compliant/attested device records |
| PIM/JIT | `pim.py` with eligibility, MFA, justification, TTL and expiry |
| SCIM | `scim.py` provisioning/deprovisioning target |
| Non-human lifecycle dependency | User deprovisioning can quarantine owned TokenSystem agents |
| Central internal token broker | `broker.py`, issuing TokenSystem-compatible internal JWTs |
| SIEM analytics | `detections.py` reads JSONL audit events and emits local alerts |

## Architecture

```text
Simulated AD
   |
   | hybrid sync
   v
Simulated Cloud Directory
   |
   +-------------------------+
   |                         |
Browser                     CLI
Auth Code + PKCE            Device Code
   |                         |
   +-----------> Simulated OIDC IdP
                     |
                     | external enterprise JWT
                     v
                Enterprise Broker
                - validate JWKS
                - CA decision
                - entitlement intersection
                - PIM decision
                - device trust
                     |
                     | short-lived sender-constrained JWT
                     v
                Existing TokenSystem
                     |
                     v
                internal_api.py
                     |
                     v
                Audit + local detections
```

## Quick start

From the TokenSystem repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python3 enterprise_sim/bootstrap.py
```

Start the existing protected API:

```bash
python3 internal_api.py
```

Start the simulated enterprise IdP:

```bash
python3 enterprise_sim/idp_server.py
```

Optional browser SSO portal:

```bash
python3 enterprise_sim/browser_client.py
```

Then open:

```text
http://127.0.0.1:8200
```

Default lab credentials:

```text
user: developer01
password: LabPassword!1
MFA OTP: 654321
managed device: linux-laptop-001
unmanaged device: personal-laptop-001
```

These are intentionally local demo credentials, not production secrets.

## CLI authentication flow

```bash
python3 enterprise_sim/cli_client.py login --auto
python3 enterprise_sim/cli_client.py exchange --scopes build.read
python3 enterprise_sim/cli_client.py call-api --path /build/status
```

Expected result: the IdP authenticates the user, the broker validates the external token and Conditional Access state, the broker issues a TokenSystem-compatible internal token, and the protected API validates its sender-constrained proof.

## PIM / JIT flow

Without PIM:

```bash
python3 enterprise_sim/cli_client.py login --auto
python3 enterprise_sim/cli_client.py exchange --scopes deploy.prod
```

Expected: `pim_activation_required`.

Activate temporary privilege:

```bash
python3 enterprise_sim/cli_client.py pim-activate \
  --role Production-Admin \
  --justification "production troubleshooting lab"

python3 enterprise_sim/cli_client.py login --auto
python3 enterprise_sim/cli_client.py exchange --scopes deploy.prod
python3 enterprise_sim/cli_client.py call-api \
  --method POST \
  --path /deploy/prod \
  --body '{"change":"lab-deployment"}'
```

The internal token carries `pim=true`, the active role and stronger authentication context. The existing internal API already requires the `pim` claim for `/deploy/prod`.

## Conditional Access exercises

Unmanaged device:

```bash
python3 enterprise_sim/cli_client.py login --auto --device personal-laptop-001
```

GPU-sensitive or privileged issuance will be denied because the device is not managed/compliant/attested.

High-risk user:

```bash
python3 enterprise_sim/cli_client.py set-risk high
python3 enterprise_sim/cli_client.py login --auto
```

Restore:

```bash
python3 enterprise_sim/cli_client.py set-risk low
```

Device compliance kill switch:

```bash
python3 enterprise_sim/cli_client.py set-device-compliance false
```

Restore:

```bash
python3 enterprise_sim/cli_client.py set-device-compliance true
```

## Hybrid directory + SCIM lifecycle

Show a simulated AD-to-cloud sync:

```bash
python3 enterprise_sim/cli_client.py directory-sync
```

Provision the user to a local SCIM target:

```bash
python3 enterprise_sim/cli_client.py scim-provision
python3 enterprise_sim/cli_client.py scim-list
```

Leaver flow:

```bash
python3 enterprise_sim/cli_client.py scim-deprovision --disable-source
```

This disables the source user and attempts to quarantine TokenSystem agents owned by that user.

Restore the lab user:

```bash
python3 enterprise_sim/cli_client.py enable-user
python3 enterprise_sim/cli_client.py scim-provision
```

## Defensive attack/control lab

```bash
python3 enterprise_sim/attack_lab.py
```

It checks:
- normal managed-device access
- unmanaged-device denial
- missing MFA
- production access without PIM
- high-risk authentication denial

Existing TokenSystem replay, scope and agent failure demos remain available and should be run alongside this lab.

## Detection engineering

Generate local SIEM-style alerts from enterprise and TokenSystem audit events:

```bash
python3 enterprise_sim/detections.py
```

Rules include:
- token replay
- PKCE/proof failure
- high-risk identity denial
- PIM activation
- scope escalation
- owner-deprovisioned agent quarantine
- repeated denial burst

The output is written to:

```text
.state/enterprise_sim/alerts.json
```

## What remains simulated

This lab intentionally does **not** claim that:
- the IdP is Microsoft Entra ID,
- device posture comes from Intune,
- PIM is Microsoft PIM,
- SCIM is backed by a SaaS provider,
- audit data is stored in Splunk,
- keys are HSM-backed,
- TLS/mTLS is production grade.

Those are production substitutions, not weaknesses in the learning objective. The lab exists to make the control plane, data flows, claims, policy decisions and failure modes observable end to end.
