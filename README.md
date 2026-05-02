# Centralized Token Service Demo (Linux CLI, OBO, PKI, and GPU API Controls)

This repository is a personal proof-of-concept showing how a centralized token service can secure internal APIs used by Linux developer tooling and automated agents.

The implementation is centered on identity architecture controls:

- short-lived JWT access tokens
- refresh-token rotation with reuse detection
- OBO (on-behalf-of) exchange for downstream APIs
- scoped authorization for internal and GPU endpoints
- step-up tokens for privileged operations
- sender-constrained tokens with certificate thumbprint binding (`cnf.x5t#S256`)
- explicit agent identities (`agent_id`) and audit context
- Zero Trust-style verification at each hop (identity, device proof, scope, and audience checks)
- audit logging for authentication, token, and authorization events
- JWKS publication for verifier services

> Note: This is a local demonstration. In production, an enterprise IdP and security platform would provide user authentication, MFA, risk and policy enforcement, and lifecycle governance.

---

## Repository layout

- `token_service.py` — centralized token service APIs (device flow simulation, token issuance, refresh, OBO, step-up, agent token issuance)
- `internal_api.py` — protected internal and GPU-oriented API endpoints
- `devctl.py` — CLI driver used to demonstrate end-to-end flows
- `token_utils.py` — JWT signing/validation, cert thumbprints, proof signing/verification helpers
- `pki_bootstrap.py` — local PKI artifact bootstrap for demo certificates/keys
- `requirements.txt` — Python dependencies

---

## Prerequisites

- Linux or WSL
- Python 3.10+
- `pip`

---

## Quick start

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python pki_bootstrap.py
```

Then start services in separate terminals:

### Terminal 1: token service

```bash
source .venv/bin/activate
python token_service.py
```

### Terminal 2: protected API

```bash
source .venv/bin/activate
python internal_api.py
```

### Terminal 3: run demo flows

```bash
source .venv/bin/activate
python devctl.py login --auto
python devctl.py obo-build
python devctl.py gpu-submit
python devctl.py gpu-jobs
python devctl.py refresh
python devctl.py deploy-prod
python devctl.py gpu-quota-update --subject developer01 --quota 3
python devctl.py register-agent
python devctl.py agent-comment
python devctl.py agent-gpu-submit
python devctl.py audit
```

---

## Demo flow mapping

- `login --auto`: simulates interactive sign-in completion and issues short-lived access + rotating refresh tokens.
- `obo-build`: exchanges a user token for a downstream API token while preserving the user context.
- `gpu-submit` / `gpu-jobs`: demonstrates least-privilege GPU scopes.
- `refresh`: demonstrates one-time refresh token usage and token family revocation on reuse.
- `deploy-prod` and `gpu-quota-update`: demonstrates step-up requirements for privileged actions.
- `register-agent`, `agent-comment`, `agent-gpu-submit`: demonstrates non-anonymous agent identity and auditable actions.

---

## Architecture (unchanged)

```text
Developer CLI / Agent Runtime
        |
        | login + proof of key possession
        v
Centralized Token Service
        | short-lived JWT, refresh rotation, OBO, step-up, agent claims
        v
Protected Internal API / GPU API
        | JWT, scope, audience, and sender-proof validation
        v
Internal services and GPU workloads
```

---

## Production considerations

For a production implementation, common hardening steps include:

- integrate a real enterprise IdP flow (Device Code or Auth Code + PKCE)
- enforce MFA and conditional access policies
- persist token/agent/audit state in a durable datastore
- protect signing keys with HSM/KMS-backed key management
- add centralized audit export and alerting (SIEM)
- implement stronger operational controls (rotation, backup, incident response)
- add comprehensive automated testing and CI policy checks

---

## Interview framing

This project is intentionally small and explainable: it demonstrates identity-bound API access without introducing unnecessary architecture complexity. It is suited for discussing security tradeoffs, threat reduction, and practical authorization design in backend systems.
