# Entra-Style Centralized Token Service Demo for Linux CLI + OBO + PKI + Agentic AI + GPU

This project is a working local demo of a centralized token system for Linux developer machines and NVIDIA-style GPU workflows.

It demonstrates:

- Linux developer CLI authentication without long-lived API keys or personal tokens
- Entra-style Device Code / PKCE architecture, simulated locally for demo purposes
- Short-lived JWT access tokens
- JWKS endpoint for local API validation
- Refresh-token rotation and reuse detection
- OBO / On-Behalf-Of flow to preserve original user context across backend calls
- PIM/step-up style privileged access
- Corporate PKI-style device certificates for Linux machine trust
- PKCS#12 `.p12` bundles for certificate import workflows
- Sender-constrained tokens using `cnf.x5t#S256`
- Agentic AI tokens with explicit `agent_id`, `actor_type`, `agent_owner`, `initiating_user`, and scopes
- GPU-specific protected APIs, least-privilege scopes, and quota controls

> This is a local interview demo. In production, Entra ID would handle real user authentication, MFA, Conditional Access, PIM, risk signals, and app registration.

---

## Why this solves the interview problem

Developers and AI agents should not use static API keys, shared service accounts, or anonymous tokens to access internal systems. This design replaces those with a centralized token service that enforces identity, device trust, token expiry, refresh rotation, scopes, OBO, agent identity, and audit logging.

For NVIDIA-style workflows, GPU resources are treated as high-value infrastructure. Developers and agents need explicit scopes such as:

- `gpu.job.read`
- `gpu.job.submit`
- `gpu.job.cancel`
- `gpu.quota.update`
- `gpu.cluster.admin`

Low-risk GPU job submission can use normal scoped tokens. High-risk GPU quota/admin operations require PIM/step-up.

---

## Files

- `pki_bootstrap.py` - creates demo CA, Linux device cert, agent cert, token signing cert, and PKCS#12 bundles
- `token_service.py` - centralized token service
- `internal_api.py` - protected internal API and GPU scheduler API
- `devctl.py` - Linux developer CLI demo
- `token_utils.py` - JWT, JWKS, PKI proof, and helper functions
- `requirements.txt` - Python dependencies

---

## Setup

Use Linux or WSL Ubuntu on Windows.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python pki_bootstrap.py
```

This creates:

```text
pki/ca.cert.pem
pki/linux-laptop-001.cert.pem
pki/linux-laptop-001.key.pem
pki/linux-laptop-001.p12
pki/agent-gpu-planner-dev.cert.pem
pki/agent-gpu-planner-dev.key.pem
pki/agent-gpu-planner-dev.p12
pki/token-signing.cert.pem
pki/token-signing.key.pem
```

PKCS#12 demo password: `changeit`

---

## Run

Open three terminals.

### Terminal 1 - token service

```bash
source .venv/bin/activate
python token_service.py
```

Runs on `http://127.0.0.1:8000`.

### Terminal 2 - protected internal/GPU API

```bash
source .venv/bin/activate
python internal_api.py
```

Runs on `http://127.0.0.1:9000`.

### Terminal 3 - CLI tests

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

## What each command proves

### `python devctl.py login --auto`

Simulates Linux CLI login using an Entra-style flow. The Linux machine proves possession of its private key. The token service issues a short-lived access token and rotating refresh token.

Interview line:

> This replaces long-lived API keys on Linux developer machines with short-lived, certificate-bound tokens.

### `python devctl.py obo-build`

Shows OBO flow. The CLI has a token for the token service; the token service exchanges it for a downstream internal API token while preserving original user context.

Interview line:

> OBO preserves the original developer identity across backend-to-backend calls.

### `python devctl.py gpu-submit`

Submits a GPU job using an OBO token with `gpu.job.submit` scope.

Interview line:

> GPU job submission is authorized through least-privilege scopes instead of broad static credentials.

### `python devctl.py gpu-jobs`

Reads GPU jobs using `gpu.job.read` scope.

### `python devctl.py refresh`

Rotates the refresh token. The old refresh token becomes invalid. Reuse of an old refresh token would revoke the token family.

Interview line:

> Refresh tokens are single-use; reuse indicates possible theft and triggers token-family revocation.

### `python devctl.py deploy-prod`

Requests step-up/PIM-style privileged scope `deploy.prod` and calls a protected production endpoint.

Interview line:

> Normal commands use normal scopes; production commands require step-up and short-lived elevated tokens.

### `python devctl.py gpu-quota-update --subject developer01 --quota 3`

Requests PIM/step-up for high-risk GPU admin action `gpu.quota.update`.

Interview line:

> GPU quota and admin changes are high-risk and cost-sensitive, so they require step-up and full audit.

### `python devctl.py register-agent`

Registers an AI agent as a first-class identity with explicit `agent_id`, owner, environment, scopes, certificate binding, and GPU quota.

### `python devctl.py agent-comment`

Agent receives a token with explicit identity claims and calls an API.

### `python devctl.py agent-gpu-submit`

Agent submits a GPU job using its own `agent_id`, certificate-bound token, GPU scope, and quota policy.

Interview line:

> The AI agent is not anonymous. The token and audit log show agent ID, owner, initiating user, scopes, and GPU job details.

---

## Architecture explanation

```text
Developer on Linux CLI
        |
        | Entra-style login + Linux cert proof
        v
Centralized Token Service
        |  short-lived JWT / refresh rotation / OBO / step-up / agent tokens
        v
Protected API / GPU Scheduler API
        |  validates JWT, JWKS, scopes, audience, cert proof
        v
Internal services, GPU clusters, build systems, model workflows
```

---

## Production changes

For production, replace the simulated parts with:

- Real Microsoft Entra ID Device Code Flow or Authorization Code + PKCE
- Entra MFA, Conditional Access, PIM, and Identity Protection
- Intune/MDM/EDR device compliance for Linux posture
- HSM/Key Vault for token signing keys
- Durable database for refresh tokens, agent registry, revocation, and audit events
- SIEM integration
- Regional HA, rate limiting, monitoring, alerting, and runbooks
- Automated certificate lifecycle management for Linux devices and agent runtimes

---

## Panel-ready summary

> I designed a centralized token system for Linux developer CLI and agentic AI workflows. Entra remains the IdP for authentication, MFA, Conditional Access, and PIM. The custom token service standardizes internal access by issuing short-lived JWTs, rotating refresh tokens, supporting OBO, enforcing scopes, publishing JWKS, and logging audit events. PKI binds tokens to trusted Linux devices and agent runtimes, reducing replay risk. GPU scheduler APIs are protected with GPU-specific scopes and quota controls. AI agents have explicit `agent_id`, owner, initiating user, certificate binding, and least-privilege scopes, so their actions are attributable, revocable, and auditable.
