# Centralized Token Service Demo (Linux CLI, OBO, PKI, Agent Lifecycle)

This repository is a technical proof-of-concept for centralized token issuance and authorization across internal APIs, GPU-oriented actions, and automated agents.

## Current capabilities

- Short-lived RS256 JWT access tokens.
- JWKS endpoint for verifier key discovery.
- Refresh-token rotation with reuse detection and token-family revocation.
- OBO (on-behalf-of) token exchange for downstream APIs.
- OBO lineage claims in delegated tokens: `act`, `obo_chain`, `original_user`, `acting_agent`, `target_service`, `target_action`.
- Least-privilege scope downscoping during OBO exchange.
- Sender-constrained / certificate-bound tokens using `cnf.x5t#S256`.
- Agent lifecycle management and agent token issuance.
- Agent operations: registration, disable, enable, rotate-cert.
- GPU submit authorization flow.
- Step-up/PIM-style token flow for privileged actions.
- `/introspect` and `/revoke` token endpoints.
- JSON audit database and append-only JSONL audit log.
- `audit-tail` CLI command.
- Failure-path demo commands for denied agent and denied scope scenarios.

---

## Repository layout

- `token_service.py` — token service API surface for login simulation, token issuance, refresh, OBO exchange, step-up, introspection/revocation, and agent lifecycle endpoints.
- `internal_api.py` — protected internal API endpoints, including GPU-oriented authorization checks.
- `devctl.py` — CLI for login, OBO exchange, GPU actions, agent lifecycle commands, audit inspection, and failure-path demos.
- `token_utils.py` — JWT issue/verify utilities, JWKS helper logic, certificate thumbprint and proof helpers.
- `policy_engine.py` — policy and scope-decision helpers used by authorization paths.
- `pki_bootstrap.py` — demo PKI/certificate bootstrap for local sender-constrained token workflows.
- `dashboard.py` — optional Streamlit dashboard for service and audit visibility.
- `requirements.txt` — Python dependencies.

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
python3 pki_bootstrap.py
```

Start services in separate terminals.

### Terminal 1: token service

```bash
source .venv/bin/activate
python3 token_service.py
```

### Terminal 2: protected API

```bash
source .venv/bin/activate
python3 internal_api.py
```

### Terminal 3: CLI flows

```bash
source .venv/bin/activate
python3 devctl.py demo-full
python3 devctl.py obo-build
python3 devctl.py demo-failure-disabled-agent
python3 devctl.py demo-failure-scope-denied
python3 devctl.py audit-tail
```

---

## Manual demo flow

- `python3 devctl.py login --auto` — simulate device/login completion and issue user access + refresh tokens.
- `python3 devctl.py obo-build` — perform OBO exchange for scoped downstream token issuance.
- `python3 devctl.py gpu-submit` — call GPU submit path with least-privilege scope checks.
- `python3 devctl.py register-agent` — register an agent identity and certificate binding.
- `python3 devctl.py agent-comment` — issue and use an agent token for internal comment action.
- `python3 devctl.py agent-gpu-submit` — issue and use an agent token for GPU submit action.
- `python3 devctl.py deploy-prod` — run privileged action path that requires step-up token flow.
- `python3 devctl.py audit` — inspect summarized audit data.
- `python3 devctl.py audit-tail` — tail recent append-only audit events.

---

## OBO behavior

During OBO exchange:

1. The incoming token is validated (signature, audience/path checks, and required claims).
2. Requested scopes must be a subset of the user token scopes.
3. If `agent_id` is supplied, requested scopes must also be a subset of that agent's `allowed_scopes` and the agent must be active.
4. The delegated token is minted with lineage/delegation claims (`act`, `obo_chain`, `original_user`, `acting_agent`, `target_service`, `target_action`).
5. If scope constraints fail, the service returns `scope_not_allowed`.

---

## Agent lifecycle

Agent lifecycle endpoints exposed by the token service:

- `POST /agent/register`
- `POST /agent/disable`
- `POST /agent/enable`
- `POST /agent/rotate-cert`
- `POST /agent/token`

These support explicit activation state management plus certificate rotation and agent-scoped token issuance.

---

## Audit logging

Audit persistence is split into:

- `.state/audit.json` — JSON audit database/state snapshot.
- `.state/audit_log.jsonl` — append-only JSON Lines event log.
- `write_audit_event()` — event writer used by token and authorization flows.

Use:

```bash
python3 devctl.py audit-tail
```

to inspect recent append-only entries.

---

## Failure demos

- `python3 devctl.py demo-failure-disabled-agent`
  - Expected result: disabled agent request is denied with `agent_not_active`.
- `python3 devctl.py demo-failure-scope-denied`
  - Expected result: unauthorized scope request is denied with `scope_not_allowed`.

---

## Production considerations

For production deployment, common controls include:

- Real enterprise IdP integration.
- Real TLS/mTLS and certificate lifecycle automation.
- HSM/KMS-backed signing keys.
- Durable datastore for token, agent, and audit state.
- Hashed refresh tokens at rest.
- SIEM export for centralized detection/response.
- API rate limiting and abuse controls.
- High-availability deployment and operational failover.
- Replay cache and/or `jti` denylist strategy.
- Agent governance workflow for registration, approval, review, and deprovisioning.

## Production Innovation Demo Flows

Run these demo commands from Linux/WSL after starting token service and internal API:

- `python devctl.py demo-conditional-rotation`
- `python devctl.py demo-refresh-replay`
- `python devctl.py demo-device-attested-renewal`
- `python devctl.py demo-action-specific-gpu-token`
- `python devctl.py audit-verify`

Interview lines:
- Rotation should be policy-aware, not mechanical.
- Replay detection turns token rotation into a security sensor.
- A trusted user on an untrusted device should not receive high-trust tokens.
- GPU access should be exact, short-lived, and auditable.
- Every token should explain why access was allowed.
- Audit should be evidence, not just logs.

Each flow now emits policy decision evidence where available (`policy_id`, `policy_version`, `decision_id`, `decision`, `risk_level`, `reason`, `audit_event_id`) and writes tamper-evident hash chain fields (`previous_hash`, `event_hash`) into audit events.

For quick local validation:

```bash
bash scripts/validate_production_demos.sh
```

## Why JWT in this demo?

JWT is intentionally the **primary demo token format** to make claims and validation logic visible during interview walkthroughs. In distributed systems, JWT also enables local validation while still supporting centralized controls.

Security controls demonstrated:
- short TTL
- audience restriction
- scope narrowing
- jti denylist checks for sensitive APIs
- refresh rotation
- token-family replay kill switch
- certificate/device binding
- policy decision evidence
- tamper-evident audit chain

If NVIDIA uses opaque tokens in production, this same metadata can move server-side and be returned through introspection.

Even with JWT local validation, introspection is useful for sensitive APIs, debugging, revocation checks, and compatibility with opaque-token architectures.

## Production Innovation Demo Commands

- `python3 devctl.py demo-conditional-rotation`
- `python3 devctl.py demo-jwt-replay-kill-switch`
- `python3 devctl.py demo-refresh-replay`
- `python3 devctl.py demo-device-attested-renewal`
- `python3 devctl.py demo-action-specific-gpu-token`
- `python3 devctl.py audit-verify`

Interview lines:
- Rotation should be policy-aware, not mechanical.
- JWTs are short-lived, but for high-risk APIs I also check jti revocation.
- Replay detection turns rotation into a security sensor.
- A trusted user on an untrusted device should not receive high-trust JWTs.
- GPU access should be exact, short-lived, and auditable.
- Every JWT should explain why access was allowed.
- Audit should be evidence, not just logs.
- The demo has unsafe local modes clearly guarded so they cannot be accidentally used in production.
