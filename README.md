# Centralized Token Service Demo

This repository is a technical proof-of-concept for centralized token issuance and authorization across internal APIs, GPU-oriented actions, Linux device trust, and automated agent identities.

## Project ownership

This proof-of-concept was designed and implemented by **Koushik Anand** as a hands-on security architecture and engineering demo for a centralized token service.

The goal of the project is to demonstrate practical understanding of:

- short-lived token issuance
- refresh-token rotation and reuse detection
- OBO token exchange and least-privilege downscoping
- sender-constrained proof validation
- Linux device trust and device-attested renewal checks
- agent / non-human identity lifecycle governance
- action-specific authorization for protected GPU operations
- revocation, introspection, and replay controls
- tamper-evident audit logging

All demo flows are intentionally runnable locally so the architecture, controls, and tradeoffs can be inspected and explained end to end.

## Current capabilities

- Short-lived RS256 JWT access tokens.
- JWKS endpoint for verifier key discovery.
- Refresh-token rotation with reuse detection and token-family revocation.
- OBO token exchange for narrower downstream API tokens.
- OBO lineage claims in delegated tokens: `act`, `obo_chain`, `original_user`, `acting_agent`, `target_service`, and `target_action`.
- Least-privilege scope downscoping during OBO exchange.
- Sender-constrained and certificate-bound tokens using `cnf.x5t#S256`.
- Device registry lifecycle: device registration, status checks, enable/disable, and certificate rotation.
- Agent lifecycle management and agent token issuance.
- Agent operations: registration, disable, enable, and certificate rotation.
- GPU submit authorization flow with action-specific GPU claims.
- Step-up token flow for privileged actions.
- `/introspect` and `/revoke` token endpoints.
- JSON audit database and append-only JSONL audit log.
- Tamper-evident audit hash chain verification.
- Failure-path demo commands for denied agent and denied scope scenarios.

## Repository layout

- `token_service.py` - token service API surface for login simulation, token issuance, refresh, OBO exchange, step-up, introspection, revocation, and agent lifecycle endpoints.
- `internal_api.py` - protected internal API endpoints, including GPU-oriented authorization checks.
- `devctl.py` - CLI for login, OBO exchange, GPU actions, agent lifecycle commands, audit inspection, and demo flows.
- `token_utils.py` - JWT issue and verify utilities, JWKS helper logic, certificate thumbprint helpers, proof helpers, JTI revocation, and audit helpers.
- `policy_engine.py` - policy and scope-decision helpers used by authorization paths.
- `policies.yaml` - demo policy definitions for GPU, deployment, quota, and agent-token flows.
- `device_registry.py` - local Linux device registry and posture checks.
- `device_attestation.py` - simulated device-attestation evidence store for local demo flows.
- `pki_bootstrap.py` - demo PKI and certificate bootstrap for local sender-constrained token workflows.
- `dashboard.py` - optional Streamlit dashboard for service and audit visibility.
- `requirements.txt` - Python dependencies.

## Prerequisites

- Linux or WSL
- Python 3.10+
- `pip`

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

### Terminal 2: protected internal API

```bash
source .venv/bin/activate
python3 internal_api.py
```

### Terminal 3: recommended security walkthrough

Run the focused security demo flows below after the token service and protected API are running:

```bash
source .venv/bin/activate
rm -rf .state
python3 pki_bootstrap.py

python3 devctl.py demo-conditional-rotation
python3 devctl.py demo-jwt-replay-kill-switch
python3 devctl.py demo-refresh-replay
python3 devctl.py demo-device-attested-renewal
python3 devctl.py demo-action-specific-gpu-token
python3 devctl.py audit-verify
python3 devctl.py demo-failure-disabled-agent
python3 devctl.py demo-failure-scope-denied
```

This sequence demonstrates device binding, policy-aware refresh, JWT replay control, refresh replay detection, simulated device-attested renewal, action-specific GPU tokens, API-side deny cases, tamper-evident audit verification, agent lifecycle enforcement, and least-privilege scope denial.

If repeated GPU demo runs return `gpu_quota_exceeded`, restart `internal_api.py`. The protected API stores demo GPU jobs in memory while the process is running, so restarting it clears local in-memory quota state.

## Production demo flows

The main production/security-focused flows are:

- `python3 devctl.py demo-conditional-rotation`
  - Shows refresh succeeds while trust is valid and fails with `conditional_rotation_denied` after device trust changes.
- `python3 devctl.py demo-jwt-replay-kill-switch`
  - Shows a JWT succeeds once, then the same JWT is denied after `jti` revocation.
- `python3 devctl.py demo-refresh-replay`
  - Shows old refresh token reuse is detected after rotation.
- `python3 devctl.py demo-device-attested-renewal`
  - Shows simulated Linux device attestation and denial when the device becomes untrusted.
- `python3 devctl.py demo-action-specific-gpu-token`
  - Shows an action-specific GPU JWT with job, dataset, action, quota, environment, model, runtime, policy, risk, and JTI claims, plus deny cases for mismatches.
- `python3 devctl.py audit-verify`
  - Verifies the append-only audit hash chain.

For quick local validation, use:

```bash
bash scripts/validate_production_demos.sh
```

The validation script starts local services, runs the production/security flows, and stops the services when complete.

## Manual demo flow

The individual commands below are useful for exploring the system manually:

- `python3 devctl.py login --auto` - simulate device/login completion and issue user access and refresh tokens.
- `python3 devctl.py obo-build` - perform OBO exchange for scoped downstream token issuance.
- `python3 devctl.py gpu-submit` - call GPU submit path with least-privilege scope checks.
- `python3 devctl.py gpu-jobs` - list submitted GPU jobs.
- `python3 devctl.py register-agent` - register an agent identity and certificate binding.
- `python3 devctl.py agent-comment` - issue and use an agent token for an internal comment action.
- `python3 devctl.py agent-gpu-submit` - issue and use an agent token for a GPU submit action.
- `python3 devctl.py deploy-prod` - run privileged action path that requires step-up token flow.
- `python3 devctl.py audit` - inspect summarized audit data.
- `python3 devctl.py audit-tail` - tail recent append-only audit events.

## OBO behavior

During OBO exchange:

1. The incoming token is validated using signature, audience, sender-constrained proof, and required-claim checks.
2. Requested scopes must be a subset of the user token scopes.
3. If `agent_id` is supplied, requested scopes must also be a subset of that agent's `allowed_scopes` and the agent must be active.
4. The delegated token is minted with lineage claims: `act`, `obo_chain`, `original_user`, `acting_agent`, `target_service`, and `target_action`.
5. If `gpu_context` is supplied for `gpu.job.submit`, the downstream token receives action-specific GPU claims.
6. If scope constraints fail, the service returns `scope_not_allowed`.

## Action-specific GPU authorization

The GPU submit flow can issue a downstream token with action-specific claims such as:

- `job_id`
- `dataset_id`
- `gpu_action`
- `gpu_quota`
- `environment`
- `model_id`
- `max_runtime_seconds`
- `policy_id`
- `policy_version`
- `decision_id`
- `risk_level`
- `jti`

The protected API validates the JWT and sender-constrained proof, then compares request fields against token claims. Missing or mismatched claims are denied with reasons such as `action_specific_claims_required`, `job_id_mismatch`, `dataset_id_mismatch`, `environment_mismatch`, `model_id_mismatch`, `gpu_quota_exceeded`, or `runtime_exceeded`.

## Agent lifecycle

Agent lifecycle endpoints exposed by the token service:

- `POST /agent/register`
- `POST /agent/disable`
- `POST /agent/enable`
- `POST /agent/rotate-cert`
- `POST /agent/token`

These endpoints support activation state management, certificate rotation, scoped agent-token issuance, and audit lineage. An agent record includes an `agent_id`, owner, environment, allowed scopes, certificate thumbprint, quota metadata, and active/disabled status.

Failure-path command:

```bash
python3 devctl.py demo-failure-disabled-agent
```

Expected result: the agent is registered, then disabled, and subsequent agent use is denied with `agent_not_active`.

## Device registry lifecycle

The local device registry supports registering, listing, enabling, disabling, and rotating registered Linux devices. Device records include a `device_id`, owner, certificate thumbprint, status, and posture metadata.

The live cryptographic walkthrough uses the bundled demo device certificate for `linux-laptop-001`. Additional device records can be registered for lifecycle simulation. Full runtime multi-device proof-of-possession requires separate device certificate/key material per device and dynamic device selection from the presented certificate or mTLS identity.

## Audit logging

Audit persistence is split into:

- `.state/audit.json` - JSON audit database and state snapshot.
- `.state/audit_log.jsonl` - append-only JSON Lines event log.
- `write_audit_event()` - event writer used by token and authorization flows.

Audit events may include:

- `previous_hash`
- `event_hash`
- `policy_id`
- `policy_version`
- `decision_id`
- `decision`
- `risk_level`
- `reason`
- `user`
- `agent_id`
- `token_id`
- `scopes`

Use this command to inspect recent append-only entries:

```bash
python3 devctl.py audit-tail
```

Use this command to verify the hash chain:

```bash
python3 devctl.py audit-verify
```

## Failure demos

- `python3 devctl.py demo-failure-disabled-agent`
  - Expected result: disabled agent request is denied with `agent_not_active`.
- `python3 devctl.py demo-failure-scope-denied`
  - Expected result: unauthorized scope request is denied with `scope_not_allowed`.

## Production considerations

For production deployment, common controls include:

- Real enterprise IdP integration.
- Real TLS and mTLS.
- Certificate lifecycle automation.
- Device registry backed by durable inventory and posture sources.
- TPM-backed attestation where available, or signed Linux posture evidence.
- HSM or KMS-backed signing keys.
- Signing-key rotation using `kid` and JWKS publishing.
- Durable datastore for token, agent, device, policy, and audit state.
- Hashed refresh tokens at rest.
- SIEM export for centralized detection and response.
- API rate limiting and abuse controls.
- High-availability deployment and operational failover.
- Replay cache and `jti` denylist strategy for sensitive APIs.
- Agent governance workflow for registration, approval, review, and deprovisioning.
- Version-controlled policy ownership, review, rollback, and audit trails.

## JWT usage in this demo

JWT is used as the main demo token format so token claims and validation behavior are easy to inspect locally.

Security controls demonstrated:

- Short token lifetime.
- Audience restriction.
- Scope narrowing.
- `jti` denylist checks for sensitive APIs.
- Refresh-token rotation.
- Token-family replay kill switch.
- Certificate and device binding.
- Action-specific GPU claims.
- Policy decision evidence.
- Tamper-evident audit chain.

The same metadata can also be stored server-side and exposed through introspection when using opaque tokens.

Even with local JWT validation, introspection is useful for sensitive APIs, debugging, revocation checks, and compatibility with opaque-token architectures.
