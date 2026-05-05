# Microsoft Entra ID Integration Design

## Purpose

This project uses Microsoft Entra ID as the enterprise identity provider and a custom centralized token service as the internal authorization and token-broker layer.

Entra authenticates human users and provides enterprise identity signals. The custom token service validates enterprise identity context and issues short-lived internal tokens for protected internal APIs, GPU workflows, agent workflows, and production-sensitive operations.

## High-Level Production Flow

1. A user signs in through Microsoft Entra ID.
2. Entra issues an access token intended for the custom token service.
3. The token service validates issuer, audience, expiration, signature, tenant, user, groups, roles, and available device or compliance context.
4. The token service maps Entra identity claims to internal policy.
5. The token service issues a short-lived internal access token with least-privilege scopes.
6. Internal APIs validate the internal token issued by the token service.
7. Token issuance, OBO exchanges, step-up events, agent actions, GPU actions, and policy decisions are written to audit.

## Entra Responsibilities

- Human user authentication
- MFA and Conditional Access
- User and group lifecycle
- Enterprise tenant identity
- App registration for the token service
- App roles or delegated scopes
- Device and compliance context where available
- Stronger authentication context for sensitive operations

## Custom Token Service Responsibilities

- Validate Entra-issued JWTs
- Issue internal short-lived JWTs
- Enforce device certificate binding
- Enforce on-behalf-of token exchange
- Enforce agent identity registration
- Bind agent identity to certificate thumbprint
- Enforce least-privilege scopes
- Enforce GPU quota and sensitive-action policy
- Generate audit events
- Support user, device, token, and agent lifecycle controls

## OBO Flow

For user-delegated access, the custom token service follows an OBO-style pattern:

1. CLI or internal client presents an Entra user token to the token service.
2. Token service validates the user token.
3. Token service checks policy for the requested downstream API scope.
4. Token service issues an internal API token with the user identity preserved.
5. Internal API receives a scoped token with audience and scope restricted to that API.

Example internal scopes:

- `build.read`
- `gpu.job.submit`
- `gpu.job.read`
- `deploy.prod`
- `gpu.quota.update`

## Step-Up Flow

Sensitive operations require stronger authorization before an internal token is issued.

Examples:

- `deploy.prod`
- `gpu.quota.update`
- `agent.rotate_cert`
- `policy.admin`

In production, this can map to Conditional Access and stronger authentication context. In the local demo, this is represented by the step-up token flow.

## Agent and Non-Human Identity Flow

Agents should not share generic service accounts. Each agent receives:

- Unique immutable `agent_id`
- Owner
- Purpose
- Environment
- Allowed scopes
- Certificate thumbprint
- GPU quota
- Active or disabled status
- Audit trail

The token service does not trust the `agent_id` string alone. It validates:

- Agent exists in the registry
- Agent status is active
- Certificate thumbprint matches
- Proof-of-possession signature is valid
- Requested scopes are allowed
- Quota is within policy

## Why Use a Custom Token Service With Entra?

Entra is the enterprise identity provider. The custom token service adds internal platform enforcement closer to protected workloads:

- GPU job authorization
- Agent-specific identity governance
- Certificate-bound proof-of-possession for Linux workflows
- Internal OBO token shaping
- Fine-grained internal scopes
- Local audit correlation across user, device, agent, and GPU actions

In short: Entra proves who the user is. The custom token service decides what the user, device, or agent is allowed to do inside the platform.

## Production Hardening

Production deployment would replace local demo primitives with:

- Entra app registrations
- JWKS-based Entra token validation
- Managed workload identity for services
- HSM/KMS-backed signing keys
- TLS/mTLS
- Central audit export
- Durable database for token, device, user, and agent registry
- Scheduler-native GPU governance integration
