# Threat model

## Scope and assumptions

This lab models a small read-only campaign-search API containing synthetic data. It is not deployed,
does not represent an employer system, and deliberately excludes authentication, write operations,
secrets, cloud infrastructure and third-party integrations. Those exclusions must not be mistaken for
completed controls.

## Trust boundaries and assets

| Element | Classification | Security concern |
| --- | --- | --- |
| HTTP query string and headers | Untrusted input | Injection, control characters, oversized values |
| Flask request handling | Trust boundary | Validation, error handling and response policy |
| SQL statement construction | Critical boundary | Code/data separation and least privilege |
| Campaign records | Synthetic asset | Confidentiality and integrity demonstration |
| Logs/request IDs | Operational metadata | Log injection and cross-request correlation |

## STRIDE analysis

| Threat | Example | Primary control | Verification |
| --- | --- | --- | --- |
| Spoofing | Caller supplies a misleading request ID | Constrained request-ID grammar | Invalid ID replacement test |
| Tampering | SQL metacharacters alter the query | SQLite parameter binding | Boolean and UNION payload tests |
| Repudiation | Requests cannot be correlated | Response request ID | Preservation/generation tests |
| Information disclosure | Framework error exposes internals | Structured JSON errors, debug disabled | 404 response test |
| Denial of service | Oversized request values | Length/body limits | Overlong-name test |
| Elevation of privilege | Not applicable to unauthenticated read-only lab | Out of scope; document rather than claim | Scope review |

## Abuse cases

1. An attacker sends `' OR 1=1 --` to expand the result set.
2. An attacker uses `UNION SELECT` to inject attacker-controlled rows.
3. A client sends control characters in metadata to corrupt downstream logs.
4. A client probes missing routes hoping to obtain stack traces.
5. A client submits oversized input to consume application or logging resources.

## Residual risk

This exercise uses an in-memory database and Flask's test client. A production design would also need
authentication and authorisation, TLS termination, rate limiting, centralised safe logging, database
credentials with minimum privileges, monitoring, deployment hardening, dependency governance and
incident-response procedures.
