# Advanced CodeQL AppSec Lab

[![Security lab](https://github.com/imandarvishi/codeql-appsec-lab/actions/workflows/security.yml/badge.svg)](https://github.com/imandarvishi/codeql-appsec-lab/actions/workflows/security.yml)

An interview-ready, multi-tenant Python application-security lab demonstrating vulnerability
reproduction, authorization design, source-to-sink analysis, secure remediation, property-based
testing, threat modelling and software-supply-chain controls. All records are fictional.

## What this version demonstrates

| Capability | Implementation |
| --- | --- |
| SQL-injection analysis | CWE-89 vulnerable sample with documented source, sink and trust boundary |
| Secure remediation | SQLite parameter binding in the main application |
| Abuse-case testing | Boolean injection, UNION injection, apostrophes and malformed input |
| API hardening | Length limits, control-character rejection, JSON errors and body-size limit |
| Response policy | CSP, clickjacking, MIME-sniffing, cache and referrer headers |
| Operational security | Validated/generated correlation IDs |
| Authentication | Short-lived signed lab tokens with strict claim validation |
| Authorization | Tenant-scoped database queries prevent BOLA/IDOR; admin RBAC |
| Auditability | Bounded security-decision events without token capture |
| CI security | Python matrix, Ruff, Bandit, CodeQL and dependency audit |
| Supply chain | CycloneDX SBOM artifact and Dependabot configuration |
| Container | Minimal image, non-root UID and narrow build context |
| API contract | OpenAPI 3.1 specification with auth and error responses |
| Design assurance | STRIDE threat model, residual-risk record and remediation review |

## Repository layout

```text
app.py                       Hardened Flask application
examples/vulnerable_app.py   Deliberately vulnerable SAST sample
tests/test_app.py             Behavioural and security regression suite
docs/THREAT_MODEL.md          Assets, trust boundaries, STRIDE and abuse cases
docs/SECURITY_REVIEW.md       Finding, remediation and evidence expectations
docs/openapi.yaml              OpenAPI 3.1 API contract
Dockerfile                     Non-root demonstration container
.github/workflows/security.yml CI and CodeQL pipeline
```

## Run locally

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements-dev.txt
python -m unittest discover -s tests -v
ruff check app.py tests
bandit -q -r app.py
python -m pip_audit -r requirements.txt
python -m cyclonedx_py requirements requirements.txt --output-file sbom.json
```

Never deploy `examples/vulnerable_app.py`. It remains present so reviewers can compare the vulnerable
and remediated data flows and so CodeQL has a deliberate training finding.

## Interview explanation

Start with the trust boundary: an HTTP parameter is untrusted, while the SQL interpreter is a
sensitive sink. Explain why parameter binding provides code/data separation, then use the tests as
executable security requirements. Discuss why SAST can trace flows that tests may miss, while tests
prove concrete behaviour that SAST does not. Finish with residual risk rather than claiming the app is
“fully secure.” For the authorization path, explain why filtering by both object ID and the
authenticated tenant prevents BOLA, and why returning 404 avoids confirming cross-tenant existence.

The signed token implementation is intentionally a lab mechanism, not a home-grown production
identity service. A real deployment should validate tokens issued by a managed identity provider,
handle key rotation and revocation, and send immutable audit events to central storage.

This is an AI-assisted personal learning lab. Describe only the work you personally ran, reviewed and
can explain. It is not evidence of production GHAS administration or enterprise CI/CD ownership.
