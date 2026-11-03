# Security Policy

KnoxCall is a credential-custody platform; the security of this SDK is part of
that promise. We appreciate reports from the community.

## Reporting a vulnerability

Please report suspected vulnerabilities privately — do **not** open a public
GitHub issue for a security report.

- Email: **security@knoxcall.com**
- Or use GitHub's private "Report a vulnerability" advisory flow on this
  repository.

Include enough detail to reproduce: the affected version, the SDK surface
involved (auth/credential handling, the data-plane `call()` path, webhook
verification, etc.), and a proof-of-concept where possible. Please do not
include real customer secrets or tokens in your report.

| Timeline | Action |
|---|---|
| Within 24 hours | Acknowledgement of your report |
| Within 72 hours | Initial assessment and severity classification |
| Within 14 days | Remediation plan confirmed and shared with you |
| Within 90 days | Fix released (critical / high); coordinated disclosure |

We support coordinated disclosure and will credit reporters who wish to be
named once a fix is released.

## Scope

In scope: credential resolution and storage (`~/.knoxcall/credentials.json`,
the file lock and refresh rotation), OAuth/PKCE/device flows, DPoP proof
generation, the data-plane credential-transmission rules, webhook signature
verification, and secret redaction in logs/errors.

Out of scope: vulnerabilities in your own application code, third-party
transport libraries (report those upstream), and issues that require a
pre-compromised local machine or a maliciously modified credentials file.

## Handling of secrets by this SDK

- OAuth client secrets, access tokens, and refresh tokens are wrapped so they
  are excluded from `toString`/inspect/log output.
- The credentials file is written with `0600` permissions inside a `0700`
  directory (advisory on Windows, where the file inherits the user-profile
  ACL).
- Refresh tokens are single-use and rotated on every refresh; suspected reuse
  revokes the token family server-side.
