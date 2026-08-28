# Security Policy

## Responsible use

ConfigSentinel AI is an alpha defensive-security prototype. Use it only on configurations and environments you are authorized to assess. Do not upload customer configurations, credentials, private keys, tokens, or other sensitive data to an external model provider without explicit organizational approval.

The current release does not connect to network devices, execute generated commands, or apply configuration changes. Remediation files are previews and require independent review and an approved change process.

## Reporting a vulnerability

Do not publish sensitive details in a public issue. Contact the VEYRONIX maintainers through a private GitHub security advisory or another private channel available to the project maintainers. Include a concise description, affected version or commit, safe reproduction steps, impact assessment, and suggested mitigation. Redact all real credentials and customer data from reports.

## Secrets

Never commit `.env` files, provider keys, private keys, raw production configurations, or unredacted audit outputs. Use environment variables or an approved secret manager for local experiments. The repository `.gitignore` blocks common local secret and cache files, but users remain responsible for checking staged changes before committing.

## API deployment boundary

The local FastAPI adapter is intentionally unauthenticated when used on its default loopback bind. For a controlled non-loopback deployment, set `CONFIGSENTINEL_API_TOKEN`; audit, detection, and control-pack endpoints then require `Authorization: Bearer <token>`, while health endpoints remain available for liveness checks. This token mode is a minimum boundary, not a substitute for an organization’s identity provider.

Any production exposure also requires TLS termination, rate limiting, structured request/audit logging, secret-manager integration, tenant isolation, retention controls, and an independent security review. Do not expose the development server directly to the public internet.

## Model safety

LLM output is untrusted data. Keep the deterministic compliance engine authoritative, validate structured output, maintain input and prompt version metadata, and never execute model-generated commands. Disable the copilot when the data-flow approval or privacy boundary is unclear.
