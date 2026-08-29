# API Keys and Environment Variables

## Short answer

**Core local functionality requires no third-party API key.** The deterministic SDK, CLI, local FastAPI audit API, parser registry, control pack, local history, PDF export, remediation preview, baseline/drift checks, and GitOps gate can run without external services.

The project should not request an API key from a judge for the core SIH demo. External credentials are needed only for optional features or for a future hosted deployment.

## Required for local core mode

| Variable | Secret? | Required? | Purpose | Recommended value |
|---|---|---:|---|---|
| `PYTHONPATH` | No | For source checkout | Lets Python import the package before installation. | `src` |
| `VEYRONIX_API_HOST` | No | No | Local API bind address. | `127.0.0.1` |
| `VEYRONIX_API_PORT` | No | No | Local API port. | `8000` |
| `VITE_API_BASE_URL` | No | Usually | Frontend URL for the local FastAPI adapter. | `http://127.0.0.1:8000` |

## Optional local security guard

| Variable | Secret? | Required? | Purpose | Notes |
|---|---|---:|---|---|
| `CONFIGSENTINEL_API_TOKEN` | **Yes** | No for local-only demo; recommended for API exposure | Enables a shared bearer-token guard for non-health API routes. | Generate a long random value. This is not user authentication, RBAC, or tenant isolation. Never commit it. |

Example:

```bash
export CONFIGSENTINEL_API_TOKEN="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
```

## Optional AI copilot credentials

The AI flow is disabled by default and must remain opt-in because configuration text can contain credentials, topology, and management details.

| Variable | Secret? | Required? | Purpose | Notes |
|---|---|---:|---|---|
| `CONFIGSENTINEL_LLM_ENABLED` | No | No | Enables the optional LLM gateway. | Keep `false` for offline demo mode. |
| `CONFIGSENTINEL_LLM_ENDPOINT` | No | Only when AI is enabled | OpenAI-compatible chat-completions endpoint. | Use an approved provider or approved internal endpoint. |
| `CONFIGSENTINEL_LLM_API_KEY_ENV` | No | No | Names the environment variable containing the provider key. | Defaults to `OPENAI_API_KEY`. |
| `OPENAI_API_KEY` or named provider key | **Yes** | Only when AI is enabled | Authenticates the configured LLM provider. | Store in a secret manager or protected environment; never in source control or frontend code. |
| `CONFIGSENTINEL_LLM_MODEL` | No | Only when AI is enabled | Approved model identifier. | Choose based on privacy, capability, cost, and local policy. |
| `CONFIGSENTINEL_LLM_TIMEOUT_S` | No | No | Provider timeout. | Defaults to `20`. |
| `CONFIGSENTINEL_LLM_MAX_INPUT_CHARS` | No | No | Input bound. | Defaults to `24000`. |
| `CONFIGSENTINEL_LLM_MAX_OUTPUT_CHARS` | No | No | Output bound. | Defaults to `8000`. |

No AI key is needed for deterministic audits. Enabling a provider does not make AI authoritative; deterministic statuses must remain unchanged.

## Optional encrypted backup credential

| Variable | Secret? | Required? | Purpose | Notes |
|---|---|---:|---|---|
| `CONFIGSENTINEL_BACKUP_PASSPHRASE` | **Yes** | Only for encrypted backup/restore commands | Encrypts local backup artifacts when the backup extra is installed. | Use a secret manager or protected shell input. Never commit it. |

## Existing frontend scaffold variables that are not required by the active product

| Variable | Current status | Recommendation |
|---|---|---|
| `VITE_OAUTH_PORTAL_URL` | OAuth URL helper exists, but no active login/callback/session implementation uses it. | Do not request it until identity-backed authentication is implemented. |
| `VITE_APP_ID` | Same unused OAuth scaffold. | Do not request it until identity-backed authentication is implemented. |
| `VITE_FRONTEND_FORGE_API_KEY` | Referenced by the template `Map.tsx` component, which is not part of the ConfigSentinel workflow. | Remove the unused component/config or document it separately if maps become a real feature. Do not add this key to the SIH setup. |
| `VITE_FRONTEND_FORGE_API_URL` | Same template-only map reference. | Not required for the current product. |

## Future hosted deployment credentials

A production deployment will require an identity provider configuration, database/storage credentials, TLS certificate management, rate-limit infrastructure, and possibly a secret-manager integration. These are not currently shipped as working integrations. They must be added in the security/operations phase rather than represented as fake environment variables.

The implementation must never put server secrets in `VITE_*` variables because Vite variables are exposed to browser code. Provider API keys, bearer secrets, database credentials, signing keys, and backup passphrases belong only on the server or in a managed secret store.

## SIH judge setup

For the recommended offline/GitOps demo, use no external API keys. Start the local API and frontend with `VITE_API_BASE_URL` only. If demonstrating API protection, add a temporary `CONFIGSENTINEL_API_TOKEN`. Demonstrate AI only if the team has an approved provider and has verified redaction and privacy handling; otherwise present AI as disabled-by-default architecture and do not expose a fake live claim.
