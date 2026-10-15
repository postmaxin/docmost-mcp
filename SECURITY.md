# Security policy and deployment boundary

The MCP gateway Bearer token and the Docmost credential are different secrets.
Use independent high-entropy values and rotate them independently.

## Authentication modes

`/mcp` accepts two kinds of credential. At least one must be configured — the
server refuses to start with neither.

| | Static Bearer token | Account OAuth |
| --- | --- | --- |
| Enabled by | `DOCMOST_MCP_BEARER_TOKEN` | `DOCMOST_MCP_ACCOUNT_AUTH=true` |
| Identity | one shared Docmost credential | each user's own Docmost account |
| Docmost permissions | whatever the shared account has | inherited per user |
| Token lifetime | until rotated | short-lived, memory-only |
| Intended for | single user, automation, break-glass | shared and multi-user servers |

Both may be enabled at once: the static token is checked first and is the
break-glass path. **Enabling account OAuth makes the static token optional, not
harmless** — anything holding it still acts as the shared account, so drop
`DOCMOST_MCP_BEARER_TOKEN` entirely on a multi-user deployment unless you need it.

Account OAuth uses authorization code flow with PKCE (S256 required), exact
registered redirect URIs, CSRF-protected login, per-account failed-login
throttling, one-time authorization codes, and opaque tokens stored only as
SHA-256 hashes. Grants live in memory, so a restart requires users to sign in
again — deliberately.

Dynamic client registration is open (as MCP clients expect) but stores
nothing: the issued `client_id` carries the client's redirect URIs and name,
signed with HMAC-SHA256 under a key generated at startup, and is verified at
authorization. Anonymous registrations therefore cannot exhaust memory or lock
out real clients. A restart rotates the key, so clients re-register — as they
already must, since grants do not survive a restart.

## Supported boundary

The default configuration is for a single machine: loopback HTTP, exact Host and
Origin allowlists, and a local MCP client. If traffic leaves the machine, put the
server behind an HTTPS reverse proxy or private authenticated overlay network. The
Rust process intentionally does not terminate TLS.

For a shared remote endpoint, enable per-account OAuth so each MCP client inherits
the authorizing user's Docmost permissions. Use a dedicated least-privilege
account only for single-user or automated service workloads. Keep writes disabled
unless an operator needs them. MCP clients must show the exact mutation to the
user before sending `confirm: true`.

## Secret handling

- Never commit `.env`; it is ignored by Git.
- Prefer a secret manager or container orchestrator secret injection.
- Prefer `DOCMOST_API_TOKEN` when your Docmost edition supports it.
- Email/password authentication does not persist the password when supplied via
  environment variables.
- Account OAuth sends the password only to the MCP login handler and immediately
  exchanges it with Docmost; the password is never stored. Account access grants
  are memory-only and are invalidated by a process restart.
- OS-keychain persistence is preferred for interactive stdio mode. File fallback
  requires `DOCMOST_ALLOW_FILE_CREDENTIALS=true`.

The audit log records timestamp, operation, target identifier, and status only.
It deliberately excludes page content, comment content, passwords, and tokens.

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/Rahulk644/docmost-mcp/security/advisories/new).
Please do not open a public issue for a security problem.

Include the version or commit, your configuration (with secrets redacted), and the
steps to reproduce. Expect an initial response within seven days.

Only the latest `main` is supported. This project is not affiliated with Docmost:
report vulnerabilities in Docmost itself to
[the Docmost project](https://github.com/docmost/docmost), not here.
