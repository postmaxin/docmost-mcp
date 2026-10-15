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
| Token lifetime | until rotated | access: short-lived, memory-only; refresh: sealed, single-use, until the Docmost session expires |
| Intended for | single user, automation, break-glass | shared and multi-user servers |

Both may be enabled at once: the static token is checked first and is the
break-glass path. **Enabling account OAuth makes the static token optional, not
harmless** — anything holding it still acts as the shared account, so drop
`DOCMOST_MCP_BEARER_TOKEN` entirely on a multi-user deployment unless you need it.

Account OAuth uses authorization code flow with PKCE (S256 required), exact
registered redirect URIs, CSRF-protected login, per-account failed-login
throttling, one-time authorization codes, and opaque access tokens stored only
as SHA-256 hashes, in memory.

### Refresh tokens and what is at rest

Each grant carries the user's Docmost session token. The server never writes
that token to its own disk:

- **Access tokens** are opaque, live in memory as SHA-256 hashes, and last at
  most an hour. A restart forgets them; the client gets a 401 and refreshes.
- **Refresh tokens** are not stored by the server at all. Each one is an
  AES-256-GCM sealed blob (`dmr1.…`) holding the client it was issued to (as a
  hash), the scope, the Docmost session, an expiry (the Docmost session's) and
  a rotation id. The client stores it; without the key it is opaque and cannot
  be altered. Because nothing server-side is needed to redeem it, it survives
  a restart.
- **The key** is 32 random bytes in `~/.docmost-local-mcp/refresh-token.key`
  (override with `DOCMOST_MCP_REFRESH_KEY_FILE`), created on first start with
  mode 0600 in a 0700 directory. A file of the wrong length stops startup
  rather than being replaced. **This file is the secret to protect**: anyone
  who has it *and* a client's stored refresh token can read the Docmost
  session inside. Deleting it (and restarting) invalidates every outstanding
  refresh token; users then sign in again. Tokens are also bound to
  `DOCMOST_MCP_PUBLIC_URL` and `DOCMOST_BASE_URL`, so changing either has the
  same effect.
- **Single use.** Every refresh rotates the token. Rotation state per
  authorization (no credentials, just a counter) is kept in memory; presenting
  a token that was already redeemed refuses it and revokes every token
  descended from the same authorization, so a stolen copy and the legitimate
  client cannot both keep going.
- **Revalidation.** Before issuing anything, a refresh asks Docmost
  (`/api/users/me`) whether the session is still valid. If Docmost answers 401
  or 403 (signed out, revoked, expired) the refresh fails with
  `invalid_grant`, so signing out of Docmost also cuts off agents at their
  next refresh. If Docmost cannot be reached the refresh proceeds: the session
  is still checked by Docmost on every tool call.

Residual risks, stated plainly:

- Rotation state is lost on restart. After a restart, each authorization's
  first refresh is accepted whichever of its unexpired tokens is presented,
  including one already redeemed before the restart. A thief holding a copied
  refresh token therefore gets one redemption per restart; when the
  legitimate client then refreshes, the reuse is detected and both lose
  access. A revocation triggered by reuse is likewise forgotten on restart.
- Revocation of a refresh-token family after a Docmost rejection is also
  held in memory. After a restart, such a family is refused only because
  Docmost still rejects its session at refresh; if Docmost cannot be reached
  at that moment, the refresh succeeds and the first tool call revokes it
  again.
- An access token outlives a Docmost sign-out until a tool call or refresh
  discovers the rejection (at most an hour), though Docmost itself rejects
  the session on every call.
- Refresh tokens are bearer credentials until the Docmost session expires (or
  the key is deleted). Clients should store them as they would any OAuth
  refresh token.

Dynamic client registration is open (as MCP clients expect) but stores
nothing: the issued `client_id` carries the client's redirect URIs and name,
signed with HMAC-SHA256, and is verified at authorization. Anonymous
registrations therefore cannot exhaust memory or lock out real clients. The
signing key is created on first start in `~/.docmost-local-mcp/client-id.key`
(mode 0600; override with `DOCMOST_MCP_CLIENT_ID_KEY_FILE`) and survives
restarts, because clients cache their `client_id` and do not re-register on
their own. Deleting the file invalidates every issued `client_id`; affected
clients must clear their stored authentication and connect again.

Each grant carries the Docmost session captured at consent, and lives no longer
than that session. Once Docmost rejects it (the user signed out, the session was
revoked, or it expired), the server drops every access token and unredeemed
code carrying it, revokes every refresh-token family carrying it (refresh tokens
are sealed and held by the client, so the family is what can be revoked), and
`/mcp` answers 401 with the OAuth challenge so the client signs in again. A
refresh also checks the session with Docmost first, which is what refuses a
family this process has not seen since a restart.

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
  exchanges it with Docmost; the password is never stored. Access grants are
  memory-only; refresh tokens are sealed and held by the client (see above).
  Back up or mount `refresh-token.key` with the same care as other secrets.
- OS-keychain persistence is preferred for interactive stdio mode. File fallback
  requires `DOCMOST_ALLOW_FILE_CREDENTIALS=true`.

The audit log records timestamp, operation, target identifier, and status only.
It deliberately excludes page content, comment content, uploaded file contents,
passwords, and tokens.

## Reporting a vulnerability

Report privately through
[GitHub Security Advisories](https://github.com/Rahulk644/docmost-mcp/security/advisories/new).
Please do not open a public issue for a security problem.

Include the version or commit, your configuration (with secrets redacted), and the
steps to reproduce. Expect an initial response within seven days.

Only the latest `main` is supported. This project is not affiliated with Docmost:
report vulnerabilities in Docmost itself to
[the Docmost project](https://github.com/docmost/docmost), not here.
