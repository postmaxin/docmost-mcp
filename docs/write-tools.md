# Write-tool safety contract

The server exposes twelve mutation tools: `docmost_create_page`, `docmost_update_page`,
`docmost_duplicate_page`, `docmost_copy_page_to_space`, `docmost_move_page`, `docmost_move_page_to_space`,
`docmost_create_space`, `docmost_update_space`, `docmost_create_comment`, `docmost_update_comment`,
`docmost_upload_attachment` and `docmost_begin_upload`.

All twelve are default-deny. A mutation reaches Docmost only when both conditions are
true:

1. The operator starts the server with `DOCMOST_MCP_ENABLE_WRITES=true`.
2. The individual tool call includes `confirm: true` after the user reviews the
   exact target and proposed change.

Example:

```json
{
  "confirm": true,
  "space_id": "018f...uuid",
  "title": "Release Notes",
  "markdown": "- First stable release"
}
```

Before dispatch, the server writes an `authorized` metadata event to its audit
log. If that preflight audit cannot be written, the mutation is blocked. It then
records `succeeded` or `failed`; an outcome-log failure is reported to server logs
without falsely retrying a mutation that may already have completed.

Audit entries contain only timestamp, tool name, target ID/slug, and status. They
never contain Markdown bodies, file contents, file names, passwords, or tokens.

## Uploading attachments

`docmost_upload_attachment` uploads one file to a page through Docmost's own
`POST /api/files/upload`, the endpoint the editor uses, so the result is an ordinary
Docmost attachment. It needs edit access to the page.

```json
{
  "confirm": true,
  "page_id": "018f...uuid-or-slug",
  "file_name": "chart.png",
  "mime_type": "image/png",
  "content_base64": "iVBORw0KGgo..."
}
```

- **The file travels in the arguments, as base64.** Over HTTP the server is usually on
  another machine and cannot read the client's filesystem, so there is no file-path
  option. An agent has to generate every base64 character as output, so prefer
  `docmost_begin_upload` (below) whenever the client can run a command such as `curl`.
- **Pass `size` and `sha256` when you can.** Base64 that was altered in copying often
  still decodes; with these set, a mismatch is refused instead of stored.
- **The limit is 2 MiB after decoding.** Base64 adds a third, and the Streamable HTTP
  transport refuses request bodies over 4 MiB, so this is what fits in one call.
  Oversized, empty, or malformed content and path-like file names are rejected before
  the write gate, and nothing is audited for them. Docmost's own
  `FILE_UPLOAD_SIZE_LIMIT` still applies.
- **Docmost normalizes the file name** (for example, spaces become underscores) and
  derives the stored MIME type from the extension. Use the name the tool returns.
- **Uploading doesn't change the page body.** The tool returns the attachment ID and its
  path, `/api/files/{attachment_id}/{file_name}`. To show it, put that path in page
  Markdown via `docmost_update_page` or `docmost_create_page`: `![alt](path)` embeds an
  image and `[name](path)` links any file. Keep the path relative. Docmost serves it
  only to signed-in users who can view the page, and the editor stores the same relative form.

## Staged uploads

`docmost_begin_upload` gets a file to Docmost without the bytes passing through the
model. It needs the HTTP transport with `DOCMOST_MCP_PUBLIC_URL` set.

```json
{
  "confirm": true,
  "page_id": "018f...uuid-or-slug",
  "file_name": "chart.png",
  "mime_type": "image/png",
  "size": 36814,
  "sha256": "46c7e28c947ac78c..."
}
```

1. The call is a write like any other: default-deny, `confirm: true`, and audited as
   `begin_upload`. It returns a single-use URL, `{DOCMOST_MCP_PUBLIC_URL}/uploads/{token}`.
2. The client sends the raw file there with one `PUT`, for example
   `curl -fsS -T chart.png '<url>'`.
3. The server checks the body is exactly `size` bytes with the declared SHA-256. Only
   then does it upload to Docmost as the session that began the upload (pinned when the
   upload is approved, so it can't switch accounts in between), auditing it as
   `upload_attachment` (`authorized`, then `succeeded` or `failed`). The response is
   JSON with the attachment ID, its `path`, and a `markdown` snippet.

The URL is the credential, so the route needs no bearer token. Its token is 256 random
bits, stored only as a hash, bound to one page, file name, MIME type, size and SHA-256,
usable once, and valid for 10 minutes. Any request uses it up, including one whose body
is refused, so a failed attempt needs a new `docmost_begin_upload`. Two cases don't use
it up: when too many uploads are already in progress (four at once), the server answers
`503` and the URL can be retried. A body that hasn't fully arrived within 10 minutes is
refused with `408`. `DOCMOST_MCP_PUBLIC_URL` must be an `https://` origin outside
localhost; otherwise staged uploads are turned off with a warning. The body streams to
this server rather than through the JSON-RPC transport, so the limit is
`DOCMOST_MCP_MAX_UPLOAD_BYTES` (50 MiB by default) rather than 2 MiB. Docmost's own
`FILE_UPLOAD_SIZE_LIMIT` still applies.

Docmost permissions remain authoritative. Use a service account that can modify
only the spaces this MCP server is meant to manage.
