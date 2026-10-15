# Write-tool safety contract

The server exposes eleven mutation tools: `docmost_create_page`, `docmost_update_page`,
`docmost_duplicate_page`, `docmost_copy_page_to_space`, `docmost_move_page`, `docmost_move_page_to_space`,
`docmost_create_space`, `docmost_update_space`, `docmost_create_comment`, `docmost_update_comment`,
and `docmost_upload_attachment`.

All eleven are default-deny. A mutation reaches Docmost only when both conditions are
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
  option.
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

Docmost permissions remain authoritative. Use a service account that can modify
only the spaces this MCP server is meant to manage.
