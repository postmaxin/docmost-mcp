# Changelog

All notable changes are documented here. The format loosely follows
[Keep a Changelog](https://keepachangelog.com/), and versions aim to follow
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed
- **Every tool is now prefixed `docmost_`** (`docmost_list_spaces`,
  `docmost_create_page`, …). The MCP naming convention calls for a service prefix
  because clients routinely load several servers at once — and five names
  (`create_page`, `create_space`, `duplicate_page`, `get_page`, `move_page`)
  collided outright with another MCP running alongside this one. When two servers
  expose the same tool name the resolution is client-specific (auto-namespace,
  error, or last-wins), none of which is acceptable for an agent choosing between
  two different products. **Breaking** for anyone who pinned the old names.

### Fixed
- **`docmost_get_page` no longer drops embeds and other Docmost blocks.** An
  `embed` (YouTube, Vimeo, Loom, ...) inside a list item vanished from the
  Markdown, as did every block in a list item after its first paragraph, so an
  agent reading a page concluded the link was gone. A top-level embed came back
  as `[Embedded content](url)`, which Docmost re-imports as a plain link. Embeds
  now render as a bare link, `[url](url)`, which both Docmost's import
  (`docmost_create_page`) and `docmost_update_page` turn back into an embed for
  the providers Docmost embeds. Extra blocks in list items are kept, indented
  under the item. Draw.io and Excalidraw diagrams render as images; videos,
  audio, PDFs and file attachments as links; math as `$...$`/`$$...$$`; and
  callouts as Docmost's `:::type` fences.
- **Pagination metadata is now returned, making the `cursor` parameter usable.**
  Every cursor-based list tool accepted a `cursor`, but responses were folded into
  a bare `Vec` that discarded the rest — so nothing ever told the caller what the
  *next* cursor was, and every list silently stopped at page one. List tools now
  return the next cursor, the total when the server provides one, and whether more
  results exist.

  `has_more` is deliberately tri-state: it is set only when the server actually
  says so (an explicit `hasNextPage`, or a `nextCursor` implying more), and is
  reported as *unknown* otherwise. It is never inferred from `items.len() == limit`
  — a final page that happens to be exactly full would then report more results,
  and an agent would page forever.

  The response envelope is parsed defensively (nested `meta`, flat fields, or
  absent) because Docmost has shipped more than one shape and a Community instance
  may omit it entirely.
- **List output now states its display cap.** Renderers show the first 10 items (20
  for members) and previously reported "Showing 10 of 10", which reads as "that is
  everything". The footer now names the cap, the total, and the cursor to continue.

- **`response_format: json` now really does return complete records.** Serde drops
  unknown keys by default, so the "complete records" promise was false: any field
  Docmost returned that this server did not model — `createdAt`, `workspaceId`,
  `isLocked`, `contributors`, `permissions` and so on — was silently discarded.
  Every response type now captures unmodelled fields and re-emits them at the top
  level, so JSON output matches what the API actually sent and new Docmost fields
  appear without a code change. (`Eq` was dropped from these types, since
  `serde_json::Value` is not `Eq`; nothing required it.)
- **`docmost_get_page` returned prose on the not-found path even in JSON mode.** A
  caller asking for `json` got a sentence when the page was missing, breaking any
  parser. It now returns `{"page": null, "markdown": null}`.
- Three more agent-visible tool references left unprefixed by the rename: comment
  guidance pointed at `list_workspace_members`, and page-write guidance at
  `move_page` and `create_page`.

### Added
- CI: `cargo fmt --check`, strict `clippy -D warnings`, the test suite, a
  **production image build with a runtime smoke test**, and a dependency-advisory
  audit. The image build is what catches a broken `Dockerfile` COPY path — the
  cargo jobs stayed green while the image was broken by the crate rename.
- Repository hygiene: `CHANGELOG.md`, `CODE_OF_CONDUCT.md`, and issue/PR templates.

## [1.0.0]

Initial hardened release, forked from
[`wisflux/docmost-local-mcp`](https://github.com/wisflux/docmost-local-mcp) at
`0bb2960` (upstream 0.9.2, MIT) — see [UPSTREAM.md](UPSTREAM.md).

### Added
- Authenticated MCP **Streamable HTTP** transport on `rmcp` 3.1.0.
- **Bearer authentication** with constant-time comparison, a 32-byte minimum, and
  rejection of placeholder/example tokens.
- **Host and Origin validation** (DNS-rebinding protection).
- Headless environment-based Docmost authentication: API token, or Community
  edition email/password.
- **Default-deny writes** — mutations require both server-side enablement
  (`DOCMOST_MCP_ENABLE_WRITES`) and per-call `confirm: true`.
- Metadata-only mutation audit log.
- Keychain-first credential storage.
- Docker packaging and Codex plugin metadata.
- 20 tools across spaces, pages, page content, comments, and members.

### Removed
- The upstream npm launcher and its **install-time binary download**. Fetching a
  prebuilt binary at install time is a supply-chain risk; this build compiles from
  source instead.
