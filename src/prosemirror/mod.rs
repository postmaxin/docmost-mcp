//! Conversion between Docmost's ProseMirror JSON page/comment bodies and Markdown.
//!
//! - [`reader`] — ProseMirror JSON → Markdown (used by read tools such as `docmost_get_page`).
//! - [`writer`] — Markdown → ProseMirror JSON (used by `docmost_update_page` and the comment
//!   tools). `docmost_create_page` instead uploads raw Markdown to Docmost's import endpoint.
//! - [`nodes`] — ProseMirror node builders shared by the writer.
//! - [`embed`] — which URLs Docmost turns into an `embed` node.

mod embed;
mod nodes;
mod reader;
mod writer;

pub use reader::prosemirror_to_markdown;
pub use writer::markdown_to_prosemirror;
