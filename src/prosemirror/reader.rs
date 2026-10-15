//! ProseMirror JSON → Markdown.

use serde_json::Value;

pub fn prosemirror_to_markdown(content: &Value) -> String {
    if !is_document_node(content) {
        return String::new();
    }

    let nodes = content
        .get("content")
        .and_then(Value::as_array)
        .cloned()
        .unwrap_or_default();

    convert_nodes(&nodes, 0).trim().to_string()
}

fn is_document_node(value: &Value) -> bool {
    value
        .get("type")
        .and_then(Value::as_str)
        .map(|node_type| node_type == "doc")
        .unwrap_or(false)
}

fn convert_nodes(nodes: &[Value], indent: usize) -> String {
    let mut output = Vec::new();

    for node in nodes {
        match node_type(node) {
            Some("paragraph") => {
                let text = extract_text(children(node));
                if !text.is_empty() {
                    output.push(text);
                    output.push(String::new());
                }
            }
            Some("heading") => {
                let level = node
                    .get("attrs")
                    .and_then(|attrs| attrs.get("level"))
                    .and_then(Value::as_u64)
                    .unwrap_or(1)
                    .clamp(1, 6);
                output.push(format!(
                    "{} {}",
                    "#".repeat(level as usize),
                    extract_text(children(node))
                ));
                output.push(String::new());
            }
            Some("bulletList") => {
                output.push(convert_list(children(node), false, indent, 1));
                output.push(String::new());
            }
            Some("orderedList") => {
                let start = node
                    .get("attrs")
                    .and_then(|attrs| attrs.get("start"))
                    .and_then(Value::as_u64)
                    .unwrap_or(1);
                output.push(convert_list(children(node), true, indent, start));
                output.push(String::new());
            }
            Some("taskList") => {
                output.push(convert_task_list(children(node), indent));
                output.push(String::new());
            }
            Some("codeBlock") => {
                let language = node
                    .get("attrs")
                    .and_then(|attrs| attrs.get("language"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                output.push(format!("```{language}"));
                output.push(extract_text(children(node)));
                output.push("```".to_string());
                output.push(String::new());
            }
            Some("blockquote") => {
                let inner = convert_nodes(children(node), indent);
                let quoted = inner
                    .lines()
                    .filter(|line| !line.is_empty())
                    .map(|line| format!("> {line}"))
                    .collect::<Vec<_>>()
                    .join("\n");
                if !quoted.is_empty() {
                    output.push(quoted);
                    output.push(String::new());
                }
            }
            Some("horizontalRule") => {
                output.push("---".to_string());
                output.push(String::new());
            }
            Some("table") => {
                let table = convert_table(node);
                if !table.is_empty() {
                    output.push(table);
                    output.push(String::new());
                }
            }
            Some("image") => {
                let src = node
                    .get("attrs")
                    .and_then(|attrs| attrs.get("src"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                if !src.is_empty() {
                    let alt = node
                        .get("attrs")
                        .and_then(|attrs| attrs.get("alt"))
                        .and_then(Value::as_str)
                        .unwrap_or("image");
                    output.push(format!("![{alt}]({src})"));
                    output.push(String::new());
                }
            }
            Some("embed") => {
                // A bare link (text == URL): Docmost's import turns that back into an
                // embed for a known provider, and so does `markdown_to_prosemirror`.
                let src = attr_str(node, "src");
                if !src.is_empty() {
                    output.push(format!("[{src}]({src})"));
                    output.push(String::new());
                }
            }
            Some("drawio") | Some("excalidraw") => {
                // Diagrams are stored as an image attachment (SVG) of the drawing.
                let src = attr_str(node, "src");
                if !src.is_empty() {
                    let title = first_non_empty(&[attr_str(node, "title"), attr_str(node, "alt")])
                        .unwrap_or("diagram");
                    output.push(format!("![{title}]({src})"));
                    output.push(String::new());
                }
            }
            Some("video") | Some("audio") | Some("pdf") | Some("attachment") => {
                // Uploaded media and files: a link to the attachment, as Docmost's own
                // Markdown export writes a video.
                let src = first_non_empty(&[attr_str(node, "src"), attr_str(node, "url")]);
                if let Some(src) = src {
                    let fallback = node_type(node).unwrap_or("file");
                    let name = first_non_empty(&[attr_str(node, "name"), attr_str(node, "alt")])
                        .unwrap_or(fallback);
                    output.push(format!("[{name}]({src})"));
                    output.push(String::new());
                }
            }
            Some("mathBlock") => {
                let text = attr_str(node, "text");
                if !text.is_empty() {
                    output.push(format!("$$\n{text}\n$$"));
                    output.push(String::new());
                }
            }
            Some("callout") => {
                // Docmost's Markdown import and export both use `:::type` fences.
                let inner = convert_nodes(children(node), 0);
                if !inner.is_empty() {
                    let callout_type = match attr_str(node, "type") {
                        "" => "info",
                        callout_type => callout_type,
                    };
                    output.push(format!(":::{callout_type}\n{inner}\n:::"));
                    output.push(String::new());
                }
            }
            _ => {}
        }
    }

    output.join("\n").trim_end().to_string()
}

fn extract_text(content: &[Value]) -> String {
    let mut parts = Vec::new();

    for item in content {
        match node_type(item) {
            Some("text") => {
                let mut text = item
                    .get("text")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .to_string();

                if let Some(marks) = item.get("marks").and_then(Value::as_array) {
                    for mark in marks {
                        match node_type(mark) {
                            Some("bold") => text = format!("**{text}**"),
                            Some("italic") => text = format!("*{text}*"),
                            Some("code") => text = format!("`{text}`"),
                            Some("strike") => text = format!("~~{text}~~"),
                            Some("link") => {
                                let href = mark
                                    .get("attrs")
                                    .and_then(|attrs| attrs.get("href"))
                                    .and_then(Value::as_str)
                                    .unwrap_or("");
                                if !href.is_empty() {
                                    text = format!("[{text}]({href})");
                                }
                            }
                            _ => {}
                        }
                    }
                }

                parts.push(text);
            }
            Some("mention") => {
                // Render a mention back as the `[label](user:ID)` convention the writer reads.
                let attrs = item.get("attrs");
                let label = attrs
                    .and_then(|a| a.get("label"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                let entity_type = attrs
                    .and_then(|a| a.get("entityType"))
                    .and_then(Value::as_str)
                    .unwrap_or("user");
                let entity_id = attrs
                    .and_then(|a| a.get("entityId"))
                    .and_then(Value::as_str)
                    .unwrap_or("");
                // A `[` or `]` in the label would break the `[label](...)` syntax and the
                // writer would mis-parse it, so fall back to a plain `@label` there.
                if entity_id.is_empty() || label.contains(['[', ']']) {
                    parts.push(format!("@{label}"));
                } else {
                    parts.push(format!("[{label}]({entity_type}:{entity_id})"));
                }
            }
            Some("mathInline") => {
                let text = attr_str(item, "text");
                if !text.is_empty() {
                    parts.push(format!("${text}$"));
                }
            }
            Some("hardBreak") => parts.push("\n".to_string()),
            _ if !children(item).is_empty() => parts.push(extract_text(children(item))),
            _ => {}
        }
    }

    parts.join("")
}

fn convert_list(items: &[Value], ordered: bool, indent: usize, start: u64) -> String {
    let mut output = Vec::new();

    for (index, item) in items.iter().enumerate() {
        if node_type(item) != Some("listItem") {
            continue;
        }

        let marker = if ordered {
            format!("{}. ", start + index as u64)
        } else {
            "- ".to_string()
        };
        output.push(convert_list_item(item, &marker, marker.len(), indent));
    }

    output.join("\n")
}

fn convert_task_list(items: &[Value], indent: usize) -> String {
    let mut output = Vec::new();

    for item in items {
        if node_type(item) != Some("taskItem") {
            continue;
        }

        let checked = item
            .get("attrs")
            .and_then(|attrs| attrs.get("checked"))
            .and_then(Value::as_bool)
            .unwrap_or(false);
        let marker = if checked { "- [x] " } else { "- [ ] " };
        // Continuation lines align with the text after `- `, not after the checkbox.
        output.push(convert_list_item(item, marker, 2, indent));
    }

    output.join("\n")
}

/// Render one list or task item. The first paragraph goes on the marker line and nested
/// lists follow directly. Any other block child (an embed, image, further paragraph, code
/// block, ...) is set off by a blank line and indented to `continuation` columns past the
/// marker, so it stays inside the item instead of being dropped.
fn convert_list_item(item: &Value, marker: &str, continuation: usize, indent: usize) -> String {
    let prefix = " ".repeat(indent);
    let block_prefix = " ".repeat(indent + continuation);
    let mut lines = vec![format!("{prefix}{marker}")];
    let mut has_first_paragraph = false;

    for child in children(item) {
        match node_type(child) {
            Some("paragraph") if !has_first_paragraph => {
                let text = extract_text(children(child));
                if !text.is_empty() {
                    has_first_paragraph = true;
                    lines[0].push_str(&text);
                }
            }
            Some("bulletList") | Some("orderedList") | Some("taskList") => {
                lines.push(convert_nodes(std::slice::from_ref(child), indent + 2));
            }
            _ => {
                let block = convert_nodes(std::slice::from_ref(child), 0);
                if block.is_empty() {
                    continue;
                }
                // A block in an item that has no leading paragraph starts on the marker
                // line itself: Markdown does not allow a list item to open with a blank
                // line followed by content.
                let first_in_item = !has_first_paragraph && lines.len() == 1;
                has_first_paragraph = true;
                for (index, line) in block.lines().enumerate() {
                    if index == 0 && first_in_item {
                        lines[0].push_str(line);
                    } else if index == 0 {
                        lines.push(String::new());
                        lines.push(format!("{block_prefix}{line}"));
                    } else if line.is_empty() {
                        lines.push(String::new());
                    } else {
                        lines.push(format!("{block_prefix}{line}"));
                    }
                }
            }
        }
    }

    lines.join("\n")
}

fn convert_table(table_node: &Value) -> String {
    let mut rows = Vec::new();

    for row in children(table_node) {
        if node_type(row) != Some("tableRow") {
            continue;
        }

        let mut cells = Vec::new();
        for cell in children(row) {
            match node_type(cell) {
                Some("tableCell") | Some("tableHeader") => {
                    let cell_text = convert_nodes(children(cell), 0)
                        .split_whitespace()
                        .collect::<Vec<_>>()
                        .join(" ");
                    cells.push(cell_text);
                }
                _ => {}
            }
        }

        if !cells.is_empty() {
            rows.push(cells);
        }
    }

    let Some(first_row) = rows.first() else {
        return String::new();
    };

    let mut lines = Vec::new();
    lines.push(format!("| {} |", first_row.join(" | ")));
    lines.push(format!(
        "| {} |",
        first_row
            .iter()
            .map(|_| "---")
            .collect::<Vec<_>>()
            .join(" | ")
    ));

    for row in rows.into_iter().skip(1) {
        lines.push(format!("| {} |", row.join(" | ")));
    }

    lines.join("\n")
}

fn attr_str<'a>(node: &'a Value, key: &str) -> &'a str {
    node.get("attrs")
        .and_then(|attrs| attrs.get(key))
        .and_then(Value::as_str)
        .unwrap_or("")
}

fn first_non_empty<'a>(values: &[&'a str]) -> Option<&'a str> {
    values.iter().copied().find(|value| !value.is_empty())
}

fn node_type(node: &Value) -> Option<&str> {
    node.get("type").and_then(Value::as_str)
}

fn children(node: &Value) -> &[Value] {
    node.get("content")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or(&[])
}
