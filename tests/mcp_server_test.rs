use anyhow::Result;
use docmost_mcp::{server::DocmostMcpServer, types::StartupConfig};
use rmcp::{
    ClientHandler, ServiceExt,
    model::{CallToolRequestParams, ClientConfig},
};

#[derive(Debug, Clone, Default)]
struct DummyClientHandler;

impl ClientHandler for DummyClientHandler {
    fn get_info(&self) -> ClientConfig {
        ClientConfig::default()
    }
}

#[tokio::test]
async fn server_lists_expected_tools() -> Result<()> {
    let (server_transport, client_transport) = tokio::io::duplex(16 * 1024);

    let server_handle = tokio::spawn(async move {
        let server = DocmostMcpServer::new(StartupConfig::default())?;
        server.serve(server_transport).await?.waiting().await?;
        anyhow::Ok(())
    });

    let client = DummyClientHandler.serve(client_transport).await?;
    let tools = client.list_tools(None).await?;
    let tool_names = tools
        .tools
        .iter()
        .map(|tool| tool.name.to_string())
        .collect::<Vec<_>>();

    for expected in [
        "docmost_list_spaces",
        "docmost_search_docs",
        "docmost_search_pages",
        "docmost_get_space",
        "docmost_get_page",
        "docmost_list_pages",
        "docmost_list_child_pages",
        "docmost_get_comments",
        "docmost_list_workspace_members",
        "docmost_get_current_user",
        "docmost_create_page",
        "docmost_update_page",
        "docmost_duplicate_page",
        "docmost_copy_page_to_space",
        "docmost_move_page",
        "docmost_move_page_to_space",
        "docmost_create_space",
        "docmost_update_space",
        "docmost_create_comment",
        "docmost_update_comment",
    ] {
        assert!(
            tool_names.iter().any(|name| name == expected),
            "missing tool {expected}"
        );
    }

    // Exactly the expected surface: no accidental extra/duplicate registration.
    assert_eq!(
        tool_names.len(),
        20,
        "unexpected tool count: {tool_names:?}"
    );
    let mut unique = tool_names.clone();
    unique.sort();
    unique.dedup();
    assert_eq!(
        unique.len(),
        tool_names.len(),
        "duplicate tool names registered"
    );

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn server_all_tools_expose_object_input_schemas() -> Result<()> {
    let (server_transport, client_transport) = tokio::io::duplex(16 * 1024);

    let server_handle = tokio::spawn(async move {
        let server = DocmostMcpServer::new(StartupConfig::default())?;
        server.serve(server_transport).await?.waiting().await?;
        anyhow::Ok(())
    });

    let client = DummyClientHandler.serve(client_transport).await?;
    let tools = client.list_tools(None).await?;
    for tool in tools.tools {
        assert_eq!(
            tool.input_schema
                .get("type")
                .and_then(|value| value.as_str()),
            Some("object"),
            "tool {} must expose object input schema",
            tool.name
        );
    }

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn server_get_page_requires_slug_id_schema() -> Result<()> {
    let (server_transport, client_transport) = tokio::io::duplex(16 * 1024);

    let server_handle = tokio::spawn(async move {
        let server = DocmostMcpServer::new(StartupConfig::default())?;
        server.serve(server_transport).await?.waiting().await?;
        anyhow::Ok(())
    });

    let client = DummyClientHandler.serve(client_transport).await?;
    let tools = client.list_tools(None).await?;
    let get_page = tools
        .tools
        .into_iter()
        .find(|tool| tool.name == "docmost_get_page")
        .expect("get_page tool should exist");
    let properties = get_page
        .input_schema
        .get("properties")
        .and_then(|value| value.as_object())
        .expect("get_page tool should expose properties");

    assert!(properties.contains_key("slug_id"));

    let result = client
        .call_tool(
            CallToolRequestParams::new("docmost_get_page").with_arguments(serde_json::Map::new()),
        )
        .await?;
    assert_eq!(result.is_error, Some(true));
    assert!(format!("{result:?}").contains("slug_id"));

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}

#[tokio::test]
async fn server_required_input_fields_are_present() -> Result<()> {
    let (server_transport, client_transport) = tokio::io::duplex(16 * 1024);

    let server_handle = tokio::spawn(async move {
        let server = DocmostMcpServer::new(StartupConfig::default())?;
        server.serve(server_transport).await?.waiting().await?;
        anyhow::Ok(())
    });

    let client = DummyClientHandler.serve(client_transport).await?;
    let tools = client.list_tools(None).await?;

    for (tool_name, property_name) in [
        ("docmost_get_page", "slug_id"),
        ("docmost_get_space", "space_id"),
        ("docmost_list_pages", "space_id"),
        ("docmost_list_child_pages", "page_id"),
        ("docmost_get_comments", "page_id"),
        ("docmost_search_docs", "query"),
        ("docmost_search_pages", "query"),
        ("docmost_create_page", "space_id"),
        ("docmost_create_page", "title"),
        ("docmost_update_page", "page_id"),
        ("docmost_duplicate_page", "page_id"),
        ("docmost_copy_page_to_space", "page_id"),
        ("docmost_copy_page_to_space", "space_id"),
        ("docmost_move_page", "page_id"),
        ("docmost_move_page_to_space", "page_id"),
        ("docmost_move_page_to_space", "space_id"),
        ("docmost_create_space", "name"),
        ("docmost_create_space", "slug"),
        ("docmost_update_space", "space_id"),
        ("docmost_create_comment", "page_id"),
        ("docmost_create_comment", "markdown"),
        ("docmost_update_comment", "comment_id"),
        ("docmost_update_comment", "markdown"),
        ("docmost_create_page", "confirm"),
        ("docmost_update_page", "confirm"),
        ("docmost_duplicate_page", "confirm"),
        ("docmost_copy_page_to_space", "confirm"),
        ("docmost_move_page", "confirm"),
        ("docmost_move_page_to_space", "confirm"),
        ("docmost_create_space", "confirm"),
        ("docmost_update_space", "confirm"),
        ("docmost_create_comment", "confirm"),
        ("docmost_update_comment", "confirm"),
    ] {
        let tool = tools
            .tools
            .iter()
            .find(|tool| tool.name == tool_name)
            .unwrap_or_else(|| panic!("{tool_name} tool should exist"));
        let properties = tool
            .input_schema
            .get("properties")
            .and_then(|value| value.as_object())
            .unwrap_or_else(|| panic!("{tool_name} should expose properties"));
        assert!(
            properties.contains_key(property_name),
            "{tool_name} should contain property {property_name}"
        );
        let required = tool
            .input_schema
            .get("required")
            .and_then(|value| value.as_array())
            .unwrap_or_else(|| panic!("{tool_name} should expose a required-fields list"));
        assert!(
            required
                .iter()
                .any(|value| value.as_str() == Some(property_name)),
            "{tool_name}.{property_name} should be required"
        );
    }

    client.cancel().await?;
    server_handle.await??;
    Ok(())
}
