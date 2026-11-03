use std::future::Future;

use rmcp::{
    ServerHandler,
    handler::server::router::tool::ToolRouter,
    model::{ErrorData, Implementation, ServerCapabilities, ServerInfo},
    tool_handler,
};

use crate::{docmost_client::DocmostClient, staged_upload::UploadStager};

mod render;
mod tools;
mod tools_attachment;
mod tools_page_write;
mod tools_write;

pub(crate) use tools_attachment::{attachment_markdown, attachment_path};

#[derive(Debug, Clone)]
pub struct DocmostMcpServer {
    client: DocmostClient,
    tool_router: ToolRouter<Self>,
    writes_enabled: bool,
    /// Present only over HTTP with a public URL; see [`crate::staged_upload`].
    stager: Option<UploadStager>,
}

#[tool_handler(router = self.tool_router)]
impl ServerHandler for DocmostMcpServer {
    fn get_info(&self) -> ServerInfo {
        ServerInfo::new(ServerCapabilities::builder().enable_tools().build())
            .with_server_info(
                Implementation::new("docmost-mcp", env!("CARGO_PKG_VERSION"))
                    .with_title("Docmost MCP")
                    .with_description("Authenticated Streamable HTTP bridge for Docmost"),
            )
            .with_instructions(
                "Search and read Docmost spaces, pages, members, and comments. Mutation tools are default-deny and require both server-side write enablement and confirm=true after the user reviews the exact change."
            )
    }
}

fn internal_error(error: anyhow::Error) -> ErrorData {
    ErrorData::internal_error(error.to_string(), None)
}

impl DocmostMcpServer {
    /// Enable `docmost_begin_upload` by sharing the HTTP server's pending-upload store.
    pub fn with_stager(mut self, stager: Option<UploadStager>) -> Self {
        self.stager = stager;
        self
    }

    pub(crate) async fn run_write<T, F>(
        &self,
        confirmed: bool,
        operation: &str,
        target: &str,
        future: F,
    ) -> Result<T, ErrorData>
    where
        F: Future<Output = anyhow::Result<T>>,
    {
        if !self.writes_enabled {
            return Err(ErrorData::invalid_params(
                "Docmost mutations are disabled. Set DOCMOST_MCP_ENABLE_WRITES=true on the server and retry only after user approval.".to_string(),
                None,
            ));
        }
        if !confirmed {
            return Err(ErrorData::invalid_params(
                "This mutation requires confirm=true after the user reviews the exact action."
                    .to_string(),
                None,
            ));
        }

        crate::audit::record_mutation(operation, target, "authorized")
            .await
            .map_err(internal_error)?;
        let result = future.await;
        let status = if result.is_ok() {
            "succeeded"
        } else {
            "failed"
        };
        if let Err(error) = crate::audit::record_mutation(operation, target, status).await {
            tracing::error!(%operation, %target, %status, %error, "Failed to append mutation outcome to audit log");
        }
        result.map_err(internal_error)
    }
}
