use anyhow::Result;
use rmcp::{ServiceExt, transport::stdio};
use tooling::substrate::SubstrateTool;
use tracing_subscriber::{self, EnvFilter};

mod tooling;

pub use tooling::*;

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize the tracing subscriber with file and stdout logging
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::DEBUG.into()))
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .init();

    tracing::info!("Starting MCP server");

    // Create an instance of our server
    let service = SubstrateTool::new()
        .await
        .serve(stdio())
        .await
        .inspect_err(|e| {
            tracing::error!("serving error: {:?}", e);
        })?;

    service.waiting().await?;
    Ok(())
}
