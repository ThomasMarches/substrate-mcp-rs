# Substrate MCP Server

[![MIT License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/Rust-2025-brightgreen)](https://www.rust-lang.org/)

A Model Context Protocol [(MCP)](https://modelcontextprotocol.io/introduction) server for Substrate blockchains, written in Rust. This project exposes dynamic Substrate blockchain operations (querying balances, blocks, pallets, storage, events, and more) via the MCP protocol, and is fully configurable via environment variables.

Designed to interface with the [subxt](https://github.com/paritytech/subxt) crate.

## ✨ Features

- Query account balances and storage dynamically
- List pallets and their entries
- Fetch and filter events and extrinsics
- Submit and watch dynamic signed transactions
- Access system and block information
- Custom RPC calls to Substrate nodes

## 🚀 Potential Use Cases

1. AI-Driven Blockchain Operations

    - Integrate with LLMs (like Cursor or Claude) to allow users to ask questions in natural language (e.g., "What was the last transfer from Alice?"), which are translated into MCP tool calls.
    - Build a chatbot that can answer questions, fetch balances, or explain on-chain activity using your MCP server as the backend.
    - Use the MCP server to provide live updates on-chain activity, such as balance changes or transaction statuses, to development tools like VSCode, Cursor, Claude Code, etc.

2. Custom Dashboards and Monitoring

    - Create custom dashboards and monitoring systems for your Substrate blockchain
    - Display real-time data and analytics on your blockchain operations
    - Set up alerts and notifications for critical events
    - Use AI agents to detect suspicious activity by analyzing events and extrinsics in real time.

## 🛠️ Requirements

- Rust
- Access to a Substrate node endpoint (WebSocket)
- A valid signing keypair (as hex)
- Runtime metadata file for your target chain (see below for naming and placement)

## 📦 Installation

Clone the repository and build:

```sh
git clone https://github.com/ThomasMarches/substrate-mcp-rs.git
cd substrate-mcp-rs
cargo build --release
```

## ⚙️ Configuration

Create a `.env` file in the project root with the following variables:

```env
# WebSocket endpoint for the Substrate node
RPC_URL=wss://your-node-url.example.com

# Signing keypair as hex (32 bytes, e.g. output of subkey inspect-key --scheme Sr25519)
SIGNING_KEYPAIR_HEX=your_signing_keypair_hex_here
```

### Generating a Signing Keypair

You can generate a keypair and get the secret seed in hex using [subkey](https://paritytech.github.io/polkadot-sdk/master/subkey/index.html):

```sh
subkey generate --scheme Sr25519 --output-type Json
```

Use the `secretSeed` field (strip the 0x prefix if present) for `SIGNING_KEYPAIR_HEX`.

### Obtaining and Placing Runtime Metadata

Export the runtime metadata from your node and place it at `artifacts/metadata.scale`:

```sh
subxt metadata -f bytes > artifacts/metadata.scale
```

**Important:** The file must be named `metadata.scale` and located in the `artifacts/` directory before building. The build will fail if this file is missing or misnamed.

## ▶️ Usage

To start the MCP server:

```sh
cargo run --release
```

The server will start and listen for MCP requests via stdio.

## 🖇️ Integrating with Cursor

To use this MCP server with [Cursor](https://www.cursor.so/), you need to add it to your Cursor MCP configuration. This allows Cursor to discover and interact with your Substrate MCP server.

1. Build your server in release mode:

   ```sh
   cargo build --release
   ```

2. Locate the path to the built binary (typically `target/release/substrate-mcp-rs`).

3. In your project (or global) `.cursor/mcp.json` file, add an entry for your server. For example:

   ```json
   {
     "mcpServers": {
       "substrate-mcp-rs": {
         "command": "$PROJECT_ROOT_ABSOLUTE_PATH/target/release/substrate-mcp-rs",
         "args": []
       }
     }
   }
   ```

   - Replace the `command` path with the absolute path to your built binary if it differs.

4. Restart Cursor. It should now detect and connect to your Substrate MCP server, making its tools available for use.

For more details, see the [Cursor documentation](https://docs.cursor.com/context/model-context-protocol) or the [Model Context Protocol introduction](https://modelcontextprotocol.io/introduction).

## 🧰 Available Tools

The server exposes a set of tools for interacting with a Substrate blockchain, including:

- `query_balance`: Fetch the balance of an account
- `list_pallets`: List all pallets in the runtime
- `list_pallet_entries`: List all storage entries for a pallet
- `dynamic_runtime_call`: Execute a runtime API call
- `send_dynamic_signed_transaction`: Construct, sign, and send a transaction
- `query_storage`: Query storage by pallet and entry
- `get_latest_events`: Get all events from the latest block
- `find_events`: Find specific events by pallet and variant
- `get_latest_block`: Get details about the latest block
- `get_block_by_hash`: Get block details by hash
- `find_extrinsics`: Find extrinsics in the latest block
- `get_system_info`: Get system info via RPC
- `custom_rpc`: Make a custom RPC call

See [`src/tooling/substrate.rs`](src/tooling/substrate.rs) for full details and parameters.

## 🗂️ Project Structure

- `src/main.rs`: Entry point, sets up logging and starts the MCP server
- `src/tooling/`: Contains the Substrate tool implementation
- `artifacts/`: Place your runtime metadata file here as `metadata.scale` (required before building)

## 📈 Next Steps and Goals

- [ ] Add E2E tests
- [ ] Add Unit tests
- [ ] Add more tools

## 🤝 Contributing

Contributions are welcome! Please open issues or pull requests. For larger changes, open an issue first to discuss your proposal.

- Follow Rust best practices and ensure code is documented
- Run `cargo fmt` and `cargo clippy` before submitting
- Add tests where possible

## 📄 License

MIT
