//! Substrate integration tools for the MCP server.
//!
//! This module provides dynamic access to Substrate blockchain operations (balances, pallets, storage, events, transactions, etc.)
//! via the Model Context Protocol (MCP). Configuration is via environment variables and runtime metadata.

use dotenv::dotenv;
use hex;
use rmcp::model::{CallToolResult, Content};
use rmcp::tool;
use rmcp::{Error as McpError, RoleServer, ServerHandler, model::*, service::RequestContext};
use serde_json;
use serde_json::json;
use std::env;
use std::{str::FromStr, sync::Arc};
use subxt::backend::{legacy::LegacyRpcMethods, rpc::RpcClient};
use subxt::config::polkadot::PolkadotExtrinsicParamsBuilder as Params;
use subxt::config::substrate::AccountId32;
use subxt::dynamic::Value;
use subxt::ext::subxt_rpcs::client::RpcParams;
use subxt::tx::TxStatus;
use subxt::utils::H256;
use subxt::{Config, OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::Keypair;
use tokio::sync::Mutex;
use tracing;

// Generate an interface that we can use from the node's metadata.
#[subxt::subxt(runtime_metadata_path = "artifacts/metadata.scale")]
pub mod substrate {}

type SubstrateConfig = PolkadotConfig;

/// Main tool for interacting with a Substrate blockchain via MCP.
///
/// Provides dynamic querying, transaction submission, and runtime API access.
#[derive(Clone)]
pub struct SubstrateTool {
    api: Arc<Mutex<OnlineClient<SubstrateConfig>>>,
    rpc_client: Arc<Mutex<RpcClient>>,
    rpc_methods: Arc<Mutex<LegacyRpcMethods<SubstrateConfig>>>,
    signing_keypair: Option<Keypair>,
}

#[tool(tool_box)]
impl SubstrateTool {
    /// Create a new SubstrateTool, loading configuration from environment variables.
    ///
    /// - `RPC_URL`: WebSocket endpoint for the Substrate node
    /// - `SIGNING_KEYPAIR_HEX`: Signing keypair as hex (32 bytes, optional)
    ///
    /// If the signing keypair is missing or invalid, transaction-signing tools will return an error, but the server will still start.
    ///
    /// # Logging
    /// Logs a warning if the signing keypair is missing or invalid, and info if loaded successfully.
    pub async fn new() -> Self {
        dotenv().ok();
        let rpc_url = env::var("RPC_URL").expect("RPC_URL must be set in .env");
        let rpc = RpcClient::from_url(&rpc_url)
            .await
            .expect("Failed to create rpc client");
        let client = OnlineClient::<SubstrateConfig>::from_rpc_client(rpc.clone())
            .await
            .expect("Failed to create API client");

        let signing_keypair = env::var("SIGNING_KEYPAIR_HEX")
            .inspect_err(|_| {
                tracing::warn!("SIGNING_KEYPAIR_HEX not set; signing will be disabled");
            })
            .ok()
            .and_then(|signing_keypair_hex| {
                hex::decode(signing_keypair_hex.trim())
                    .map_err(|e| {
                        tracing::warn!(
                            "Failed to decode SIGNING_KEYPAIR_HEX as hex: {e}; signing will be disabled"
                        );
                    })
                    .ok()
            })
            .and_then(|bytes| {
                if bytes.len() == 32 {
                    let secret_key_array: [u8; 32] = bytes.as_slice().try_into().expect(
                        "SIGNING_KEYPAIR_HEX: Slice of 32 bytes should convert to array [u8; 32]",
                    );

                    Keypair::from_secret_key(secret_key_array)
                        .map_err(|e| {
                            tracing::warn!(
                                "Invalid SIGNING_KEYPAIR_HEX: {e}; signing will be disabled"
                            );
                        })
                        .ok()
                } else {
                    tracing::warn!("SIGNING_KEYPAIR_HEX is not 32 bytes; signing will be disabled");
                    None
                }
            })
            .inspect(|_| {
                    tracing::info!("Loaded signing keypair from SIGNING_KEYPAIR_HEX");
            });

        Self {
            api: Arc::new(Mutex::new(client)),
            rpc_client: Arc::new(Mutex::new(rpc.clone())),
            rpc_methods: Arc::new(Mutex::new(LegacyRpcMethods::<SubstrateConfig>::new(rpc))),
            signing_keypair,
        }
    }

    /// Fetch the free balance of an account.
    ///
    /// # Parameters
    /// - `account`: SS58-encoded account address
    ///
    /// # Returns
    /// The free balance as a string, or an error if not found.
    #[tool(description = "Fetch the balance of an account")]
    pub async fn query_balance(
        &self,
        #[tool(param)] account: String,
    ) -> Result<CallToolResult, McpError> {
        let client = self.api.lock().await;
        let account_id = AccountId32::from_str(&account).map_err(|e| {
            McpError::invalid_params(
                "Invalid account address",
                Some(serde_json::json!({ "error": e.to_string() })),
            )
        })?;

        let storage = client.storage().at_latest().await.map_err(|e| {
            McpError::internal_error(format!("Failed to access storage: {}", e), None)
        })?;

        let account_balance = storage
            .fetch(&substrate::storage().balances().account(&account_id))
            .await
            .map_err(|e| {
                McpError::resource_not_found(
                    format!(
                        "Failed to fetch account balance: {} for account: {}",
                        e, account
                    ),
                    None,
                )
            })?;

        match account_balance {
            Some(balance) => Ok(CallToolResult::success(vec![Content::text(
                balance.free.to_string(),
            )])),
            None => Err(McpError::resource_not_found(
                format!("Balance was not found for account: {}", account),
                None,
            )),
        }
    }

    /// List all pallets in the runtime metadata.
    ///
    /// # Returns
    /// A list of pallet names.
    #[tool(description = "List all pallets")]
    pub async fn list_pallets(&self) -> Result<CallToolResult, McpError> {
        let client = self.api.lock().await;

        Ok(CallToolResult::success(
            client
                .metadata()
                .pallets()
                .map(|p| Content::text(p.name().to_string()))
                .collect(),
        ))
    }

    /// List all storage entries for a given pallet.
    ///
    /// # Parameters
    /// - `pallet_name`: Name of the pallet
    ///
    /// # Returns
    /// A list of storage entry names.
    #[tool(description = "List all of a pallet's entries")]
    pub async fn list_pallet_entries(
        &self,
        #[tool(param)] pallet_name: String,
    ) -> Result<CallToolResult, McpError> {
        let client = self.api.lock().await;
        let client_metadata = client.metadata();

        // Find the pallet
        let pallet = client_metadata
            .pallets()
            .find(|p| *p.name() == pallet_name)
            .ok_or(McpError::invalid_params("Pallet not found", None))?;

        // Get storage
        let storage = pallet
            .storage()
            .ok_or(McpError::invalid_params("Pallet has no storage", None))?;

        // Collect entry names
        let entries = storage
            .entries()
            .iter()
            .map(|e| Content::text(e.name().to_string()))
            .collect();

        Ok(CallToolResult::success(entries))
    }

    /// Execute a dynamic runtime API call.
    ///
    /// # Parameters
    /// - `trait_name`: Runtime API trait name
    /// - `method_name`: Method name
    /// - `args_data`: Arguments as strings
    ///
    /// # Returns
    /// The result of the runtime API call as a string.
    #[tool(description = "Execute a dynamic runtime API call")]
    pub async fn dynamic_runtime_call(
        &self,
        #[tool(param)] trait_name: String,
        #[tool(param)] method_name: String,
        #[tool(param)] args_data: Vec<String>,
    ) -> Result<CallToolResult, McpError> {
        let client = self.api.lock().await;

        let runtime_api_call = subxt::dynamic::runtime_api_call(trait_name, method_name, args_data);
        let runtime_api = client.runtime_api().at_latest().await.map_err(|e| {
            McpError::internal_error(format!("Failed to access runtime api: {}", e), None)
        })?;

        let call_result = runtime_api.call(runtime_api_call).await.map_err(|e| {
            McpError::internal_error(format!("Failed to call runtime api: {}", e), None)
        })?;

        let result = call_result.to_value().map_err(|e| {
            McpError::internal_error(
                format!("Failed to convert runtime api result to value: {}", e),
                None,
            )
        })?;

        Ok(CallToolResult::success(vec![Content::text(
            result.to_string(),
        )]))
    }

    /// Construct, sign, and submit a dynamic transaction.
    ///
    /// # Parameters
    /// - `pallet_name`: Pallet name
    /// - `call_name`: Call name
    /// - `call_parameters`: Call parameters as a string
    /// - `mortality`, `nonce`, `tip_of_asset_id`, `tip`, `tip_of`: Optional transaction params
    ///
    /// # Returns
    /// Transaction hash if successful.
    #[tool(description = "Constructs, signs and sends a dynamic transaction")]
    #[allow(clippy::too_many_arguments)]
    pub async fn send_dynamic_signed_transaction(
        &self,
        #[tool(param)] pallet_name: String,
        #[tool(param)] call_name: String,
        #[tool(param)] call_parameters: String,
        #[tool(param)] mortality: Option<u64>,
        #[tool(param)] nonce: Option<u64>,
        #[tool(param)] tip_of_asset_id: Option<<SubstrateConfig as Config>::AssetId>,
        #[tool(param)] tip: Option<u128>,
        #[tool(param)] tip_of: Option<u128>,
    ) -> Result<CallToolResult, McpError> {
        let signing_keypair = self
            .signing_keypair
            .as_ref()
            .ok_or(McpError::internal_error("Signing keypair is not set", None))?;
        let client = self.api.lock().await;

        let tx = subxt::dynamic::tx(
            pallet_name,
            call_name,
            vec![Value::from_bytes(call_parameters.as_bytes())],
        );
        let mut tx_params = Params::new();

        if let Some(mortality) = mortality {
            tx_params = tx_params.mortal(mortality);
        }

        if let Some(nonce) = nonce {
            tx_params = tx_params.nonce(nonce);
        }

        if let (Some(tip_of_asset_id), Some(tip_of)) = (tip_of_asset_id, tip_of) {
            tx_params = tx_params.tip_of(tip_of, tip_of_asset_id);
        }

        if let Some(tip) = tip {
            tx_params = tx_params.tip(tip);
        }

        let tx_hash = client
            .tx()
            .sign_and_submit(&tx, signing_keypair, tx_params.build())
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to submit transaction: {}", e), None)
            })?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Transaction {tx_hash:?} was successfully submitted",
        ))]))
    }

    /// Construct, sign, and submit a dynamic transaction and wait for it to be included in a block.
    ///
    /// # Parameters
    /// - `pallet_name`: Pallet name
    /// - `call_name`: Call name
    /// - `call_parameters`: Call parameters as a string
    /// - `mortality`, `nonce`, `tip_of_asset_id`, `tip`, `tip_of`: Optional transaction params
    ///
    /// # Returns
    /// The transaction hash and the block number it was included in.
    #[tool(
        description = "Constructs and sends a transaction and waits for it to be included in a block"
    )]
    #[allow(clippy::too_many_arguments)]
    pub async fn send_dynamic_transaction_and_wait(
        &self,
        #[tool(param)] pallet_name: String,
        #[tool(param)] call_name: String,
        #[tool(param)] call_parameters: String,
        #[tool(param)] mortality: Option<u64>,
        #[tool(param)] nonce: Option<u64>,
        #[tool(param)] tip_of_asset_id: Option<<SubstrateConfig as Config>::AssetId>,
        #[tool(param)] tip: Option<u128>,
        #[tool(param)] tip_of: Option<u128>,
    ) -> Result<CallToolResult, McpError> {
        let signing_keypair = self
            .signing_keypair
            .as_ref()
            .ok_or(McpError::internal_error("Signing keypair is not set", None))?;
        let client = self.api.lock().await;

        let tx = subxt::dynamic::tx(
            pallet_name,
            call_name,
            vec![Value::from_bytes(call_parameters.as_bytes())],
        );
        let mut tx_params = Params::new();

        if let Some(mortality) = mortality {
            tx_params = tx_params.mortal(mortality);
        }

        if let Some(nonce) = nonce {
            tx_params = tx_params.nonce(nonce);
        }

        if let (Some(tip_of_asset_id), Some(tip_of)) = (tip_of_asset_id, tip_of) {
            tx_params = tx_params.tip_of(tip_of, tip_of_asset_id);
        }

        if let Some(tip) = tip {
            tx_params = tx_params.tip(tip);
        }

        let mut tx_progress = client
            .tx()
            .sign_and_submit_then_watch(&tx, signing_keypair, tx_params.build())
            .await
            .map_err(|e| {
                McpError::internal_error(format!("Failed to send transaction: {}", e), None)
            })?;

        let mut result = None;

        while let Some(status) = tx_progress.next().await {
            if let TxStatus::InFinalizedBlock(in_block) = status.map_err(|e| {
                McpError::internal_error(format!("Failed to get transaction status: {}", e), None)
            })? {
                result = Some(in_block);
            }
        }

        let result = result.ok_or(McpError::internal_error(
            "Transaction could not be finalized",
            None,
        ))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "Transaction {:?} is finalized in block {:?}",
            result.extrinsic_hash(),
            result.block_hash()
        ))]))
    }

    /// Query storage dynamically by providing pallet and storage item names.
    ///
    /// # Parameters
    /// - `pallet_name`: Pallet name
    /// - `entry_name`: Storage item name
    /// - `storage_keys`: Optional storage keys as a list of strings
    ///
    /// # Returns
    /// The storage value as a string.
    #[tool(description = "Query storage dynamically by providing pallet and storage item names")]
    pub async fn query_storage(
        &self,
        #[tool(param)] pallet_name: String,
        #[tool(param)] entry_name: String,
        #[tool(param)] storage_keys: Option<Vec<String>>,
    ) -> Result<CallToolResult, McpError> {
        let client = self.api.lock().await;

        // Convert storage keys to Values if provided
        let keys: Vec<_> = storage_keys
            .map(|keys| {
                keys.into_iter()
                    .map(|k| Value::from_bytes(k.as_bytes()))
                    .collect()
            })
            .unwrap_or_default();

        // Build the dynamic storage query
        let storage_query = subxt::dynamic::storage(&pallet_name, &entry_name, keys);

        // Execute the storage query
        let storage = client.storage().at_latest().await.map_err(|e| {
            McpError::internal_error(format!("Failed to access storage: {}", e), None)
        })?;

        let fetch_result = storage.fetch(&storage_query).await.map_err(|e| {
            McpError::resource_not_found(
                format!(
                    "Failed to fetch storage for pallet: {}, storage: {}. Error: {}",
                    pallet_name, entry_name, e
                ),
                None,
            )
        })?;

        match fetch_result {
            Some(value) => {
                let decoded = value.to_value().map_err(|e| {
                    McpError::internal_error(format!("Failed to decode storage value: {}", e), None)
                })?;

                Ok(CallToolResult::success(vec![Content::text(
                    decoded.to_string(),
                )]))
            }
            None => Ok(CallToolResult::success(vec![Content::text(
                "No value found at storage location".to_string(),
            )])),
        }
    }

    /// Get all events from the latest block.
    ///
    /// # Returns
    /// A list of events with their details.
    #[tool(description = "Get all events from the latest block")]
    pub async fn get_latest_events(&self) -> Result<CallToolResult, McpError> {
        let client = self.api.lock().await;

        // Get events from the latest block
        let events = client.events().at_latest().await.map_err(|e| {
            McpError::internal_error(format!("Failed to fetch events: {}", e), None)
        })?;

        // Collect all events with their details
        let mut event_details = Vec::new();
        for event in events.iter() {
            let event = event.map_err(|e| {
                McpError::internal_error(format!("Failed to decode event: {}", e), None)
            })?;

            event_details.push(Content::text(format!(
                "{}::{}: {}",
                event.pallet_name(),
                event.variant_name(),
                event.field_values().map_err(|e| {
                    McpError::internal_error(format!("Failed to get field values: {}", e), None)
                })?
            )));
        }

        Ok(CallToolResult::success(event_details))
    }

    /// Find specific events by pallet and variant name.
    ///
    /// # Parameters
    /// - `pallet_name`: Pallet name
    /// - `event_name`: Event name
    ///
    /// # Returns
    /// A list of events with their details.
    #[tool(description = "Find specific events by pallet and variant name")]
    pub async fn find_events(
        &self,
        #[tool(param)] pallet_name: String,
        #[tool(param)] event_name: String,
    ) -> Result<CallToolResult, McpError> {
        let client = self.api.lock().await;

        // Get events from the latest block
        let events = client.events().at_latest().await.map_err(|e| {
            McpError::internal_error(format!("Failed to fetch events: {}", e), None)
        })?;

        // Find matching events
        let mut matching_events = Vec::new();
        for event in events.iter() {
            let event = event.map_err(|e| {
                McpError::internal_error(format!("Failed to decode event: {}", e), None)
            })?;

            if event.pallet_name() == pallet_name && event.variant_name() == event_name {
                matching_events.push(Content::text(format!(
                    "{}::{}: {}",
                    pallet_name,
                    event_name,
                    event.field_values().map_err(|e| {
                        McpError::internal_error(format!("Failed to get field values: {}", e), None)
                    })?
                )));
            }
        }

        if matching_events.is_empty() {
            matching_events.push(Content::text(format!(
                "No events found matching {}::{}",
                pallet_name, event_name
            )));
        }

        Ok(CallToolResult::success(matching_events))
    }

    /// Get a constant value from a specific pallet.
    ///
    /// # Parameters
    /// - `pallet_name`: Pallet name
    /// - `constant_name`: Constant name
    ///
    /// # Returns
    /// The constant value as a string.
    #[tool(description = "Get a constant value from a specific pallet")]
    pub async fn get_constant(
        &self,
        #[tool(param)] pallet_name: String,
        #[tool(param)] constant_name: String,
    ) -> Result<CallToolResult, McpError> {
        let client = self.api.lock().await;

        // Create a dynamic constant query
        let constant_query = subxt::dynamic::constant(&pallet_name, &constant_name);

        // Get the constant value
        let value = client.constants().at(&constant_query).map_err(|e| {
            McpError::resource_not_found(
                format!(
                    "Failed to get constant {}::{}: {}",
                    pallet_name, constant_name, e
                ),
                None,
            )
        })?;

        // Convert to a readable format
        let constant_value = value.to_value().map_err(|e| {
            McpError::internal_error(format!("Failed to decode constant value: {}", e), None)
        })?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "{}::{} = {}",
            pallet_name, constant_name, constant_value
        ))]))
    }

    /// Get details about the latest finalized block.
    ///
    /// # Returns
    /// A list of block details.
    #[tool(description = "Get details about the latest finalized block")]
    pub async fn get_latest_block(&self) -> Result<CallToolResult, McpError> {
        let client = self.api.lock().await;

        // Get the latest block
        let block = client.blocks().at_latest().await.map_err(|e| {
            McpError::internal_error(format!("Failed to get latest block: {}", e), None)
        })?;

        let mut details = Vec::new();

        // Block header info
        let block_number = block.header().number;
        let block_hash = block.hash();
        details.push(Content::text(format!("Block #{}", block_number)));
        details.push(Content::text(format!("Hash: {}", block_hash)));

        // Get extrinsics
        let extrinsics = block.extrinsics().await.map_err(|e| {
            McpError::internal_error(format!("Failed to get extrinsics: {}", e), None)
        })?;

        details.push(Content::text("Extrinsics:".to_string()));
        for ext in extrinsics.iter() {
            let idx = ext.index();

            // Get extrinsic metadata
            let meta = ext.extrinsic_metadata().map_err(|e| {
                McpError::internal_error(format!("Failed to get extrinsic metadata: {}", e), None)
            })?;

            // Get field values
            let fields = ext.field_values().map_err(|e| {
                McpError::internal_error(format!("Failed to get field values: {}", e), None)
            })?;

            details.push(Content::text(format!(
                "  #{}: {}/{}",
                idx,
                meta.pallet.name(),
                meta.variant.name
            )));
            details.push(Content::text(format!("    Fields: {}", fields)));

            // Get associated events
            if let Ok(events) = ext.events().await {
                details.push(Content::text("    Events:".to_string()));
                for evt in events.iter().flatten() {
                    if let Ok(values) = evt.field_values() {
                        details.push(Content::text(format!(
                            "      {}::{}: {}",
                            evt.pallet_name(),
                            evt.variant_name(),
                            values
                        )));
                    }
                }
            }

            // Get transaction extensions if available
            if let Some(extensions) = ext.transaction_extensions() {
                details.push(Content::text("    Transaction Extensions:".to_string()));
                for extension in extensions.iter() {
                    if let Ok(value) = extension.value() {
                        details.push(Content::text(format!(
                            "      {}: {}",
                            extension.name(),
                            value
                        )));
                    }
                }
            }
        }

        Ok(CallToolResult::success(details))
    }

    /// Get details about a specific block by its hash.
    ///
    /// # Parameters
    /// - `block_hash`: Block hash
    ///
    /// # Returns
    /// A list of block details.
    #[tool(description = "Get details about a specific block by its hash")]
    pub async fn get_block_by_hash(
        &self,
        #[tool(param)] block_hash: String,
    ) -> Result<CallToolResult, McpError> {
        let client = self.api.lock().await;

        // Parse the block hash
        let hash_bytes = hex::decode(block_hash.trim_start_matches("0x")).map_err(|e| {
            McpError::invalid_params(format!("Invalid block hash format: {}", e), None)
        })?;

        // Get the block
        let block = client
            .blocks()
            .at(H256::from_slice(&hash_bytes))
            .await
            .map_err(|e| {
                McpError::resource_not_found(format!("Failed to get block: {}", e), None)
            })?;

        let mut details = Vec::new();

        // Block header info
        let block_number = block.header().number;
        details.push(Content::text(format!("Block #{}", block_number)));
        details.push(Content::text(format!("Hash: {}", block_hash)));

        // Get extrinsics
        let extrinsics = block.extrinsics().await.map_err(|e| {
            McpError::internal_error(format!("Failed to get extrinsics: {}", e), None)
        })?;

        details.push(Content::text("Extrinsics:".to_string()));
        for ext in extrinsics.iter() {
            let idx = ext.index();
            let meta = ext.extrinsic_metadata().map_err(|e| {
                McpError::internal_error(format!("Failed to get extrinsic metadata: {}", e), None)
            })?;

            let fields = ext.field_values().map_err(|e| {
                McpError::internal_error(format!("Failed to get field values: {}", e), None)
            })?;

            details.push(Content::text(format!(
                "  #{}: {}/{}",
                idx,
                meta.pallet.name(),
                meta.variant.name
            )));
            details.push(Content::text(format!("    Fields: {}", fields)));

            // Get associated events
            if let Ok(events) = ext.events().await {
                details.push(Content::text("    Events:".to_string()));
                for evt in events.iter().flatten() {
                    if let Ok(values) = evt.field_values() {
                        details.push(Content::text(format!(
                            "      {}::{}: {}",
                            evt.pallet_name(),
                            evt.variant_name(),
                            values
                        )));
                    }
                }
            }
        }

        Ok(CallToolResult::success(details))
    }

    /// Find specific extrinsics in the latest block by pallet and call names.
    ///
    /// # Parameters
    /// - `pallet_name`: Pallet name
    /// - `call_name`: Call name
    ///
    /// # Returns
    /// A list of extrinsics with their details.
    #[tool(description = "Find specific extrinsics in the latest block by pallet and call names")]
    pub async fn find_extrinsics(
        &self,
        #[tool(param)] pallet_name: String,
        #[tool(param)] call_name: String,
    ) -> Result<CallToolResult, McpError> {
        let client = self.api.lock().await;

        // Get the latest block
        let block = client.blocks().at_latest().await.map_err(|e| {
            McpError::internal_error(format!("Failed to get latest block: {}", e), None)
        })?;

        let mut found_extrinsics = Vec::new();
        let extrinsics = block.extrinsics().await.map_err(|e| {
            McpError::internal_error(format!("Failed to get extrinsics: {}", e), None)
        })?;

        for ext in extrinsics.iter() {
            let meta = ext.extrinsic_metadata().map_err(|e| {
                McpError::internal_error(format!("Failed to get extrinsic metadata: {}", e), None)
            })?;

            if meta.pallet.name() == pallet_name && meta.variant.name == call_name {
                let idx = ext.index();
                let fields = ext.field_values().map_err(|e| {
                    McpError::internal_error(format!("Failed to get field values: {}", e), None)
                })?;

                found_extrinsics.push(Content::text(format!(
                    "Extrinsic #{}: {}/{}\n  Fields: {}",
                    idx, pallet_name, call_name, fields
                )));

                // Include associated events
                if let Ok(events) = ext.events().await {
                    for evt in events.iter().flatten() {
                        if let Ok(values) = evt.field_values() {
                            found_extrinsics.push(Content::text(format!(
                                "  Event: {}::{}: {}",
                                evt.pallet_name(),
                                evt.variant_name(),
                                values
                            )));
                        }
                    }
                }
            }
        }

        if found_extrinsics.is_empty() {
            found_extrinsics.push(Content::text(format!(
                "No extrinsics found matching {}/{}",
                pallet_name, call_name
            )));
        }

        Ok(CallToolResult::success(found_extrinsics))
    }

    /// Get basic system information via RPC.
    ///
    /// # Returns
    /// A list of system information.
    #[tool(description = "Get basic system information via RPC")]
    pub async fn get_system_info(&self) -> Result<CallToolResult, McpError> {
        let rpc = self.rpc_methods.lock().await;
        let mut info = Vec::new();

        // Get various system information
        let name = rpc.system_name().await.map_err(|e| {
            McpError::internal_error(format!("Failed to get system name: {}", e), None)
        })?;
        info.push(Content::text(format!("System Name: {}", name)));

        let health = rpc.system_health().await.map_err(|e| {
            McpError::internal_error(format!("Failed to get system health: {}", e), None)
        })?;
        info.push(Content::text(format!("Health: {:?}", health)));

        let chain = rpc
            .system_chain()
            .await
            .map_err(|e| McpError::internal_error(format!("Failed to get chain: {}", e), None))?;
        info.push(Content::text(format!("Chain: {}", chain)));

        let properties = rpc.system_properties().await.map_err(|e| {
            McpError::internal_error(format!("Failed to get system properties: {}", e), None)
        })?;

        properties.iter().for_each(|(key, value)| {
            info.push(Content::text(format!("{}: {}", key, value)));
        });

        Ok(CallToolResult::success(info))
    }

    /// Make a custom RPC call.
    ///
    /// # Parameters
    /// - `method`: RPC method name
    /// - `params`: Optional parameters as a string
    ///
    /// # Returns
    /// The result of the RPC call as a string.
    #[tool(description = "Make a custom RPC call")]
    pub async fn custom_rpc(
        &self,
        #[tool(param)] method: String,
        #[tool(param)] params: Option<String>,
    ) -> Result<CallToolResult, McpError> {
        let rpc_client = self.rpc_client.lock().await;
        let params = params.unwrap_or_default();

        let mut rpc_params = RpcParams::new();
        rpc_params.push(params).map_err(|e| {
            McpError::internal_error(format!("Failed to parse params: {}", e), None)
        })?;

        let result: String = rpc_client
            .request(&method, rpc_params)
            .await
            .map_err(|e| McpError::internal_error(format!("RPC call failed: {}", e), None))?;

        Ok(CallToolResult::success(vec![Content::text(format!(
            "{}: {}",
            method, result
        ))]))
    }
}

#[tool(tool_box)]
impl ServerHandler for SubstrateTool {
    fn get_info(&self) -> ServerInfo {
        ServerInfo {
            protocol_version: ProtocolVersion::V_2024_11_05,
            capabilities: ServerCapabilities::builder()
                .enable_prompts()
                .enable_resources()
                .enable_tools()
                .build(),
            server_info: Implementation::from_build_env(),
            instructions: Some("This server provides Substrate integration tools. You can query account balances using the query_balance tool.".to_string()),
        }
    }

    async fn list_resources(
        &self,
        _request: Option<PaginatedRequestParam>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourcesResult, McpError> {
        Ok(ListResourcesResult {
            resources: vec![],
            next_cursor: None,
        })
    }

    async fn read_resource(
        &self,
        ReadResourceRequestParam { uri }: ReadResourceRequestParam,
        _: RequestContext<RoleServer>,
    ) -> Result<ReadResourceResult, McpError> {
        Err(McpError::resource_not_found(
            "resource_not_found",
            Some(json!({
                "uri": uri
            })),
        ))
    }

    async fn list_prompts(
        &self,
        _request: Option<PaginatedRequestParam>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListPromptsResult, McpError> {
        Ok(ListPromptsResult {
            next_cursor: None,
            prompts: vec![Prompt::new(
                "example_prompt",
                Some("This is an example prompt that takes one required argument, message"),
                Some(vec![PromptArgument {
                    name: "message".to_string(),
                    description: Some("A message to put in the prompt".to_string()),
                    required: Some(true),
                }]),
            )],
        })
    }

    async fn get_prompt(
        &self,
        GetPromptRequestParam { name, arguments }: GetPromptRequestParam,
        _: RequestContext<RoleServer>,
    ) -> Result<GetPromptResult, McpError> {
        match name.as_str() {
            "example_prompt" => {
                let message = arguments
                    .and_then(|json| json.get("message")?.as_str().map(|s| s.to_string()))
                    .ok_or_else(|| {
                        McpError::invalid_params("No message provided to example_prompt", None)
                    })?;

                let prompt =
                    format!("This is an example prompt with your message here: '{message}'");
                Ok(GetPromptResult {
                    description: None,
                    messages: vec![PromptMessage {
                        role: PromptMessageRole::User,
                        content: PromptMessageContent::text(prompt),
                    }],
                })
            }
            _ => Err(McpError::invalid_params("prompt not found", None)),
        }
    }

    async fn list_resource_templates(
        &self,
        _request: Option<PaginatedRequestParam>,
        _: RequestContext<RoleServer>,
    ) -> Result<ListResourceTemplatesResult, McpError> {
        Ok(ListResourceTemplatesResult {
            next_cursor: None,
            resource_templates: Vec::new(),
        })
    }
}
