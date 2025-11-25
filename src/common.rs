use miden_client::{
    Client as MidenClient, ClientError, DebugMode,
    account::{Account, AccountId},
    builder::ClientBuilder,
    keystore::FilesystemKeyStore,
    note::{Note, NoteRelevance},
    rpc::{Endpoint, TonicRpcClient},
    store::{InputNoteRecord, NoteFilter},
};

use miden_objects::account::AccountComponent;
use serde::de::{self, value::Error};

use std::sync::Arc;

type Client = MidenClient<FilesystemKeyStore<rand::prelude::StdRng>>;

// Clears keystore & default sqlite file
pub async fn delete_keystore_and_store() {
    let store_path = "./store.sqlite3";
    if tokio::fs::metadata(store_path).await.is_ok() {
        if let Err(e) = tokio::fs::remove_file(store_path).await {
            eprintln!("failed to remove {}: {}", store_path, e);
        } else {
            println!("cleared sqlite store: {}", store_path);
        }
    } else {
        println!("store not found: {}", store_path);
    }

    let keystore_dir = "./keystore";
    match tokio::fs::read_dir(keystore_dir).await {
        Ok(mut dir) => {
            while let Ok(Some(entry)) = dir.next_entry().await {
                let file_path = entry.path();
                if let Err(e) = tokio::fs::remove_file(&file_path).await {
                    eprintln!("failed to remove {}: {}", file_path.display(), e);
                } else {
                    println!("removed file: {}", file_path.display());
                }
            }
        }
        Err(e) => eprintln!("failed to read directory {}: {}", keystore_dir, e),
    }
}

// Helper to instantiate Client
pub async fn instantiate_client(endpoint: Endpoint) -> Result<Client, ClientError> {
    let timeout_ms = 10_000;
    let rpc_api = Arc::new(TonicRpcClient::new(&endpoint, timeout_ms));

    let client = ClientBuilder::new()
        .rpc(rpc_api.clone())
        .filesystem_keystore("./keystore")
        .in_debug_mode(DebugMode::Enabled)
        .build()
        .await?;

    Ok(client)
}

pub async fn create_multisig_account_component() -> Result<AccountComponent, Error> {
    crate::masm_builder::build_multisig_component(vec![])
        .map_err(|e| de::Error::custom(e.to_string()))
}

// Waits for note
pub async fn wait_for_note(
    client: &mut Client,
    account_id: Option<Account>,
    expected: &Note,
) -> Result<(), ClientError> {
    use tokio::time::{Duration, sleep};

    loop {
        client.sync_state().await?;

        // Notes that can be consumed right now
        let consumable: Vec<(InputNoteRecord, Vec<(AccountId, NoteRelevance)>)> = client
            .get_consumable_notes(account_id.as_ref().map(|acc| acc.id()))
            .await?;

        // Notes submitted that are now committed
        let committed: Vec<InputNoteRecord> = client.get_input_notes(NoteFilter::Committed).await?;

        // Check both vectors
        let found = consumable.iter().any(|(rec, _)| rec.id() == expected.id())
            || committed.iter().any(|rec| rec.id() == expected.id());

        if found {
            println!("✅ note found {}", expected.id().to_hex());
            break;
        }

        println!("Note {} not found. Waiting...", expected.id().to_hex());
        sleep(Duration::from_secs(2)).await;
    }

    Ok(())
}
