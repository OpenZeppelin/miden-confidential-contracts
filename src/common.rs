use miden_client::{
    Client as MidenClient, ClientError, DebugMode,
    account::{Account, AccountId},
    builder::ClientBuilder,
    keystore::FilesystemKeyStore,
    note::{Note, NoteRelevance},
    rpc::{Endpoint, TonicRpcClient},
    store::{InputNoteRecord, NoteFilter},
};

use miden_lib::transaction::TransactionKernel;
use miden_objects::{
    account::AccountComponent,
    assembly::{Assembler, DefaultSourceManager, Library, LibraryPath, Module, ModuleKind},
};

use serde::de::value::Error;
use std::{fs, path::Path, sync::Arc};

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

// Creates library
pub fn create_library(
    account_code: String,
    library_path: &str,
) -> Result<Library, Box<dyn std::error::Error>> {
    let assembler: Assembler = TransactionKernel::assembler().with_debug_mode(true);
    let source_manager = Arc::new(DefaultSourceManager::default());
    let module = Module::parser(ModuleKind::Library).parse_str(
        LibraryPath::new(library_path)?,
        account_code,
        &source_manager,
    )?;
    let library = assembler.clone().assemble_library([module])?;
    Ok(library)
}

pub async fn create_multisig_account_component() -> Result<AccountComponent, Error> {
    let assembler: Assembler = TransactionKernel::assembler().with_debug_mode(true);
    let multisig_code = fs::read_to_string(Path::new("./masm/auth/multisig.masm")).unwrap();
    let multisig_component = AccountComponent::compile(multisig_code, assembler.clone(), vec![])
        .unwrap()
        .with_supports_all_types();

    Ok(multisig_component)
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
