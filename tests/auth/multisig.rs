use miden_confidential_contracts::common::create_library;
use miden_lib::account::wallets::BasicWallet;
use miden_objects::account::{
    Account, AccountBuilder, AccountId, AccountStorageMode, AccountType, AuthSecretKey,
};
use miden_objects::asset::FungibleAsset;
use miden_objects::crypto::dsa::rpo_falcon512::{PublicKey, SecretKey};
use miden_objects::note::NoteType;
use miden_objects::testing::account_id::{
    ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET, ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE,
};
use miden_objects::transaction::OutputNote;
use miden_objects::{Felt, Word};
use miden_testing::MockChainBuilder;
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

/// Additions:
use miden_lib::transaction::TransactionKernel;
use miden_objects::{
    account::AccountComponent,
    assembly::{Assembler, Library},
};
use std::{fs, path::Path};

use miden_objects::account::{StorageMap, StorageSlot};

// ================================================================================================
// HELPER FUNCTIONS
// ================================================================================================

type MultisigPlusPsmTestSetup = (
    Vec<SecretKey>,
    Vec<PublicKey>,
    Vec<BasicAuthenticator<ChaCha20Rng>>,
    SecretKey,
    PublicKey,
    BasicAuthenticator<ChaCha20Rng>,
);

pub struct AuthMultisig {
    approvers: Vec<PublicKey>,
    default_threshold: u32,
    proc_threshold_map: Vec<(Word, u32)>,
}

fn setup_keys_and_authenticators_with_psm(
    num_approvers: usize,
    threshold: usize,
) -> anyhow::Result<MultisigPlusPsmTestSetup> {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let mut secret_keys = Vec::new();
    let mut public_keys = Vec::new();
    let mut authenticators = Vec::new();

    for _ in 0..num_approvers {
        let sec_key = SecretKey::with_rng(&mut rng);
        let pub_key = sec_key.public_key();

        secret_keys.push(sec_key);
        public_keys.push(pub_key);
    }

    // Create authenticators only for the signers we'll actually use
    for i in 0..threshold {
        let authenticator = BasicAuthenticator::<ChaCha20Rng>::new_with_rng(
            &[(
                public_keys[i].to_commitment(),
                AuthSecretKey::RpoFalcon512(secret_keys[i].clone()),
            )],
            rng.clone(),
        );
        authenticators.push(authenticator);
    }

    // Create a PSM authenticator (assuming PSM uses a single key for simplicity)
    let psm_sec_key = SecretKey::with_rng(&mut rng);
    let psm_pub_key = psm_sec_key.public_key();
    let psm_authenticator = BasicAuthenticator::<ChaCha20Rng>::new_with_rng(
        &[(
            psm_pub_key.to_commitment(),
            AuthSecretKey::RpoFalcon512(psm_sec_key.clone()),
        )],
        rng,
    );

    Ok((
        secret_keys,
        public_keys,
        authenticators,
        psm_sec_key,
        psm_pub_key,
        psm_authenticator,
    ))
}

fn create_multisig_account_with_psm_public_key(
    multisig: AuthMultisig,
    asset_amount: u64,
    psm_public_key: PublicKey,
    psm_selector: u32,
) -> anyhow::Result<Account> {
    // Create a kernel based assembler for the account components
    let base_asm: Assembler = TransactionKernel::assembler().with_debug_mode(true);

    // Create PSM component
    // Load PSM library
    let psm_code = fs::read_to_string(Path::new("./masm/auth/psm.masm")).unwrap();
    let psm_lib: Library = create_library(psm_code.clone(), "external::psm").unwrap();

    // Create PSM component with the library
    let multisig_asm = base_asm.clone().with_dynamic_library(psm_lib).unwrap();

    // Create PSM component
    let psm_component = AccountComponent::compile(psm_code.clone(), multisig_asm.clone(), vec![])
        .unwrap()
        .with_supports_all_types();

    let multisig_code = fs::read_to_string(Path::new("./masm/auth/multisig.masm")).unwrap();

    // Multisig storage slots
    let mut multisig_slots = Vec::with_capacity(5);
    let num_approvers = multisig.approvers.len() as u32;

    // Slot 0: THRESHOLD_CONFIG_SLOT
    multisig_slots.push(StorageSlot::Value(Word::from([
        multisig.default_threshold,
        num_approvers,
        0,
        0,
    ])));

    // Slot 1: PUBLIC_KEYS_MAP_SLOT
    let map_entries = multisig
        .approvers
        .iter()
        .enumerate()
        .map(|(i, pub_key)| (Word::from([i as u32, 0, 0, 0]), (*pub_key).to_commitment()));

    multisig_slots.push(StorageSlot::Map(
        StorageMap::with_entries(map_entries).unwrap(),
    ));

    // Slot 2: EXECUTED_TXS_SLOT
    multisig_slots.push(StorageSlot::Map(StorageMap::default()));

    // Slot 3: PROC_THRESHOLD_MAP_SLOT
    let proc_threshold_roots = StorageMap::with_entries(
        multisig
            .proc_threshold_map
            .iter()
            .map(|(proc_root, threshold)| (*proc_root, Word::from([*threshold, 0, 0, 0]))),
    )
    .unwrap();
    multisig_slots.push(StorageSlot::Map(proc_threshold_roots));

    // Slot 4: PSM_SELECTOR_SLOT
    multisig_slots.push(StorageSlot::Value(Word::from([psm_selector, 0, 0, 0])));

    // Slot 5: PSM_PUBLIC_KEY_MAP_SLOT
    let map_entries_psm_key = vec![(Word::from([0u32, 0, 0, 0]), psm_public_key.to_commitment())];
    multisig_slots.push(StorageSlot::Map(
        StorageMap::with_entries(map_entries_psm_key).unwrap(),
    ));

    let multisig_component =
        AccountComponent::compile(multisig_code, multisig_asm.clone(), multisig_slots)
            .unwrap()
            .with_supports_all_types();

    let multisig_psm_account = AccountBuilder::new([0; 32])
        .with_auth_component(multisig_component)
        .with_component(psm_component)
        .with_component(BasicWallet)
        .account_type(AccountType::RegularAccountUpdatableCode)
        .storage_mode(AccountStorageMode::Public)
        .with_assets(vec![FungibleAsset::mock(asset_amount)])
        .build_existing()?;

    Ok(multisig_psm_account)
}

// ================================================================================================
// TESTS
// ================================================================================================

/// Tests basic 2-of-2 multisig functionality with note creation.
///
/// This test verifies that a multisig account with 2 approvers and threshold 2
/// can successfully execute a transaction that creates an output note when both
/// required signatures are provided.
///
/// **Roles:**
/// - 2 Approvers (multisig signers)
/// - 1 Multisig Contract
/// - 1 PSM Approver
#[tokio::test]
async fn test_multisig_2_of_2_with_note_creation_with_psm() -> anyhow::Result<()> {
    // Setup keys and authenticators with psm
    let (
        _secret_keys,
        public_keys,
        authenticators,
        _psm_secret_key,
        psm_public_key,
        psm_authenticator,
    ) = setup_keys_and_authenticators_with_psm(2, 2)?;

    // Create multisig account
    let multisig_starting_balance = 10u64;

    // Define multisig configuration
    let multisig = AuthMultisig {
        approvers: public_keys.clone(),
        default_threshold: 2,
        proc_threshold_map: vec![],
    };

    // Create multisig + psm account
    let mut multisig_account = create_multisig_account_with_psm_public_key(
        multisig,
        multisig_starting_balance,
        psm_public_key.clone(),
        1,
    )?;

    let output_note_asset = FungibleAsset::mock(0);

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();

    // Create output note using add_p2id_note for spawn note
    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE
            .try_into()
            .unwrap(),
        &[output_note_asset],
        NoteType::Public,
    )?;

    // Create spawn note that will create the output note
    let input_note = mock_chain_builder.add_spawn_note([&output_note])?;

    let mut mock_chain = mock_chain_builder.build().unwrap();

    let salt = Word::from([Felt::new(1); 4]);

    // Execute transaction without signatures - should fail
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[input_note.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .auth_args(salt)
        .build()?;

    let tx_summary = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    // Get signatures from both approvers
    let msg = tx_summary.as_ref().to_commitment();
    let tx_summary = SigningInputs::TransactionSummary(tx_summary);

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment().into(), &tx_summary)
        .await?;
    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment().into(), &tx_summary)
        .await?;

    // Get signature from psm
    let psm_sig = psm_authenticator
        .get_signature(psm_public_key.to_commitment().into(), &tx_summary)
        .await?;

    // Execute transaction with signatures - should succeed
    let tx_context_execute = mock_chain
        .build_tx_context(multisig_account.id(), &[input_note.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note)])
        .add_signature(public_keys[0].clone().into(), msg, sig_1)
        .add_signature(public_keys[1].clone().into(), msg, sig_2)
        .add_signature(psm_public_key.clone().into(), msg, psm_sig)
        .auth_args(salt)
        .build()?
        .execute()
        .await?;

    multisig_account.apply_delta(tx_context_execute.account_delta())?;

    mock_chain.add_pending_executed_transaction(&tx_context_execute)?;
    mock_chain.prove_next_block()?;

    assert_eq!(
        multisig_account
            .vault()
            .get_balance(AccountId::try_from(ACCOUNT_ID_PUBLIC_FUNGIBLE_FAUCET)?)?,
        multisig_starting_balance - output_note_asset.unwrap_fungible().amount()
    );

    Ok(())
}
