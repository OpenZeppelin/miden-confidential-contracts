use miden_confidential_contracts::masm_builder::{build_multisig_component, build_psm_component};
use miden_lib::account::wallets::BasicWallet;
use miden_lib::note::create_p2id_note;
use miden_lib::utils::ScriptBuilder;
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
use miden_objects::vm::AdviceMap;
use miden_objects::{Felt, Hasher, Word};
use miden_processor::crypto::RpoRandomCoin;
use miden_testing::MockChainBuilder;
use miden_testing::utils::create_spawn_note;
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

use miden_processor::AdviceInputs;
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

type MultisigTestSetup = (
    Vec<SecretKey>,
    Vec<PublicKey>,
    Vec<BasicAuthenticator<ChaCha20Rng>>,
);

type PsmTestSetup = (SecretKey, PublicKey, BasicAuthenticator<ChaCha20Rng>);

/// Sets up secret keys, public keys, and authenticators for multisig testing
fn setup_keys_and_authenticators(
    num_approvers: usize,
    threshold: usize,
) -> anyhow::Result<MultisigTestSetup> {
    let seed: [u8; 32] = rand::random();
    let mut rng = ChaCha20Rng::from_seed(seed);

    let mut secret_keys = Vec::new();
    let mut public_keys = Vec::new();
    let mut authenticators = Vec::new();

    for _ in 0..num_approvers {
        let sec_key = SecretKey::with_rng(&mut rng);
        let pub_key = sec_key.public_key();

        secret_keys.push(sec_key);
        public_keys.push(pub_key);
    }

    // Create authenticators for required signers
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

    Ok((secret_keys, public_keys, authenticators))
}

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

fn setup_keys_and_authenticator_for_psm() -> anyhow::Result<PsmTestSetup> {
    // Change the RNG seed to avoid key collision with other setups!!!
    let mut rng = ChaCha20Rng::from_seed([8u8; 32]);

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

    Ok((psm_sec_key, psm_pub_key, psm_authenticator))
}

fn create_multisig_account_with_psm_public_key(
    multisig: AuthMultisig,
    asset_amount: u64,
    psm_public_key: PublicKey,
    psm_selector: u32,
) -> anyhow::Result<Account> {
    // --- PSM slots ---
    let mut psm_slots = Vec::with_capacity(2);
    psm_slots.push(StorageSlot::Value(Word::from([psm_selector, 0, 0, 0])));

    let map_entries_psm_key = vec![(Word::from([0u32, 0, 0, 0]), psm_public_key.to_commitment())];
    psm_slots.push(StorageSlot::Map(StorageMap::with_entries(
        map_entries_psm_key,
    )?));

    let psm_component = build_psm_component(psm_slots)?;

    // --- Multisig slots (senin mevcut kodun aynen) ---
    let mut multisig_slots = Vec::with_capacity(4);
    let num_approvers = multisig.approvers.len() as u32;

    multisig_slots.push(StorageSlot::Value(Word::from([
        multisig.default_threshold,
        num_approvers,
        0,
        0,
    ])));

    let map_entries = multisig
        .approvers
        .iter()
        .enumerate()
        .map(|(i, pub_key)| (Word::from([i as u32, 0, 0, 0]), (*pub_key).to_commitment()));

    multisig_slots.push(StorageSlot::Map(StorageMap::with_entries(map_entries)?));

    multisig_slots.push(StorageSlot::Map(StorageMap::default()));

    let proc_threshold_roots = StorageMap::with_entries(
        multisig
            .proc_threshold_map
            .iter()
            .map(|(proc_root, threshold)| (*proc_root, Word::from([*threshold, 0, 0, 0]))),
    )?;
    multisig_slots.push(StorageSlot::Map(proc_threshold_roots));

    let multisig_component = build_multisig_component(multisig_slots)?;

    // Account build kısmı senin aynen:
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

/// Tests updating multisig signers and threshold with PSM authentication.
#[tokio::test]
async fn test_multisig_update_signers_with_psm() -> anyhow::Result<()> {
    // This function can be implemented similarly to test_multisig_update_signers,
    // but with the addition of PSM related logic.
    let (
        _secret_keys,
        public_keys,
        authenticators,
        _psm_secret_key,
        psm_public_key,
        psm_authenticator,
    ) = setup_keys_and_authenticators_with_psm(2, 2)?;

    // Define multisig configuration
    let multisig = AuthMultisig {
        approvers: public_keys.clone(),
        default_threshold: 2,
        proc_threshold_map: vec![],
    };

    let multisig_account =
        create_multisig_account_with_psm_public_key(multisig, 10, psm_public_key.clone(), 1)?;

    // SECTION 1: Execute a transaction script to update signers and threshold
    // ================================================================================

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();

    let output_note_asset = FungibleAsset::mock(0);

    // Create output note for spawn note
    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE
            .try_into()
            .unwrap(),
        &[output_note_asset],
        NoteType::Public,
    )?;

    let mut mock_chain = mock_chain_builder.clone().build().unwrap();

    let salt = Word::from([Felt::new(3); 4]);

    // Setup new signers
    let mut advice_map = AdviceMap::default();
    let (_new_secret_keys, new_public_keys, _new_authenticators) =
        setup_keys_and_authenticators(4, 4)?;

    let threshold = 3u64;
    let num_of_approvers = 4u64;

    // Create vector with threshold config and public keys (4 field elements each)
    let mut config_and_pubkeys_vector = Vec::new();
    config_and_pubkeys_vector.extend_from_slice(&[
        Felt::new(threshold),
        Felt::new(num_of_approvers),
        Felt::new(0),
        Felt::new(0),
    ]);

    // Add each public key to the vector
    for public_key in new_public_keys.iter().rev() {
        let key_word: Word = public_key.to_commitment();
        config_and_pubkeys_vector.extend_from_slice(key_word.as_elements());
    }

    // Hash the vector to create config hash
    let multisig_config_hash = Hasher::hash_elements(&config_and_pubkeys_vector);

    // Insert config and public keys into advice map
    advice_map.insert(multisig_config_hash, config_and_pubkeys_vector);

    let psm_code = fs::read_to_string(Path::new("./masm/auth/psm.masm")).unwrap();
    let multisig_code = fs::read_to_string(Path::new("./masm/auth/multisig.masm")).unwrap();

    let tx_script_code = r#"
    use.external::multisig

    begin
        exec.multisig::update_signers_and_threshold
    end
    "#;

    let tx_script = ScriptBuilder::new(true)
        .with_linked_module("external::multisig", multisig_code.clone())?
        .with_linked_module("openzeppelin::psm", psm_code.clone())?
        .compile_tx_script(tx_script_code)?;

    let advice_inputs = AdviceInputs {
        map: advice_map.clone(),
        ..Default::default()
    };

    // Pass the MULTISIG_CONFIG_HASH as the tx_script_args
    let tx_script_args: Word = multisig_config_hash;

    // Execute transaction without signatures first to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script.clone())
        .tx_script_args(tx_script_args)
        .extend_advice_inputs(advice_inputs.clone())
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

    let psm_sig = psm_authenticator
        .get_signature(psm_public_key.to_commitment().into(), &tx_summary)
        .await?;

    // Execute transaction with signatures - should succeed
    let update_approvers_tx = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script)
        .tx_script_args(multisig_config_hash)
        .add_signature(public_keys[0].clone().into(), msg, sig_1)
        .add_signature(public_keys[1].clone().into(), msg, sig_2)
        .add_signature(psm_public_key.clone().into(), msg, psm_sig)
        .auth_args(salt)
        .extend_advice_inputs(advice_inputs)
        .build()?
        .execute()
        .await
        .unwrap();

    // Verify the transaction executed successfully
    assert_eq!(
        update_approvers_tx.account_delta().nonce_delta(),
        Felt::new(1)
    );

    mock_chain.add_pending_executed_transaction(&update_approvers_tx)?;
    mock_chain.prove_next_block()?;

    // Apply the delta to get the updated account with new signers
    let mut updated_multisig_account = multisig_account.clone();
    updated_multisig_account.apply_delta(update_approvers_tx.account_delta())?;

    // Verify that the public keys were actually updated in storage
    for (i, expected_key) in new_public_keys.iter().enumerate() {
        let storage_key = [
            Felt::new(i as u64),
            Felt::new(0),
            Felt::new(0),
            Felt::new(0),
        ]
        .into();
        let storage_item = updated_multisig_account
            .storage()
            .get_map_item(1, storage_key)
            .unwrap();

        let expected_word: Word = expected_key.to_commitment();

        assert_eq!(
            storage_item, expected_word,
            "Public key {} doesn't match expected value",
            i
        );
    }

    // Verify the threshold was updated by checking storage slot 0
    let threshold_config_storage = updated_multisig_account.storage().get_item(0).unwrap();

    assert_eq!(
        threshold_config_storage[0],
        Felt::new(threshold),
        "Threshold was not updated correctly"
    );
    assert_eq!(
        threshold_config_storage[1],
        Felt::new(num_of_approvers),
        "Num approvers was not updated correctly"
    );

    // SECTION 2: Create a second transaction signed by the new owners
    // ================================================================================

    // Now test creating a note with the new signers
    // Setup authenticators for the new signers (we need 3 out of 4 for threshold 3)
    let mut new_authenticators = Vec::new();
    for i in 0..3 {
        let authenticator = BasicAuthenticator::<ChaCha20Rng>::new_with_rng(
            &[(
                new_public_keys[i].to_commitment(),
                AuthSecretKey::RpoFalcon512(_new_secret_keys[i].clone()),
            )],
            ChaCha20Rng::from_seed([0u8; 32]),
        );
        new_authenticators.push(authenticator);
    }

    // Create a new output note for the second transaction with new signers
    let output_note_new = create_p2id_note(
        updated_multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE
            .try_into()
            .unwrap(),
        vec![output_note_asset],
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::empty()),
    )?;

    // Create a new spawn note for the second transaction
    let input_note_new = create_spawn_note([&output_note_new])?;

    let salt_new = Word::from([Felt::new(4); 4]);

    // Build the new mock chain with the updated account and notes
    let mut new_mock_chain_builder =
        MockChainBuilder::with_accounts([updated_multisig_account.clone()]).unwrap();
    new_mock_chain_builder.add_output_note(OutputNote::Full(input_note_new.clone()));
    let new_mock_chain = new_mock_chain_builder.build().unwrap();

    // Execute transaction without signatures first to get tx summary
    let tx_context_init_new = new_mock_chain
        .build_tx_context(updated_multisig_account.id(), &[input_note_new.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .auth_args(salt_new)
        .build()?;

    let tx_summary_new = match tx_context_init_new.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    // Get signatures from 3 of the 4 new approvers (threshold is 3)
    let msg_new = tx_summary_new.as_ref().to_commitment();
    let tx_summary_new = SigningInputs::TransactionSummary(tx_summary_new);

    let sig_1_new = new_authenticators[0]
        .get_signature(new_public_keys[0].to_commitment().into(), &tx_summary_new)
        .await?;
    let sig_2_new = new_authenticators[1]
        .get_signature(new_public_keys[1].to_commitment().into(), &tx_summary_new)
        .await?;
    let sig_3_new = new_authenticators[2]
        .get_signature(new_public_keys[2].to_commitment().into(), &tx_summary_new)
        .await?;
    let psm_sig = psm_authenticator
        .get_signature(psm_public_key.to_commitment().into(), &tx_summary_new)
        .await?;

    // SECTION 3: Properly handle multisig authentication with the updated signers
    // ================================================================================

    // Execute transaction with new signatures - should succeed
    let tx_context_execute_new = new_mock_chain
        .build_tx_context(updated_multisig_account.id(), &[input_note_new.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note_new)])
        .add_signature(new_public_keys[0].clone().into(), msg_new, sig_1_new)
        .add_signature(new_public_keys[1].clone().into(), msg_new, sig_2_new)
        .add_signature(new_public_keys[2].clone().into(), msg_new, sig_3_new)
        .add_signature(psm_public_key.clone().into(), msg_new, psm_sig)
        .auth_args(salt_new)
        .build()?
        .execute()
        .await?;

    // Verify the transaction executed successfully with new signers
    assert_eq!(
        tx_context_execute_new.account_delta().nonce_delta(),
        Felt::new(1)
    );

    Ok(())
}

/// Tests psm public key update functionality.
///
/// This test verifies that a multisig account can:
/// 1. Execute a transaction script to update the psm public key without needing a psm signature
/// 2. Create a second transaction signed by the new psm public key
/// 3. Properly handle multisig psm authentication with the updated psm public key.
///
/// **Roles:**
/// - 2 Original Approvers (multisig signers)
/// - 1 PSM Approver
/// - 1 Multisig Contract
/// - 1 Transaction Script calling the update_psm_public_key procedure
#[tokio::test]
async fn test_multisig_update_psm_public_key() -> anyhow::Result<()> {
    let (
        _secret_keys,
        public_keys,
        authenticators,
        _psm_secret_key,
        psm_public_key,
        _psm_authenticator,
    ) = setup_keys_and_authenticators_with_psm(2, 2)?;

    // Define multisig configuration
    let multisig = AuthMultisig {
        approvers: public_keys.clone(),
        default_threshold: 2,
        proc_threshold_map: vec![],
    };

    let multisig_account =
        create_multisig_account_with_psm_public_key(multisig, 10, psm_public_key.clone(), 1)?;

    // SECTION 1: Execute a transaction script to update PSM public key
    // ================================================================================

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([multisig_account.clone()]).unwrap();

    let output_note_asset = FungibleAsset::mock(0);

    // Create output note for spawn note
    let output_note = mock_chain_builder.add_p2id_note(
        multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE
            .try_into()
            .unwrap(),
        &[output_note_asset],
        NoteType::Public,
    )?;

    let mut mock_chain = mock_chain_builder.clone().build().unwrap();

    let salt = Word::from([Felt::new(3); 4]);

    // Setup New PSM Public Key
    let mut advice_inputs = AdviceInputs::default();
    let (_new_psm_secret_key, _new_psm_public_key, _new_psm_authenticatior) =
        setup_keys_and_authenticator_for_psm()?;

    // Add new psm public key to advice inputs
    advice_inputs
        .stack
        .extend_from_slice(_new_psm_public_key.to_commitment().as_elements());

    let psm_code = fs::read_to_string(Path::new("./masm/auth/psm.masm")).unwrap();
    let multisig_code = fs::read_to_string(Path::new("./masm/auth/multisig.masm")).unwrap();

    let tx_script_code = r#"
    use.openzeppelin::psm

    begin
        call.psm::update_psm_public_key
    end
    "#;

    let tx_script = ScriptBuilder::new(true)
        .with_linked_module("external::multisig", multisig_code.clone())?
        .with_linked_module("openzeppelin::psm", psm_code.clone())?
        .compile_tx_script(tx_script_code)?;

    // Execute transaction without signatures first to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script.clone())
        .extend_advice_inputs(advice_inputs.clone())
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

    // Execute transaction with signatures without a need of the PSM signature! - should succeed
    let update_psm_public_key_tx = mock_chain
        .build_tx_context(multisig_account.id(), &[], &[])?
        .tx_script(tx_script)
        .add_signature(public_keys[0].clone().into(), msg, sig_1)
        .add_signature(public_keys[1].clone().into(), msg, sig_2)
        .auth_args(salt)
        .extend_advice_inputs(advice_inputs)
        .build()?
        .execute()
        .await
        .unwrap();

    // Verify the transaction executed successfully
    assert_eq!(
        update_psm_public_key_tx.account_delta().nonce_delta(),
        Felt::new(1)
    );

    mock_chain.add_pending_executed_transaction(&update_psm_public_key_tx)?;
    mock_chain.prove_next_block()?;

    // Apply the delta to get the updated account with new psm public key
    let mut updated_multisig_account = multisig_account.clone();
    updated_multisig_account.apply_delta(update_psm_public_key_tx.account_delta())?;

    let storage_key = [Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0)].into();

    // Verify the psm public key was actually updated in storage
    let storage_item = updated_multisig_account
        .storage()
        .get_map_item(5, storage_key)
        .unwrap();

    let expected_word: Word = _new_psm_public_key.to_commitment();

    println!("Expected PSM Public Key: {:?}", expected_word);
    println!("Stored PSM Public Key:   {:?}", storage_item);

    assert_eq!(
        storage_item, expected_word,
        "PSM Public key doesn't match expected value"
    );

    // SECTION 2: Create a second transaction signed by the new PSM public key
    // Now test creating a note with the new psm public key
    // Create a new output note for the second transaction with new psm public key
    let output_note_new = create_p2id_note(
        updated_multisig_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE
            .try_into()
            .unwrap(),
        vec![output_note_asset],
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::empty()),
    )?;

    // Create a new spawn note for the second transaction
    let input_note_new = create_spawn_note([&output_note_new])?;
    let salt_new = Word::from([Felt::new(4); 4]);

    // Build the new mock chain with the updated account and notes
    let mut new_mock_chain_builder =
        MockChainBuilder::with_accounts([updated_multisig_account.clone()]).unwrap();
    new_mock_chain_builder.add_output_note(OutputNote::Full(input_note_new.clone()));
    let new_mock_chain = new_mock_chain_builder.build().unwrap();

    // Execute transaction without signatures first to get tx summary
    let tx_context_init_new = new_mock_chain
        .build_tx_context(updated_multisig_account.id(), &[input_note_new.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .auth_args(salt_new)
        .build()?;

    let tx_summary_new = match tx_context_init_new.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    // Get signatures from approvers
    let msg_new = tx_summary_new.as_ref().to_commitment();
    let tx_summary_new = SigningInputs::TransactionSummary(tx_summary_new);

    let sig_1_new = authenticators[0]
        .get_signature(public_keys[0].to_commitment().into(), &tx_summary_new)
        .await?;
    let sig_2_new = authenticators[1]
        .get_signature(public_keys[1].to_commitment().into(), &tx_summary_new)
        .await?;
    // Get signature from new psm public key
    let psm_sig_new = _new_psm_authenticatior
        .get_signature(_new_psm_public_key.to_commitment().into(), &tx_summary_new)
        .await?;

    assert_ne!(
        _new_psm_public_key.to_commitment(),
        public_keys[0].to_commitment(),
        "PSM public key MUST NOT equal any multisig signer key in this test"
    );

    // SECTION 3: Properly handle multisig PSM authentication with the updated PSM public key
    // Execute transaction with new psm public key - should succeed
    // ================================================================================
    let tx_context_execute_new = new_mock_chain
        .build_tx_context(updated_multisig_account.id(), &[input_note_new.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note_new)])
        .add_signature(public_keys[0].clone().into(), msg_new, sig_1_new)
        .add_signature(public_keys[1].clone().into(), msg_new, sig_2_new)
        .add_signature(_new_psm_public_key.clone().into(), msg_new, psm_sig_new)
        .auth_args(salt_new)
        .build()?
        .execute()
        .await?;

    // Verify the transaction executed successfully with new PSM public key
    assert_eq!(
        tx_context_execute_new.account_delta().nonce_delta(),
        Felt::new(1)
    );

    Ok(())
}
