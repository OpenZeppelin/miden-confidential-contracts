use miden_confidential_contracts::masm_builder::{get_timelocked_account_library, get_psm_library};
use miden_confidential_contracts::timelocked_account::{
    TimelockedAccountBuilder, TimelockedAccountConfig
};
use miden_lib::errors::MasmError;
use miden_lib::note::create_p2id_note;
use miden_lib::utils::ScriptBuilder;
use miden_objects::account::Account;
use miden_objects::account::auth::{AuthSecretKey, PublicKey, PublicKeyCommitment};
use miden_objects::asset::FungibleAsset;
use miden_objects::crypto::rand::RpoRandomCoin;
use miden_objects::note::NoteType;
use miden_objects::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
use miden_objects::transaction::OutputNote;
use miden_objects::vm::{AdviceInputs, AdviceMap};
use miden_objects::{Felt, Hasher, Word};
use miden_testing::{MockChainBuilder, assert_transaction_executor_error};
use miden_testing::utils::create_spawn_note;
use miden_tx::TransactionExecutorError;
use miden_tx::auth::{BasicAuthenticator, SigningInputs, TransactionAuthenticator};
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

// ================================================================================================
// HELPER FUNCTIONS
// ================================================================================================

type TimelockedAccountTestSetup = (
    Vec<AuthSecretKey>,
    Vec<PublicKey>,
    Vec<BasicAuthenticator>,
    AuthSecretKey,
    PublicKey,
    BasicAuthenticator,
);

type PureTimelockedAccountTestSetup = (Vec<AuthSecretKey>, Vec<PublicKey>, Vec<BasicAuthenticator>);
type PsmTestSetup = (AuthSecretKey, PublicKey, BasicAuthenticator);

// Setup keys and authenticators for a timelocked account
// Num approvers has to be equal to 2
// 1 approver is primary key for the timelocked account
// 1 approver is secondary key for the timelocked account
fn setup_keys_and_authenticators_without_psm()
-> anyhow::Result<PureTimelockedAccountTestSetup> {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let mut secret_keys = Vec::new();
    let mut public_keys = Vec::new();
    let mut authenticators = Vec::new();

    for _ in 0..2 {
        let sec_key = AuthSecretKey::new_rpo_falcon512_with_rng(&mut rng);
        let pub_key = sec_key.public_key();

        secret_keys.push(sec_key);
        public_keys.push(pub_key);
    }

    // Create authenticators for all approvers!
    for secret_key in secret_keys.iter().take(2) {
        let authenticator = BasicAuthenticator::new(core::slice::from_ref(secret_key));
        authenticators.push(authenticator);
    }

    Ok((
        secret_keys,
        public_keys,
        authenticators,
    ))
}

// Setup keys and authenticators for a timelocked account
// Num approvers has to be equal to 2
// 1 approver is primary key for the timelocked account
// 1 approver is secondary key for the timelocked account
// PSM key is separate
fn setup_keys_and_authenticators_for_timelocked_account()
-> anyhow::Result<TimelockedAccountTestSetup> {
    let mut rng = ChaCha20Rng::from_seed([0u8; 32]);

    let mut secret_keys = Vec::new();
    let mut public_keys = Vec::new();
    let mut authenticators = Vec::new();

    for _ in 0..2 {
        let sec_key = AuthSecretKey::new_rpo_falcon512_with_rng(&mut rng);
        let pub_key = sec_key.public_key();

        secret_keys.push(sec_key);
        public_keys.push(pub_key);
    }

    // Create authenticators for all approvers!
    for secret_key in secret_keys.iter().take(2) {
        let authenticator = BasicAuthenticator::new(core::slice::from_ref(secret_key));
        authenticators.push(authenticator);
    }

    // Create a PSM authenticator
    let psm_sec_key = AuthSecretKey::new_rpo_falcon512_with_rng(&mut rng);
    let psm_pub_key = psm_sec_key.public_key();
    let psm_authenticator = BasicAuthenticator::new(core::slice::from_ref(&psm_sec_key));

    Ok((
        secret_keys,
        public_keys,
        authenticators,
        psm_sec_key,
        psm_pub_key,
        psm_authenticator,
    ))
}

// Setup keys and authenticator for PSM only
fn setup_keys_and_authenticator_for_psm() -> anyhow::Result<PsmTestSetup> {
    // Change the RNG seed to avoid key collision with other setups!!!
    let mut rng = ChaCha20Rng::from_seed([8u8; 32]);

    // Create a PSM authenticator (assuming PSM uses a single key for simplicity)
    let psm_sec_key = AuthSecretKey::new_rpo_falcon512_with_rng(&mut rng);
    let psm_pub_key = psm_sec_key.public_key();
    let psm_authenticator = BasicAuthenticator::new(core::slice::from_ref(&psm_sec_key));

    Ok((psm_sec_key, psm_pub_key, psm_authenticator))
}

// Create a timelocked account
// Threshold is 1 (only primary/secondary key is needed to sign)
// Public keys are the approver keys (primary and secondary keys)
// PSM public key is the PSM approver key
fn create_timelocked_account(
    public_keys: &[PublicKey],
    psm_public_key: PublicKey,
    psm_enabled: bool,
) -> anyhow::Result<Account> {
    let signer_commitments: Vec<PublicKeyCommitment> =
        public_keys.iter().map(|pk| pk.to_commitment()).collect();
    let psm_commitment = psm_public_key.to_commitment();

    let config = TimelockedAccountConfig::new(
        signer_commitments[0],
        signer_commitments[1],
        psm_commitment,
        0,
    )
    .with_psm_enabled(psm_enabled);

    TimelockedAccountBuilder::new(config).build_existing()
}

// Create a timelocked account with delay
fn create_timelocked_account_with_delay(
    public_keys: &[PublicKey],
    psm_public_key: PublicKey,
    psm_enabled: bool,
    num_delay_blocks: u32,
) -> anyhow::Result<Account> {
    let signer_commitments: Vec<PublicKeyCommitment> =
        public_keys.iter().map(|pk| pk.to_commitment()).collect();
    let psm_commitment = psm_public_key.to_commitment();

    let config = TimelockedAccountConfig::new(
        signer_commitments[0],
        signer_commitments[1],
        psm_commitment,
        num_delay_blocks,
    )
    .with_psm_enabled(psm_enabled);

    TimelockedAccountBuilder::new(config).build_existing()
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
// Signature requirement changed to 1-of-2 for timelocked account
// Sign with only primary key for this test
async fn test_timelocked_account_with_note_creation_sign_with_primary_key() -> anyhow::Result<()> {
    // Setup keys and authenticators with psm
    let (
        _secret_keys,
        public_keys,
        authenticators,
        _psm_secret_key,
        psm_public_key,
        psm_authenticator,
    ) = setup_keys_and_authenticators_for_timelocked_account()?;

    // Create timelocked account with PSM enabled
    let mut timelocked_account =
        create_timelocked_account(&public_keys, psm_public_key.clone(), true)?;

    let output_note_asset = FungibleAsset::mock(0);

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([timelocked_account.clone()]).unwrap();

    // Create output note using add_p2id_note for spawn note
    let output_note = mock_chain_builder.add_p2id_note(
        timelocked_account.id(),
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
        .build_tx_context(timelocked_account.id(), &[input_note.id()], &[])?
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
        .get_signature(public_keys[0].to_commitment(), &tx_summary)
        .await?;

    // Get signature from psm
    let psm_sig = psm_authenticator
        .get_signature(psm_public_key.to_commitment(), &tx_summary)
        .await?;

    // Execute transaction with a signature from primary key - should succeed
    let tx_context_execute = mock_chain
        .build_tx_context(timelocked_account.id(), &[input_note.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note)])
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(psm_public_key.to_commitment(), msg, psm_sig)
        .auth_args(salt)
        .build()?
        .execute()
        .await?;

    timelocked_account.apply_delta(tx_context_execute.account_delta())?;

    mock_chain.add_pending_executed_transaction(&tx_context_execute)?;
    mock_chain.prove_next_block()?;

    // Verify the transaction executed successfully (balance check removed since we don't preload assets)
    Ok(())
}

#[tokio::test]
// Signature requirement changed to 1-of-2 for timelocked account
// Sign with only secondary key for this test
async fn test_timelocked_account_with_note_creation_sign_with_secondary_key() -> anyhow::Result<()>
{
    // Setup keys and authenticators with psm
    let (
        _secret_keys,
        public_keys,
        authenticators,
        _psm_secret_key,
        psm_public_key,
        psm_authenticator,
    ) = setup_keys_and_authenticators_for_timelocked_account()?;

    // Create timelocked account with PSM enabled
    let mut timelocked_account =
        create_timelocked_account(&public_keys, psm_public_key.clone(), true)?;

    let output_note_asset = FungibleAsset::mock(0);

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([timelocked_account.clone()]).unwrap();

    // Create output note using add_p2id_note for spawn note
    let output_note = mock_chain_builder.add_p2id_note(
        timelocked_account.id(),
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
        .build_tx_context(timelocked_account.id(), &[input_note.id()], &[])?
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

    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary)
        .await?;

    // Get signature from psm
    let psm_sig = psm_authenticator
        .get_signature(psm_public_key.to_commitment(), &tx_summary)
        .await?;

    // Execute transaction with a signature from primary key - should succeed
    let tx_context_execute = mock_chain
        .build_tx_context(timelocked_account.id(), &[input_note.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note)])
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
        .add_signature(psm_public_key.to_commitment(), msg, psm_sig)
        .auth_args(salt)
        .build()?
        .execute()
        .await?;

    timelocked_account.apply_delta(tx_context_execute.account_delta())?;

    mock_chain.add_pending_executed_transaction(&tx_context_execute)?;
    mock_chain.prove_next_block()?;

    // Verify the transaction executed successfully (balance check removed since we don't preload assets)
    Ok(())
}

/// Tests psm public key update functionality.
///
/// This test verifies that a timelocked account can:
/// 1. Execute a transaction script with one signature to update the PSM public key - should fail
/// 2. Execute a transaction script to update the psm public key without needing a psm signature
///     with a threshold of 2 (both primary and secondary keys must sign) - should succeed.
/// 3. Create a second transaction signed by the new psm public key
/// 4. Properly handle timelocked psm authentication with the updated psm public key.
///
/// **Roles:**
/// - 1 Primary Key Approver
/// - 1 Secondary Key Approver
/// - 1 PSM Approver
/// - 1 Timelocked Account Contract
/// - 1 Transaction Script calling the update_psm_public_key procedure
#[tokio::test]
async fn test_timelocked_account_update_psm_public_key() -> anyhow::Result<()> {
    let (
        _secret_keys,
        public_keys,
        authenticators,
        _psm_secret_key,
        psm_public_key,
        _psm_authenticator,
    ) = setup_keys_and_authenticators_for_timelocked_account()?;

    // Initialize with PSM selector = OFF so key update doesn't require PSM signature
    // This is the expected flow: disable PSM, update key, then enable PSM in a follow-up tx
    let timelocked_account =
        create_timelocked_account(&public_keys, psm_public_key.clone(), true)?;

    // SECTION 1: Execute a transaction script to update PSM public key
    // ================================================================================

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([timelocked_account.clone()]).unwrap();

    let output_note_asset = FungibleAsset::mock(0);

    // Create output note for spawn note
    let output_note = mock_chain_builder.add_p2id_note(
        timelocked_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE
            .try_into()
            .unwrap(),
        &[output_note_asset],
        NoteType::Public,
    )?;

    let mut mock_chain = mock_chain_builder.clone().build().unwrap();

    let salt = Word::from([Felt::new(3); 4]);

    // Setup New PSM Public Key
    let (_new_psm_secret_key, _new_psm_public_key, _new_psm_authenticatior) =
        setup_keys_and_authenticator_for_psm()?;

    // Add new psm public key to advice inputs
    let new_psm_key_word: Word = _new_psm_public_key.to_commitment().into();
    let advice_inputs = AdviceInputs::default().with_stack(
        new_psm_key_word
            .as_elements()
            .iter()
            .copied(),
    );

    // Build the PSM library for transaction script
    let psm_library = get_psm_library()?;

    // Use call.:: syntax for dynamically linked library procedure calls (v0.12+)
    // This script updates the PSM key and then enables PSM verification
    let tx_script_code = r#"
    begin
        call.::update_psm_public_key
    end
    "#;

    let tx_script = ScriptBuilder::new(true)
        .with_dynamically_linked_library(&psm_library)?
        .compile_tx_script(tx_script_code)?;

    // Execute transaction without signatures first to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(timelocked_account.id(), &[], &[])?
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
        .get_signature(public_keys[0].to_commitment(), &tx_summary)
        .await?;

    // Execute transaction with only one signature - should fail
    let failed_update_psm_public_key_err = mock_chain
        .build_tx_context(timelocked_account.id(), &[], &[])?
        .tx_script(tx_script)
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .auth_args(salt)
        .extend_advice_inputs(advice_inputs)
        .build()?
        .execute()
        .await
        .expect_err("tx with only one signature must be Unauthorized");

    assert!(matches!(
        failed_update_psm_public_key_err,
        TransactionExecutorError::Unauthorized(_)
    ));

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary)
        .await?;

    let sig_2 = authenticators[1]
        .get_signature(public_keys[1].to_commitment(), &tx_summary)
        .await?;

    let new_tx_script = ScriptBuilder::new(true)
        .with_dynamically_linked_library(&psm_library)?
        .compile_tx_script(tx_script_code)?;

    let advice_inputs = AdviceInputs::default().with_stack(
        new_psm_key_word
            .as_elements()
            .iter()
            .copied(),
    );

    // Execute transaction with both signatures - should succeed
    let update_psm_public_key_tx = mock_chain
        .build_tx_context(timelocked_account.id(), &[], &[])?
        .tx_script(new_tx_script)
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(public_keys[1].to_commitment(), msg, sig_2)
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
    let mut updated_timelocked_account = timelocked_account.clone();
    updated_timelocked_account.apply_delta(update_psm_public_key_tx.account_delta())?;

    let storage_key = [Felt::new(0), Felt::new(0), Felt::new(0), Felt::new(0)].into();

    // Verify the psm public key was actually updated in storage
    // Storage slot 7 is the PSM public key map:
    // 5 from timelocked account storage layout
    // 2 from psm storage layout
    let storage_item = updated_timelocked_account
        .storage()
        .get_map_item(7, storage_key)
        .unwrap();

    let expected_word: Word = _new_psm_public_key.to_commitment().into();

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
        updated_timelocked_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE
            .try_into()
            .unwrap(),
        vec![output_note_asset],
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::default()),
    )?;

    // Create a new spawn note for the second transaction
    let input_note_new = create_spawn_note([&output_note_new])?;
    let salt_new = Word::from([Felt::new(2); 4]);

    // Build the new mock chain with the updated account and notes
    let mut new_mock_chain_builder =
        MockChainBuilder::with_accounts([updated_timelocked_account.clone()]).unwrap();
    new_mock_chain_builder.add_output_note(OutputNote::Full(input_note_new.clone()));
    let new_mock_chain = new_mock_chain_builder.build().unwrap();

    // Execute transaction without signatures first to get tx summary
    let tx_context_init_new = new_mock_chain
        .build_tx_context(updated_timelocked_account.id(), &[input_note_new.id()], &[])?
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
        .get_signature(public_keys[0].to_commitment(), &tx_summary_new)
        .await?;

    // Get signature from new psm public key
    let psm_sig_new = _new_psm_authenticatior
        .get_signature(_new_psm_public_key.to_commitment(), &tx_summary_new)
        .await?;

    assert_ne!(
        _new_psm_public_key.to_commitment(),
        public_keys[0].to_commitment(),
        "PSM public key MUST NOT equal any multisig signer key in this test"
    );

    // SECTION 3: Procedures which are not update psm key require PSM signature
    // Execute transaction without a psm signature - should fail
    let failed_tx_without_psm_sig = new_mock_chain
        .build_tx_context(updated_timelocked_account.id(), &[input_note_new.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note_new.clone())])
        .add_signature(public_keys[0].to_commitment(), msg_new, sig_1_new)
        .auth_args(salt_new)
        .build()?
        .execute()
        .await
        .expect_err("tx without psm signature must be Unauthorized");

    assert!(matches!(
        failed_tx_without_psm_sig,
        TransactionExecutorError::Unauthorized(_)
    ));

    let sig_1_new = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_new)
        .await?;

    // SECTION 4: Properly handle multisig PSM authentication with the updated PSM public key
    // Execute transaction with new psm public key - should succeed
    // ================================================================================
    let tx_context_execute_new = new_mock_chain
        .build_tx_context(updated_timelocked_account.id(), &[input_note_new.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note_new)])
        .add_signature(public_keys[0].to_commitment(), msg_new, sig_1_new)
        .add_signature(_new_psm_public_key.to_commitment(), msg_new, psm_sig_new)
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

/// Tests psm public key update functionality.
///
/// This test verifies that a timelocked account can:
/// 1. Execute a transaction script to propose key (either primary or secondary) rotation with one signature - should succeed
/// 2. Early attempt to execute key rotation with only one signature - should fail
/// 3. Execute a successful transaction script to execute key rotation with one signature - should succeed
/// 4. Create a second transaction signed by the new owners
/// 5. Properly handle timelocked authentication with the new signer
///
/// **Roles:**
/// - 1 (Primary Key) Approver
/// - 1 (Secondary Key) Approver
/// - 1 (New Primary Key) Approver
/// - 1 (PSM) Approver
/// - 1 Timelocked Account Contract
/// - 1 Transaction Script calling the propose_key_rotation procedure
/// - 1 Transaction Script calling the execute_key_rotation procedure
#[tokio::test]
async fn test_timelocked_account_propose_execute_key_rotation() -> anyhow::Result<()> {
    let (
        _secret_keys,
        public_keys,
        authenticators,
        _psm_secret_key,
        psm_public_key,
        _psm_authenticator,
    ) = setup_keys_and_authenticators_for_timelocked_account()?;

    // Initialize with PSM selector = OFF so key update doesn't require PSM signature
    // This is the expected flow: disable PSM, update key, then enable PSM in a follow-up tx
    let num_delay_blocks = 10u32;
    let timelocked_account = create_timelocked_account_with_delay(&public_keys, psm_public_key.clone(), true, num_delay_blocks)?;

    // SECTION 1: Execute a transaction script to propose key (either primary or secondary) rotation 
    // with one signature - should succeed
    // ================================================================================

    let mut mock_chain_builder =
        MockChainBuilder::with_accounts([timelocked_account.clone()]).unwrap();

    let output_note_asset = FungibleAsset::mock(0);

    // Create output note for spawn note
    let output_note = mock_chain_builder.add_p2id_note(
        timelocked_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE
            .try_into()
            .unwrap(),
        &[output_note_asset],
        NoteType::Public,
    )?;

    let mut mock_chain = mock_chain_builder.clone().build().unwrap();
    mock_chain.prove_until_block(2)?;
    let salt = Word::from([Felt::new(3); 4]);

    // Setup new signers
    let mut advice_map = AdviceMap::default();
    let (_new_secret_keys, new_public_keys, _new_authenticators) =
        setup_keys_and_authenticators_without_psm()?;

    let threshold = 1u64;
    let num_of_approvers = 2u64;

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
        let key_word: Word = public_key.to_commitment().into();
        config_and_pubkeys_vector.extend_from_slice(key_word.as_elements());
    }

    // Hash the vector to create config hash
    let timelocked_account_config_hash = Hasher::hash_elements(&config_and_pubkeys_vector);

    // Insert config and public keys into advice map
    advice_map.insert(timelocked_account_config_hash, config_and_pubkeys_vector);

    // Build the multisig library for transaction script
    let timelocked_account_library = get_timelocked_account_library()?;

    // Use call.:: syntax for dynamically linked library procedure calls (v0.12+)
    let tx_script_code = r#"
    begin
        call.::propose_key_rotation
    end
    "#;

    let tx_script = ScriptBuilder::new(true)
        .with_dynamically_linked_library(&timelocked_account_library)?
        .compile_tx_script(tx_script_code)?;

    let advice_inputs = AdviceInputs::default()
        .with_map(advice_map.clone().into_iter().map(|(k, v)| (k, v.to_vec())));

    // Pass the MULTISIG_CONFIG_HASH as the tx_script_args
    let tx_script_args: Word = timelocked_account_config_hash;

    // Execute transaction without signatures first to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(timelocked_account.id(), &[], &[])?
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
        .get_signature(public_keys[0].to_commitment(), &tx_summary)
        .await?;

    let psm_sig = _psm_authenticator
        .get_signature(psm_public_key.to_commitment(), &tx_summary)
        .await?;

    // Execute transaction with signatures - should succeed
    let propose_key_rotation_tx = mock_chain
        .build_tx_context(timelocked_account.id(), &[], &[])?
        .tx_script(tx_script)
        .tx_script_args(timelocked_account_config_hash)
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(psm_public_key.to_commitment(), msg, psm_sig)
        .auth_args(salt)
        .extend_advice_inputs(advice_inputs.clone())
        .build()?
        .execute()
        .await
        .unwrap();

    // Verify the transaction executed successfully
    assert_eq!(
        propose_key_rotation_tx.account_delta().nonce_delta(),
        Felt::new(1)
    );

    mock_chain.add_pending_executed_transaction(&propose_key_rotation_tx)?;
    mock_chain.prove_next_block()?;

    // Apply the delta to get the updated account with new signers
    let mut updated_timelocked_account = timelocked_account.clone();
    updated_timelocked_account.apply_delta(propose_key_rotation_tx.account_delta())?;


    // SECTION 2: Early attempt to execute key rotation with only one signature - should fail
    // ================================================================================

    let tx_script_code = r#"
    begin
        call.::execute_key_rotation
    end
    "#;

    let tx_script = ScriptBuilder::new(true)
        .with_dynamically_linked_library(&timelocked_account_library)?
        .compile_tx_script(tx_script_code)?;

    let early_attempt_block = num_delay_blocks - 1;
    
    mock_chain.prove_until_block(early_attempt_block)?;

    // Execute transaction should fail due to timelock
    let early_execute_err = mock_chain
        .build_tx_context_at(early_attempt_block, timelocked_account.id(), &[], &[])?
        .tx_script(tx_script.clone())
        .tx_script_args(tx_script_args)
        .extend_advice_inputs(advice_inputs.clone())
        .auth_args(salt)
        .build()?
        .execute()
        .await;

    pub const ERR_KEY_ROTATION_STILL_TIMELOCKED: MasmError = MasmError::from_static_str("key rotation still timelocked");
    assert_transaction_executor_error!(early_execute_err, ERR_KEY_ROTATION_STILL_TIMELOCKED);

    // SECTION 3: Successful execute_key_rotation after delay - should succeed
    // ================================================================================

    // Safe block to execute after timelock
    let execute_block = num_delay_blocks + 10;

    // Advance the chain to execute block
    mock_chain.prove_until_block(execute_block)?;

    // Execute transaction without signatures first to get tx summary
    let tx_context_init = mock_chain
        .build_tx_context(timelocked_account.id(), &[], &[])?
        .tx_script(tx_script.clone())
        .tx_script_args(tx_script_args)
        .extend_advice_inputs(advice_inputs.clone())
        .auth_args(salt)
        .build()?;


    let tx_summary_new = match tx_context_init.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    // Get signatures from both approvers
    let msg = tx_summary_new.as_ref().to_commitment();
    let tx_summary_new = SigningInputs::TransactionSummary(tx_summary_new);

    let sig_1 = authenticators[0]
        .get_signature(public_keys[0].to_commitment(), &tx_summary_new)
        .await?;

    let psm_sig = _psm_authenticator
        .get_signature(psm_public_key.to_commitment(), &tx_summary_new)
        .await?;

    // Passes the timelock, so this should succeed
    let execute_key_rotation_tx = mock_chain
        .build_tx_context_at(execute_block, timelocked_account.id(), &[], &[])?
        .tx_script(tx_script)
        .tx_script_args(tx_script_args)   
        .extend_advice_inputs(advice_inputs)
        .add_signature(public_keys[0].to_commitment(), msg, sig_1)
        .add_signature(psm_public_key.to_commitment(), msg, psm_sig)
        .auth_args(salt)
        .build()?
        .execute()
        .await
        .unwrap();

    assert_eq!(
        execute_key_rotation_tx.account_delta().nonce_delta(),
        Felt::new(1)
    );

    mock_chain.add_pending_executed_transaction(&execute_key_rotation_tx)?;
    mock_chain.prove_next_block()?;

    let mut rotated_timelocked_account = updated_timelocked_account.clone();
    rotated_timelocked_account.apply_delta(execute_key_rotation_tx.account_delta())?;

    // Verify that the public keys were actually updated in storage
    for (i, expected_key) in new_public_keys.iter().enumerate() {
        let storage_key = [
            Felt::new(i as u64),
            Felt::new(0),
            Felt::new(0),
            Felt::new(0),
        ]
        .into();
        let storage_item = rotated_timelocked_account
            .storage()
            .get_map_item(1, storage_key)
            .unwrap();

        let expected_word: Word = expected_key.to_commitment().into();

        assert_eq!(
            storage_item, expected_word,
            "Public key {} doesn't match expected value",
            i
        );
    }

    // Verify the threshold was updated by checking storage slot 0
    let threshold_config_storage = rotated_timelocked_account.storage().get_item(0).unwrap();

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

    // SECTION 4: Create a second transaction signed by the new owners

    // Now test creating a note with the new signers
    // Setup authenticators for the new signers we need 2 out of 2
    let mut new_authenticators = Vec::new();
    for secret_key in _new_secret_keys.iter().take(2) {
        let authenticator = BasicAuthenticator::new(core::slice::from_ref(secret_key));
        new_authenticators.push(authenticator);
    }

    // Create a new output note for the second transaction with new signers
    let output_note_new = create_p2id_note(
        rotated_timelocked_account.id(),
        ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE
            .try_into()
            .unwrap(),
        vec![output_note_asset],
        NoteType::Public,
        Default::default(),
        &mut RpoRandomCoin::new(Word::default()),
    )?;

    // Create a new spawn note for the second transaction
    let input_note_new = create_spawn_note([&output_note_new])?;

    let salt_new = Word::from([Felt::new(2); 4]);

    // Build the new mock chain with the updated account and notes
    let mut new_mock_chain_builder =
        MockChainBuilder::with_accounts([rotated_timelocked_account.clone()]).unwrap();
    new_mock_chain_builder.add_output_note(OutputNote::Full(input_note_new.clone()));
    let new_mock_chain = new_mock_chain_builder.build().unwrap();

    // Execute transaction without signatures first to get tx summary
    let tx_context_init_new = new_mock_chain
        .build_tx_context(rotated_timelocked_account.id(), &[input_note_new.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note.clone())])
        .auth_args(salt_new)
        .build()?;

    let tx_summary_new = match tx_context_init_new.execute().await.unwrap_err() {
        TransactionExecutorError::Unauthorized(tx_effects) => tx_effects,
        error => panic!("expected abort with tx effects: {error:?}"),
    };

    // Get signatures from 1 of the 2 new approvers (threshold is 2)
    let msg_new = tx_summary_new.as_ref().to_commitment();
    let tx_summary_new = SigningInputs::TransactionSummary(tx_summary_new);

    let sig_1_new = new_authenticators[0]
        .get_signature(new_public_keys[0].to_commitment(), &tx_summary_new)
        .await?;

    let psm_sig = _psm_authenticator
        .get_signature(psm_public_key.to_commitment(), &tx_summary_new)
        .await?;

    // SECTION 5: Properly handle multisig authentication with the updated signers
    // ================================================================================
    // Execute transaction with new signatures - should succeed
    let tx_context_execute_new = new_mock_chain
        .build_tx_context(rotated_timelocked_account.id(), &[input_note_new.id()], &[])?
        .extend_expected_output_notes(vec![OutputNote::Full(output_note_new)])
        .add_signature(new_public_keys[0].to_commitment(), msg_new, sig_1_new)
        .add_signature(psm_public_key.to_commitment(), msg_new, psm_sig)
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