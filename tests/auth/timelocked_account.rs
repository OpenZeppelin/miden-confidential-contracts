use miden_confidential_contracts::masm_builder::{get_multisig_library, get_psm_library};
use miden_confidential_contracts::timelocked_account::{
    TimelockedAccountBuilder, TimelockedAccountConfig,
};
use miden_lib::note::create_p2id_note;
use miden_lib::utils::ScriptBuilder;
use miden_objects::account::Account;
use miden_objects::account::auth::{AuthSecretKey, PublicKey, PublicKeyCommitment};
use miden_objects::asset::FungibleAsset;
use miden_objects::crypto::rand::RpoRandomCoin;
use miden_objects::note::NoteType;
use miden_objects::testing::account_id::ACCOUNT_ID_REGULAR_PUBLIC_ACCOUNT_UPDATABLE_CODE;
use miden_objects::transaction::OutputNote;
use miden_objects::vm::AdviceInputs;
use miden_objects::{Felt, Word};
use miden_testing::MockChainBuilder;
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

type PsmTestSetup = (AuthSecretKey, PublicKey, BasicAuthenticator);

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
