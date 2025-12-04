# PSM Usage Standard

In this document, **PSM** refers to the off-chain service defined in the
[OpenZeppelin/private-state-manager](https://github.com/OpenZeppelin/private-state-manager) repository, which provides a cloud backup and synchronization layer for **Miden private accounts**, so that their private state can be recovered instead of being permanently lost if a local device or storage fails.

This repository implements the on-chain contracts for the Private State Manager
for Miden confidential accounts, and wires them into multisig accounts.

For any multisig account configured to use PSM, the design goal is that every multisig operation must be authenticated both by the multisig policy and by the PSM’s view of the private state, via a valid PSM signature (with the sole exception of PSM key rotation).

In other words, the PSM is not just an “extra” layer, it is an integral part of the
account’s authorization logic.

## Using Private State Manager in a Multisig Account

Private State Manager is a protection from losing the private state. In other words, users must be able to recover a consistent private state.

Every multisig operation that can impact private state must:
  - satisfy the configured multisig threshold.
  - verified by the PSM via a valid PSM signature.

The PSM acts as a state guardian that only signs transactions compatible with its view of the private state.

### Example: 1-of-N “receive token” case:

A typical multisig configuration might set “receive token” to 1-of-N multisig threshold, so that *any* signer can receive funds for the account.

Without using the PSM, other N−1 signers will be effected:

- One malicious signer may approve “receive token” operations that put the **private state** at risk for the other signers.
- The rest of the signers have no independent mechanism to ensure the operation is compatible with the updated private state.

By using the PSM:

- “Receive token” is effectively treated as **(1-of-N multisig) + (1 PSM signature)**.
- The remaining N−1 signers are protected because a single malicious signer is **not enough**, since the PSM enforces that
all signed operations are consistent with the private state it is backing up.

In terms of storage in the PSM contract, this is represented by a selector we refer to as **`PSM_SELECTOR_SLOT`**

- `1` → PSM signature required for all authenticated operations.
- `0` → PSM signature requirement disabled for the PSM key rotation.

## Threat model: malicious or compromised PSM

We must also assume the PSM itself can become **malicious or compromised**:

- PSM server is compromised.
- PSM key is leaked.
- PSM operator stops signing or censors users.

In such a case, users must be able to rotate the compromised PSM key. There is a dedicated procedure, **`update_psm_key`**, that is allowed to run **without** a PSM signature. This procedure is used to **rotate the PSM public key** stored on-chain. For this procedure only, the PSM signature requirement is **temporarily deactivated** so that users can escape from a broken PSM.

All other procedures and operations require both:

- Multisig authentication `M-of-N` and
- PSM signature verification

## Integration with `multisig.masm`

The PSM verification logic is intended to be used **from the multisig authentication component**
(for example from `multisig.masm`), not directly by arbitrary contracts.

For multisig accounts that are configured to use PSM, the `auth__` procedure is responsible for
invoking the PSM verification helper after it has validated the multisig signatures.

Inside `auth__`, we only call the PSM verification helper. All selector handling and PSM-specific
logic is encapsulated in that helper procedure:

```masm
use openzeppelin::psm

#! PSM verification call from `auth__`.
#! Inputs:  [MSG]
#! Outputs: [MSG]
#!
#! Notes:
#! - MSG is TX_SUMMARY_COMMITMENT provided by `auth__`.
#! - PSM signature is supplied via the advice stack when required.

# ------ Verifying PSM Signature ------
# Stack: [MSG]
call.psm::verify_psm_signature

# On success, the stack is [MSG] again.
return
