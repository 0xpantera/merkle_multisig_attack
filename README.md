Generate a README.md file explaining the project. It is meant to demonstrate common vulnerabilities when using cryptographic primitives. In the merkle_replay_attack an airdrop contract that uses merkle trees to distribute tokens, can get attacked by replaying a proof. In the `multisig_threshold_attack` a multisig wallet can be attacked by exploiting the threshold requirement if one of the signers is compromised. Additionally, explain the `utils.merkle_tree` module and how it can be used to create and verify merkle proofs.

# Merkle Multisig Attack Demo

This project demonstrates common vulnerabilities when using cryptographic primitives like Merkle trees and digital signatures in smart contracts. It showcases two specific attack vectors:

1. **Merkle Replay Attack**: Exploiting a flaw in an airdrop contract that uses Merkle trees
2. **Multisig Threshold Attack**: Compromising a multisig wallet with a vulnerable threshold verification

## Merkle Replay Attack

The `merkle_replay_attack` module demonstrates a vulnerability in airdrop contracts that use Merkle trees for verification but don't track which users have already claimed their tokens.

### Vulnerability

The `Airdrop` contract verifies that a user is eligible for an airdrop by checking if their data (address and amount) is included in a Merkle tree. However, it lacks a mechanism to track which users have already claimed their tokens. This allows users to submit the same proof multiple times and claim the airdrop repeatedly.

### The Attack

In the `test_replay_attack.cairo` test, we demonstrate:

1. Alice legitimately claims her airdrop with a valid proof
2. The attacker legitimately claims their airdrop with a valid proof
3. The attacker then repeatedly claims their airdrop with the same proof, stealing tokens

### Mitigation

To fix this vulnerability, the contract should maintain a record of addresses that have already claimed their tokens, for example:

```cairo
#[storage]
struct Storage {
    merkle_root: felt252,
    claimed: Map<ContractAddress, bool>,
    owner: ContractAddress,
    token: IERC20MintingAndBurningDispatcher
}

fn claim_airdrop(...) {
    // Check if already claimed
    assert(!self.claimed.read(to), 'Already claimed');

    // Verify proof
    // ...

    // Mark as claimed
    self.claimed.write(to, true);

    // Mint tokens
    // ...
}
```

## Multisig Threshold Attack

The `multisig_threshold_attack` module demonstrates a vulnerability in multisig wallets that don't properly validate the uniqueness of signatures.

### Vulnerability

The `Multisig` contract requires a certain number of signatures (threshold) to execute a transaction. However, it doesn't check if the same signer is used multiple times. This means if an attacker compromises one private key, they can reuse that signature to meet the threshold requirement.

### The Attack

In the `test_threshold_attack.cairo` test, we demonstrate:

1. A multisig wallet is set up with two signers (Alice and Bob) and a threshold of 2
2. The attacker only has access to Alice's private key
3. The attacker creates a malicious transaction and signs it with Alice's key
4. The attacker duplicates Alice's signature to satisfy the threshold requirement
5. The contract accepts the transaction since it sees two signatures, even though they're from the same signer

### Mitigation

The contract should check that each signature comes from a unique signer:

```cairo
fn is_valid_signature_span(
    self: @ContractState, hash: felt252, signature: Span<felt252>,
) -> bool {
    let threshold = self.threshold.read();
    assert(threshold != 0, 'Uninitialized');

    let mut signatures = deserialize_signatures(signature)
        .expect('signature/invalid-len');

    // Make sure we have the correct number of signatures
    assert(threshold == signatures.len(), 'signature/invalid-len');

    // Track used signers to prevent reuse
    let mut used_signers: Array<felt252> = array![];

    // Verify each signature
    for signature_ref in signatures {
        let signature = *signature_ref;
        let signer = signature.signer;

        // Check signer hasn't been used already
        for used in used_signers.span() {
            assert(*used != signer, 'signer/already-used');
        }
        used_signers.append(signer);

        if !self.is_valid_signer_signature(
            hash,
            signer,
            signature.signature_r,
            signature.signature_s,
        ) { return false; }
    }
    true
}
```

## Utils.merkle_tree Module

The `utils.merkle_tree` module provides utility functions for creating and verifying Merkle trees and proofs.

### Key Components:

1. **Data Structure**: The `AddressAmount` struct represents a leaf in the Merkle tree, containing an address and an amount.

2. **Predefined Data**: The module includes predefined data for Alice and the Attacker, which are used to generate leaves in the Merkle tree.

3. **Core Functions**:
   - `generate_leaves()`: Creates an array of leaves by hashing each address-amount pair
   - `generate_merkle_root()`: Computes the Merkle root from the leaves
   - `generate_alice_proof()`: Generates a Merkle proof for Alice's leaf
   - `generate_attacker_proof()`: Generates a Merkle proof for the Attacker's leaf

### How to Use the Merkle Tree Module:

1. **Generate Leaves**:
   ```cairo
   let leaves = generate_leaves();
   ```

2. **Generate the Merkle Root**:
   ```cairo
   let merkle_root = generate_merkle_root();
   ```

3. **Generate Proofs**:
   ```cairo
   let alice_proof = generate_alice_proof();
   let attacker_proof = generate_attacker_proof();
   ```

4. **Verify Proofs**:
   ```cairo
   let mut merkle_tree: MerkleTree<Hasher> = MerkleTreeTrait::new();
   let alice_leaf = core::pedersen::pedersen(ALICE_DATA.address, ALICE_DATA.amount);
   let is_valid = merkle_tree.verify(merkle_root, alice_leaf, alice_proof);
   ```

## Security Best Practices

When working with cryptographic primitives like Merkle trees and digital signatures, keep these best practices in mind:

1. **Track claimed airdrops**: Always maintain a record of addresses that have already claimed tokens
2. **Validate unique signers**: Ensure each signature in a multisig wallet comes from a unique signer
3. **Use nonces**: Implement nonces to prevent replay attacks
4. **Comprehensive testing**: Test edge cases and potential attack vectors thoroughly

## Running the Tests

You can run the tests using the Starknet Foundry's `snforge` tool:

```bash
scarb test
```
