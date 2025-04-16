use merkle_multisig_attack::merkle_replay_attack::airdrop::{
    IAirdropDispatcher, IAirdropDispatcherTrait,
};
use merkle_multisig_attack::utils::helpers;
use openzeppelin_access::ownable::interface::{IOwnableDispatcher, IOwnableDispatcherTrait};
use openzeppelin_token::erc20::interface::{IERC20Dispatcher, IERC20DispatcherTrait};
use snforge_std::{
    ContractClassTrait, DeclareResultTrait, declare, start_cheat_caller_address,
    stop_cheat_caller_address,
};
use starknet::ContractAddress;

fn deploy_airdrop(
    deployer: ContractAddress, token: ContractAddress, merkle_root: felt252,
) -> (ContractAddress, IAirdropDispatcher) {
    let contract_class = declare("TokenAirdrop").unwrap().contract_class();
    let mut data_to_constructor = Default::default();
    Serde::serialize(@deployer, ref data_to_constructor);
    Serde::serialize(@token, ref data_to_constructor);
    Serde::serialize(@merkle_root, ref data_to_constructor);
    let (address, _) = contract_class.deploy(@data_to_constructor).unwrap();
    return (address, IAirdropDispatcher { contract_address: address });
}

#[test]
fn test_cryptography_1() {
    // Accounts
    let deployer: ContractAddress = 123.try_into().unwrap();
    let alice: ContractAddress = 0x3e5d25b4ed900ab935cfb82bdd6efc9c2ef32531acdceaec8493fb3c497372e
        .try_into()
        .unwrap();
    let attacker: ContractAddress =
        0x76f96ec1eae6475a759c0e21bf94166d1cf2dc276e864b5d34339c153ff8706
        .try_into()
        .unwrap();

    // Deployments
    let (token_address, token_dispatcher) = helpers::deploy_erc20("AirdropToken", "ADT");
    let token_ownable_dispatcher = IOwnableDispatcher { contract_address: token_address };
    let (airdrop_address, airdrop_dispatcher) = deploy_airdrop(
        deployer, token_address, 0x61392a26b48e1d07e233cb327a98b1a94c02fe5e55ca22ce6513d03400399f4,
    );

    // Transfer ownership on the token contract to the airdrop contract so it can mint tokens
    start_cheat_caller_address(token_address, deployer);
    token_ownable_dispatcher.transfer_ownership(airdrop_address);
    stop_cheat_caller_address(token_address);

    // Alice airdrop Data
    let amount: u256 = 100_u256;
    let proofs = array![0x3c27feb3db62fb40e8c47073385d81c6978a27c38f282ccabfb483591083d8];
    // Alice is claiming her airdrop
    start_cheat_caller_address(airdrop_address, alice);
    airdrop_dispatcher.claim_airdrop(alice, amount, proofs.span());
    stop_cheat_caller_address(airdrop_address);
    assert!(token_dispatcher.balance_of(alice) == amount, "Couldn't claim Alice's airdrop");

    // Attacker is claiming the airdrop
    // Proof was generated using `cryptography_1/scripts_for_merkle_tree_generation/merkle_tree.ts`
    let amount = 500_u256;
    let proofs = array![0x1b611fdbf955a5921b321543d224bd6b859394cb0eee28182570de8e4c72c17];
    start_cheat_caller_address(airdrop_address, attacker);
    airdrop_dispatcher.claim_airdrop(attacker, amount, proofs.span());
    stop_cheat_caller_address(airdrop_address);
    assert!(token_dispatcher.balance_of(attacker) == amount, "Couldn't claim Attacker's airdrop");

    // TODO: Mint at least 1000 tokens to yourself (Attacker)
    // Attack Start //

    // Attack End //

    // Check that the balance is correct
    assert(token_dispatcher.balance_of(attacker) >= 1000, 'Wrong balance');
}
