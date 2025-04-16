use core::result::ResultTrait;
use openzeppelin_token::erc20::interface::IERC20Dispatcher;
use openzeppelin_token::erc721::interface::IERC721Dispatcher;
use snforge_std::cheatcodes::contract_class::{ContractClassTrait, DeclareResultTrait, declare};
use snforge_std::cheatcodes::execution_info::caller_address::{
    start_cheat_caller_address, stop_cheat_caller_address,
};
use starknet::ContractAddress;

#[starknet::interface]
trait IERC20MintingAndBurning<TState> {
    fn mint(ref self: TState, recipient: ContractAddress, amount: u256) -> bool;
    fn burn(ref self: TState, amount: u256) -> bool;
}

#[starknet::interface]
trait IERC721Mintable<TContractState> {
    fn mint(ref self: TContractState, to: ContractAddress, token_id: u256);
}


pub fn get_deployer() -> ContractAddress {
    123.try_into().unwrap()
}

pub fn one_ether() -> u256 {
    1_000_000_000_000_000_000
}

fn one_ether_felt() -> felt252 {
    1_000_000_000_000_000_000
}

pub fn deploy_eth() -> (ContractAddress, IERC20Dispatcher) {
    // Declaring the contract class
    let contract_class = declare("ETHToken").unwrap().contract_class();
    // Creating the data to send to the constructor, first specifying as a default value
    let mut data_to_constructor = Default::default();
    // Creating the address of the deployer
    let deployer_address: ContractAddress = 123.try_into().unwrap();
    // Pack the data into the constructor
    Serde::serialize(@deployer_address, ref data_to_constructor);
    // Deploying the contract, and getting the address
    let (address, _) = contract_class.deploy(@data_to_constructor).unwrap();
    return (address, IERC20Dispatcher { contract_address: address });
}

fn deploy_usdc() -> (ContractAddress, IERC20Dispatcher) {
    // Declaring the contract class
    let contract_class = declare("USDCToken").unwrap().contract_class();
    // Creating the data to send to the constructor, first specifying as a default value
    let mut data_to_constructor = Default::default();
    // Creating the address of the deployer
    let deployer_address: ContractAddress = 123.try_into().unwrap();
    // Pack the data into the constructor
    Serde::serialize(@deployer_address, ref data_to_constructor);
    // Deploying the contract, and getting the address
    let (address, _) = contract_class.deploy(@data_to_constructor).unwrap();
    return (address, IERC20Dispatcher { contract_address: address });
}

fn deploy_nft() -> (ContractAddress, IERC721Dispatcher) {
    // Declaring the contract class
    let contract_class = declare("NFTMock").unwrap().contract_class();
    // Creating the address of the deployer
    let deployer_address: ContractAddress = 123.try_into().unwrap();
    // Deploying the contract, and getting the address
    let (address, _) = contract_class.deploy(@array![deployer_address.into()]).unwrap();
    return (address, IERC721Dispatcher { contract_address: address });
}

pub fn deploy_erc20(name: ByteArray, symbol: ByteArray) -> (ContractAddress, IERC20Dispatcher) {
    // Declaring the contract class
    let contract_class = declare("CustomERC20").unwrap().contract_class();
    // Creating the data to send to the constructor, first specifying as a default value
    let mut data_to_constructor = Default::default();
    // Creating the address of the deployer
    let deployer_address: ContractAddress = 123.try_into().unwrap();
    // Pack the data into the constructor
    Serde::serialize(@deployer_address, ref data_to_constructor);
    Serde::serialize(@name, ref data_to_constructor);
    Serde::serialize(@symbol, ref data_to_constructor);
    // Deploying the contract, and getting the address
    let (address, _) = contract_class.deploy(@data_to_constructor).unwrap();
    return (address, IERC20Dispatcher { contract_address: address });
}

pub fn mint_erc20(token: ContractAddress, receiver: ContractAddress, amount: u256) {
    let deployer: ContractAddress = 123.try_into().unwrap();
    let erc20_dispatcher_minting = IERC20MintingAndBurningDispatcher { contract_address: token };
    start_cheat_caller_address(token, deployer);
    erc20_dispatcher_minting.mint(receiver, amount);
    stop_cheat_caller_address(token);
}

fn mint_nft(nft: ContractAddress, receiver: ContractAddress, token_id: u256) {
    let deployer: ContractAddress = 123.try_into().unwrap();
    let nft_dispatcher = IERC721MintableDispatcher { contract_address: nft };
    start_cheat_caller_address(nft, deployer);
    nft_dispatcher.mint(receiver, token_id);
    stop_cheat_caller_address(nft);
}
