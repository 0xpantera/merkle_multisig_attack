use starknet::ContractAddress;

#[starknet::interface]
pub trait IERC20MintingAndBurning<TState> {
    fn mint(ref self: TState, recipient: ContractAddress, amount: u256) -> bool;
    fn burn(ref self: TState, amount: u256) -> bool;
}


#[starknet::contract]
mod ETHToken {
    use openzeppelin_token::erc20::{ERC20Component, ERC20HooksEmptyImpl};
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};
    use starknet::{ContractAddress, get_caller_address};

    component!(path: ERC20Component, storage: erc20, event: ERC20Event);

    #[abi(embed_v0)]
    impl ERC20MixinImpl = ERC20Component::ERC20MixinImpl<ContractState>;

    impl ERC20InternalImpl = ERC20Component::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        owner: ContractAddress,
        #[substorage(v0)]
        erc20: ERC20Component::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ERC20Event: ERC20Component::Event,
    }

    #[constructor]
    fn constructor(ref self: ContractState, owner: ContractAddress) {
        let name = "ETHToken";
        let symbol = "ETH";
        self.erc20.initializer(name, symbol);
        self.owner.write(owner);
    }

    #[abi(embed_v0)]
    impl ERC20MintingBurningImpl of super::IERC20MintingAndBurning<ContractState> {
        fn mint(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
            self.assert_owner();
            self.erc20.mint(recipient, amount);
            true
        }
        fn burn(ref self: ContractState, amount: u256) -> bool {
            self.erc20.burn(get_caller_address(), amount);
            true
        }
    }

    #[generate_trait]
    impl InternalFunctions of InternalFunctionsTrait {
        fn assert_owner(ref self: ContractState) {
            assert(self.owner.read() == get_caller_address(), 'Only owner');
        }
    }
}
