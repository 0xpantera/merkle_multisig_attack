use starknet::ContractAddress;

#[starknet::interface]
trait IERC20MintingAndBurning<TState> {
    fn mint(ref self: TState, recipient: ContractAddress, amount: u256) -> bool;
    fn burn(ref self: TState, amount: u256) -> bool;
}

#[starknet::contract]
mod CustomERC20 {
    use openzeppelin_token::erc20::{ERC20Component, ERC20HooksEmptyImpl};
    use starknet::{ContractAddress, get_caller_address};
    use openzeppelin_access::ownable::OwnableComponent;

    component!(path: ERC20Component, storage: erc20, event: ERC20Event);
    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);

    #[abi(embed_v0)]
    impl ERC20MixinImpl = ERC20Component::ERC20MixinImpl<ContractState>;
    impl ERC20InternalImpl = ERC20Component::InternalImpl<ContractState>;
    #[abi(embed_v0)]
    impl OwnableImpl = OwnableComponent::OwnableImpl<ContractState>;
    impl OwnableInternalImpl = OwnableComponent::InternalImpl<ContractState>;

    #[storage]
    struct Storage {
        #[substorage(v0)]
        erc20: ERC20Component::Storage,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        #[flat]
        ERC20Event: ERC20Component::Event,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
    }

    #[constructor]
    fn constructor(
        ref self: ContractState, 
        owner: ContractAddress, 
        name: ByteArray, 
        symbol: ByteArray
    ) {
        self.erc20.initializer(name, symbol);
        self.ownable.initializer(owner);
    }

    #[abi(embed_v0)]
    impl ERC20MintingBurningImpl of super::IERC20MintingAndBurning<ContractState> {
        fn mint(ref self: ContractState, recipient: ContractAddress, amount: u256) -> bool {
            self.ownable.assert_only_owner();
            self.erc20.mint(recipient, amount);
            true
        }
        fn burn(ref self: ContractState, amount: u256) -> bool {
            self.erc20.burn(get_caller_address(), amount);
            true
        }
    }
}
