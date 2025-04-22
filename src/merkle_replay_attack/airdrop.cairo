use starknet::ContractAddress;

#[starknet::interface]
pub trait IAirdrop<TContractState> {
    fn get_merkle_root(self: @TContractState) -> felt252;
    fn claim_airdrop(
        ref self: TContractState, to: ContractAddress, amount: u256, proof: Span<felt252>,
    );
}

#[starknet::contract]
mod Airdrop {
    use alexandria_merkle_tree::merkle_tree::pedersen::PedersenHasherImpl;
    use alexandria_merkle_tree::merkle_tree::{Hasher, MerkleTree, MerkleTreeTrait};
    use merkle_multisig_attack::utils::mock_eth::{
        IERC20MintingAndBurningDispatcher, IERC20MintingAndBurningDispatcherTrait,
    };
    use starknet::ContractAddress;
    use starknet::storage::{StoragePointerReadAccess, StoragePointerWriteAccess};

    #[storage]
    struct Storage {
        merkle_root: felt252, // The Merkle Tree Root
        owner: ContractAddress, // The Owner of the contract
        token: IERC20MintingAndBurningDispatcher // Airdropped Token
    }

    #[constructor]
    fn constructor(
        ref self: ContractState,
        owner: ContractAddress,
        token: ContractAddress,
        merkle_root: felt252,
    ) {
        self.owner.write(owner);
        self.merkle_root.write(merkle_root);
        self.token.write(IERC20MintingAndBurningDispatcher { contract_address: token });
    }

    #[abi(embed_v0)]
    impl IAirdropImpl of super::IAirdrop<ContractState> {
        // Get the Merkle Root
        fn get_merkle_root(self: @ContractState) -> felt252 {
            self.merkle_root.read()
        }

        // Claim the airdrop by providing the data and proof.
        // @param to: The address of the user claiming the airdrop
        // @param amount: The amount of tokens to mint
        // @param proof: The Merkle Proof (all the siblings of the leaf to lead to the root)
        fn claim_airdrop(
            ref self: ContractState, to: ContractAddress, amount: u256, proof: Span<felt252>,
        ) {
            // Initializing the Merkletree
            let mut merkle_tree: MerkleTree<Hasher> = MerkleTreeTrait::new();
            // Pedersen Hashing of the user's address and amount to generate the leaf
            let to_felt252: felt252 = to.try_into().unwrap();
            let amount_felt252: felt252 = amount.try_into().unwrap();
            let leaf_hash: felt252 = core::pedersen::pedersen(to_felt252, amount_felt252);

            // Verifying the proof
            let valid_proof: bool = merkle_tree.verify(self.merkle_root.read(), leaf_hash, proof);
            assert(valid_proof, 'Invalid proof');

            // Minting the tokens
            self.token.read().mint(to, amount);
        }
    }
}
