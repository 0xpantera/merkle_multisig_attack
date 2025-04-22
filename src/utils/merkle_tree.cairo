use alexandria_merkle_tree::merkle_tree::{Hasher, MerkleTree, MerkleTreeTrait};
use alexandria_merkle_tree::merkle_tree::pedersen::PedersenHasherImpl;
use core::fmt::{Display, Formatter, Error};

#[derive(Drop, Clone, Hash)]
struct AddressAmount {
    address: felt252,
    amount: felt252
}

impl AADisplay of Display<AddressAmount> {
    fn fmt(self: @AddressAmount, ref f: Formatter) -> Result<(), Error> {
        let str: ByteArray = format!(
            "AddressAmount ({}, {})", *self.address, *self.amount
        );
        f.buffer.append(@str);
        Ok(())
    }
}

const ALICE_DATA: AddressAmount = AddressAmount { 
    address: 0x3e5d25b4ed900ab935cfb82bdd6efc9c2ef32531acdceaec8493fb3c497372e,
    amount: 100,
};

const ATTACKER_DATA: AddressAmount = AddressAmount {
    address: 0x76f96ec1eae6475a759c0e21bf94166d1cf2dc276e864b5d34339c153ff8706,
    amount: 500,
};

pub fn generate_merkle_root() -> felt252 {
    let mut merkle_tree: MerkleTree<Hasher> = MerkleTreeTrait::new();
    let leaves = generate_leaves();
    // for ALICE_DATA
    let leaf_index = 0; 
    let proof = merkle_tree.compute_proof(leaves.clone(), leaf_index);

    merkle_tree.compute_root(*leaves[0], proof)
}

pub fn generate_alice_proof() -> Span<felt252> {
    let mut merkle_tree: MerkleTree<Hasher> = MerkleTreeTrait::new();
    let leaves = generate_leaves();
    merkle_tree.compute_proof(leaves, 0)
}

pub fn generate_attacker_proof() -> Span<felt252> {
    let mut merkle_tree: MerkleTree<Hasher> = MerkleTreeTrait::new();
    let leaves = generate_leaves();
    merkle_tree.compute_proof(leaves, 1)
}

fn generate_leaves() -> Array<felt252> {
    let pairs = array![ALICE_DATA, ATTACKER_DATA];
    let mut leaves: Array<felt252> = array![];
    for pair in pairs {
        leaves.append(
            core::pedersen::pedersen(pair.address, pair.amount)
        )
    }
    leaves
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate() {

        let leaves = generate_leaves();

        // compute a proof for the first leaf
        let alice_proof = generate_alice_proof();
        let attacker_proof = generate_attacker_proof();

        println!("Proof for Alice leaf: {:x}", *alice_proof[0]);
        println!("Proof for Attacker leaf: {:x}", *attacker_proof[0]);

        assert_eq!(*alice_proof[0], *leaves[1]);

        

        // Generate merkle root
        let merkle_root = generate_merkle_root();
        println!("Merkle root: {:x}", merkle_root);

        // Verification example
        let mut merkle_tree: MerkleTree<Hasher> = MerkleTreeTrait::new();

        let alice_leaf = core::pedersen::pedersen(ALICE_DATA.address, ALICE_DATA.amount);
        let is_valid_alice = merkle_tree.verify(merkle_root, alice_leaf, alice_proof);
        println!("Is valid proof for Alice leaf? {:?}", is_valid_alice);
        assert!(is_valid_alice);


        let attacker_leaf = core::pedersen::pedersen(ATTACKER_DATA.address, ATTACKER_DATA.amount);
        let is_valid_attacker = merkle_tree.verify(merkle_root, attacker_leaf, attacker_proof);
        println!("Is valid proof for Alice leaf? {:?}", is_valid_attacker);
        assert!(is_valid_attacker);
        
    }
}