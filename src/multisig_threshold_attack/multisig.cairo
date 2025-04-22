use starknet::account::Call;

#[starknet::interface]
pub trait IMultisig<T> {
    fn __execute__(ref self: T, calls: Span<Call>) -> Array<Span<felt252>>;
    fn __validate__(self: @T, calls: Span<Call>) -> felt252;
    fn is_valid_signature(self: @T, hash: felt252, signature: Array<felt252>) -> felt252;
    fn supports_interface(self: @T, interface_id: felt252) -> bool;
}

// @title SRC-6 Standard Account
#[starknet::interface]
trait ISRC6<T> {
    // Note: changed from Array to Span for testing
    // @notice Execute a transaction through the account
    // @param calls The list of calls to execute
    // @return The list of each call's serialized return value
    fn __execute__(ref self: T, calls: Span<Call>) -> Array<Span<felt252>>;

    // @notice Assert whether the transaction is valid to be executed
    // @param calls The list of calls to execute
    // @return The string 'VALID' represented as a felt when is valid
    fn __validate__(self: @T, calls: Span<Call>) -> felt252;

    // @notice Assert whether a given signature for a given hash is valid
    // @dev signatures must be deserialized
    // @param hash The hash of the data
    // @param signature The signature to be validated
    // @return The string 'VALID' represented as a felt when is valid
    fn is_valid_signature(self: @T, hash: felt252, signature: Array<felt252>) -> felt252;
}

// @title SRC-5 Iterface detection
#[starknet::interface]
trait ISRC5<T> {
    // @notice Query if a contract implements an interface
    // @param interface_id The interface identifier, as specified in SRC-5
    // @return `true` if the contract implements `interface_id`, `false` otherwise
    fn supports_interface(self: @T, interface_id: felt252) -> bool;
}

#[starknet::contract(account)]
mod Multisig {
    use core::ecdsa;
    use core::num::traits::zero::Zero;
    use starknet::account::Call;
    use starknet::storage::{
        Map, StorageMapReadAccess, StorageMapWriteAccess, StoragePointerReadAccess,
        StoragePointerWriteAccess,
    };
    use starknet::syscalls::call_contract_syscall;
    use super::{ISRC5, ISRC6};

    // hash of SNIP-6 trait
    const SRC6_INTERFACE_ID: felt252 =
        1270010605630597976495846281167968799381097569185364931397797212080166453709; 
    const MAX_SIGNERS_COUNT: usize = 32;

    #[storage]
    struct Storage {
        // Map of signers that can sign transactions
        signers: Map<felt252, felt252>,
        // Amount of signatures required to execute a transaction
        threshold: usize,
        outside_nonce: Map<felt252, felt252>,
    }

    // @notice Contructor of the account
    // @dev Asserts threshold in relation with signers-len
    // @param threshold Initial threshold
    // @param signers Array of inital signers' public-keys
    #[constructor]
    fn constructor(ref self: ContractState, threshold: usize, signers: Array<felt252>) {
        assert_threshold(threshold, signers.len());

        self.add_signers(signers.span(), 0);
        self.threshold.write(threshold);
    }

    // Implementation of ISRC6 interface (used for accounts on starknet)
    #[abi(embed_v0)]
    impl SRC6 of ISRC6<ContractState> {
        fn __execute__(
            ref self: ContractState, calls: Span<Call>,
        ) -> Array<Span<felt252>> {
            assert_only_protocol();
            execute_multicall(calls)
        }

        fn __validate__(self: @ContractState, calls: Span<Call>) -> felt252 {
            assert_only_protocol();
            assert(calls.len() > 0, 'validate/no-calls');
            self.assert_valid_calls(calls);
            starknet::VALIDATED
        }

        fn is_valid_signature(
            self: @ContractState, hash: felt252, signature: Array<felt252>,
        ) -> felt252 {
            if self.is_valid_signature_span(hash, signature.span()) {
                starknet::VALIDATED
            } else {
                0
            }
        }
    }

    // Implementation of the SRC5 interface
    #[abi(embed_v0)]
    impl SRC5 of ISRC5<ContractState> {
        fn supports_interface(self: @ContractState, interface_id: felt252) -> bool {
            interface_id == SRC6_INTERFACE_ID
        }
    }

    #[generate_trait]
    impl Private of PrivateTrait {
        // @notice Add signers to the contract
        fn add_signers(ref self: ContractState, mut signers: Span<felt252>, last: felt252) {
            if let Some(signer_ref) = signers.pop_front() {
                let signer = *signer_ref;
                assert(signer != 0, 'signer/zero-signer');
                assert(!self.is_signer_using_last(signer, last), 'signer/is-already-signer');
                self.signers.write(last, signer);
                self.add_signers(signers, signer);
            }
        }

        // @notice Asserts whether the signer is using the last signer
        fn is_signer_using_last(self: @ContractState, signer: felt252, last: felt252) -> bool {
            if signer == 0 {
                return false;
            }
            let next = self.signers.read(signer);
            if next != 0 {
                return true;
            }
            last == signer
        }

        // @notice Asserts whether the signature is valid
        fn is_valid_signature_span(
            self: @ContractState, hash: felt252, signature: Span<felt252>,
        ) -> bool {
            let threshold = self.threshold.read();
            assert(threshold != 0, 'Uninitialized');

            let mut signatures = deserialize_signatures(signature)
                .expect('signature/invalid-len');

            // Make sure we have the correct amount of signatures in the span
            assert(threshold == signatures.len(), 'signature/invalid-len');

            // Verify each signature
            for signature_ref in signatures {
                let signature = *signature_ref;
                if !self.is_valid_signer_signature(
                    hash,
                    signature.signer,
                    signature.signature_r,
                    signature.signature_s,
                ) { return false; }
            }
            true
        }

        // @notice Asserts whether the signature is valid ECDSA signature for this wallet
        fn is_valid_signer_signature(
            self: @ContractState,
            hash: felt252,
            signer: felt252,
            signature_r: felt252,
            signature_s: felt252,
        ) -> bool {
            assert(self.is_signer(signer), 'signer/not-a-signer');
            ecdsa::check_ecdsa_signature(hash, signer, signature_r, signature_s)
        }

        // @notice Asserts whether the signer is a signer
        fn is_signer(self: @ContractState, signer: felt252) -> bool {
            if signer == 0 {
                return false;
            }
            let next = self.signers.read(signer);
            if next != 0 {
                return true;
            }
            self.get_last() == signer
        }

        // @notice Get the last signer
        fn get_last(self: @ContractState) -> felt252 {
            let mut curr = self.signers.read(0);
            loop {
                let next = self.signers.read(curr);
                if next == 0 {
                    break curr;
                }
                curr = next;
            }
        }

        // @notice Asserts whether the transaction is valid to be executed
        fn assert_valid_calls(self: @ContractState, calls: Span<Call>) {
            assert_no_self_call(calls);

            let tx_info = starknet::get_tx_info().unbox();
            assert(
                self.is_valid_signature_span(tx_info.transaction_hash, tx_info.signature),
                'call/invalid-signature',
            )
        }
    }

    // @notice Asserts whether the threshold is valid
    fn assert_threshold(threshold: usize, signers_len: usize) {
        assert(threshold != 0, 'threshold/is-zero');
        assert(signers_len != 0, 'signers_len/is-zero');
        assert(signers_len <= MAX_SIGNERS_COUNT, 'signers_len/too-high');
        assert(threshold <= signers_len, 'threshold/too-high');
    }

    #[derive(Copy, Drop, Serde)]
    struct SignerSignature {
        signer: felt252,
        signature_r: felt252,
        signature_s: felt252,
    }

    // @notice Deserialize signatures
    fn deserialize_signatures(mut serialized: Span<felt252>) -> Option<Span<SignerSignature>> {
        let mut signatures = array![];
        while let Some(s) = Serde::deserialize(ref serialized) {
            signatures.append(s);
        }
        Some(signatures.span())
    }

    // @notice Assert that only the Sequencer can call the contract
    // Sequencer will always have address 0
    fn assert_only_protocol() {
        assert(starknet::get_caller_address().is_zero(), 'caller/non-zero');
    }

    // @notice Check that the calls are not triggering external wallet methods itself
    fn assert_no_self_call(mut calls: Span<Call>) {
        let self = starknet::get_contract_address();
        for call in calls {
            assert(*call.to != self, 'call/call-to-self');
        }
    }

    // @notice Execute multiple calls
    fn execute_multicall(mut calls: Span<Call>) -> Array<Span<felt252>> {
        // Check if some calls are provided
        assert(calls.len() != 0, 'execute/no-calls');
        let mut result: Array<Span<felt252>> = array![];
        let mut idx = 0;
        // Loop through all calls
        // If a call fails, return the error
        for call in calls {
            match call_contract_syscall(*call.to, *call.selector, *call.calldata) {
                Ok(retdata) => {
                    result.append(retdata);
                    idx += 1;
                },
                Err(err) => {
                    let mut data = array![];
                    data.append('call/multicall-failed');
                    data.append(idx);
                    let mut err = err;
                    for v in err {
                        data.append(v);
                    }
                    panic(data);
                },
            }
        }
        result
    }
}
