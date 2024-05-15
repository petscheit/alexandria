use core::hash::HashStateTrait;
use core::pedersen::PedersenTrait;
use core::poseidon::PoseidonTrait;
use core::integer;

#[derive(Drop, Serde)]
pub struct BinaryNode {
    left: felt252,
    right: felt252,
}

#[generate_trait]
pub impl BinaryNodeImpl of BinaryNodeTrait {
    fn new(left: felt252, right: felt252) -> BinaryNode {
        BinaryNode { left, right }
    }
}

#[derive(Drop, Copy, Serde)]
pub struct EdgeNode {
    path: felt252,
    child: felt252,
    length: u8,
}

#[generate_trait]
pub impl EdgeNodeImpl of EdgeNodeTrait {
    fn new(path: felt252, child: felt252, length: u8) -> EdgeNode {
        EdgeNode { path, child, length }
    }
}

#[derive(Drop, Serde)]
pub enum TrieNode {
    Binary: BinaryNode,
    Edge: EdgeNode,
}

#[derive(Destruct, Serde)]
pub struct ContractData {
    class_hash: felt252,
    nonce: felt252,
    contract_state_hash_version: felt252,
    storage_proof: Array<TrieNode>
}
#[derive(Destruct, Drop, PartialEq)]
pub enum Membership{
    Included: felt252,
    NotIncluded
}

enum TraverseRes {
    Invalid,
    Included,
    NotIncluded
}

#[generate_trait]
pub impl ContractDataImpl of ContractDataTrait {
    fn new(
        class_hash: felt252,
        nonce: felt252,
        contract_state_hash_version: felt252,
        storage_proof: Array<TrieNode>
    ) -> ContractData {
        ContractData { class_hash, nonce, contract_state_hash_version, storage_proof }
    }
}

#[derive(Destruct, Serde)]
pub struct ContractStateProof {
    class_commitment: felt252,
    contract_proof: Array<TrieNode>,
    contract_data: ContractData
}

#[generate_trait]
pub impl ContractStateProofImpl of ContractStateProofTrait {
    fn new(
        class_commitment: felt252, contract_proof: Array<TrieNode>, contract_data: ContractData
    ) -> ContractStateProof {
        ContractStateProof { class_commitment, contract_proof, contract_data, }
    }
}

/// Verify Starknet storage proof. For reference see:
/// - ([state](https://docs.starknet.io/documentation/architecture_and_concepts/State/starknet-state/))
/// - ([pathfinder_getproof API endpoint](https://github.com/eqlabs/pathfinder/blob/main/doc/rpc/pathfinder_rpc_api.json))
/// - ([pathfinder storage implementation](https://github.com/eqlabs/pathfinder/blob/main/crates/merkle-tree/src/tree.rs))
/// # Arguments
/// * `expected_state_commitment` - state root `proof` is going to be verified against
/// * `contract_address` - `contract_address` of the value to be verified
/// * `storage_address` - `storage_address` of the value to be verified
/// * `proof` - `ContractStateProof` representing storage proof
/// # Returns
/// * `felt252` - `value` at `storage_address` if verified, panic otherwise.
pub fn verify(
    expected_state_commitment: felt252,
    contract_address: felt252,
    storage_address: felt252,
    proof: ContractStateProof
) -> felt252 {
    let contract_data = proof.contract_data;

    let (contract_root_hash, storage_value) = traverse(
        storage_address, contract_data.storage_proof
    );

    let contract_state_hash = pedersen_hash_4(
        contract_data.class_hash,
        contract_root_hash,
        contract_data.nonce,
        contract_data.contract_state_hash_version
    );

    let (contracts_tree_root, expected_contract_state_hash) = traverse(
        contract_address, proof.contract_proof
    );

    assert(expected_contract_state_hash == contract_state_hash, 'wrong contract_state_hash');

    let state_commitment = poseidon_hash(
        'STARKNET_STATE_V0', contracts_tree_root, proof.class_commitment
    );

    assert(expected_state_commitment == state_commitment, 'wrong state_commitment');

    storage_value
}

// Verify a generic starknet MPT proof. This function uses downward traversing, allowing non-inclusion to be verified aswell. 
pub fn verify_mpt_proof(
    root: felt252,
    key: felt252,
    proof: Array<TrieNode>,
) -> Option<Membership> {
    traverse_downward(root, key, proof)
}

pub fn verify_leaf_update(
    root: felt252,
    key: felt252,
    proof_pre: Array<TrieNode>,
    proof_post: Array<TrieNode>,
) -> Option<(felt252, felt252)> {
    let res = traverse_downward(root, key, proof_pre);

    match res {
        Option::None => { return Option::None; },
        Option::Some(_) => {}
    }

    let (root_post, value) = traverse(key, proof_post);
    Option::Some((root_post, value))
}

// This function hashes through the proof path, starting at the root and ending at the leaf. This enables the verification of Non-Inclusion proofs.
fn traverse_downward(root: felt252, key: felt252, proof: Array<TrieNode>) -> Option<Membership> {
    let mut nodes = proof.span();
    let mut expected_hash = root;
    let mut remaining_path: u256 = key.into();

    let mut i = 0;
    let mut offset = 0;
    let res = loop {
        if i == proof.len(){
            break TraverseRes::Included;
        }
        match nodes.get(i) {
            Option::Some(node) => {
                if(expected_hash != node_hash(node.unbox())) {
                    break TraverseRes::Invalid;
                }

                match node.unbox() {
                    TrieNode::Binary(binary_node) => {
                        let depth: u8 = (250 - (i + offset)).try_into().unwrap();
                        let devisor: u256 = pow(2, depth).into();
                        let d: NonZero<u256> = devisor.try_into().unwrap();
                        let (q, r) = DivRem::div_rem(remaining_path, d);
                        if q > 0 {
                            expected_hash = *binary_node.right;
                        } else {
                            expected_hash = *binary_node.left;
                        }
                        remaining_path = r;
                    },
                    TrieNode::Edge(edge_node) => {
                        let depth: u8 = (251 - (i + offset)).try_into().unwrap();
                        let devisor: u256 = pow(2, depth - *edge_node.length).into();
                        let d: NonZero<u256> = devisor.try_into().unwrap();
                        let (q, r) = DivRem::div_rem(remaining_path, d);
                        let path: u256 = (*edge_node.path).into();

                        if path != q {
                            break TraverseRes::NotIncluded;
                        }

                        expected_hash = *edge_node.child;
                        remaining_path = r;
                        let len = *edge_node.length - 1;
                        let len1: u32 = len.into();
                        offset = offset +  len1;
                    }
                }
            },
            Option::None => { break TraverseRes::Included; }
        }
        i = i + 1;
    };

    match res {
        TraverseRes::Invalid => Option::None,
        TraverseRes::NotIncluded => Option::Some(Membership::NotIncluded),
        TraverseRes::Included => {
            if remaining_path != 0 {
                return Option::None;
            } else {
                return Option::Some(Membership::Included(expected_hash));
            }
        }
    }
}

fn traverse(expected_path: felt252, proof: Array<TrieNode>) -> (felt252, felt252) {
    let mut nodes = proof.span();
    let expected_path_u256: u256 = expected_path.into();

    let leaf = *match nodes.pop_back().unwrap() {
        TrieNode::Binary(_) => panic!("expected Edge got Leaf"),
        TrieNode::Edge(edge) => edge
    };

    let mut expected_hash = node_hash(@TrieNode::Edge(leaf));
    let value = leaf.child;
    let mut path = leaf.path;
    let mut path_length_pow2 = pow(2, leaf.length);

    loop {
        match nodes.pop_back() {
            Option::Some(node) => {
                match node {
                    TrieNode::Binary(binary_node) => {
                        if expected_path_u256 & path_length_pow2.into() > 0 {
                            assert(expected_hash == *binary_node.right, 'invalid node hash - 1');
                            path += path_length_pow2;
                        } else {
                            assert(expected_hash == *binary_node.left, 'invalid node hash - 2');
                        };
                        path_length_pow2 *= 2;
                    },
                    TrieNode::Edge(edge_node) => {
                        assert(expected_hash == *edge_node.child, 'invalid node hash - 3');
                        path += *edge_node.path * path_length_pow2;
                        path_length_pow2 *= pow(2, *edge_node.length);
                    }
                }
                expected_hash = node_hash(node);
            },
            Option::None => { break; }
        };
    };
    assert(expected_path == path, 'invalid proof path');
    (expected_hash, value)
}

#[inline]
fn node_hash(node: @TrieNode) -> felt252 {
    match node {
        TrieNode::Binary(binary) => pedersen_hash(*binary.left, *binary.right),
        TrieNode::Edge(edge) => pedersen_hash(*edge.child, *edge.path) + (*edge.length).into()
    }
}

// TODO: replace with lookup table once array constants are available in Cairo
fn pow(x: felt252, n: u8) -> felt252 {
    if n == 0 {
        1
    } else if n == 1 {
        x
    } else if (n & 1) == 1 {
        x * pow(x * x, n / 2)
    } else {
        pow(x * x, n / 2)
    }
}

#[inline(always)]
fn pedersen_hash(a: felt252, b: felt252) -> felt252 {
    PedersenTrait::new(a).update(b).finalize()
}

#[inline(always)]
fn pedersen_hash_4(a: felt252, b: felt252, c: felt252, d: felt252) -> felt252 {
    PedersenTrait::new(a).update(b).update(c).update(d).finalize()
}

#[inline(always)]
fn poseidon_hash(a: felt252, b: felt252, c: felt252) -> felt252 {
    PoseidonTrait::new().update(a).update(b).update(c).finalize()
}
