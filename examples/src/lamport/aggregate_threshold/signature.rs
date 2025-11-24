// Copyright (c) Facebook, Inc. and its affiliates.
//
// This source code is licensed under the MIT license found in the
// LICENSE file in the root directory of this source tree.

use winterfell::{
    crypto::MerkleTree,
    math::{fields::f128::BaseElement, FieldElement},
};

use crate::{
    lamport::signature::PublicKey,
    utils::rescue::{Hash, Rescue128},
};

// AGGREGATED PUBLIC KEY GROUP
// ================================================================================================

/// Represents a group of public keys aggregated using a Merkle tree.
/// Each group can have its own threshold requirement for signature verification.
pub struct PublicKeyGroup {
    keys: Vec<PublicKey>,
    tree: MerkleTree<Rescue128>,
    threshold: usize,
}

impl PublicKeyGroup {
    /// Creates a new public key group with the specified keys and threshold.
    /// 
    /// # Arguments
    /// * `keys` - Vector of public keys to aggregate
    /// * `threshold` - Minimum number of valid signatures required from this group
    pub fn new(mut keys: Vec<PublicKey>, threshold: usize) -> Self {
        assert!(threshold <= keys.len(), "Threshold cannot exceed number of keys");
        assert!(threshold > 0, "Threshold must be at least 1");
        
        // sort keys in ascending order
        keys.sort();

        // convert keys to hashes; each key is hashed using Rescue hash function
        let mut leaves: Vec<Hash> = Vec::new();
        for key in keys.iter() {
            leaves.push(Rescue128::digest(&key.to_elements()));
        }

        // pad the list of keys with zero keys to make sure the number of leaves is greater than
        // the number of keys and is a power of two
        let num_leaves = if leaves.len().is_power_of_two() {
            (leaves.len() + 1).next_power_of_two()
        } else {
            leaves.len().next_power_of_two()
        };
        let zero_hash = Rescue128::digest(&[BaseElement::ZERO, BaseElement::ZERO]);
        for _ in leaves.len()..num_leaves {
            leaves.push(zero_hash);
        }

        // build a Merkle tree of all leaves
        let tree = MerkleTree::new(leaves).unwrap();

        PublicKeyGroup { keys, tree, threshold }
    }

    /// Returns the Merkle root of this group's aggregated public keys.
    pub fn root(&self) -> Hash {
        *self.tree.root()
    }

    /// Returns the threshold for this group.
    pub fn threshold(&self) -> usize {
        self.threshold
    }

    /// Returns the number of individual keys in this group.
    pub fn num_keys(&self) -> usize {
        self.keys.len()
    }

    /// Returns number of leaves in the Merkle tree (always a power of two).
    pub fn num_leaves(&self) -> usize {
        self.tree.leaves().len()
    }

    /// Returns an individual key at the specified index, if one exists.
    pub fn get_key(&self, index: usize) -> Option<PublicKey> {
        if index < self.keys.len() {
            Some(self.keys[index])
        } else {
            None
        }
    }

    /// Returns a Merkle path to the specified leaf.
    pub fn get_leaf_path(&self, index: usize) -> Vec<Hash> {
        let (leaf, path) = self.tree.prove(index).unwrap();
        let mut result = vec![leaf];
        result.extend_from_slice(&path);
        result
    }
}

// MULTI-GROUP AGGREGATED KEY
// ================================================================================================

/// Represents multiple public key groups, each with its own threshold requirement.
/// The groups themselves are aggregated into a Merkle tree.
pub struct MultiGroupPublicKey {
    groups: Vec<PublicKeyGroup>,
    group_tree: MerkleTree<Rescue128>,
}

impl MultiGroupPublicKey {
    /// Creates a new multi-group public key from a vector of groups.
    pub fn new(groups: Vec<PublicKeyGroup>) -> Self {
        assert!(!groups.is_empty(), "Must have at least one group");

        // build leaves from group roots
        let mut leaves: Vec<Hash> = groups.iter().map(|g| g.root()).collect();

        // pad to power of two
        let num_leaves = if leaves.len().is_power_of_two() {
            (leaves.len() + 1).next_power_of_two()
        } else {
            leaves.len().next_power_of_two()
        };
        let zero_hash = Rescue128::digest(&[BaseElement::ZERO, BaseElement::ZERO]);
        for _ in leaves.len()..num_leaves {
            leaves.push(zero_hash);
        }

        // build Merkle tree of group roots
        let group_tree = MerkleTree::new(leaves).unwrap();

        MultiGroupPublicKey { groups, group_tree }
    }

    /// Returns the root hash of all groups.
    pub fn root(&self) -> Hash {
        *self.group_tree.root()
    }

    /// Returns the number of groups.
    pub fn num_groups(&self) -> usize {
        self.groups.len()
    }

    /// Returns a reference to a specific group.
    pub fn get_group(&self, index: usize) -> Option<&PublicKeyGroup> {
        self.groups.get(index)
    }

    /// Returns the Merkle path for a group.
    pub fn get_group_path(&self, index: usize) -> Vec<Hash> {
        let (leaf, path) = self.group_tree.prove(index).unwrap();
        let mut result = vec![leaf];
        result.extend_from_slice(&path);
        result
    }

    /// Returns the number of leaves in the group tree.
    pub fn num_group_leaves(&self) -> usize {
        self.group_tree.leaves().len()
    }
}
