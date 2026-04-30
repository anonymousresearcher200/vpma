
use sha2::{Sha256, Digest};

/// Energy record structure for Merkle tree leaves
#[derive(Clone, Debug)]
pub struct EnergyRecord {
    pub pid: u32,
    pub cpu_time: f64,
    pub energy_joules: f64,
    pub power_watts: f64,
    pub vm_name: String,
    pub timestamp: String,
}

impl EnergyRecord {
    /// Create a new energy record
    pub fn new(
        pid: u32,
        cpu_time: f64,
        energy_joules: f64,
        power_watts: f64,
        vm_name: String,
        timestamp: String,
    ) -> Self {
        Self {
            pid,
            cpu_time,
            energy_joules,
            power_watts,
            vm_name,
            timestamp,
        }
    }

    /// Serialize record to bytes for hashing
    pub fn to_bytes(&self) -> Vec<u8> {
        format!(
            "{}|{:.6}|{:.6}|{:.6}|{}|{}",
            self.pid,
            self.cpu_time,
            self.energy_joules,
            self.power_watts,
            self.vm_name,
            self.timestamp
        ).into_bytes()
    }
}

/// Internal node in the Merkle tree
#[derive(Clone, Debug)]
pub struct MerkleNode {
    /// Level in tree (0 = leaves, higher = toward root)
    pub level: u32,
    /// Position at this level (left to right)
    pub position: u32,
    /// Hash value
    pub hash: [u8; 32],
    /// Left child hash (None for leaves)
    pub left_child: Option<[u8; 32]>,
    /// Right child hash (None for leaves)
    pub right_child: Option<[u8; 32]>,
}

pub struct MerkleTree {
    /// Root hash of the tree
    pub root: Option<[u8; 32]>,
    /// All leaf hashes (for proof generation)
    pub leaf_hashes: Vec<[u8; 32]>,
    /// Number of original leaves (before padding)
    pub leaf_count: usize,
    /// All internal nodes by level (for O(log n) proof retrieval)
    /// Level 0 = leaves, Level 1 = first internal level, etc.
    pub internal_nodes: Vec<MerkleNode>,
    /// Tree height (number of levels including leaves)
    pub height: usize,
}

impl MerkleTree {
    pub fn build(records: &[EnergyRecord]) -> Self {
        if records.is_empty() {
            return Self {
                root: None,
                leaf_hashes: Vec::new(),
                leaf_count: 0,
                internal_nodes: Vec::new(),
                height: 0,
            };
        }

        // Create leaf hashes from records
        let mut leaf_hashes: Vec<[u8; 32]> = records
            .iter()
            .map(|record| sha256(&record.to_bytes()))
            .collect();

        let leaf_count = leaf_hashes.len();
        let mut internal_nodes = Vec::new();
        
        // Store leaf nodes (level 0)
        for (pos, hash) in leaf_hashes.iter().enumerate() {
            internal_nodes.push(MerkleNode {
                level: 0,
                position: pos as u32,
                hash: *hash,
                left_child: None,
                right_child: None,
            });
        }

        // Build tree bottom-up
        let mut current_level = leaf_hashes.clone();
        let mut level_num: u32 = 0;

        // Pad to even if necessary
        if current_level.len() % 2 == 1 {
            let last = *current_level.last().unwrap();
            current_level.push(last);
        }

        while current_level.len() > 1 {
            let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
            level_num += 1;
            
            for (pos, chunk) in current_level.chunks(2).enumerate() {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
                let parent_hash = hash_pair(&left, &right);
                next_level.push(parent_hash);
                
                // Store internal node
                internal_nodes.push(MerkleNode {
                    level: level_num,
                    position: pos as u32,
                    hash: parent_hash,
                    left_child: Some(left),
                    right_child: Some(right),
                });
            }
            
            current_level = next_level;
            
            // Pad next level if odd
            if current_level.len() > 1 && current_level.len() % 2 == 1 {
                let last = *current_level.last().unwrap();
                current_level.push(last);
            }
        }

        Self {
            root: Some(current_level[0]),
            leaf_hashes,
            leaf_count,
            internal_nodes,
            height: (level_num + 1) as usize,
        }
    }

    /// Get all nodes at a specific level
    pub fn get_nodes_at_level(&self, level: u32) -> Vec<&MerkleNode> {
        self.internal_nodes.iter()
            .filter(|n| n.level == level)
            .collect()
    }

    /// Get node at specific level and position
    pub fn get_node(&self, level: u32, position: u32) -> Option<&MerkleNode> {
        self.internal_nodes.iter()
            .find(|n| n.level == level && n.position == position)
    }

    /// Get the root hash
    pub fn root_hash(&self) -> Option<[u8; 32]> {
        self.root
    }

    /// Get root hash as hex string
    pub fn root_hash_hex(&self) -> String {
        match self.root {
            Some(hash) => hex::encode(hash),
            None => "0".repeat(64),
        }
    }

    /// Verify that a record exists in the tree at a given index
    pub fn verify_record(&self, record: &EnergyRecord, leaf_index: usize) -> bool {
        if leaf_index >= self.leaf_hashes.len() {
            return false;
        }

        let computed_hash = sha256(&record.to_bytes());
        computed_hash == self.leaf_hashes[leaf_index]
    }

    /// Generate a Merkle proof for a leaf at given index
    pub fn generate_proof(&self, leaf_index: usize) -> Option<MerkleProof> {
        if leaf_index >= self.leaf_count {
            return None;
        }

        let mut proof_hashes = Vec::new();
        let mut proof_directions = Vec::new();
        
        let mut current_index = leaf_index;
        let mut current_level = self.leaf_hashes.clone();
        
        // Pad to even if necessary
        if current_level.len() % 2 == 1 {
            let last = *current_level.last().unwrap();
            current_level.push(last);
        }

        while current_level.len() > 1 {
            // Find sibling index
            let sibling_index = if current_index % 2 == 0 {
                current_index + 1
            } else {
                current_index - 1
            };

            if sibling_index < current_level.len() {
                proof_hashes.push(current_level[sibling_index]);
                proof_directions.push(current_index % 2 == 1); // true if we're on the right
            }

            // Build next level
            let mut next_level = Vec::new();
            for chunk in current_level.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
                next_level.push(hash_pair(&left, &right));
            }
            
            current_level = next_level;
            if current_level.len() > 1 && current_level.len() % 2 == 1 {
                let last = *current_level.last().unwrap();
                current_level.push(last);
            }
            
            current_index /= 2;
        }

        Some(MerkleProof {
            leaf_hash: self.leaf_hashes[leaf_index],
            proof_hashes,
            proof_directions,
            leaf_index,
        })
    }
}

/// Merkle proof for verifying a single record
#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub leaf_hash: [u8; 32],
    pub proof_hashes: Vec<[u8; 32]>,
    pub proof_directions: Vec<bool>, // true = sibling is on left
    pub leaf_index: usize,
}

impl MerkleProof {
    /// Verify this proof against a root hash
    pub fn verify(&self, root_hash: &[u8; 32]) -> bool {
        let mut current_hash = self.leaf_hash;

        for (sibling_hash, is_left) in self.proof_hashes.iter().zip(self.proof_directions.iter()) {
            if *is_left {
                current_hash = hash_pair(sibling_hash, &current_hash);
            } else {
                current_hash = hash_pair(&current_hash, sibling_hash);
            }
        }

        current_hash == *root_hash
    }

    /// Serialize proof to JSON string
    pub fn to_json(&self) -> String {
        format!(
            r#"{{"leaf_hash":"{}","proof_hashes":[{}],"directions":[{}],"leaf_index":{}}}"#,
            hex::encode(self.leaf_hash),
            self.proof_hashes.iter().map(|h| format!("\"{}\"", hex::encode(h))).collect::<Vec<_>>().join(","),
            self.proof_directions.iter().map(|d| if *d { "true" } else { "false" }).collect::<Vec<_>>().join(","),
            self.leaf_index
        )
    }
}

/// SHA-256 hash function
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    let result = hasher.finalize();
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&result);
    hash
}

/// Hash two nodes together: SHA256(left || right)
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut combined = [0u8; 64];
    combined[..32].copy_from_slice(left);
    combined[32..].copy_from_slice(right);
    sha256(&combined)
}

/// Hash a record and return hex string
pub fn hash_record(record: &EnergyRecord) -> String {
    hex::encode(sha256(&record.to_bytes()))
}

/// Rebuild Merkle root from leaf hashes (for verification)
pub fn compute_root_from_leaves(leaf_hashes: &[[u8; 32]]) -> Option<[u8; 32]> {
    if leaf_hashes.is_empty() {
        return None;
    }

    let mut current_level: Vec<[u8; 32]> = leaf_hashes.to_vec();

    // Pad to even if necessary
    if current_level.len() % 2 == 1 {
        let last = *current_level.last().unwrap();
        current_level.push(last);
    }

    while current_level.len() > 1 {
        let mut next_level = Vec::with_capacity((current_level.len() + 1) / 2);
        
        for chunk in current_level.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };
            next_level.push(hash_pair(&left, &right));
        }
        
        current_level = next_level;
        
        if current_level.len() > 1 && current_level.len() % 2 == 1 {
            let last = *current_level.last().unwrap();
            current_level.push(last);
        }
    }

    Some(current_level[0])
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_record(pid: u32) -> EnergyRecord {
        EnergyRecord::new(
            pid,
            pid as f64 * 0.1,
            pid as f64 * 0.001,
            pid as f64 * 0.5,
            "test_vm".to_string(),
            format!("2026-02-06T10:00:{:02}Z", pid % 60),
        )
    }

    #[test]
    fn test_merkle_tree_single_record() {
        let records = vec![make_record(1)];
        let tree = MerkleTree::build(&records);
        
        assert!(tree.root.is_some());
        assert_eq!(tree.leaf_count, 1);
        assert!(tree.verify_record(&records[0], 0));
    }

    #[test]
    fn test_merkle_tree_multiple_records() {
        let records: Vec<EnergyRecord> = (1..=4).map(make_record).collect();
        let tree = MerkleTree::build(&records);
        
        assert!(tree.root.is_some());
        assert_eq!(tree.leaf_count, 4);
        
        for (i, record) in records.iter().enumerate() {
            assert!(tree.verify_record(record, i));
        }
    }

    #[test]
    fn test_merkle_proof() {
        let records: Vec<EnergyRecord> = (1..=4).map(make_record).collect();
        let tree = MerkleTree::build(&records);
        let root_hash = tree.root_hash().unwrap();
        
        for i in 0..4 {
            let proof = tree.generate_proof(i).unwrap();
            assert!(proof.verify(&root_hash), "Proof failed for leaf {}", i);
        }
    }

    #[test]
    fn test_tamper_detection() {
        let records: Vec<EnergyRecord> = (1..=4).map(make_record).collect();
        let tree = MerkleTree::build(&records);
        
        // Tampered record
        let tampered = make_record(999);
        assert!(!tree.verify_record(&tampered, 0));
    }

    #[test]
    fn test_compute_root_from_leaves() {
        let records: Vec<EnergyRecord> = (1..=4).map(make_record).collect();
        let tree = MerkleTree::build(&records);
        
        let recomputed = compute_root_from_leaves(&tree.leaf_hashes).unwrap();
        assert_eq!(tree.root_hash().unwrap(), recomputed);
    }
}
