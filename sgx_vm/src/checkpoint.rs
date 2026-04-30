
use std::fs;
use std::path::Path;

/// Checkpoint data stored in SGX sealed storage
#[derive(Clone, Debug)]
pub struct Checkpoint {
    /// Latest chained root hash
    pub latest_chained_root: [u8; 32],
    /// Number of blocks in chain
    pub block_count: u64,
    /// VM name
    pub vm_name: String,
    /// Last update timestamp
    pub last_updated: u64,
}

impl Checkpoint {
    /// Create a new checkpoint
    pub fn new(vm_name: String) -> Self {
        Self {
            latest_chained_root: [0u8; 32],
            block_count: 0,
            vm_name,
            last_updated: current_timestamp(),
        }
    }

    /// Update checkpoint with new block
    pub fn update(&mut self, chained_root: [u8; 32], block_count: u64) {
        self.latest_chained_root = chained_root;
        self.block_count = block_count;
        self.last_updated = current_timestamp();
    }

    /// Get chained root as hex
    pub fn chained_root_hex(&self) -> String {
        hex::encode(self.latest_chained_root)
    }

    /// Serialize checkpoint to bytes
    /// Format: [32 bytes root][8 bytes count][8 bytes timestamp][vm_name]
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&self.latest_chained_root);
        bytes.extend_from_slice(&self.block_count.to_le_bytes());
        bytes.extend_from_slice(&self.last_updated.to_le_bytes());
        bytes.extend_from_slice(self.vm_name.as_bytes());
        bytes
    }

    /// Deserialize checkpoint from bytes
    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        if bytes.len() < 48 {
            return None;
        }

        let mut root = [0u8; 32];
        root.copy_from_slice(&bytes[0..32]);

        let count = u64::from_le_bytes([
            bytes[32], bytes[33], bytes[34], bytes[35],
            bytes[36], bytes[37], bytes[38], bytes[39],
        ]);

        let timestamp = u64::from_le_bytes([
            bytes[40], bytes[41], bytes[42], bytes[43],
            bytes[44], bytes[45], bytes[46], bytes[47],
        ]);

        let vm_name = String::from_utf8_lossy(&bytes[48..]).to_string();

        Some(Self {
            latest_chained_root: root,
            block_count: count,
            vm_name,
            last_updated: timestamp,
        })
    }
}

pub struct SealedStorage {
    /// Path to sealed data file
    path: String,
    /// Sealing key (in real SGX, derived from CPU)
    seal_key: [u8; 32],
}

impl SealedStorage {
    /// Create sealed storage manager
    pub fn new(path: &str) -> Self {
        // In real SGX: key derived from EGETKEY
        // For simulation: use fixed key (NOT SECURE - demo only)
        let seal_key = derive_seal_key();
        
        Self {
            path: path.to_string(),
            seal_key,
        }
    }

    /// Seal and save checkpoint
    pub fn save(&self, checkpoint: &Checkpoint) -> Result<(), SealError> {
        let plaintext = checkpoint.to_bytes();
        
        // Compute HMAC for integrity
        let mac = compute_hmac(&self.seal_key, &plaintext);
        
        // In real SGX: use sgx_seal_data
        // For simulation: store plaintext + MAC
        let mut sealed = Vec::new();
        sealed.extend_from_slice(&mac);
        sealed.extend_from_slice(&plaintext);
        
        // Write to file
        fs::write(&self.path, &sealed)
            .map_err(|e| SealError::IoError(e.to_string()))?;
        
        println!("[SGX-SEAL] Checkpoint saved: block={}, root={}...",
            checkpoint.block_count,
            &checkpoint.chained_root_hex()[..16]
        );
        
        Ok(())
    }

    /// Load and unseal checkpoint
    pub fn load(&self) -> Result<Option<Checkpoint>, SealError> {
        let path = Path::new(&self.path);
        if !path.exists() {
            return Ok(None);
        }
        
        let sealed = fs::read(&self.path)
            .map_err(|e| SealError::IoError(e.to_string()))?;
        
        if sealed.len() < 32 {
            return Err(SealError::InvalidData("Too short".to_string()));
        }
        
        let stored_mac = &sealed[0..32];
        let plaintext = &sealed[32..];
        
        // Verify HMAC
        let computed_mac = compute_hmac(&self.seal_key, plaintext);
        if stored_mac != computed_mac {
            return Err(SealError::TamperingDetected);
        }
        
        // Deserialize
        let checkpoint = Checkpoint::from_bytes(plaintext)
            .ok_or_else(|| SealError::InvalidData("Parse failed".to_string()))?;
        
        println!("[SGX-SEAL] Checkpoint loaded: block={}, root={}...",
            checkpoint.block_count,
            &checkpoint.chained_root_hex()[..16]
        );
        
        Ok(Some(checkpoint))
    }

    /// Verify database matches checkpoint
    pub fn verify_against_db(
        &self,
        db_block_count: u64,
        db_latest_root: &str,
    ) -> VerifyResult {
        let checkpoint = match self.load() {
            Ok(Some(cp)) => cp,
            Ok(None) => return VerifyResult::NoCheckpoint,
            Err(e) => return VerifyResult::LoadError(format!("{:?}", e)),
        };

        // Check block count
        if db_block_count != checkpoint.block_count {
            return VerifyResult::BlockCountMismatch {
                checkpoint: checkpoint.block_count,
                database: db_block_count,
            };
        }

        // Check root hash
        let cp_root = checkpoint.chained_root_hex();
        if db_latest_root != cp_root {
            return VerifyResult::RootMismatch {
                checkpoint: cp_root,
                database: db_latest_root.to_string(),
            };
        }

        VerifyResult::Valid
    }
}

/// Verification result
#[derive(Debug, Clone)]
pub enum VerifyResult {
    Valid,
    NoCheckpoint,
    LoadError(String),
    BlockCountMismatch { checkpoint: u64, database: u64 },
    RootMismatch { checkpoint: String, database: String },
}

impl VerifyResult {
    pub fn is_valid(&self) -> bool {
        matches!(self, VerifyResult::Valid)
    }
    
    pub fn is_no_checkpoint(&self) -> bool {
        matches!(self, VerifyResult::NoCheckpoint)
    }
}

/// Seal errors
#[derive(Debug)]
pub enum SealError {
    IoError(String),
    InvalidData(String),
    TamperingDetected,
}

fn derive_seal_key() -> [u8; 32] {
    use sha2::{Sha256, Digest};
    
    // In production: This would be CPU-derived via EGETKEY
    // The key would be unique to this enclave and CPU
    let mut hasher = Sha256::new();
    hasher.update(b"SGX_SEAL_KEY_SIMULATION_ONLY");
    hasher.update(b"scaphandre_energy_blockchain");
    
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Compute HMAC-SHA256
fn compute_hmac(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;
    
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = HmacSha256::new_from_slice(key)
        .expect("HMAC can take key of any size");
    mac.update(data);
    
    let result = mac.finalize().into_bytes();
    let mut hmac = [0u8; 32];
    hmac.copy_from_slice(&result);
    hmac
}

/// Get current timestamp
fn current_timestamp() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_checkpoint_serialization() {
        let mut cp = Checkpoint::new("test_vm".to_string());
        cp.update([0xAB; 32], 100);
        
        let bytes = cp.to_bytes();
        let restored = Checkpoint::from_bytes(&bytes).unwrap();
        
        assert_eq!(restored.latest_chained_root, [0xAB; 32]);
        assert_eq!(restored.block_count, 100);
        assert_eq!(restored.vm_name, "test_vm");
    }

    #[test]
    fn test_sealed_storage() {
        let path = "/tmp/test_checkpoint.sealed";
        let storage = SealedStorage::new(path);
        
        let mut cp = Checkpoint::new("test_vm".to_string());
        cp.update([0xCD; 32], 50);
        
        storage.save(&cp).unwrap();
        
        let loaded = storage.load().unwrap().unwrap();
        assert_eq!(loaded.block_count, 50);
        assert_eq!(loaded.latest_chained_root, [0xCD; 32]);
        
        // Cleanup
        fs::remove_file(path).ok();
    }

    #[test]
    fn test_tamper_detection() {
        let path = "/tmp/test_tamper.sealed";
        let storage = SealedStorage::new(path);
        
        let cp = Checkpoint::new("test_vm".to_string());
        storage.save(&cp).unwrap();
        
        // Tamper with the file
        let mut data = fs::read(path).unwrap();
        if data.len() > 40 {
            data[40] ^= 0xFF; // Flip some bits
        }
        fs::write(path, &data).unwrap();
        
        // Should detect tampering
        let result = storage.load();
        assert!(matches!(result, Err(SealError::TamperingDetected)));
        
        // Cleanup
        fs::remove_file(path).ok();
    }
}
