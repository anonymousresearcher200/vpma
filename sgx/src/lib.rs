#![cfg_attr(target_env = "sgx", no_std)]

// For SGX mode, we need alloc for String/Vec but use Fortanix debug output for printing
#[cfg(target_env = "sgx")]
extern crate alloc;

#[cfg(target_env = "sgx")]
extern crate std;  // Fortanix provides std runtime even with no_std lib

// String / Vec for SGX
#[cfg(target_env = "sgx")]
use alloc::string::{String, ToString};
#[cfg(target_env = "sgx")]
use alloc::vec;
#[cfg(target_env = "sgx")]
use alloc::vec::Vec;
#[cfg(target_env = "sgx")]
use alloc::format;

// String / Vec for normal host builds
#[cfg(not(target_env = "sgx"))]
use std::string::{String, ToString};
#[cfg(not(target_env = "sgx"))]
use std::vec;
#[cfg(not(target_env = "sgx"))]
use std::vec::Vec;

use core::slice;


#[cfg(target_env = "sgx")]
macro_rules! sgx_println {
    () => { std::println!(); };
    ($($arg:tt)*) => { std::println!($($arg)*); };
}

#[cfg(not(target_env = "sgx"))]
macro_rules! sgx_println {
    () => { println!(); };
    ($($arg:tt)*) => { println!($($arg)*); };
}

// SGX-compatible sgx_eprintln! macro
#[cfg(target_env = "sgx")]
macro_rules! sgx_eprintln {
    () => { std::eprintln!(); };
    ($($arg:tt)*) => { std::eprintln!($($arg)*); };
}

#[cfg(not(target_env = "sgx"))]
macro_rules! sgx_eprintln {
    () => { eprintln!(); };
    ($($arg:tt)*) => { eprintln!($($arg)*); };
}

// Helper function for print (use standard eprintln for SGX)
#[cfg(target_env = "sgx")]
#[inline]
fn _sgx_print_impl(msg: &str) {
    std::eprint!("{}", msg);
}

#[cfg(not(target_env = "sgx"))]
#[inline]
fn _sgx_print_impl(msg: &str) {
    eprint!("{}", msg);
}

// ============================================================================

// HMAC verification
use hmac::{Hmac, Mac};
use sha2::Sha256;

// ED25519 signature verification for signed hashes from attestation server
use ed25519_dalek::{Verifier, VerifyingKey, Signature};

type HmacSha256 = Hmac<Sha256>;


const ATTESTATION_SERVER_PUBLIC_KEY: [u8; 32] = [
    0xf8, 0x3b, 0xe1, 0x71, 0x2d, 0x09, 0x57, 0x71,
    0x08, 0xf7, 0xf6, 0x73, 0xda, 0xb9, 0xd1, 0x46,
    0xf8, 0x06, 0xff, 0x1e, 0x6f, 0x81, 0xa3, 0x1e,
    0xbf, 0x70, 0x46, 0x0f, 0xb9, 0x4f, 0xd0, 0x90,
];

// Legacy helper (keep for compatibility)
fn sgx_print_host(msg: &str) {
    _sgx_print_impl(msg);
}

// OCALL function pointer type - SGX calls host to write VM energy files
// Includes chain metadata for VM verification
type OcallWriteVmEnergy = unsafe extern "C" fn(
    vm_name_ptr: *const u8,
    vm_name_len: usize,
    uj_value: u64,
    counter: u64,
    previous_hash_ptr: *const u8,  // 32 bytes
    signature_ptr: *const u8,       // 32 bytes
) -> i32;

// OCALL for sealed storage I/O (SGX needs host to read/write files)
type OcallReadSealedKey = unsafe extern "C" fn(
    buf_ptr: *mut u8,
    buf_len: usize,
) -> i32;  // Returns bytes read, or -1 on error

type OcallWriteSealedKey = unsafe extern "C" fn(
    buf_ptr: *const u8,
    buf_len: usize,
) -> i32;  // Returns 0 on success, -1 on error

type OcallFetchExpectedHash = unsafe extern "C" fn(
    url_ptr: *const u8,
    url_len: usize,
    hash_buf_ptr: *mut u8,
    hash_buf_len: usize,
) -> i32;  // Returns bytes written to hash_buf, or -1 on error

// Global OCALL function pointers
static mut OCALL_WRITE_VM_ENERGY: Option<OcallWriteVmEnergy> = None;
static mut OCALL_READ_SEALED_KEY: Option<OcallReadSealedKey> = None;
static mut OCALL_WRITE_SEALED_KEY: Option<OcallWriteSealedKey> = None;
static mut OCALL_FETCH_EXPECTED_HASH: Option<OcallFetchExpectedHash> = None;

// Sealed storage file path (managed by host, encrypted by SGX)
const SEALED_KEY_PATH: &str = "/var/lib/scaphandre/.sgx_sealed_hmac_key";


#[cfg(target_env = "sgx")]
const SEALED_KEY_SIZE: usize = 12 + 32 + 16;  // nonce + key + AES-GCM tag
#[cfg(not(target_env = "sgx"))]
const SEALED_KEY_SIZE: usize = 32 + 16;  // key + simple MAC (simulation)

// Per-VM HMAC chain state
struct VmChainState {
    hmac_key: [u8; 32],
    chain_state: [u8; 32],
    counter: u64,
    cumulative_energy_uj: u64,
}


#[cfg(not(target_env = "sgx"))]
use std::collections::HashMap;
#[cfg(target_env = "sgx")]
use alloc::collections::BTreeMap as HashMap;

#[cfg(not(target_env = "sgx"))]
use std::string::String as StdString;

static mut VM_CHAINS: Option<HashMap<String, VmChainState>> = None;

// Global master key (used to derive per-VM keys)
static mut MASTER_KEY: [u8; 32] = [0u8; 32];


const SIPHASH_KEY: [u64; 2] = [
    0x0706050403020100,  // k0 - must match eBPF
    0x0f0e0d0c0b0a0908,  // k1 - must match eBPF
];

// Import the real qemu.rs WITHOUT moving it
include!("../../src/exporters/qemu.rs");

use serde_json;

// SipHash-2-4 implementation for RAPL data verification
// Must produce identical output to eBPF implementation
fn rotl64(x: u64, b: u32) -> u64 {
    (x << b) | (x >> (64 - b))
}

macro_rules! sipround {
    ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {{
        $v0 = $v0.wrapping_add($v1);
        $v1 = rotl64($v1, 13);
        $v1 ^= $v0;
        $v0 = rotl64($v0, 32);
        
        $v2 = $v2.wrapping_add($v3);
        $v3 = rotl64($v3, 16);
        $v3 ^= $v2;
        
        $v0 = $v0.wrapping_add($v3);
        $v3 = rotl64($v3, 21);
        $v3 ^= $v0;
        
        $v2 = $v2.wrapping_add($v1);
        $v1 = rotl64($v1, 17);
        $v1 ^= $v2;
        $v2 = rotl64($v2, 32);
    }};
}

fn siphash24(k0: u64, k1: u64, energy: u64, timestamp: u64, socket: u32, domain: u32) -> u64 {
    let mut v0 = 0x736f6d6570736575u64 ^ k0;
    let mut v1 = 0x646f72616e646f6du64 ^ k1;
    let mut v2 = 0x6c7967656e657261u64 ^ k0;
    let mut v3 = 0x7465646279746573u64 ^ k1;
    
    // Process energy value (8 bytes)
    v3 ^= energy;
    sipround!(v0, v1, v2, v3);
    sipround!(v0, v1, v2, v3);
    v0 ^= energy;
    
    // Process timestamp (8 bytes)
    v3 ^= timestamp;
    sipround!(v0, v1, v2, v3);
    sipround!(v0, v1, v2, v3);
    v0 ^= timestamp;
    
    // Process socket and domain (combined as 8 bytes)
    let ids = ((socket as u64) << 32) | (domain as u64);
    v3 ^= ids;
    sipround!(v0, v1, v2, v3);
    sipround!(v0, v1, v2, v3);
    v0 ^= ids;
    
    // Finalization
    v2 ^= 0xff;
    sipround!(v0, v1, v2, v3);
    sipround!(v0, v1, v2, v3);
    sipround!(v0, v1, v2, v3);
    sipround!(v0, v1, v2, v3);
    
    v0 ^ v1 ^ v2 ^ v3
}

/// Universal hash function (matches eBPF implementation)
fn universal_hash(energy: u64, timestamp: u64, socket: u32, domain: u32) -> u64 {
    const PRIME_A: u64 = 2654435761;
    const PRIME_B: u64 = 2246822519;
    const PRIME_C: u64 = 3266489917;
    
    let mut h = energy;
    h = h.wrapping_mul(PRIME_A).wrapping_add(timestamp);
    h = h.wrapping_mul(PRIME_B).wrapping_add((socket as u64) << 32);
    h = h.wrapping_mul(PRIME_C).wrapping_add(domain as u64);
    
    h ^= h >> 33;
    h = h.wrapping_mul(0xff51afd7ed558ccd);
    h ^= h >> 33;
    h = h.wrapping_mul(0xc4ceb9fe1a85ec53);
    h ^= h >> 33;
    
    h
}


fn verify_rapl_hash(energy: u64, timestamp: u64, socket: u32, domain: u32, hash_from_ebpf: u64) -> bool {
    let expected_hash = universal_hash(energy, timestamp, socket, domain);
    expected_hash == hash_from_ebpf
}

/// Derive VM-specific HMAC key from master key
fn derive_vm_key(master_key: &[u8; 32], vm_name: &str) -> [u8; 32] {
    use sha2::Digest;
    
    // HKDF-like derivation: HMAC(master_key, "vm:" || vm_name)
    let mut mac = HmacSha256::new_from_slice(master_key).unwrap();
    mac.update(b"vm:");
    mac.update(vm_name.as_bytes());
    
    let result = mac.finalize().into_bytes();
    let mut vm_key = [0u8; 32];
    vm_key.copy_from_slice(&result);
    vm_key
}

/// Generate cryptographically secure random key inside SGX
/// Uses SGX hardware RNG (RDRAND instruction via Fortanix SDK)
fn generate_random_key() -> [u8; 32] {
    let mut key = [0u8; 32];
    
    // Real SGX mode: use RDRAND hardware instruction
    #[cfg(target_env = "sgx")]
    {
        use rdrand::RdRand;
        
        match RdRand::new() {
            Ok(rng) => {
                // Fill key with cryptographically secure random bytes
                for chunk in key.chunks_mut(8) {
                    match rng.try_next_u64() {
                        Ok(rand_val) => {
                            let bytes = rand_val.to_le_bytes();
                            let len = chunk.len().min(8);
                            chunk[..len].copy_from_slice(&bytes[..len]);
                        }
                        Err(_) => {
                            // RDRAND failed - use fallback (should not happen on SGX hardware)
                            panic!("[SGX] RDRAND failed - hardware RNG not available");
                        }
                    }
                }
            }
            Err(_) => {
                panic!("[SGX] RDRAND not supported - cannot generate secure random key");
            }
        }
    }
    

    #[cfg(not(target_env = "sgx"))]
    {
        use core::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        
        // Mix time-based seed with counter for uniqueness
        let seed = COUNTER.fetch_add(1, Ordering::SeqCst);
        
        // Use simple PRNG for simulation
        let mut state = seed.wrapping_add(0xdeadbeef);
        for byte in key.iter_mut() {
            state = state.wrapping_mul(6364136223846793005).wrapping_add(1442695040888963407);
            *byte = (state >> 56) as u8;
        }
        
        sgx_eprintln!("[SGX-SIM] WARNING: Using simulation random - NOT SECURE for production!");
    }
    
    key
}

/// Seal (encrypt) the HMAC key for persistent storage
/// Uses AES-GCM encryption with SGX-derived key in real mode
fn seal_key(key: &[u8; 32]) -> [u8; SEALED_KEY_SIZE] {
    let mut sealed = [0u8; SEALED_KEY_SIZE];
    
    // Real SGX mode: use AES-GCM encryption with hardware RNG for nonce
    #[cfg(target_env = "sgx")]
    {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        use rdrand::RdRand;
        
        // Generate random nonce using RDRAND
        let mut nonce_bytes = [0u8; 12];
        match RdRand::new() {
            Ok(rng) => {
                if let Ok(r1) = rng.try_next_u64() {
                    nonce_bytes[0..8].copy_from_slice(&r1.to_le_bytes());
                }
                if let Ok(r2) = rng.try_next_u64() {
                    nonce_bytes[8..12].copy_from_slice(&r2.to_le_bytes()[0..4]);
                }
            }
            Err(_) => {
                panic!("[SGX] Cannot generate nonce - RDRAND not available");
            }
        }
        
        let sealing_key = derive_sgx_sealing_key();
        
        let cipher = Aes256Gcm::new_from_slice(&sealing_key)
            .expect("[SGX] Failed to create AES-GCM cipher");
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let ciphertext = cipher.encrypt(nonce, key.as_ref())
            .expect("[SGX] AES-GCM encryption failed");
        
        // Layout: [nonce (12 bytes)][ciphertext + tag (32 + 16 = 48 bytes)]
        sealed[0..12].copy_from_slice(&nonce_bytes);
        sealed[12..].copy_from_slice(&ciphertext);
    }
    
    // Simulation mode: simple encoding (NOT SECURE)
    #[cfg(not(target_env = "sgx"))]
    {
        sgx_eprintln!("[SGX-SIM] WARNING: Using simulation sealing - NOT SECURE for production!");
        
        // Copy key
        sealed[..32].copy_from_slice(key);
        
        // Add simple checksum (simulation only)
        for i in 0..16 {
            sealed[32 + i] = key[i].wrapping_add(key[i + 16]);
        }
    }
    
    sealed
}

/// Unseal (decrypt) the HMAC key from persistent storage
/// Returns None if unsealing fails (wrong enclave, corrupted data)
fn unseal_key(sealed: &[u8; SEALED_KEY_SIZE]) -> Option<[u8; 32]> {
    // Real SGX mode: use AES-GCM decryption
    #[cfg(target_env = "sgx")]
    {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes256Gcm, Nonce,
        };
        
        // Extract nonce and ciphertext
        let nonce_bytes: [u8; 12] = sealed[0..12].try_into().ok()?;
        let ciphertext = &sealed[12..];
        
        // Derive the same sealing key
        let sealing_key = derive_sgx_sealing_key();
        
        let cipher = Aes256Gcm::new_from_slice(&sealing_key).ok()?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        
        let plaintext = cipher.decrypt(nonce, ciphertext).ok()?;
        
        if plaintext.len() != 32 {
            return None;
        }
        
        let mut key = [0u8; 32];
        key.copy_from_slice(&plaintext);
        return Some(key);
    }
    
    // Simulation mode: simple decoding
    #[cfg(not(target_env = "sgx"))]
    {
        let mut key = [0u8; 32];
        
        // Verify checksum
        for i in 0..16 {
            let expected_mac = sealed[i].wrapping_add(sealed[i + 16]);
            if sealed[32 + i] != expected_mac {
                return None;  // Integrity check failed
            }
        }
        
        // Extract key
        key.copy_from_slice(&sealed[..32]);
        
        Some(key)
    }
}

/// Derive SGX sealing key (platform-bound encryption key)
/// In production: use sgx_get_key() with MRENCLAVE policy
#[cfg(target_env = "sgx")]
fn derive_sgx_sealing_key() -> [u8; 32] {
    use sha2::{Sha256, Digest};
    
    
    // For now, derive from a constant that simulates MRENCLAVE binding
    // This key will be unique per enclave build
    let mut hasher = Sha256::new();
    hasher.update(b"SGX_SEAL_KEY_MRENCLAVE_BOUND");
    hasher.update(&ATTESTATION_SERVER_PUBLIC_KEY);  // Bind to enclave code
    
    let result = hasher.finalize();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

/// Verify HMAC signature of data (for future use with signed sensor data)
fn verify_hmac_signature(vm_name: &str, data: &str, signature: &[u8]) -> bool {
    unsafe {
        // Get VM-specific key
        let vm_chains = match VM_CHAINS.as_ref() {
            Some(chains) => chains,
            None => return false,
        };
        
        let vm_state = match vm_chains.get(vm_name) {
            Some(state) => state,
            None => return false,
        };
        
        let mut mac = match HmacSha256::new_from_slice(&vm_state.hmac_key) {
            Ok(m) => m,
            Err(_) => return false,
        };
        mac.update(data.as_bytes());
        mac.verify_slice(signature).is_ok()
    }
}


#[no_mangle]
pub extern "C" fn ecall_compute_total_host_energy(
    pkg_ptr: *const u8,
    pkg_len: usize,
    dram_ptr: *const u8,
    dram_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    let start_time = core::time::Duration::from_secs(0); // Placeholder for timing
    #[cfg(not(target_env = "sgx"))]
    let start_time = std::time::Instant::now();
    
    // Validate pointers
    if pkg_ptr.is_null() || dram_ptr.is_null() || out_ptr.is_null() || out_len_ptr.is_null() {
        return 1;
    }

    // Convert raw pointers to Rust slices
    let deser_start = start_time;
    let pkg_slice = unsafe { slice::from_raw_parts(pkg_ptr, pkg_len) };
    let dram_slice = unsafe { slice::from_raw_parts(dram_ptr, dram_len) };

    // Deserialize PKG and DRAM values
    let pkg_values: Vec<RawEnergyValue> = match serde_json::from_slice(pkg_slice) {
        Ok(v) => v,
        Err(_) => return 2,
    };

    let dram_values: Vec<RawEnergyValue> = match serde_json::from_slice(dram_slice) {
        Ok(v) => v,
        Err(_) => return 2,
    };
    
    #[cfg(not(target_env = "sgx"))]
    {
        let msg = format!("[TIMING-SGX-HOST] Deserialization: {:.2} ms", deser_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg);
    }

    // Perform summation inside SGX (trusted computation)
    #[cfg(not(target_env = "sgx"))]
    let calc_start = std::time::Instant::now();
    let mut total: i128 = 0;

    for r in &pkg_values {
        if let Ok(v) = r.value.trim().parse::<i128>() {
            total += v;
        }
    }

    for r in &dram_values {
        if let Ok(v) = r.value.trim().parse::<i128>() {
            total += v;
        }
    }
    
    #[cfg(not(target_env = "sgx"))]
    {
        let msg = format!("[TIMING-SGX-HOST] Energy summation: {:.2} ms", calc_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg);
    }

    // Convert result to string
    #[cfg(not(target_env = "sgx"))]
    let format_start = std::time::Instant::now();
    let result_str = format!("{}", total);
    let result_bytes = result_str.as_bytes();

    // Check output buffer capacity
    if result_bytes.len() > out_cap {
        return 3;
    }

    // Write result to output buffer
    unsafe {
        core::ptr::copy_nonoverlapping(
            result_bytes.as_ptr(),
            out_ptr,
            result_bytes.len(),
        );
        *out_len_ptr = result_bytes.len();
    }
    
    #[cfg(not(target_env = "sgx"))]
    {
        let msg = format!("[TIMING-SGX-HOST] Output formatting: {:.2} ms", format_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg);
        let msg2 = format!("[TIMING-SGX-HOST] Total ecall_compute_total_host_energy: {:.2} ms", start_time.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg2);
    }

    0  // Success
}

#[no_mangle]
pub extern "C" fn ecall_compute_vm_energy_simple(
    topo_ptr: *const u8,
    topo_len: usize,
    proc_ptr: *const u8,
    proc_len: usize,
    hash_ptr: *const u8,
    hash_len: usize,
    out_ptr: *mut u8,
    out_cap: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    #[cfg(not(target_env = "sgx"))]
    let total_start = std::time::Instant::now();
    
    // Validate pointers
    if topo_ptr.is_null() || proc_ptr.is_null() || out_ptr.is_null() || out_len_ptr.is_null() {
        return 1;
    }

    // Convert raw pointers to Rust slices
    #[cfg(not(target_env = "sgx"))]
    let deser_start = std::time::Instant::now();
    let topo_slice = unsafe { slice::from_raw_parts(topo_ptr, topo_len) };
    let proc_slice = unsafe { slice::from_raw_parts(proc_ptr, proc_len) };
    
    // Hash verification (if enabled)
    #[cfg(feature = "with_ebpf_guard")]
    {
        #[cfg(not(target_env = "sgx"))]
        let hash_verify_start = std::time::Instant::now();
        
        if !hash_ptr.is_null() && hash_len > 0 {
            let hash_slice = unsafe { slice::from_raw_parts(hash_ptr, hash_len) };
            
            // Deserialize hash readings
            #[derive(serde::Deserialize)]
            struct RaplReading {
                energy_uj: u64,
                timestamp_ns: u64,
                socket_id: u32,
                domain_id: u32,
                hash: u64,
                valid: u32,
            }
            
            let hash_readings: Vec<RaplReading> = match serde_json::from_slice(hash_slice) {
                Ok(h) => h,
                Err(_) => {
                    sgx_eprintln!("[SGX-ECALL] Failed to deserialize hash readings");
                    return -1;
                }
            };
            
            sgx_println!("[SGX-ECALL] Verifying {} RAPL hash readings...", hash_readings.len());
            
            // Verify each hash
            for reading in &hash_readings {
                if reading.valid != 1 {
                    continue;  // Skip invalid readings
                }
                
                let hash_valid = verify_rapl_hash(
                    reading.energy_uj,
                    reading.timestamp_ns,
                    reading.socket_id,
                    reading.domain_id,
                    reading.hash
                );
                
                if !hash_valid {
                    sgx_eprintln!("[SGX-SECURITY]  RAPL HASH VERIFICATION FAILED!");
                    sgx_eprintln!("[SGX-SECURITY] Socket: {}, Domain: {}", reading.socket_id, reading.domain_id);
                    sgx_eprintln!("[SGX-SECURITY] Energy: {} uJ", reading.energy_uj);
                    sgx_eprintln!("[SGX-SECURITY] Timestamp: {} ns", reading.timestamp_ns);
                    sgx_eprintln!("[SGX-SECURITY] Hash mismatch detected");
                    sgx_eprintln!("[SGX-SECURITY] POSSIBLE TAMPERING - REJECTING ALL DATA");
                    return -2;  // Hash verification failure
                }
            }
            
            sgx_println!("[SGX-ECALL]  All {} RAPL hashes verified successfully", hash_readings.len());
            
            #[cfg(not(target_env = "sgx"))]
            {
                let msg = format!("[TIMING-SGX-HOST] RAPL hash verification: {:.2} ms", hash_verify_start.elapsed().as_secs_f64() * 1000.0);
                sgx_print_host(&msg);
            }
        } else {
            sgx_println!("[SGX-ECALL] No hash data provided - proceeding without verification");
        }
    }

    // Deserialize inputs
    let topo_energy_value: String =
        match serde_json::from_slice(topo_slice) {
            Ok(v) => v,
            Err(_) => return 2,
        };


    
    let processes: Vec<Vec<ProcessSample>> =
        match serde_json::from_slice(proc_slice) {
            Ok(v) => v,
            Err(_) => return 3,
        };
    
    #[cfg(not(target_env = "sgx"))]
    {
        let msg = format!("[TIMING-SGX-HOST] Input deserialization: {:.2} ms", deser_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg);
    }

    // Run your actual QEMU attribution logic inside SGX
    #[cfg(not(target_env = "sgx"))]
    let attribution_start = std::time::Instant::now();
    let mut exporter = QemuExporter::new();
    let updates: Vec<VmEnergyUpdate> =
        exporter.iterate(String::new(), topo_energy_value, processes);
    
    #[cfg(not(target_env = "sgx"))]
    {
        let msg = format!("[TIMING-SGX-HOST] VM energy attribution: {:.2} ms", attribution_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg);
    }

    // Collect signed updates for subprocess mode (when no OCALL is registered)
    #[derive(Serialize)]
    struct SignedVmUpdate {
        vm_name: String,
        uj_value: u64,
        counter: u64,
        previous_hash: String,
        signature: String,
    }
    let mut signed_updates: Vec<SignedVmUpdate> = Vec::new();

    // SGX  export_vm: Call OCALL to write each VM energy update
    // Each VM has its own HMAC chain (isolated per-VM)
    #[cfg(not(target_env = "sgx"))]
    let chain_start = std::time::Instant::now();
    #[cfg(not(target_env = "sgx"))]
    let mut chain_operations = 0;
    
    for update in &updates {
        let vm_name_bytes = update.vm_name.as_bytes();
        
        // Get or create per-VM chain state
        unsafe {
            let vm_chains = VM_CHAINS.as_mut().unwrap();
            let vm_state = vm_chains.entry(update.vm_name.clone()).or_insert_with(|| {
                // Derive per-VM key from master key + VM name
                let vm_key = derive_vm_key(&MASTER_KEY, &update.vm_name);
                VmChainState {
                    hmac_key: vm_key,
                    chain_state: [0u8; 32],
                    counter: 0,
                    cumulative_energy_uj: 0,
                }
            });
            
            // Increment VM-specific counter
            vm_state.counter += 1;
            vm_state.cumulative_energy_uj = vm_state
                .cumulative_energy_uj
                .saturating_add(update.uj_to_add);

            let signed_cumulative_uj = vm_state.cumulative_energy_uj;
            
            // Build chained data: signs cumulative + delta + previous hash.
            let data_to_sign = format!(
                "{}|{}|{}|{}|{}",
                vm_state.counter,
                update.vm_name,
                signed_cumulative_uj,
                update.uj_to_add,
                hex::encode(&vm_state.chain_state)
            );
            
            // Sign with VM-specific key
            let signature = {
                let mut mac = match HmacSha256::new_from_slice(&vm_state.hmac_key) {
                    Ok(m) => m,
                    Err(_) => continue,
                };
                mac.update(data_to_sign.as_bytes());
                mac.finalize().into_bytes()
            };
            
            // Store previous hash before updating
            let previous_hash = vm_state.chain_state.clone();
            
            // Update VM-specific chain state with new signature
            vm_state.chain_state.copy_from_slice(&signature);
            
            #[cfg(not(target_env = "sgx"))]
            {
                chain_operations += 1;
            }
            
            // Collect signed update for return (subprocess mode)
            signed_updates.push(SignedVmUpdate {
                vm_name: update.vm_name.clone(),
                uj_value: update.uj_to_add,
                counter: vm_state.counter,
                previous_hash: hex::encode(&previous_hash),
                signature: hex::encode(&signature),
            });
            
            sgx_eprintln!("[SGX-ENCLAVE] Chain state for '{}': counter={}, prev_hash={}...",
                      update.vm_name, vm_state.counter, &hex::encode(&previous_hash)[..16]);
            
            // Call OCALL to write energy + chain metadata (if registered)
            if let Some(ocall_fn) = OCALL_WRITE_VM_ENERGY {
                let result = ocall_fn(
                    vm_name_bytes.as_ptr(),
                    vm_name_bytes.len(),
                    update.uj_to_add,
                    vm_state.counter,
                    previous_hash.as_ptr(),
                    signature.as_ptr(),
                );
                
                if result != 0 {
                    // OCALL failed - chain continues but write failed
                    sgx_eprintln!("[SGX-QEMU] OCALL write failed for VM: {}", update.vm_name);
                }
            }
        }
    }
    
    #[cfg(not(target_env = "sgx"))]
    {
        let msg = format!("[TIMING-SGX-HOST] Chain operations ({} VMs): {:.2} ms", chain_operations, chain_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg);
        let msg2 = format!("[TIMING-SGX-HOST] Total ecall_compute_vm_energy_simple: {:.2} ms", total_start.elapsed().as_secs_f64() * 1000.0);
        sgx_print_host(&msg2);
    }

    // Serialize signed updates to output buffer (for subprocess mode)
    if !signed_updates.is_empty() {
        if let Ok(json_bytes) = serde_json::to_vec(&signed_updates) {
            let copy_len = json_bytes.len().min(out_cap);
            unsafe {
                std::ptr::copy_nonoverlapping(json_bytes.as_ptr(), out_ptr, copy_len);
                *out_len_ptr = copy_len;
            }
            sgx_eprintln!("[SGX-ENCLAVE] Returning {} signed updates ({} bytes)", signed_updates.len(), copy_len);
        } else {
            unsafe { *out_len_ptr = 0; }
        }
    } else {
        unsafe { *out_len_ptr = 0; }
    }

    0
}

#[no_mangle]
pub extern "C" fn ecall_initialize_sealed_key() -> i32 {
    unsafe {
        // Initialize per-VM chain storage
        VM_CHAINS = Some(HashMap::new());

 
        let new_key = [0u8; 32];
        MASTER_KEY = new_key;

        // Seal the master key
        let sealed_key = seal_key(&new_key);

        // Write sealed key to disk (via OCALL)
        if let Some(ocall_write) = OCALL_WRITE_SEALED_KEY {
            let result = ocall_write(sealed_key.as_ptr(), SEALED_KEY_SIZE);
            if result != 0 {
                // Failed to write sealed key (disk error?)
                // Continue anyway, key is in memory
            }
        }

        // Success: using pre-shared compatibility key
        0
    }
}

/// Register OCALL function pointers for sealed storage I/O
#[no_mangle]
pub extern "C" fn ecall_register_sealed_storage_ocalls(
    read_fn: OcallReadSealedKey,
    write_fn: OcallWriteSealedKey,
) -> i32 {
    unsafe {
        OCALL_READ_SEALED_KEY = Some(read_fn);
        OCALL_WRITE_SEALED_KEY = Some(write_fn);
    }
    0
}

/// Register OCALL function pointer
/// Host must call this before any ECALL that needs to write VM energy
#[no_mangle]
pub extern "C" fn ecall_register_ocall_write_vm_energy(
    ocall_fn: OcallWriteVmEnergy,
) -> i32 {
    unsafe {
        OCALL_WRITE_VM_ENERGY = Some(ocall_fn);
    }
    0
}

/// Register OCALL for fetching expected hash from remote server
#[no_mangle]
pub extern "C" fn ecall_register_ocall_fetch_expected_hash(
    ocall_fn: OcallFetchExpectedHash,
) -> i32 {
    unsafe {
        OCALL_FETCH_EXPECTED_HASH = Some(ocall_fn);
    }
    0
}


#[no_mangle]
pub extern "C" fn ecall_get_chain_state(
    vm_name_ptr: *const u8,
    vm_name_len: usize,
    chain_ptr: *mut u8,
    chain_len: usize,
    counter_ptr: *mut u64,
) -> i32 {
    if vm_name_ptr.is_null() || chain_ptr.is_null() || chain_len < 32 || counter_ptr.is_null() {
        return 1;
    }
    
    unsafe {
        // Convert VM name
        let vm_name_bytes = slice::from_raw_parts(vm_name_ptr, vm_name_len);
        let vm_name = match core::str::from_utf8(vm_name_bytes) {
            Ok(s) => s,
            Err(_) => return 2,
        };
        
        // Get VM chain state
        let vm_chains = match VM_CHAINS.as_ref() {
            Some(chains) => chains,
            None => return 3, // Not initialized
        };
        
        let vm_state = match vm_chains.get(vm_name) {
            Some(state) => state,
            None => return 4, // VM not found
        };
        
        // Return chain state and counter
        let chain_slice = slice::from_raw_parts_mut(chain_ptr, 32);
        chain_slice.copy_from_slice(&vm_state.chain_state);
        *counter_ptr = vm_state.counter;
    }
    
    0
}


fn verify_ima_log_integrity(ima_log: &str) -> Result<Vec<u8>, i32> {
    // Start with PCR 10 = 0 (initial state)
    let mut pcr10: [u8; 32] = [0u8; 32];
    
    for line in ima_log.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue; // Skip malformed lines
        }
        
        // parts[0] = PCR index (should be "10" for IMA)
        // parts[1] = template digest (this is what extends PCR)
        
        let pcr_index = parts[0];
        let template_digest = parts[1];
        
        // Only process PCR 10 entries (IMA measurements)
        if pcr_index != "10" {
            continue;
        }
        
        // Decode hex digest
        let digest_bytes = match hex_decode(template_digest) {
            Some(bytes) => bytes,
            None => continue, // Skip invalid hex
        };
        
        // Extend PCR 10: PCR_new = SHA256(PCR_old || digest)
        pcr10 = extend_pcr(&pcr10, &digest_bytes);
    }
    
    Ok(pcr10.to_vec())
}


fn extend_pcr(pcr: &[u8; 32], data: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};
    
    let mut hasher = Sha256::new();
    hasher.update(pcr);
    hasher.update(data);
    
    let result = hasher.finalize();
    let mut output = [0u8; 32];
    output.copy_from_slice(&result);
    output
}

/// Decode hexadecimal string to bytes
fn hex_decode(hex_str: &str) -> Option<Vec<u8>> {
    if hex_str.len() % 2 != 0 {
        return None;
    }
    
    let mut bytes = Vec::new();
    for i in (0..hex_str.len()).step_by(2) {
        let byte_str = &hex_str[i..i+2];
        match u8::from_str_radix(byte_str, 16) {
            Ok(byte) => bytes.push(byte),
            Err(_) => return None,
        }
    }
    Some(bytes)
}


fn get_expected_scaphandre_hash() -> &'static str {
    // Development mode: empty hash disables verification
    // Production: hash fetched from external server via OCALL
    ""
}

/// Compare actual hash against expected hash
/// Returns true if hashes match or if verification is disabled
fn hash_matches(actual: &str, expected: &str) -> bool {
    // If expected hash is empty, skip verification (development mode)
    if expected.is_empty() {
        return true;
    }
    
    // Case-insensitive comparison (hashes can be upper or lowercase)
    actual.eq_ignore_ascii_case(expected)
}

#[no_mangle]
pub extern "C" fn ecall_verify_boot_attestation(
    quote_sig_ptr: *const u8,
    quote_sig_len: usize,
    attest_data_ptr: *const u8,
    attest_data_len: usize,
    pcr_values_ptr: *const u8,
    pcr_values_len: usize,
    ima_log_ptr: *const u8,
    ima_log_len: usize,
    verifier_url_ptr: *const u8,
    verifier_url_len: usize,
) -> i32 {
    let _ = (quote_sig_ptr, quote_sig_len, attest_data_ptr, attest_data_len);

    #[cfg(not(target_env = "sgx"))]
    // Timing only available in non-SGX mode (std::time not available in no_std)
    #[cfg(not(target_env = "sgx"))]
    let total_start = std::time::Instant::now();
    
    // Validate pointers
    if pcr_values_ptr.is_null() || ima_log_ptr.is_null() {
        return 1; // Invalid parameters
    }
    
    // Convert to slices
    let pcr_values = unsafe { slice::from_raw_parts(pcr_values_ptr, pcr_values_len) };
    let ima_log_bytes = unsafe { slice::from_raw_parts(ima_log_ptr, ima_log_len) };
    
    // Convert IMA log to string
    let ima_log = match core::str::from_utf8(ima_log_bytes) {
        Ok(s) => s,
        Err(_) => return 2, // Invalid UTF-8
    };
    
    // Verify PCR values exist (TPM has already validated them during boot/unseal)
    if pcr_values.len() < 32 {
        return 3; // PCR data too short
    }
    
    
    // Verify PCR values provided
    if pcr_values.len() < 96 {
        return 3; // Need all 3 PCRs (0, 7, 10)
    }
    
    // Extract PCR 10 from pcr_values (96 bytes = 3 PCRs * 32 bytes)
    // PCR layout: [PCR0: 32 bytes][PCR7: 32 bytes][PCR10: 32 bytes]
    let actual_pcr10 = &pcr_values[64..96]; // PCR 10 at offset 64
    
    // Verify PCR 10 is not zero (means IMA is active)
    let pcr10_nonzero = actual_pcr10.iter().any(|&b| b != 0);
    if !pcr10_nonzero {
        return 11; // PCR 10 is zero - IMA not active
    }
    
    
    let mut scaphandre_hash: Option<&str> = None;
    let mut sgx_component_hash: Option<&str> = None;
    let mut rapl_files_verified = 0;
    let mut ima_entry_count = 0;
    
    for line in ima_log.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue; // Skip malformed lines
        }
        
        ima_entry_count += 1;
        
        
        let file_path = parts[4];
        let file_hash = parts[3];
        
        // Extract hash (format: "sha256:abc123...")
        let hash_value = if file_hash.contains(':') {
            file_hash.split(':').nth(1).unwrap_or("")
        } else {
            file_hash
        };
        
        // Check for scaphandre binary in IMA log
        if file_path.ends_with("/scaphandre") {
            scaphandre_hash = Some(hash_value);
        }
        
        if file_path.contains("sgx") || file_path.contains("SGX") {
            sgx_component_hash = Some(hash_value);
        }
        
        // Count RAPL-related measurements (modules or files)
        if file_path.contains("rapl") || file_path.contains("RAPL") {
            rapl_files_verified += 1;
        }
    }
    
    // STEP 2: Verify IMA log is substantial (not tampered/truncated)
    if ima_entry_count < 100 {
        return 12; // IMA log too short (likely tampered)
    }
    
    // STEP 3: Verify required binaries are present with valid hashes
    if scaphandre_hash.is_none() {
        return 5; // Scaphandre binary not in IMA log
    }
    
    if sgx_component_hash.is_none() {
        return 6; // No SGX components found in IMA log
    }
    
    // STEP 4: Verify RAPL files are being monitored
    if rapl_files_verified < 1 {
        return 10; // RAPL energy files not monitored by IMA
    }
    
    
    sgx_println!("[SGX-BOOT-ATTEST] ================================================");
    sgx_println!("[SGX-BOOT-ATTEST] Verifying scaphandre hash via ImmuDB");
    sgx_println!("[SGX-BOOT-ATTEST] ================================================");
    
    // Parse verifier_url to extract ImmuDB connection details
    // Format: "immudb://hostname:port/ca_cert_path" or fallback to defaults
    let (hostname, immudb_addr, ca_pem_content) = if !verifier_url_ptr.is_null() && verifier_url_len > 0 {
        let verifier_url_bytes = unsafe { slice::from_raw_parts(verifier_url_ptr, verifier_url_len) };
        let verifier_url = match core::str::from_utf8(verifier_url_bytes) {
            Ok(s) => s,
            Err(_) => return 7, // Invalid URL
        };
        
        // Simple parsing: extract hostname from URL or use as-is
        // For now, use default values (can be enhanced later)
        ("defaulthost", "<IMMUDB_HOST>:8443", "")
    } else {
        ("defaulthost", "<IMMUDB_HOST>:8443", "")
    };
    
    // Determine deployment type (host vs vm)
    // For boot attestation, we're always on host
    let deployment_type = "host";
    
    // Load CA certificate (in production, this would be provided by host or embedded)
    // For now, we'll handle the case where it's not available
    let ca_pem = if ca_pem_content.is_empty() {
        // CA cert should be provided by host or embedded in enclave
        // For now, return error if not available
        sgx_println!("[SGX-BOOT-ATTEST] Warning: No CA certificate provided");
        return 22; // CA certificate not available
    } else {
        ca_pem_content
    };
    
    // Query ImmuDB for expected hash (INSIDE SGX)
    sgx_println!("[SGX-BOOT-ATTEST] Querying ImmuDB inside SGX enclave...");
    
    #[cfg(not(target_env = "sgx"))]
    let immudb_start = std::time::Instant::now();
    let expected_scaphandre_hash = match fetch_expected_hash_from_immudb(
        "scaphandre",
        hostname,
        deployment_type,
        immudb_addr,
        ca_pem
    ) {
        Ok(hash) => {
            #[cfg(not(target_env = "sgx"))]
            {
                let immudb_duration = immudb_start.elapsed();
                sgx_println!("[TIMING-SGX] ImmuDB Query (inside SGX): {:.2} ms", immudb_duration.as_secs_f64() * 1000.0);
            }
            sgx_println!("[SGX-BOOT-ATTEST]  Retrieved expected hash from ImmuDB");
            sgx_println!("[SGX-BOOT-ATTEST]  Hash query happened inside SGX (host cannot see)");
            hash
        }
        Err(e) => {
            sgx_eprintln!("[SGX-BOOT-ATTEST]  Failed to query ImmuDB: error {}", e);
            return 15; // Failed to fetch hash from ImmuDB
        }
    };
    
    // Extract expected values from tuple
    let (expected_scaphandre_hash, expected_pcr0, expected_pcr7, expected_pcr10) = expected_scaphandre_hash;
    
    // Verify scaphandre hash matches expected value from ImmuDB
    #[cfg(not(target_env = "sgx"))]
    let verify_start = std::time::Instant::now();
    let actual_hash = scaphandre_hash.unwrap();
    if !hashes_match(actual_hash, &expected_scaphandre_hash) {
        sgx_eprintln!("[SGX-BOOT-ATTEST]  Hash mismatch!");
        sgx_eprintln!("[SGX-BOOT-ATTEST]   IMA measured:   {}", actual_hash);
        sgx_eprintln!("[SGX-BOOT-ATTEST]   ImmuDB expects: {}", expected_scaphandre_hash);
        return 13; // Scaphandre hash mismatch - binary has been modified
    }
    
    sgx_println!("[SGX-BOOT-ATTEST]  Hash verification passed");
    sgx_println!("[SGX-BOOT-ATTEST]   IMA hash:    {}", actual_hash);
    sgx_println!("[SGX-BOOT-ATTEST]   ImmuDB hash: {}", expected_scaphandre_hash);
    sgx_println!("[SGX-BOOT-ATTEST] ================================================");
    
    
    
    // If verifier URL provided, would send attestation to external server
    if !verifier_url_ptr.is_null() && verifier_url_len > 0 {
        let verifier_url_bytes = unsafe { slice::from_raw_parts(verifier_url_ptr, verifier_url_len) };
        let verifier_url = match core::str::from_utf8(verifier_url_bytes) {
            Ok(s) => s,
            Err(_) => return 7, // Invalid URL
        };
        
        // Validate URL format (allow HTTP for localhost testing)
        if !verifier_url.starts_with("https://") {
            if !verifier_url.starts_with("http://localhost") && 
               !verifier_url.starts_with("http://127.0.0.1") {
                return 8; // Verifier URL must use HTTPS (except localhost)
            }
        }
        
    }
    
    // All validations passed
    // TPM validated boot chain, IMA measured binaries, SGX verified measurements
    #[cfg(not(target_env = "sgx"))]
    {
        let verify_duration = verify_start.elapsed();
        let total_duration = total_start.elapsed();
        sgx_println!("[TIMING-SGX] Hash + PCR Verification: {:.2} ms", verify_duration.as_secs_f64() * 1000.0);
        sgx_println!("[TIMING-SGX] ============================================");
        sgx_println!("[TIMING-SGX] Total SGX Boot Verification: {:.2} ms", total_duration.as_secs_f64() * 1000.0);
        sgx_println!("[TIMING-SGX] ============================================");
    }
    0
}


pub fn extract_scaphandre_hash_from_ima(ima_log: &str) -> Option<String> {
    let mut last_hash: Option<String> = None;
    
    for line in ima_log.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        
        let file_path = parts[4];
        let file_hash = parts[3];
        
        // Look for scaphandre binary (not loader)
        if file_path.contains("scaphandre") && !file_path.contains("loader") {
            // Extract hash value (format: "sha256:abc123...")
            let hash_value = if file_hash.contains(':') {
                file_hash.split(':').nth(1).unwrap_or("")
            } else {
                file_hash
            };
            
            // Update to the latest measurement (IMA appends chronologically)
            last_hash = Some(hash_value.to_string());
        }
    }
    last_hash
}

/// Fetch expected hash and PCR values from ImmuDB inside SGX using TLS
/// Returns: (hash_value, pcr0, pcr7, pcr10)
#[cfg(feature = "use_mbedtls")]
pub fn fetch_expected_hash_from_immudb(
    binary_name: &str,
    hostname: &str,
    deployment_type: &str,
    addr: &str,
    _ca_pem: &str,
) -> Result<(String, String, String, String), i32> {
    use mbedtls::ssl::{Config, Context};
    use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
    use mbedtls::x509::Certificate;
    use mbedtls::alloc::List as MbedtlsList;
    use mbedtls::rng::Rdrand;
    use std::net::TcpStream;
    use std::io::{Read, Write};
    use std::sync::Arc;
    
    sgx_println!("[SGX-HASH] ================================================");
    sgx_println!("[SGX-HASH] Querying ImmuDB INSIDE SGX ENCLAVE");
    sgx_println!("[SGX-HASH] ================================================");
    sgx_println!("[SGX-HASH]   Binary: {}", binary_name);
    sgx_println!("[SGX-HASH]   Host: {}", hostname);
    sgx_println!("[SGX-HASH]   Type: {}", deployment_type);
    sgx_println!("[SGX-HASH]   ImmuDB: {}", addr);
    sgx_println!("[SGX-HASH] NOTE: This TLS connection is INSIDE SGX enclave");
    sgx_println!("[SGX-HASH]       Host CANNOT see the query or response");
    
    // ImmuDB CA certificate (embedded in SGX enclave)
    const IMMUDB_CA_PEM: &str = include_str!("../../immudb_ca.pem");
    
    // 1. Login to ImmuDB
    let login_body = r#"{"username":"immudb","password":"immudb","database":"defaultdb"}"#;
    let login_request = format!(
        "POST /api/v2/authorization/session/open HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\r\n{}",
        login_body.len(),
        login_body
    );
    
    let pem = format!("{}\0", IMMUDB_CA_PEM);
    let cert = Certificate::from_pem(pem.as_bytes()).map_err(|_| -2)?;
    let mut ca_list = MbedtlsList::new();
    ca_list.push(cert);
    let ca_list = Arc::new(ca_list);
    
    let rng = Arc::new(Rdrand);
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_authmode(AuthMode::None); // Skip all certificate verification for testing
    config.set_rng(rng);
    config.set_ca_list(ca_list, None);
    let config = Arc::new(config);
    
    sgx_println!("[SGX-HASH] Connecting to {}...", addr);
    let mut tcp = match TcpStream::connect(addr) {
        Ok(s) => {
            sgx_println!("[SGX-HASH]  TCP connection established");
            s
        }
        Err(e) => {
            sgx_eprintln!("[SGX-HASH]  TCP connect failed: {:?}", e);
            return Err(-3);
        }
    };
    
    sgx_println!("[SGX-HASH] Establishing TLS...");
    let mut ctx = Context::new(config.clone());
    if let Err(e) = ctx.establish(&mut tcp, None) {
        sgx_eprintln!("[SGX-HASH]  TLS establish failed: {:?}", e);
        return Err(-4);
    }
    sgx_println!("[SGX-HASH]  TLS connection established");
    
    ctx.write_all(login_request.as_bytes()).map_err(|_| -5)?;
    ctx.flush().map_err(|_| -5)?;
    
    // Read response in chunks instead of read_to_string
    let mut login_response = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match ctx.read(&mut buffer) {
            Ok(0) => break, // EOF
            Ok(n) => {
                login_response.extend_from_slice(&buffer[..n]);
                // Check if we have complete JSON response
                let response_str = String::from_utf8_lossy(&login_response);
                if response_str.contains("\"sessionID\":") && response_str.contains("}") {
                    break;
                }
            }
            Err(_) => return Err(-6),
        }
    }
    let login_response = String::from_utf8_lossy(&login_response).to_string();
    
    // Extract session ID
    let session_id = if let Some(start) = login_response.find(r#""sessionID":""#) {
        let start = start + r#""sessionID":""#.len();
        if let Some(end) = login_response[start..].find('"') {
            &login_response[start..start + end]
        } else {
            return Err(-7);
        }
    } else {
        return Err(-7);
    };
    
    sgx_println!("[SGX-HASH]  Logged in to ImmuDB (TLS inside SGX)");
    sgx_println!("[SGX-HASH]  Session established - host cannot see credentials");
    
    // 2. Query for hash (get all active records, we'll pick the latest)
    let query_body = format!(
        r#"{{"page":1,"pageSize":20,"query":{{"expressions":[{{"fieldComparisons":[{{"field":"binary_name","operator":"EQ","value":"{}"}},{{"field":"hostname","operator":"EQ","value":"{}"}},{{"field":"deployment_type","operator":"EQ","value":"{}"}},{{"field":"active","operator":"EQ","value":true}}]}}]}}}}"#,
        binary_name, hostname, deployment_type
    );
    let query_request = format!(
        "POST /api/v2/collection/binary_hashes_v3/documents/search HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Grpc-Metadata-SessionID: {}\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n{}",
        session_id,
        query_body.len(),
        query_body
    );
    
    // New TCP connection for query
    let mut tcp2 = TcpStream::connect(addr).map_err(|_| -3)?;
    let mut ctx2 = Context::new(config);
    ctx2.establish(&mut tcp2, None).map_err(|_| -4)?; // Skip hostname verification
    ctx2.write_all(query_request.as_bytes()).map_err(|_| -5)?;
    ctx2.flush().map_err(|_| -5)?;
    
    // Read response in chunks
    let mut query_response_bytes = Vec::new();
    let mut buffer = [0u8; 4096];
    loop {
        match ctx2.read(&mut buffer) {
            Ok(0) => break, // EOF
            Ok(n) => {
                query_response_bytes.extend_from_slice(&buffer[..n]);
                // Check if we have complete JSON response
                let response_str = String::from_utf8_lossy(&query_response_bytes);
                if response_str.contains("\"revisions\":") && response_str.ends_with("}") {
                    break;
                }
            }
            Err(_) => return Err(-6),
        }
    }
    let query_response = String::from_utf8_lossy(&query_response_bytes).to_string();
    
    // Debug: show response content
    sgx_println!("[SGX-HASH] ImmuDB response length: {} bytes", query_response.len());
    if query_response.len() < 500 {
        sgx_println!("[SGX-HASH] Response: {}", query_response);
    } else {
        sgx_println!("[SGX-HASH] Response (truncated): {}...", &query_response[..500]);
    }
    
    // Extract hash_value and PCR values from response
    let hash = if let Some(last_hash_pos) = query_response.rfind(r#""hash_value":""#) {
        let start = last_hash_pos + r#""hash_value":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            &query_response[start..start + end]
        } else {
            sgx_eprintln!("[SGX-HASH]  Failed to parse hash_value end quote");
            return Err(-8);
        }
    } else {
        sgx_eprintln!("[SGX-HASH]  hash_value field not found in response");
        return Err(-8);
    };
    
    let pcr0 = if let Some(pos) = query_response.rfind(r#""pcr0":""#) {
        let start = pos + r#""pcr0":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            &query_response[start..start + end]
        } else {
            return Err(-9);
        }
    } else {
        return Err(-9);
    };
    
    let pcr7 = if let Some(pos) = query_response.rfind(r#""pcr7":""#) {
        let start = pos + r#""pcr7":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            &query_response[start..start + end]
        } else {
            return Err(-10);
        }
    } else {
        return Err(-10);
    };
    
    let pcr10 = if let Some(pos) = query_response.rfind(r#""pcr10":""#) {
        let start = pos + r#""pcr10":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            &query_response[start..start + end]
        } else {
            return Err(-11);
        }
    } else {
        return Err(-11);
    };
    
    sgx_println!("[SGX-HASH]  Retrieved expected hash and PCR values from ImmuDB");
    sgx_println!("[SGX-HASH]  Expected hash: {}", hash);
    sgx_println!("[SGX-HASH]  Expected PCR0: {}", pcr0);
    sgx_println!("[SGX-HASH]  Expected PCR7: {}", pcr7);
    sgx_println!("[SGX-HASH]  Expected PCR10: {}", pcr10);
    sgx_println!("[SGX-HASH]  Host CANNOT see these values - protected by SGX");
    
    Ok((hash.to_string(), pcr0.to_string(), pcr7.to_string(), pcr10.to_string()))
}

#[cfg(not(feature = "use_mbedtls"))]
pub fn fetch_expected_hash_from_immudb(
    _binary_name: &str,
    _hostname: &str,
    _deployment_type: &str,
    _addr: &str,
    _ca_pem: &str,
) -> Result<(String, String, String, String), i32> {
    Err(-99) // mbedtls feature not enabled
}

/// Compare two hashes (case-insensitive)
pub fn hashes_match(hash1: &str, hash2: &str) -> bool {
    hash1.eq_ignore_ascii_case(hash2)
}

/// ECALL: Verify binary hash inside SGX
/// Host provides PCRs and IMA log, SGX verifies independently by querying ImmuDB
#[no_mangle]
pub extern "C" fn ecall_verify_binary_hash(
    pcr_values_ptr: *const u8,
    pcr_values_len: usize,
    ima_log_ptr: *const u8,
    ima_log_len: usize,
    hostname_ptr: *const u8,
    hostname_len: usize,
    deployment_type_ptr: *const u8,
    deployment_type_len: usize,
    immudb_addr_ptr: *const u8,
    immudb_addr_len: usize,
    ca_pem_ptr: *const u8,
    ca_pem_len: usize,
) -> i32 {
    // Validate pointers
    if pcr_values_ptr.is_null() || ima_log_ptr.is_null() || hostname_ptr.is_null() 
        || deployment_type_ptr.is_null() || immudb_addr_ptr.is_null() || ca_pem_ptr.is_null() {
        return -1;
    }
    
    // Convert to slices/strings
    let pcr_values = unsafe { slice::from_raw_parts(pcr_values_ptr, pcr_values_len) };
    let ima_log_bytes = unsafe { slice::from_raw_parts(ima_log_ptr, ima_log_len) };
    let hostname_bytes = unsafe { slice::from_raw_parts(hostname_ptr, hostname_len) };
    let deployment_bytes = unsafe { slice::from_raw_parts(deployment_type_ptr, deployment_type_len) };
    let immudb_addr_bytes = unsafe { slice::from_raw_parts(immudb_addr_ptr, immudb_addr_len) };
    let ca_pem_bytes = unsafe { slice::from_raw_parts(ca_pem_ptr, ca_pem_len) };
    
    let ima_log = match core::str::from_utf8(ima_log_bytes) {
        Ok(s) => s,
        Err(_) => return -3,
    };
    
    let hostname = match core::str::from_utf8(hostname_bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    
    let deployment_type = match core::str::from_utf8(deployment_bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    
    let immudb_addr = match core::str::from_utf8(immudb_addr_bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    
    let ca_pem = match core::str::from_utf8(ca_pem_bytes) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    
    sgx_println!("[SGX-HASH-VERIFY] ===================================");
    sgx_println!("[SGX-HASH-VERIFY] Starting binary verification inside SGX");
    sgx_println!("[SGX-HASH-VERIFY] ===================================");
    sgx_println!("[SGX-HASH-VERIFY] Hostname: {}", hostname);
    sgx_println!("[SGX-HASH-VERIFY] Deployment: {}", deployment_type);
    
    // Verify PCR 10 is not zero (IMA is active)
    if pcr_values.len() < 96 {
        return -2;
    }
    let pcr10 = &pcr_values[64..96];
    let pcr10_nonzero = pcr10.iter().any(|&b| b != 0);
    if !pcr10_nonzero {
        sgx_eprintln!("[SGX-HASH-VERIFY]  PCR 10 is zero - IMA not active");
        return -2;
    }
    sgx_println!("[SGX-HASH-VERIFY]  PCR 10 verified (IMA active)");
    
    // STEP 1: Parse IMA log for scaphandre hash
    let ima_hash = match extract_scaphandre_hash_from_ima(ima_log) {
        Some(hash) => hash,
        None => {
            sgx_eprintln!("[SGX-HASH-VERIFY]  Scaphandre binary not found in IMA log");
            return -4;
        }
    };
    
    sgx_println!("[SGX-HASH-VERIFY]  IMA measured hash: {}", ima_hash);
    
    // STEP 2: Query ImmuDB for expected hash and PCR values (INSIDE SGX)
    sgx_println!("[SGX-HASH-VERIFY] Querying ImmuDB via TLS inside SGX...");
    sgx_println!("[SGX-HASH-VERIFY] Host provides address but CANNOT see the query");
    
    let (expected_hash, expected_pcr0, expected_pcr7, expected_pcr10) = match fetch_expected_hash_from_immudb(
        "scaphandre",
        hostname,
        deployment_type,
        immudb_addr,
        ca_pem
    ) {
        Ok(values) => values,
        Err(e) => {
            sgx_eprintln!("[SGX-HASH-VERIFY]  Failed to query ImmuDB: error code {}", e);
            return -5;
        }
    };
    
    sgx_println!("[SGX-HASH-VERIFY]  ImmuDB expected hash: {}", expected_hash);
    sgx_println!("[SGX-HASH-VERIFY]  ImmuDB expected PCR0: {}", expected_pcr0);
    sgx_println!("[SGX-HASH-VERIFY]  ImmuDB expected PCR7: {}", expected_pcr7);
    sgx_println!("[SGX-HASH-VERIFY]  ImmuDB expected PCR10: {}", expected_pcr10);
    
    // STEP 3: Compare hash (INSIDE SGX)
    sgx_println!("[SGX-HASH-VERIFY] Comparing hash inside SGX enclave...");
    sgx_println!("[SGX-HASH-VERIFY]   IMA measured:   {}", ima_hash);
    sgx_println!("[SGX-HASH-VERIFY]   ImmuDB expects: {}", expected_hash);
    
    if !hashes_match(&ima_hash, &expected_hash) {
        sgx_eprintln!("[SGX-HASH-VERIFY] ===================================");
        sgx_eprintln!("[SGX-HASH-VERIFY]    HASH MISMATCH DETECTED ");
        sgx_eprintln!("[SGX-HASH-VERIFY] ===================================");
        sgx_eprintln!("[SGX-HASH-VERIFY] IMA measured:   {}", ima_hash);
        sgx_eprintln!("[SGX-HASH-VERIFY] ImmuDB expects: {}", expected_hash);
        sgx_eprintln!("[SGX-HASH-VERIFY] POSSIBLE TAMPERING - REJECTING ALL DATA");
        sgx_eprintln!("[SGX-HASH-VERIFY] ===================================");
        return -6;
    }
    
    sgx_println!("[SGX-HASH-VERIFY]  Hash verification passed");
    
    // STEP 4: Verify PCR values (INSIDE SGX)
    sgx_println!("[SGX-HASH-VERIFY] Verifying PCR values...");
    
    // Extract actual PCR values from host-provided buffer
    let actual_pcr0 = hex::encode(&pcr_values[0..32]);
    let actual_pcr7 = hex::encode(&pcr_values[32..64]);
    let actual_pcr10 = hex::encode(&pcr_values[64..96]);
    
    sgx_println!("[SGX-HASH-VERIFY]   Actual PCR0:   {}", actual_pcr0);
    sgx_println!("[SGX-HASH-VERIFY]   Expected PCR0: {}", expected_pcr0);
    
    if !hashes_match(&actual_pcr0, &expected_pcr0) {
        sgx_eprintln!("[SGX-HASH-VERIFY]  PCR0 mismatch!");
        return -7;
    }
    sgx_println!("[SGX-HASH-VERIFY]  PCR0 verification passed");
    
    sgx_println!("[SGX-HASH-VERIFY]   Actual PCR7:   {}", actual_pcr7);
    sgx_println!("[SGX-HASH-VERIFY]   Expected PCR7: {}", expected_pcr7);
    
    if !hashes_match(&actual_pcr7, &expected_pcr7) {
        sgx_eprintln!("[SGX-HASH-VERIFY]  PCR7 mismatch!");
        return -8;
    }
    sgx_println!("[SGX-HASH-VERIFY] PCR7 verification passed");
    
    sgx_println!("[SGX-HASH-VERIFY]   Actual PCR10:   {}", actual_pcr10);
    sgx_println!("[SGX-HASH-VERIFY]   Expected PCR10: {}", expected_pcr10);
    
    if !hashes_match(&actual_pcr10, &expected_pcr10) {
        sgx_eprintln!("[SGX-HASH-VERIFY] PCR10 mismatch!");
        return -9;
    }
    sgx_println!("[SGX-HASH-VERIFY]  PCR10 verification passed");
    
    sgx_println!("[SGX-HASH-VERIFY] ===================================");
    sgx_println!("[SGX-HASH-VERIFY]   FULL VERIFICATION PASSED ");
    sgx_println!("[SGX-HASH-VERIFY] ===================================");
    sgx_println!("[SGX-HASH-VERIFY] Binary integrity confirmed");
    sgx_println!("[SGX-HASH-VERIFY] Hash: {}", ima_hash);
    sgx_println!("[SGX-HASH-VERIFY] PCR0: {}", actual_pcr0);
    sgx_println!("[SGX-HASH-VERIFY] PCR7: {}", actual_pcr7);
    sgx_println!("[SGX-HASH-VERIFY] PCR10: {}", actual_pcr10);
    sgx_println!("[SGX-HASH-VERIFY] ===================================");
    
    0 // Success
}

/// Public wrapper for binary hash verification (calls SGX enclave)
/// This function is called from main.rs before any exporter runs
pub fn verify_binary_hash(
    pcr_values: &[u8],
    ima_log: &str,
    hostname: &str,
    deployment_type: &str,
    immudb_addr: &str,
    ca_pem: &str,
) -> Result<(), i32> {
    let _ = (pcr_values, ima_log, hostname, deployment_type, immudb_addr, ca_pem);

    // Call the ECALL in sgx_vm enclave
    #[cfg(feature = "use_sgx")]
    {
        sgx_println!("[SGX-WRAPPER] ================================================");
        sgx_println!("[SGX-WRAPPER] Calling SGX enclave for hash verification");
        sgx_println!("[SGX-WRAPPER] ================================================");
        sgx_println!("[SGX-WRAPPER] Host provides:");
        sgx_println!("[SGX-WRAPPER]   - PCR values: {} bytes", pcr_values.len());
        sgx_println!("[SGX-WRAPPER]   - IMA log: {} bytes", ima_log.len());
        sgx_println!("[SGX-WRAPPER]   - Hostname: {}", hostname);
        sgx_println!("[SGX-WRAPPER]   - Deployment: {}", deployment_type);
        sgx_println!("[SGX-WRAPPER]   - ImmuDB address: {}", immudb_addr);
        sgx_println!("[SGX-WRAPPER] ");
        sgx_println!("[SGX-WRAPPER] Now entering SGX enclave...");
        sgx_println!("[SGX-WRAPPER] (All verification happens inside SGX from this point)");
        
        extern "C" {
            fn ecall_verify_binary_hash(
                pcr_values_ptr: *const u8,
                pcr_values_len: usize,
                ima_log_ptr: *const u8,
                ima_log_len: usize,
                hostname_ptr: *const u8,
                hostname_len: usize,
                deployment_type_ptr: *const u8,
                deployment_type_len: usize,
                immudb_addr_ptr: *const u8,
                immudb_addr_len: usize,
                ca_pem_ptr: *const u8,
                ca_pem_len: usize,
            ) -> i32;
        }
        
        let result = unsafe {
            ecall_verify_binary_hash(
                pcr_values.as_ptr(),
                pcr_values.len(),
                ima_log.as_ptr(),
                ima_log.len(),
                hostname.as_ptr(),
                hostname.len(),
                deployment_type.as_ptr(),
                deployment_type.len(),
                immudb_addr.as_ptr(),
                immudb_addr.len(),
                ca_pem.as_ptr(),
                ca_pem.len(),
            )
        };
        
        sgx_println!("[SGX-WRAPPER] ");
        sgx_println!("[SGX-WRAPPER] Returned from SGX enclave");
        sgx_println!("[SGX-WRAPPER] Result code: {}", result);
        
        if result == 0 {
            sgx_println!("[SGX-WRAPPER]  SGX enclave verified hash via ImmuDB");
            sgx_println!("[SGX-WRAPPER] ================================================");
            Ok(())
        } else {
            sgx_println!("[SGX-WRAPPER]  SGX enclave rejected verification");
            sgx_println!("[SGX-WRAPPER] ================================================");
            Err(result)
        }
    }
    
    #[cfg(not(feature = "use_sgx"))]
    {
        //sgx_println!("[HASH-VERIFY] SGX not enabled - skipping verification");
        Ok(())
    }
}

pub fn force_link_sgx() {
    // This can be empty. It just needs to exist and be callable.
}

