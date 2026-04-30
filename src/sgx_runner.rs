#[cfg(feature = "use_sgx")]
use enclave_runner::EnclaveBuilder;
#[cfg(feature = "use_sgx")]
use sgxs_loaders::isgx::Device as IsgxDevice;

use std::path::Path;
use std::io::{Write, Read, BufRead, BufReader};
use std::process::{Command, Stdio};
use std::collections::HashMap;
use std::sync::Mutex;
use std::net::TcpStream;
use serde::{Deserialize, Serialize};
use hmac::{Hmac, Mac};
use sha2::Sha256;

#[cfg(feature = "use_sgx")]
use std::sync::Arc;
#[cfg(feature = "use_sgx")]
use rustls::ClientConfig;
#[cfg(feature = "use_sgx")]
use rustls::pki_types::{ServerName, CertificateDer};

/// Enclave CA certificate (embedded) - must match the enclave's certificate
#[cfg(feature = "use_sgx")]
const ENCLAVE_CA_PEM: &str = include_str!("../enclave_ca.pem");

type HmacSha256 = Hmac<Sha256>;

/// Default path to the SGX enclave binary
pub const DEFAULT_ENCLAVE_PATH: &str = "/usr/lib/scaphandre/sgx.sgxs";

/// OCALL function pointer for writing VM energy (stored by ecall_register_ocall_write_vm_energy)
/// Signature: (vm_name_ptr, vm_name_len, uj_value, counter, previous_hash_ptr, signature_ptr) -> i32
type OcallWriteVmEnergyFn = unsafe extern "C" fn(*const u8, usize, u64, u64, *const u8, *const u8) -> i32;
static mut OCALL_WRITE_VM_ENERGY: Option<OcallWriteVmEnergyFn> = None;

/// TLS stream wrapper for the enclave connection
#[cfg(feature = "use_sgx")]
enum TlsStream {
    Rustls(rustls::StreamOwned<rustls::ClientConnection, TcpStream>),
    Plain(TcpStream),  // Fallback for debugging
}

#[cfg(feature = "use_sgx")]
impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TlsStream::Rustls(s) => s.read(buf),
            TlsStream::Plain(s) => s.read(buf),
        }
    }
}

#[cfg(feature = "use_sgx")]
impl Write for TlsStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            TlsStream::Rustls(s) => s.write(buf),
            TlsStream::Plain(s) => s.write(buf),
        }
    }
    
    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            TlsStream::Rustls(s) => s.flush(),
            TlsStream::Plain(s) => s.flush(),
        }
    }
}

/// Persistent SGX enclave connection with TLS
#[cfg(feature = "use_sgx")]
struct EnclaveConnection {
    stream: TlsStream,
    child: std::process::Child,
}

#[cfg(not(feature = "use_sgx"))]
struct EnclaveConnection {
    stream: TcpStream,
    child: std::process::Child,
}

/// Global persistent enclave connection (created once, reused for all requests)
lazy_static::lazy_static! {
    static ref ENCLAVE_CONNECTION: Mutex<Option<EnclaveConnection>> = Mutex::new(None);
}

/// Per-VM hash chain state for stub mode
struct VmChainState {
    hmac_key: [u8; 32],
    chain_state: [u8; 32],
    counter: u64,
    cumulative_energy_uj: u64,
}

/// Global hash chain state (protected by Mutex for thread safety)
lazy_static::lazy_static! {
    static ref VM_CHAINS: Mutex<HashMap<String, VmChainState>> = Mutex::new(HashMap::new());
    static ref MASTER_KEY: [u8; 32] = [0u8; 32];
}

/// Derive per-VM key from master key
fn derive_vm_key(master: &[u8; 32], vm_name: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(master).expect("HMAC key");
    mac.update(b"vm:");
    mac.update(vm_name.as_bytes());
    let result = mac.finalize().into_bytes();
    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

#[derive(Serialize)]
struct VerifyRequest {
    operation: String,       // "verify"
    pcr_values: String,      // Hex-encoded PCR 0,7,10 (96 bytes = 192 hex)
    ima_hash: String,        // SHA-256 hash of IMA log (hex)
    ima_count: usize,        // Number of IMA entries
    scaphandre_hash: String, // Extracted scaphandre binary hash from IMA
    hostname: String,
    deployment_type: String,
    immudb_addr: String,
}

#[derive(Deserialize, Debug)]
struct EnclaveResponse {
    status: i32,
    message: String,
    ima_hash: Option<String>,
    #[serde(default)]
    output_data: Option<String>,
}

/// Check if SGX hardware is available (required - no fallback)
#[cfg(feature = "use_sgx")]
pub fn check_sgx_hardware() -> Result<(), String> {
    match IsgxDevice::new() {
        Ok(_) => {
            println!("[SGX] OK SGX hardware detected and available");
            Ok(())
        }
        Err(e) => {
            Err(format!(
                "SGX hardware NOT available: {:?}\n\
                 Check that:\n\
                 - SGX is enabled in BIOS\n\
                 - /dev/isgx or /dev/sgx_enclave exists\n\
                 - Intel SGX driver is loaded\n\
                 - You have permission to access the device",
                e
            ))
        }
    }
}

#[cfg(not(feature = "use_sgx"))]
pub fn check_sgx_hardware() -> Result<(), String> {
    Err("SGX feature not compiled. Build with --features use_sgx".to_string())
}

/// Get path to the enclave binary
pub fn get_enclave_path() -> Result<String, String> {
    // Try environment variable first
    if let Ok(path) = std::env::var("SGX_ENCLAVE_PATH") {
        if Path::new(&path).exists() {
            return Ok(path);
        }
    }
    
    // Try workspace target directory (when building as part of main workspace)
    let workspace_path = "target/x86_64-fortanix-unknown-sgx/release/sgx.sgxs";
    if Path::new(workspace_path).exists() {
        return Ok(workspace_path.to_string());
    }
    
    // Try local development path (standalone sgx crate build)
    let local_path = "sgx/target/x86_64-fortanix-unknown-sgx/release/sgx.sgxs";
    if Path::new(local_path).exists() {
        return Ok(local_path.to_string());
    }
    
    // Try default installed path
    if Path::new(DEFAULT_ENCLAVE_PATH).exists() {
        return Ok(DEFAULT_ENCLAVE_PATH.to_string());
    }
    
    Err(format!(
        "SGX enclave binary not found. Tried:\n\
         - $SGX_ENCLAVE_PATH environment variable\n\
         - {}\n\
         - {}\n\
         - {}\n\
         Build the enclave with: cargo build --release --target x86_64-fortanix-unknown-sgx -p sgx",
        workspace_path, local_path, DEFAULT_ENCLAVE_PATH
    ))
}

/// Extract scaphandre binary hash from IMA log
/// Calculates current binary hash and verifies it exists in IMA
fn extract_scaphandre_hash_from_ima(ima_log: &str) -> String {
    // Get the exact path of the current executable
    let current_exe = match std::env::current_exe() {
        Ok(path) => path.to_string_lossy().to_string(),
        Err(e) => {
            eprintln!("[SGX-RUNNER] Warning: Could not get current exe path: {}", e);
            return "current_exe_error".to_string();
        }
    };
    
    println!("[SGX-RUNNER] Looking for IMA entry for: {}", current_exe);
    
    // Calculate the actual hash of the current binary
    let binary_hash = match std::fs::read(&current_exe) {
        Ok(binary_data) => {
            use sha2::{Sha256, Digest};
            let mut hasher = Sha256::new();
            hasher.update(&binary_data);
            hex::encode(hasher.finalize())
        }
        Err(e) => {
            eprintln!("[SGX-RUNNER] Warning: Could not read binary to hash: {}", e);
            return "binary_read_error".to_string();
        }
    };
    
    println!("[SGX-RUNNER] Current binary hash: {}", binary_hash);
    

    let mut found_in_ima = false;
    
    for line in ima_log.lines() {
        // Match only the EXACT current binary path
        if line.ends_with(&current_exe) {
            // Parse IMA-ng format: 10 <template-hash> ima-ng <algo:hash> <path>
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() >= 4 {
                let hash_part = parts[3];  // e.g., "sha256:abc123..."
                let ima_entry_hash = if let Some(hash) = hash_part.strip_prefix("sha256:") {
                    hash
                } else if let Some(hash) = hash_part.strip_prefix("sha1:") {
                    hash
                } else {
                    hash_part
                };
                
                // Check if this IMA entry matches our current binary
                if ima_entry_hash == binary_hash {
                    found_in_ima = true;
                    println!("[SGX-RUNNER] OK Found matching IMA entry for current binary");
                    break;
                }
            }
        }
    }
    
    if found_in_ima {
        binary_hash
    } else {
        eprintln!("[SGX-RUNNER] Warning: Current binary hash not found in IMA log");
        eprintln!("[SGX-RUNNER] Binary may have changed since last measurement");
        // Return the hash anyway - the enclave will verify against ImmuDB
        binary_hash
    }
}

#[cfg(feature = "use_sgx")]
fn spawn_enclave_with_tcp(enclave_path: &str) -> Result<(TcpStream, std::process::Child), i32> {
    let runner_path = which_ftxsgx_runner();
    println!("[SGX-RUNNER] Using runner: {}", runner_path);
    println!("[SGX-RUNNER] Starting enclave process...");
    
    // Spawn the enclave process
    let mut child = match Command::new(&runner_path)
        .arg(enclave_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())  // Show enclave stderr for debugging
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[SGX-RUNNER] Failed to spawn enclave: {}", e);
            eprintln!("[SGX-RUNNER] Make sure ftxsgx-runner is installed:");
            eprintln!("[SGX-RUNNER]   cargo install fortanix-sgx-tools");
            return Err(-202);
        }
    };
    
    println!("[SGX-RUNNER] Enclave process started (PID: {})", child.id());
    
    // Read the port from stdout (enclave prints "PORT:<number>")
    let stdout = child.stdout.take().expect("Failed to get stdout");
    let mut reader = BufReader::new(stdout);
    let mut port_line = String::new();
    
    match reader.read_line(&mut port_line) {
        Ok(0) => {
            eprintln!("[SGX-RUNNER] Enclave closed without sending port");
            let _ = child.wait();
            return Err(-210);
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("[SGX-RUNNER] Failed to read port from enclave: {}", e);
            let _ = child.wait();
            return Err(-211);
        }
    }
    
    // Parse port number
    let port_str = port_line.trim();
    let port: u16 = if let Some(p) = port_str.strip_prefix("PORT:") {
        match p.parse() {
            Ok(n) => n,
            Err(e) => {
                eprintln!("[SGX-RUNNER] Invalid port number '{}': {}", p, e);
                let _ = child.wait();
                return Err(-212);
            }
        }
    } else {
        eprintln!("[SGX-RUNNER] Unexpected enclave output: {}", port_str);
        let _ = child.wait();
        return Err(-213);
    };
    
    println!("[SGX-RUNNER] Enclave listening on port {}", port);
    
    // Connect to the enclave via TCP
    let tcp_stream = match TcpStream::connect(format!("127.0.0.1:{}", port)) {
        Ok(s) => {
            let _ = s.set_nodelay(true); // Send immediately, no waiting
            s
        }
        Err(e) => {
            eprintln!("[SGX-RUNNER] Failed to connect to enclave: {}", e);
            let _ = child.wait();
            return Err(-214);
        }
    };
    
    println!("[SGX-RUNNER] Connected to enclave via TCP");
    Ok((tcp_stream, child))
}

/// Create TLS client configuration with embedded CA certificate
#[cfg(feature = "use_sgx")]
fn create_tls_config() -> Result<Arc<ClientConfig>, i32> {
    use rustls::RootCertStore;
    
    // Parse the embedded CA certificate
    let mut root_store = RootCertStore::empty();
    
    let certs = rustls_pemfile::certs(&mut ENCLAVE_CA_PEM.as_bytes())
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    
    if certs.is_empty() {
        eprintln!("[SGX-RUNNER] Failed to parse enclave CA certificate");
        return Err(-240);
    }
    
    for cert in certs {
        if let Err(e) = root_store.add(cert) {
            eprintln!("[SGX-RUNNER] Failed to add CA cert: {:?}", e);
            return Err(-241);
        }
    }
    
    println!("[SGX-RUNNER] Loaded enclave CA certificate");
    
    // Build TLS config
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    Ok(Arc::new(config))
}

/// Get or create a persistent enclave connection with TLS
/// This avoids spawning a new enclave for every request
#[cfg(feature = "use_sgx")]
fn get_enclave_connection() -> Result<std::sync::MutexGuard<'static, Option<EnclaveConnection>>, i32> {
    let mut conn_guard = ENCLAVE_CONNECTION.lock().unwrap();
    
    // Check if we already have a connection
    if conn_guard.is_some() {
        return Ok(conn_guard);
    }
    
    // Need to create a new connection
    println!("[SGX-RUNNER] Creating persistent TLS enclave connection...");
    
    let enclave_path = match get_enclave_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[SGX-RUNNER] FATAL: {}", e);
            return Err(-201);
        }
    };
    
    let (tcp_stream, child) = spawn_enclave_with_tcp(&enclave_path)?;
    
    // Upgrade to TLS
    println!("[SGX-RUNNER] Upgrading to TLS...");
    let tls_config = create_tls_config()?;
    let server_name = ServerName::try_from("sgx-enclave".to_string())
        .map_err(|e| {
            eprintln!("[SGX-RUNNER] Invalid server name: {:?}", e);
            -242
        })?;
    let tls_conn = rustls::ClientConnection::new(tls_config, server_name)
        .map_err(|e| {
            eprintln!("[SGX-RUNNER] TLS connection failed: {:?}", e);
            -243
        })?;
    let tls_stream = rustls::StreamOwned::new(tls_conn, tcp_stream);
    
    *conn_guard = Some(EnclaveConnection { 
        stream: TlsStream::Rustls(tls_stream), 
        child 
    });
    println!("[SGX-RUNNER]  Persistent TLS enclave connection established");
    println!("[SGX-RUNNER]  All communication is now encrypted");
    
    Ok(conn_guard)
}

/// Send request using the persistent enclave connection
#[cfg(feature = "use_sgx")]
fn send_request_to_enclave(request_json: &str) -> Result<EnclaveResponse, i32> {
    let mut conn_guard = get_enclave_connection()?;
    
    let conn = conn_guard.as_mut().ok_or(-250)?;
    
    send_tls_request(&mut conn.stream, request_json)
}

/// Send request and receive response over TLS
#[cfg(feature = "use_sgx")]
fn send_tls_request(stream: &mut TlsStream, request_json: &str) -> Result<EnclaveResponse, i32> {
    let request_bytes = request_json.as_bytes();
    let len_bytes = (request_bytes.len() as u32).to_be_bytes();
    
    // Send length prefix + data
    if let Err(e) = stream.write_all(&len_bytes) {
        eprintln!("[SGX-RUNNER] TLS: Failed to send length: {}", e);
        return Err(-220);
    }
    if let Err(e) = stream.write_all(request_bytes) {
        eprintln!("[SGX-RUNNER] TLS: Failed to send request: {}", e);
        return Err(-221);
    }
    if let Err(e) = stream.flush() {
        eprintln!("[SGX-RUNNER] TLS: Failed to flush: {}", e);
        return Err(-222);
    }
    
    println!("[SGX-RUNNER] TLS: Sent {} bytes to enclave", request_bytes.len());
    
    // Read response length
    let mut len_buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_buf) {
        eprintln!("[SGX-RUNNER] TLS: Failed to read response length: {}", e);
        return Err(-223);
    }
    
    let response_len = u32::from_be_bytes(len_buf) as usize;
    println!("[SGX-RUNNER] TLS: Expecting {} bytes response", response_len);
    
    // Read response data
    let mut response_data = vec![0u8; response_len];
    if let Err(e) = stream.read_exact(&mut response_data) {
        eprintln!("[SGX-RUNNER] TLS: Failed to read response: {}", e);
        return Err(-224);
    }
    
    // Parse response JSON
    let response_str = match String::from_utf8(response_data) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[SGX-RUNNER] TLS: Invalid UTF-8 in response: {}", e);
            return Err(-225);
        }
    };
    
    match serde_json::from_str(&response_str) {
        Ok(r) => Ok(r),
        Err(e) => {
            eprintln!("[SGX-RUNNER] TLS: Failed to parse response JSON: {}", e);
            eprintln!("[SGX-RUNNER] TLS: Raw response: {}", response_str);
            Err(-226)
        }
    }
}

#[cfg(feature = "use_sgx")]
pub fn verify_in_sgx_enclave(
    pcr_values: &[u8],
    ima_log: &str,
    hostname: &str,
    deployment_type: &str,
    immudb_addr: &str,
    _ca_pem: &str,
) -> Result<(), i32> {
    println!("\n[SGX-RUNNER] ========================================");
    println!("[SGX-RUNNER] Sending verification request to SGX enclave");
    println!("[SGX-RUNNER] ========================================");
    
    // Verify SGX hardware is available
    if let Err(e) = check_sgx_hardware() {
        eprintln!("[SGX-RUNNER] FATAL: {}", e);
        return Err(-200);
    }
    
    // Compute SHA-256 hash of IMA log instead of sending the full log
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(ima_log.as_bytes());
    let ima_hash = hex::encode(hasher.finalize());
    
    // Count IMA entries
    let ima_count = ima_log.lines().count();
    
    // Extract scaphandre binary hash from IMA log
    let scaphandre_hash = extract_scaphandre_hash_from_ima(ima_log);
    
    println!("[SGX-RUNNER] IMA log: {} entries, hash: {}...", ima_count, &ima_hash[..16]);
    println!("[SGX-RUNNER] Scaphandre hash from IMA: {}", &scaphandre_hash);
    
    // Prepare request with operation type
    let request = VerifyRequest {
        operation: "verify".to_string(),
        pcr_values: hex::encode(pcr_values),
        ima_hash,
        ima_count,
        scaphandre_hash,
        hostname: hostname.to_string(),
        deployment_type: deployment_type.to_string(),
        immudb_addr: immudb_addr.to_string(),
    };
    
    let request_json = serde_json::to_string(&request).unwrap();
    println!("[SGX-RUNNER] Request JSON length: {} bytes", request_json.len());
    
    // Send request using persistent connection
    let response = send_request_to_enclave(&request_json)?;
    
    println!("[SGX-RUNNER] ========================================");
    println!("[SGX-RUNNER] Enclave response:");
    println!("[SGX-RUNNER]   Status: {}", response.status);
    println!("[SGX-RUNNER]   Message: {}", response.message);
    if let Some(ref hash) = response.ima_hash {
        println!("[SGX-RUNNER]   IMA Hash: {}", hash);
    }
    println!("[SGX-RUNNER] ========================================");
    
    if response.status == 0 {
        println!("[SGX-RUNNER]  Verification PASSED inside real SGX enclave");
        Ok(())
    } else {
        eprintln!("[SGX-RUNNER] Verification FAILED: {}", response.message);
        Err(response.status)
    }
}

#[cfg(not(feature = "use_sgx"))]
pub fn verify_in_sgx_enclave(
    _pcr_values: &[u8],
    _ima_log: &str,
    _hostname: &str,
    _deployment_type: &str,
    _immudb_addr: &str,
    _ca_pem: &str,
) -> Result<(), i32> {
    eprintln!("[SGX-RUNNER] FATAL: SGX feature not enabled at compile time");
    eprintln!("[SGX-RUNNER] Rebuild with: cargo build --features use_sgx");
    Err(-999)
}

/// Find the ftxsgx-runner executable
fn which_ftxsgx_runner() -> String {
    // Check common locations
    let paths = [
        "ftxsgx-runner",
        "/usr/bin/ftxsgx-runner",
        "/usr/local/bin/ftxsgx-runner",
        &format!("{}/.cargo/bin/ftxsgx-runner", std::env::var("HOME").unwrap_or_default()),
    ];
    
    for path in &paths {
        if std::process::Command::new(path)
            .arg("--version")
            .output()
            .is_ok()
        {
            return path.to_string();
        }
    }
    
    // Default - let PATH resolve it
    "ftxsgx-runner".to_string()
}

/// Print SGX mode information
pub fn print_sgx_info() {
    println!("\n[SGX-INFO] ========================================");
    println!("[SGX-INFO] Mode: REAL SGX HARDWARE ONLY");
    println!("[SGX-INFO] No simulation fallback - hardware required");
    
    #[cfg(feature = "use_sgx")]
    {
        match check_sgx_hardware() {
            Ok(_) => println!("[SGX-INFO]  SGX hardware available"),
            Err(e) => {
                println!("[SGX-INFO]  SGX hardware NOT available");
                println!("[SGX-INFO]   Error: {}", e);
            }
        }
        
        match get_enclave_path() {
            Ok(p) => println!("[SGX-INFO] OK Enclave binary: {}", p),
            Err(_) => println!("[SGX-INFO] FAIL Enclave binary not found"),
        }
    }
    
    #[cfg(not(feature = "use_sgx"))]
    {
        println!("[SGX-INFO]  SGX feature not compiled");
        println!("[SGX-INFO]   Build with: cargo build --features use_sgx");
    }
    
    println!("[SGX-INFO] ========================================\n");
}

pub struct SgxEnclave;

impl SgxEnclave {
    pub fn new(_enclave_path: &Path) -> Result<Self, String> {
        check_sgx_hardware()?;
        Ok(Self)
    }
    
    pub fn is_sgx_available() -> bool {
        check_sgx_hardware().is_ok()
    }
}

pub fn init_sgx_enclave() -> Result<SgxEnclave, String> {
    check_sgx_hardware()?;
    get_enclave_path()?;
    Ok(SgxEnclave)
}

pub fn is_real_sgx_mode() -> bool {
    check_sgx_hardware().is_ok()
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
    if pkg_ptr.is_null() || dram_ptr.is_null() || out_ptr.is_null() || out_len_ptr.is_null() {
        return 1;
    }
    
    let pkg_slice = unsafe { std::slice::from_raw_parts(pkg_ptr, pkg_len) };
    let dram_slice = unsafe { std::slice::from_raw_parts(dram_ptr, dram_len) };
    
    // Deserialize JSON
    #[derive(Deserialize)]
    struct RawEnergyValue {
        value: String,
    }
    
    let pkg_values: Vec<RawEnergyValue> = match serde_json::from_slice(pkg_slice) {
        Ok(v) => v,
        Err(_) => return 2,
    };
    
    let dram_values: Vec<RawEnergyValue> = match serde_json::from_slice(dram_slice) {
        Ok(v) => v,
        Err(_) => return 2,
    };
    
    // Sum up the energy values
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
    
    let result_str = format!("{}", total);
    let result_bytes = result_str.as_bytes();
    
    if result_bytes.len() > out_cap {
        return 3;
    }
    
    unsafe {
        std::ptr::copy_nonoverlapping(result_bytes.as_ptr(), out_ptr, result_bytes.len());
        *out_len_ptr = result_bytes.len();
    }
    
    0
}

/// Run VM energy computation inside REAL SGX enclave
/// Uses persistent connection to avoid spawning new enclave each time
#[cfg(feature = "use_sgx")]
pub fn compute_vm_energy_in_sgx(
    topo_json: &[u8],
    proc_json: &[u8], 
    hash_json: &[u8],
) -> Result<(), i32> {
    // Verify SGX hardware is available
    if let Err(e) = check_sgx_hardware() {
        eprintln!("[SGX-RUNNER] FATAL: {}", e);
        return Err(-200);
    }
    
    // Prepare request - encode data as hex
    #[derive(Serialize)]
    struct ComputeRequest {
        operation: String,
        topo_data: String,
        proc_data: String,
        hash_data: String,
    }
    
    let request = ComputeRequest {
        operation: "compute_vm_energy".to_string(),
        topo_data: hex::encode(topo_json),
        proc_data: hex::encode(proc_json),
        hash_data: hex::encode(hash_json),
    };
    
    let request_json = serde_json::to_string(&request).unwrap();
    let request_size = request_json.len();
    println!("[SGX-RUNNER] Request size: {} bytes ({:.1} KB)", request_size, request_size as f64 / 1024.0);
    
    // Send request using persistent connection
    let response = send_request_to_enclave(&request_json)?;
    
    println!("[SGX-RUNNER] Enclave response: status={}, msg={}", response.status, response.message);
    
    if response.status == 0 {
        // Parse signed updates from enclave output and write via OCALL
        if let Some(output_hex) = response.output_data {
            if let Ok(output_bytes) = hex::decode(&output_hex) {
                #[derive(Deserialize)]
                struct SignedVmUpdate {
                    vm_name: String,
                    uj_value: u64,
                    counter: u64,
                    previous_hash: String,
                    signature: String,
                }
                
                if let Ok(updates) = serde_json::from_slice::<Vec<SignedVmUpdate>>(&output_bytes) {
                    println!("[SGX-RUNNER] Processing {} signed updates from enclave", updates.len());
                    
                    unsafe {
                        if let Some(ocall_fn) = OCALL_WRITE_VM_ENERGY {
                            for update in &updates {
                                let prev_hash_bytes = hex::decode(&update.previous_hash).unwrap_or_default();
                                let sig_bytes = hex::decode(&update.signature).unwrap_or_default();
                                
                                // Ensure we have 32 bytes for each
                                let mut prev_hash = [0u8; 32];
                                let mut sig = [0u8; 32];
                                if prev_hash_bytes.len() >= 32 {
                                    prev_hash.copy_from_slice(&prev_hash_bytes[..32]);
                                }
                                if sig_bytes.len() >= 32 {
                                    sig.copy_from_slice(&sig_bytes[..32]);
                                }
                                
                                let vm_name_bytes = update.vm_name.as_bytes();
                                println!("[SGX-RUNNER] Writing VM '{}': {} uJ (counter={})", 
                                        update.vm_name, update.uj_value, update.counter);
                                
                                ocall_fn(
                                    vm_name_bytes.as_ptr(),
                                    vm_name_bytes.len(),
                                    update.uj_value,
                                    update.counter,
                                    prev_hash.as_ptr(),
                                    sig.as_ptr(),
                                );
                            }
                        } else {
                            println!("[SGX-RUNNER] Warning: No OCALL registered, can't write updates");
                        }
                    }
                }
            }
        }
        
        println!("[SGX-RUNNER] VM energy computed inside REAL SGX enclave");
        Ok(())
    } else {
        eprintln!("[SGX-RUNNER]  Computation failed: {}", response.message);
        Err(response.status)
    }
}

fn should_use_sgx_enclave() -> bool {
    // Use SGX if hardware is available and enclave binary exists
    #[cfg(feature = "use_sgx")]
    {
        check_sgx_hardware().is_ok() && get_enclave_path().is_ok()
    }
    #[cfg(not(feature = "use_sgx"))]
    {
        false
    }
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
    _out_cap: usize,
    out_len_ptr: *mut usize,
) -> i32 {
    use crate::exporters::qemu::{QemuExporter, ProcessSample};
    
    if topo_ptr.is_null() || proc_ptr.is_null() || out_ptr.is_null() || out_len_ptr.is_null() {
        return 1;
    }
    
    let topo_slice = unsafe { std::slice::from_raw_parts(topo_ptr, topo_len) };
    let proc_slice = unsafe { std::slice::from_raw_parts(proc_ptr, proc_len) };
    let hash_slice = unsafe { std::slice::from_raw_parts(hash_ptr, hash_len) };
    
    // In SGX mode, require real enclave execution (no stub fallback)
    #[cfg(feature = "use_sgx")]
    {
        if !should_use_sgx_enclave() {
            eprintln!("[SGX-RUNNER] Real SGX required, but SGX hardware/enclave is not available");
            return -200;
        }

        println!("[SGX-RUNNER] SGX hardware detected - forwarding to real enclave");
        match compute_vm_energy_in_sgx(topo_slice, proc_slice, hash_slice) {
            Ok(()) => {
                unsafe { *out_len_ptr = 0; }
                return 0;
            }
            Err(code) => {
                eprintln!("[SGX-RUNNER] Real enclave failed ({}) - refusing stub fallback", code);
                return code;
            }
        }
    }
    
    // Stub implementation (userspace)
    eprintln!("[SGX-STUB] Running VM energy computation in userspace (no SGX hardware)");
    
    // Deserialize topology energy value (JSON String like "9742094")
    let topo_energy_value: String = match serde_json::from_slice(topo_slice) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("[SGX-STUB] Failed to deserialize topo_energy_value: {}", e);
            eprintln!("[SGX-STUB] Raw data: {:?}", String::from_utf8_lossy(topo_slice));
            return 2;
        }
    };
    
    // Deserialize process data (Vec<Vec<ProcessSample>>)
    let processes: Vec<Vec<ProcessSample>> = match serde_json::from_slice(proc_slice) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[SGX-STUB] Failed to deserialize processes: {}", e);
            return 3;
        }
    };
    
    eprintln!("[SGX-STUB] Computing VM energy for {} process groups, topo={}", 
              processes.len(), topo_energy_value);
    
  
    let mut exporter = QemuExporter::new();
    let updates = exporter.iterate(String::new(), topo_energy_value, processes);
    
    eprintln!("[SGX-STUB] Computed {} VM energy updates", updates.len());
    
    // Write updates via export_vm OCALL with proper HMAC chain state
    let mut vm_chains = VM_CHAINS.lock().unwrap();
    
    for update in &updates {
        // Get or create per-VM chain state
        let vm_state = vm_chains.entry(update.vm_name.clone()).or_insert_with(|| {
            let vm_key = derive_vm_key(&MASTER_KEY, &update.vm_name);
            VmChainState {
                hmac_key: vm_key,
                chain_state: [0u8; 32],
                counter: 0,
                cumulative_energy_uj: 0,
            }
        });
        
        // Increment counter
        vm_state.counter += 1;
        vm_state.cumulative_energy_uj = vm_state
            .cumulative_energy_uj
            .saturating_add(update.uj_to_add);
        
  
        let data_to_sign = format!(
            "{}|{}|{}|{}|{}",
            vm_state.counter,
            update.vm_name,
            vm_state.cumulative_energy_uj,
            update.uj_to_add,
            hex::encode(&vm_state.chain_state)
        );
        
        // Compute HMAC signature
        let signature = {
            let mut mac = HmacSha256::new_from_slice(&vm_state.hmac_key).expect("HMAC key");
            mac.update(data_to_sign.as_bytes());
            let result = mac.finalize().into_bytes();
            let mut sig = [0u8; 32];
            sig.copy_from_slice(&result);
            sig
        };
        
        // Store previous hash before updating
        let previous_hash = vm_state.chain_state;
        
        // Update chain state with new signature
        vm_state.chain_state.copy_from_slice(&signature);
        
        eprintln!("[SGX-STUB] Chain state for '{}': counter={}, prev_hash={}...",
                  update.vm_name, vm_state.counter, &hex::encode(&previous_hash)[..16]);
        
        // Call the registered OCALL to write VM energy
        unsafe {
            if let Some(ocall_fn) = OCALL_WRITE_VM_ENERGY {
                let vm_name_bytes = update.vm_name.as_bytes();
                ocall_fn(
                    vm_name_bytes.as_ptr(),
                    vm_name_bytes.len(),
                    update.uj_to_add,
                    vm_state.counter,
                    previous_hash.as_ptr(),
                    signature.as_ptr(),
                );
            } else {
                eprintln!("[SGX-STUB] Warning: No OCALL registered for VM energy write");
            }
        }
    }
    
    drop(vm_chains); // Release lock
    
    // Output is not used - VM energy is written via OCALL
    unsafe {
        *out_len_ptr = 0;
    }
    
    0
}

#[no_mangle]
pub extern "C" fn ecall_initialize_sealed_key() -> i32 {
    println!("[SGX-STUB] ecall_initialize_sealed_key called (userspace stub)");
    0
}

#[no_mangle]
pub extern "C" fn ecall_register_ocall_write_vm_energy(
    ocall_fn: unsafe extern "C" fn(*const u8, usize, u64, u64, *const u8, *const u8) -> i32,
) -> i32 {
    println!("[SGX-STUB] ecall_register_ocall_write_vm_energy called - storing OCALL function");
    unsafe {
        OCALL_WRITE_VM_ENERGY = Some(ocall_fn);
    }
    0
}

#[no_mangle]
pub extern "C" fn ecall_register_ocall_fetch_expected_hash(
    _ocall_fn: unsafe extern "C" fn(*const u8, usize, *mut u8, usize) -> i32,
) -> i32 {
    println!("[SGX-STUB] ecall_register_ocall_fetch_expected_hash called (userspace stub)");
    0
}

#[no_mangle]
pub extern "C" fn ecall_register_sealed_storage_ocalls(
    _read_fn: unsafe extern "C" fn(*mut u8, usize) -> i32,
    _write_fn: unsafe extern "C" fn(*const u8, usize) -> i32,
) -> i32 {
    println!("[SGX-STUB] ecall_register_sealed_storage_ocalls called (userspace stub)");
    0
}

#[no_mangle]
#[cfg(feature = "use_sgx")]
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
    // Convert raw pointers to Rust types
    let pcr_values = if pcr_values_ptr.is_null() {
        return -1;
    } else {
        unsafe { std::slice::from_raw_parts(pcr_values_ptr, pcr_values_len) }
    };
    
    let ima_log = if ima_log_ptr.is_null() {
        ""
    } else {
        match std::str::from_utf8(unsafe { std::slice::from_raw_parts(ima_log_ptr, ima_log_len) }) {
            Ok(s) => s,
            Err(_) => return -1,
        }
    };
    
    let hostname = if hostname_ptr.is_null() {
        "unknown"
    } else {
        match std::str::from_utf8(unsafe { std::slice::from_raw_parts(hostname_ptr, hostname_len) }) {
            Ok(s) => s,
            Err(_) => "unknown",
        }
    };
    
    let deployment_type = if deployment_type_ptr.is_null() {
        "host"
    } else {
        match std::str::from_utf8(unsafe { std::slice::from_raw_parts(deployment_type_ptr, deployment_type_len) }) {
            Ok(s) => s,
            Err(_) => "host",
        }
    };
    
    let immudb_addr = if immudb_addr_ptr.is_null() {
        "127.0.0.1:<SGX_PORT>"
    } else {
        match std::str::from_utf8(unsafe { std::slice::from_raw_parts(immudb_addr_ptr, immudb_addr_len) }) {
            Ok(s) => s,
            Err(_) => "127.0.0.1:<SGX_PORT>",
        }
    };
    
    let ca_pem = if ca_pem_ptr.is_null() {
        ""
    } else {
        match std::str::from_utf8(unsafe { std::slice::from_raw_parts(ca_pem_ptr, ca_pem_len) }) {
            Ok(s) => s,
            Err(_) => "",
        }
    };
    
    // Forward to real SGX enclave via IPC
    match verify_in_sgx_enclave(pcr_values, ima_log, hostname, deployment_type, immudb_addr, ca_pem) {
        Ok(()) => 0,
        Err(code) => code,
    }
}

#[no_mangle]
#[cfg(not(feature = "use_sgx"))]
pub extern "C" fn ecall_verify_binary_hash(
    _pcr_values_ptr: *const u8,
    _pcr_values_len: usize,
    _ima_log_ptr: *const u8,
    _ima_log_len: usize,
    _hostname_ptr: *const u8,
    _hostname_len: usize,
    _deployment_type_ptr: *const u8,
    _deployment_type_len: usize,
    _immudb_addr_ptr: *const u8,
    _immudb_addr_len: usize,
    _ca_pem_ptr: *const u8,
    _ca_pem_len: usize,
) -> i32 {
    eprintln!("[SGX-STUB] ecall_verify_binary_hash called but SGX not enabled");
    -999
}
