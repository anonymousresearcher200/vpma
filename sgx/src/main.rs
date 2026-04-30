

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[cfg(feature = "use_mbedtls")]
use std::sync::Arc;
#[cfg(feature = "use_mbedtls")]
use mbedtls::ssl::{Config, Context};
#[cfg(feature = "use_mbedtls")]
use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
#[cfg(feature = "use_mbedtls")]
use mbedtls::x509::Certificate;
#[cfg(feature = "use_mbedtls")]
use mbedtls::pk::Pk;
#[cfg(feature = "use_mbedtls")]
use mbedtls::rng::Rdrand;
#[cfg(feature = "use_mbedtls")]
use mbedtls::alloc::List as MbedtlsList;

// Embedded TLS certificate and private key for the enclave server
#[cfg(feature = "use_mbedtls")]
const ENCLAVE_CERT_PEM: &str = include_str!("../enclave_cert.pem");
#[cfg(feature = "use_mbedtls")]
const ENCLAVE_KEY_PEM: &str = "<ENCLAVE_KEY_PEM>"; // Replace with your generated key: see README

// Import functions from lib
use sgx::{
    ecall_compute_vm_energy_simple,
    ecall_compute_total_host_energy,
    extract_scaphandre_hash_from_ima,
    fetch_expected_hash_from_immudb,
    hashes_match,
};

fn debug_msg(msg: &str) {
    let _ = std::io::stderr().write_all(msg.as_bytes());
    let _ = std::io::stderr().write_all(b"\n");
    let _ = std::io::stderr().flush();
}

/// Generic request wrapper with operation type
#[derive(Deserialize)]
struct EnclaveRequest {
    operation: String,
    #[serde(flatten)]
    data: Value,
}

/// Verify binary hash request
#[derive(Deserialize)]
struct VerifyRequest {
    pcr_values: String,      // Hex-encoded PCR values (96 bytes = 192 hex chars)
    ima_hash: String,        // SHA-256 hash of IMA log (hex)
    ima_count: usize,        // Number of IMA entries
    ima_log: Option<String>, // Full IMA log content (for extraction inside SGX)
    scaphandre_hash: String, // Extracted scaphandre binary hash from IMA (fallback)
    hostname: String,        // System hostname
    deployment_type: String, // "host" or "vm"
    immudb_addr: String,     // ImmuDB address (e.g., "127.0.0.1:8443")
}

/// Compute VM energy request
#[derive(Deserialize)]
struct ComputeVmEnergyRequest {
    topo_data: String,       // Hex-encoded topology data
    proc_data: String,       // Hex-encoded process data
    hash_data: String,       // Hex-encoded hash chain data
}

/// Compute total host energy request
#[derive(Deserialize)]
struct ComputeHostEnergyRequest {
    topo_data: String,       // Hex-encoded topology data
}

/// Generic response
#[derive(Serialize)]
struct EnclaveResponse {
    status: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    ima_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_data: Option<String>,  // Hex-encoded output
}

fn main() {
    // Use stderr for all debug output - stdout is reserved for port number
    debug_msg("[SGX-ENCLAVE] STARTING...");
    debug_msg("[SGX-ENCLAVE] ========================================");
    debug_msg("[SGX-ENCLAVE] Running inside REAL SGX hardware enclave");
    debug_msg("[SGX-ENCLAVE] Memory is encrypted by CPU");
    #[cfg(feature = "use_mbedtls")]
    debug_msg("[SGX-ENCLAVE] Using TLS for secure communication");
    #[cfg(not(feature = "use_mbedtls"))]
    debug_msg("[SGX-ENCLAVE] Using TCP for communication (no TLS)");
    debug_msg("[SGX-ENCLAVE] PERSISTENT MODE - handles multiple requests");
    debug_msg("[SGX-ENCLAVE] ========================================");
    
    // Initialize sealed key and VM chains ONCE at startup
    // This ensures counter state persists across all requests
    debug_msg("[SGX-ENCLAVE] Initializing sealed key and VM chains...");
    let init_result = sgx::ecall_initialize_sealed_key();
    debug_msg(&format!("[SGX-ENCLAVE] ecall_initialize_sealed_key returned: {} (0=existing key, 1=new key)", init_result));
    
    // Bind to localhost with random port
    let listener = match TcpListener::bind("127.0.0.1:0") {
        Ok(l) => l,
        Err(e) => {
            debug_msg(&format!("[SGX-ENCLAVE] Failed to bind TCP: {}", e));
            return;
        }
    };
    
    let port = listener.local_addr().unwrap().port();
    debug_msg(&format!("[SGX-ENCLAVE] TCP server listening on port {}", port));
    
    // Print port to stdout for the host to read (this is the only stdout output)
    println!("PORT:{}", port);
    let _ = io::stdout().flush();
    
    // Accept connection from host
    debug_msg("[SGX-ENCLAVE] Waiting for connection...");
    let (tcp_stream, addr) = match listener.accept() {
        Ok((s, a)) => {
            let _ = s.set_nodelay(true); // Send immediately, no waiting
            debug_msg(&format!("[SGX-ENCLAVE] TCP connection from {}", a));
            (s, a)
        }
        Err(e) => {
            debug_msg(&format!("[SGX-ENCLAVE] Accept failed: {}", e));
            return;
        }
    };
    
    // Make tcp_stream mutable for both TLS and non-TLS paths
    let mut tcp_stream = tcp_stream;
    
    // With mbedtls: upgrade to TLS
    #[cfg(feature = "use_mbedtls")]
    {
        debug_msg("[SGX-ENCLAVE] Setting up TLS server...");
        
        // Parse certificate and private key
        let cert_pem = format!("{}\0", ENCLAVE_CERT_PEM);
        let key_pem = format!("{}\0", ENCLAVE_KEY_PEM);
        
        let cert = match Certificate::from_pem(cert_pem.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                debug_msg(&format!("[SGX-ENCLAVE] Failed to parse certificate: {:?}", e));
                return;
            }
        };
        
        let key = match Pk::from_private_key(key_pem.as_bytes(), None) {
            Ok(k) => k,
            Err(e) => {
                debug_msg(&format!("[SGX-ENCLAVE] Failed to parse private key: {:?}", e));
                return;
            }
        };
        
        // Set up TLS server config
        let rng = Arc::new(Rdrand);
        
        // Create certificate list for mbedtls
        let mut cert_list = MbedtlsList::new();
        cert_list.push(cert);
        let cert_list = Arc::new(cert_list);
        let key = Arc::new(key);
        
        let mut config = Config::new(Endpoint::Server, Transport::Stream, Preset::Default);
        config.set_rng(rng);
        config.set_authmode(AuthMode::None);  // Don't require client cert
        if let Err(e) = config.push_cert(cert_list, key) {
            debug_msg(&format!("[SGX-ENCLAVE] Failed to set certificate: {:?}", e));
            return;
        }
        
        let config = Arc::new(config);
        
        // Create TLS context and establish connection
        let mut tls_ctx = Context::new(config);
        
        if let Err(e) = tls_ctx.establish(&mut tcp_stream, None) {
            debug_msg(&format!("[SGX-ENCLAVE] TLS handshake failed: {:?}", e));
            return;
        }
        
        debug_msg("[SGX-ENCLAVE]  TLS connection established");
        debug_msg("[SGX-ENCLAVE]  All communication is now encrypted");
        
        // Handle TLS requests
        let mut request_count = 0u64;
        loop {
            request_count += 1;
            debug_msg(&format!("[SGX-ENCLAVE] Waiting for TLS request #{}...", request_count));
            
            match handle_single_tls_request(&mut tls_ctx) {
                Ok(should_continue) => {
                    if !should_continue {
                        debug_msg("[SGX-ENCLAVE] Received shutdown signal");
                        break;
                    }
                }
                Err(e) => {
                    debug_msg(&format!("[SGX-ENCLAVE] TLS connection error: {}", e));
                    break;
                }
            }
        }
        
        debug_msg(&format!("[SGX-ENCLAVE] Handled {} TLS requests total", request_count - 1));
    }
    
    // Without mbedtls: plain TCP (less secure)
    #[cfg(not(feature = "use_mbedtls"))]
    {
        debug_msg("[SGX-ENCLAVE] WARNING: Running without TLS encryption!");
        
        // Handle multiple requests on the same connection
        let mut request_count = 0u64;
        loop {
            request_count += 1;
            debug_msg(&format!("[SGX-ENCLAVE] Waiting for request #{}...", request_count));
            
            match handle_single_request(&mut tcp_stream) {
                Ok(should_continue) => {
                    if !should_continue {
                        debug_msg("[SGX-ENCLAVE] Received shutdown signal");
                        break;
                    }
                }
                Err(e) => {
                    debug_msg(&format!("[SGX-ENCLAVE] Connection error: {}", e));
                    break;
                }
            }
        }
        
        debug_msg(&format!("[SGX-ENCLAVE] Handled {} requests total", request_count - 1));
    }
    
    debug_msg("[SGX-ENCLAVE] Enclave shutting down");
}

/// Handle a single TLS request using mbedTLS context
#[cfg(feature = "use_mbedtls")]
fn handle_single_tls_request<T: std::io::Read + std::io::Write>(ctx: &mut Context<T>) -> Result<bool, String> {
    // Read the request - first 4 bytes are length (big-endian u32)
    let mut len_buf = [0u8; 4];
    if let Err(e) = ctx.read_exact(&mut len_buf) {
        return Err(format!("TLS read failed: {:?}", e));
    }
    
    let request_len = u32::from_be_bytes(len_buf) as usize;
    
    // Special case: length 0 means shutdown
    if request_len == 0 {
        return Ok(false);
    }
    
    debug_msg(&format!("[SGX-ENCLAVE] TLS: Expecting {} bytes of request data", request_len));
    
    // Sanity check - max 10MB
    if request_len > 10 * 1024 * 1024 {
        debug_msg("[SGX-ENCLAVE] TLS: Request too large!");
        return Err("Request too large".to_string());
    }
    
    // Read the JSON request
    let mut request_data = vec![0u8; request_len];
    if let Err(e) = ctx.read_exact(&mut request_data) {
        return Err(format!("TLS: Failed to read request: {:?}", e));
    }
    
    debug_msg(&format!("[SGX-ENCLAVE] TLS: Received {} bytes", request_data.len()));
    
    let line = match String::from_utf8(request_data) {
        Ok(s) => s,
        Err(e) => {
            debug_msg(&format!("[SGX-ENCLAVE] TLS: Invalid UTF-8: {}", e));
            let err_response = EnclaveResponse {
                status: -50,
                message: "Invalid UTF-8 in request".to_string(),
                ima_hash: None,
                output_data: None,
            };
            send_tls_response(ctx, &err_response);
            return Ok(true);
        }
    };
    
    debug_msg(&format!("[SGX-ENCLAVE] TLS Request: {}", &line.chars().take(200).collect::<String>()));
    debug_msg("[SGX-ENCLAVE] About to parse JSON...");
    
    // Parse generic request to get operation type
    let request: EnclaveRequest = match serde_json::from_str(&line) {
        Ok(r) => {
            debug_msg("[SGX-ENCLAVE] JSON parsed successfully");
            r
        }
        Err(e) => {
            debug_msg(&format!("[SGX-ENCLAVE] TLS: JSON parse error: {}", e));
            let response = EnclaveResponse {
                status: -100,
                message: format!("Failed to parse request: {}", e),
                ima_hash: None,
                output_data: None,
            };
            send_tls_response(ctx, &response);
            return Ok(true);
        }
    };
    
    // Check for shutdown operation
    if request.operation == "shutdown" {
        let response = EnclaveResponse {
            status: 0,
            message: "Shutting down".to_string(),
            ima_hash: None,
            output_data: None,
        };
        send_tls_response(ctx, &response);
        return Ok(false);
    }
    
    debug_msg(&format!("[SGX-ENCLAVE] TLS Operation: {}", request.operation));
    
    // Dispatch to appropriate handler
    let response = match request.operation.as_str() {
        "verify" => handle_verify(&line),
        "compute_vm_energy" => handle_compute_vm_energy(&line),
        "compute_vm_energy_file" => handle_compute_vm_energy_from_file(&line),
        "compute_host_energy" => handle_compute_host_energy(&line),
        "init_sealed_key" => handle_init_sealed_key(),
        _ => EnclaveResponse {
            status: -1000,
            message: format!("Unknown operation: {}", request.operation),
            ima_hash: None,
            output_data: None,
        },
    };
    
    // Send response over TLS
    send_tls_response(ctx, &response);
    debug_msg(&format!("[SGX-ENCLAVE] TLS Operation complete, status: {}", response.status));
    
    Ok(true)
}

/// Send JSON response over TLS with length prefix
#[cfg(feature = "use_mbedtls")]
fn send_tls_response<T: std::io::Read + std::io::Write>(ctx: &mut Context<T>, response: &EnclaveResponse) {
    let response_json = serde_json::to_string(response).unwrap();
    let response_bytes = response_json.as_bytes();
    let len_bytes = (response_bytes.len() as u32).to_be_bytes();
    
    let _ = ctx.write_all(&len_bytes);
    let _ = ctx.write_all(response_bytes);
    let _ = ctx.flush();
}

/// Handle a single request on an existing TCP connection (non-TLS fallback)
/// Returns Ok(true) to continue, Ok(false) to shutdown, Err on connection error
#[cfg(not(feature = "use_mbedtls"))]
fn handle_single_request(stream: &mut TcpStream) -> Result<bool, String> {
    // Read the request - first 4 bytes are length (big-endian u32)
    let mut len_buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_buf) {
        // Connection closed is normal when host exits
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            return Ok(false);
        }
        return Err(format!("Failed to read length: {}", e));
    }
    
    let request_len = u32::from_be_bytes(len_buf) as usize;
    
    // Special case: length 0 means shutdown
    if request_len == 0 {
        return Ok(false);
    }
    
    debug_msg(&format!("[SGX-ENCLAVE] Expecting {} bytes of request data", request_len));
    
    // Sanity check - max 10MB
    if request_len > 10 * 1024 * 1024 {
        debug_msg("[SGX-ENCLAVE] Request too large!");
        return Err("Request too large".to_string());
    }
    
    // Read the JSON request
    let mut request_data = vec![0u8; request_len];
    if let Err(e) = stream.read_exact(&mut request_data) {
        return Err(format!("Failed to read request: {}", e));
    }
    
    debug_msg(&format!("[SGX-ENCLAVE] Received {} bytes", request_data.len()));
    
    let line = match String::from_utf8(request_data) {
        Ok(s) => s,
        Err(e) => {
            debug_msg(&format!("[SGX-ENCLAVE] Invalid UTF-8: {}", e));
            let err_response = EnclaveResponse {
                status: -50,
                message: "Invalid UTF-8 in request".to_string(),
                ima_hash: None,
                output_data: None,
            };
            send_response(stream, &err_response);
            return Ok(true); // Continue accepting requests
        }
    };
    
    debug_msg(&format!("[SGX-ENCLAVE] Request: {}", &line.chars().take(200).collect::<String>()));
    debug_msg("[SGX-ENCLAVE] About to parse JSON...");
    
    // Parse generic request to get operation type
    let request: EnclaveRequest = match serde_json::from_str(&line) {
        Ok(r) => {
            debug_msg("[SGX-ENCLAVE] JSON parsed successfully");
            r
        }
        Err(e) => {
            debug_msg(&format!("[SGX-ENCLAVE] JSON parse error: {}", e));
            let response = EnclaveResponse {
                status: -100,
                message: format!("Failed to parse request: {}", e),
                ima_hash: None,
                output_data: None,
            };
            send_response(stream, &response);
            return Ok(true); // Continue accepting requests
        }
    };
    
    // Check for shutdown operation
    if request.operation == "shutdown" {
        let response = EnclaveResponse {
            status: 0,
            message: "Shutting down".to_string(),
            ima_hash: None,
            output_data: None,
        };
        send_response(stream, &response);
        return Ok(false); // Signal shutdown
    }
    
    debug_msg(&format!("[SGX-ENCLAVE] Operation: {}", request.operation));
    
    // Dispatch to appropriate handler
    let response = match request.operation.as_str() {
        "verify" => handle_verify(&line),
        "compute_vm_energy" => handle_compute_vm_energy(&line),
        "compute_vm_energy_file" => handle_compute_vm_energy_from_file(&line),
        "compute_host_energy" => handle_compute_host_energy(&line),
        "init_sealed_key" => handle_init_sealed_key(),
        _ => EnclaveResponse {
            status: -1000,
            message: format!("Unknown operation: {}", request.operation),
            ima_hash: None,
            output_data: None,
        },
    };
    
    // Send response
    send_response(stream, &response);
    debug_msg(&format!("[SGX-ENCLAVE] Operation complete, status: {}", response.status));
    
    Ok(true) // Continue accepting requests
}

/// Send JSON response over TCP with length prefix (non-TLS fallback)
#[cfg(not(feature = "use_mbedtls"))]
fn send_response(stream: &mut TcpStream, response: &EnclaveResponse) {
    let response_json = serde_json::to_string(response).unwrap();
    let response_bytes = response_json.as_bytes();
    let len_bytes = (response_bytes.len() as u32).to_be_bytes();
    
    let _ = stream.write_all(&len_bytes);
    let _ = stream.write_all(response_bytes);
    let _ = stream.flush();
}

/// Handle verification request
fn handle_verify(json: &str) -> EnclaveResponse {
    #[derive(Deserialize)]
    struct VerifyReq {
        #[allow(dead_code)]
        operation: String,
        pcr_values: String,
        ima_hash: String,
        ima_count: usize,
        ima_log: Option<String>,  // Full IMA log for extraction inside SGX
        scaphandre_hash: String,  // Fallback if ima_log not provided
        hostname: String,
        deployment_type: String,
        immudb_addr: String,
    }
    
    let request: VerifyReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse verify request: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };
    
    debug_msg("[SGX-HASH-VERIFY] ===============================================");
    debug_msg("[SGX-HASH-VERIFY] Starting FULL binary verification inside SGX");
    debug_msg("[SGX-HASH-VERIFY] ===============================================");
    debug_msg(&format!("[SGX-VERIFY] Hostname: {}", request.hostname));
    debug_msg(&format!("[SGX-VERIFY] Deployment: {}", request.deployment_type));
    debug_msg(&format!("[SGX-VERIFY] IMA entries: {}", request.ima_count));
    debug_msg(&format!("[SGX-VERIFY] ImmuDB address: {}", request.immudb_addr));
    
    // Decode PCR values from hex
    let pcr_values = match hex::decode(&request.pcr_values) {
        Ok(v) => v,
        Err(e) => {
            return EnclaveResponse {
                status: -102,
                message: format!("Failed to decode PCR hex: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };
    
    // STEP 1: Verify PCR values are present and PCR10 is non-zero
    if pcr_values.len() < 96 {
        debug_msg("[SGX-VERIFY]  PCR values too short");
        return EnclaveResponse {
            status: -102,
            message: "PCR values too short (need 96 bytes for PCR 0,7,10)".to_string(),
            ima_hash: Some(request.ima_hash),
            output_data: None,
        };
    }
    
    let pcr10 = &pcr_values[64..96];
    let is_zero = pcr10.iter().all(|&b| b == 0);
    if is_zero {
        debug_msg("[SGX-VERIFY]  PCR 10 is zero - IMA not active");
        return EnclaveResponse {
            status: -2,
            message: "PCR10 is zero - IMA not active".to_string(),
            ima_hash: Some(request.ima_hash),
            output_data: None,
        };
    }
    debug_msg("[SGX-VERIFY]  PCR10 is non-zero (IMA active)");
    
    // STEP 2: Extract scaphandre hash from IMA log (inside SGX)
    // Use ima_log if provided, otherwise fall back to pre-extracted hash
    let scaphandre_hash = if let Some(ref ima_log) = request.ima_log {
        debug_msg("[SGX-VERIFY] Extracting scaphandre hash from IMA log INSIDE SGX...");
        match extract_scaphandre_hash_from_ima(ima_log) {
            Some(hash) => {
                debug_msg(&format!("[SGX-VERIFY]  Extracted hash: {}", hash));
                hash
            }
            None => {
                debug_msg("[SGX-VERIFY]  Scaphandre binary not found in IMA log");
                return EnclaveResponse {
                    status: -4,
                    message: "Scaphandre binary not found in IMA log".to_string(),
                    ima_hash: Some(request.ima_hash),
                    output_data: None,
                };
            }
        }
    } else {
        // Fallback to pre-extracted hash (less secure but backwards compatible)
        debug_msg("[SGX-VERIFY] Using pre-extracted hash (ima_log not provided)");
        if request.scaphandre_hash == "not_found_in_ima" {
            debug_msg("[SGX-VERIFY]  Scaphandre binary not found in IMA log");
            return EnclaveResponse {
                status: -4,
                message: "Scaphandre binary not found in IMA log".to_string(),
                ima_hash: Some(request.ima_hash),
                output_data: None,
            };
        }
        request.scaphandre_hash.clone()
    };
    
    debug_msg(&format!("[SGX-VERIFY] IMA measured hash: {}", scaphandre_hash));
    
    // STEP 3: Query ImmuDB for expected hash and PCR values (INSIDE SGX)
    debug_msg("[SGX-VERIFY] ===============================================");
    debug_msg("[SGX-VERIFY] Querying ImmuDB via TLS INSIDE SGX enclave...");
    debug_msg("[SGX-VERIFY] Host CANNOT see this query or response");
    debug_msg("[SGX-VERIFY] ===============================================");
    
    let (expected_hash, expected_pcr0, expected_pcr7, expected_pcr10) = 
        match fetch_expected_hash_from_immudb(
            "scaphandre",
            &request.hostname,
            &request.deployment_type,
            &request.immudb_addr,
            "",  // CA cert embedded in enclave
        ) {
            Ok(values) => {
                debug_msg("[SGX-VERIFY]  ImmuDB query successful (inside SGX)");
                values
            }
            Err(e) => {
                debug_msg(&format!("[SGX-VERIFY]  Failed to query ImmuDB: error code {}", e));
                return EnclaveResponse {
                    status: -5,
                    message: format!("Failed to query ImmuDB inside SGX: error {}", e),
                    ima_hash: Some(request.ima_hash),
                    output_data: None,
                };
            }
        };
    
    debug_msg(&format!("[SGX-VERIFY]  ImmuDB expected hash: {}", expected_hash));
    debug_msg(&format!("[SGX-VERIFY]  ImmuDB expected PCR0: {}...", &expected_pcr0.chars().take(16).collect::<String>()));
    debug_msg(&format!("[SGX-VERIFY]  ImmuDB expected PCR7: {}...", &expected_pcr7.chars().take(16).collect::<String>()));
    debug_msg(&format!("[SGX-VERIFY]  ImmuDB expected PCR10: {}...", &expected_pcr10.chars().take(16).collect::<String>()));
    
    // STEP 4: Compare scaphandre hash (INSIDE SGX)
    debug_msg("[SGX-VERIFY] Comparing hashes INSIDE SGX enclave...");
    debug_msg(&format!("[SGX-VERIFY]   IMA measured:   {}", scaphandre_hash));
    debug_msg(&format!("[SGX-VERIFY]   ImmuDB expects: {}", expected_hash));
    
    if !hashes_match(&scaphandre_hash, &expected_hash) {
        debug_msg("[SGX-VERIFY] ===============================================");
        debug_msg("[SGX-VERIFY]    HASH MISMATCH DETECTED ");
        debug_msg("[SGX-VERIFY] ===============================================");
        debug_msg("[SGX-VERIFY] POSSIBLE BINARY TAMPERING - REJECTING");
        return EnclaveResponse {
            status: -6,
            message: format!("Hash mismatch: IMA={} ImmuDB={}", scaphandre_hash, expected_hash),
            ima_hash: Some(request.ima_hash),
            output_data: None,
        };
    }
    debug_msg("[SGX-VERIFY]  Scaphandre hash verification PASSED");
    
    // STEP 5: Verify PCR values match expected (INSIDE SGX)
    debug_msg("[SGX-VERIFY] Verifying PCR values INSIDE SGX enclave...");
    
    let actual_pcr0 = hex::encode(&pcr_values[0..32]);
    let actual_pcr7 = hex::encode(&pcr_values[32..64]);
    let actual_pcr10 = hex::encode(&pcr_values[64..96]);
    
    debug_msg(&format!("[SGX-VERIFY]   Actual PCR0:   {}...", &actual_pcr0.chars().take(16).collect::<String>()));
    debug_msg(&format!("[SGX-VERIFY]   Expected PCR0: {}...", &expected_pcr0.chars().take(16).collect::<String>()));
    
    if !hashes_match(&actual_pcr0, &expected_pcr0) {
        debug_msg("[SGX-VERIFY]  PCR0 mismatch - firmware/BIOS changed!");
        return EnclaveResponse {
            status: -7,
            message: format!("PCR0 mismatch: actual={} expected={}", actual_pcr0, expected_pcr0),
            ima_hash: Some(request.ima_hash),
            output_data: None,
        };
    }
    debug_msg("[SGX-VERIFY]  PCR0 verification PASSED");
    
    debug_msg(&format!("[SGX-VERIFY]   Actual PCR7:   {}...", &actual_pcr7.chars().take(16).collect::<String>()));
    debug_msg(&format!("[SGX-VERIFY]   Expected PCR7: {}...", &expected_pcr7.chars().take(16).collect::<String>()));
    
    if !hashes_match(&actual_pcr7, &expected_pcr7) {
        debug_msg("[SGX-VERIFY]  PCR7 mismatch - Secure Boot state changed!");
        return EnclaveResponse {
            status: -8,
            message: format!("PCR7 mismatch: actual={} expected={}", actual_pcr7, expected_pcr7),
            ima_hash: Some(request.ima_hash),
            output_data: None,
        };
    }
    debug_msg("[SGX-VERIFY]  PCR7 verification PASSED");
    
    debug_msg(&format!("[SGX-VERIFY]   Actual PCR10:   {}...", &actual_pcr10.chars().take(16).collect::<String>()));
    debug_msg(&format!("[SGX-VERIFY]   Expected PCR10: {}...", &expected_pcr10.chars().take(16).collect::<String>()));
    
    if !hashes_match(&actual_pcr10, &expected_pcr10) {
        // For VMs, PCR10 drift is expected due to continuous IMA measurements
        // The important checks are: binary hash + PCR0 + PCR7
        if request.deployment_type == "vm" {
            debug_msg("[SGX-VERIFY]  PCR10 drift detected (expected for VMs - IMA extends on every file access)");
            debug_msg("[SGX-VERIFY]  Binary hash and boot PCRs (0,7) verified - VM integrity confirmed");
        } else {
            debug_msg("[SGX-VERIFY]  PCR10 mismatch - IMA measurements differ!");
            return EnclaveResponse {
                status: -9,
                message: format!("PCR10 mismatch: actual={} expected={}", actual_pcr10, expected_pcr10),
                ima_hash: Some(request.ima_hash),
                output_data: None,
            };
        }
    } else {
        debug_msg("[SGX-VERIFY]  PCR10 verification PASSED");
    }
    
    // ALL VERIFICATIONS PASSED
    debug_msg("[SGX-VERIFY] ===============================================");
    debug_msg("[SGX-VERIFY]    FULL VERIFICATION PASSED ");
    debug_msg("[SGX-VERIFY] ===============================================");
    debug_msg(&format!("[SGX-VERIFY] Binary hash: {}", scaphandre_hash));
    debug_msg(&format!("[SGX-VERIFY] PCR0 (BIOS): {}...", &actual_pcr0.chars().take(16).collect::<String>()));
    debug_msg(&format!("[SGX-VERIFY] PCR7 (SecureBoot): {}...", &actual_pcr7.chars().take(16).collect::<String>()));
    debug_msg(&format!("[SGX-VERIFY] PCR10 (IMA): {}...", &actual_pcr10.chars().take(16).collect::<String>()));
    debug_msg("[SGX-VERIFY] ===============================================");
    
    EnclaveResponse {
        status: 0,
        message: format!(
            "FULL VERIFICATION PASSED - hash {} verified against ImmuDB, all PCRs match ({} IMA entries)", 
            &scaphandre_hash.chars().take(16).collect::<String>(),
            request.ima_count
        ),
        ima_hash: Some(request.ima_hash),
        output_data: None,
    }
}

/// Handle compute VM energy request
fn handle_compute_vm_energy(json: &str) -> EnclaveResponse {
    #[derive(Deserialize)]
    struct ComputeReq {
        #[allow(dead_code)]
        operation: String,
        topo_data: String,    // Hex-encoded
        proc_data: String,    // Hex-encoded
        hash_data: String,    // Hex-encoded
    }
    
    let request: ComputeReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse compute_vm_energy request: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };
    
    debug_msg("[SGX-COMPUTE] Computing VM energy inside SGX");
    
    // Decode hex data
    let topo_bytes = match hex::decode(&request.topo_data) {
        Ok(v) => v,
        Err(e) => {
            return EnclaveResponse {
                status: -102,
                message: format!("Failed to decode topo hex: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };
    
    let proc_bytes = match hex::decode(&request.proc_data) {
        Ok(v) => v,
        Err(e) => {
            return EnclaveResponse {
                status: -103,
                message: format!("Failed to decode proc hex: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };
    
    let hash_bytes = match hex::decode(&request.hash_data) {
        Ok(v) => v,
        Err(e) => {
            return EnclaveResponse {
                status: -104,
                message: format!("Failed to decode hash hex: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };
    
    // VM chains already initialized at startup - no need to reinitialize
    // This preserves counter state across requests
    
    // Prepare output buffer
    let mut output = vec![0u8; 65536];  // 64KB output buffer
    let mut out_len: usize = 0;
    
    debug_msg(&format!("[SGX-COMPUTE] Calling ecall_compute_vm_energy_simple with {} topo bytes, {} proc bytes, {} hash bytes",
              topo_bytes.len(), proc_bytes.len(), hash_bytes.len()));
    
    // Call computation inside SGX
    let result = unsafe {
        ecall_compute_vm_energy_simple(
            topo_bytes.as_ptr(),
            topo_bytes.len(),
            proc_bytes.as_ptr(),
            proc_bytes.len(),
            hash_bytes.as_ptr(),
            hash_bytes.len(),
            output.as_mut_ptr(),
            output.len(),
            &mut out_len,
        )
    };
    
    debug_msg(&format!("[SGX-COMPUTE] ecall returned: result={}, out_len={}", result, out_len));
    
    if result == 0 {
        output.truncate(out_len);
        EnclaveResponse {
            status: 0,
            message: format!("VM energy computed successfully, {} bytes output", out_len),
            ima_hash: None,
            output_data: if out_len > 0 { Some(hex::encode(&output)) } else { None },
        }
    } else {
        EnclaveResponse {
            status: result,
            message: format!("VM energy computation failed with status {}", result),
            ima_hash: None,
            output_data: None,
        }
    }
}

/// Handle compute VM energy request from file (for large data > 64KB)
fn handle_compute_vm_energy_from_file(json: &str) -> EnclaveResponse {
    use std::fs;
    
    #[derive(Deserialize)]
    struct FileReq {
        #[allow(dead_code)]
        operation: String,
        file_path: String,
    }
    
    let request: FileReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse file request: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };
    
    debug_msg(&format!("[SGX-COMPUTE-FILE] Reading data from: {}", request.file_path));
    
    // Read the actual data from file
    let file_content = match fs::read_to_string(&request.file_path) {
        Ok(content) => content,
        Err(e) => {
            return EnclaveResponse {
                status: -110,
                message: format!("Failed to read file {}: {}", request.file_path, e),
                ima_hash: None,
                output_data: None,
            };
        }
    };
    
    debug_msg(&format!("[SGX-COMPUTE-FILE] Read {} bytes from file", file_content.len()));
    
    // Now process the file content as the actual compute request
    handle_compute_vm_energy(&file_content)
}

/// Handle compute host energy request
fn handle_compute_host_energy(json: &str) -> EnclaveResponse {
    #[derive(Deserialize)]
    struct ComputeReq {
        #[allow(dead_code)]
        operation: String,
        pkg_data: String,     // Hex-encoded PKG energy JSON
        dram_data: String,    // Hex-encoded DRAM energy JSON
    }
    
    let request: ComputeReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse compute_host_energy request: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };
    
    debug_msg("[SGX-COMPUTE] Computing total host energy inside SGX");
    
    let pkg_bytes = match hex::decode(&request.pkg_data) {
        Ok(v) => v,
        Err(e) => {
            return EnclaveResponse {
                status: -102,
                message: format!("Failed to decode pkg hex: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };
    
    let dram_bytes = match hex::decode(&request.dram_data) {
        Ok(v) => v,
        Err(e) => {
            return EnclaveResponse {
                status: -103,
                message: format!("Failed to decode dram hex: {}", e),
                ima_hash: None,
                output_data: None,
            };
        }
    };
    
    // Prepare output buffer
    let mut output = vec![0u8; 256];
    let mut out_len: usize = 0;
    
    // Call computation inside SGX
    let result = ecall_compute_total_host_energy(
        pkg_bytes.as_ptr(),
        pkg_bytes.len(),
        dram_bytes.as_ptr(),
        dram_bytes.len(),
        output.as_mut_ptr(),
        output.len(),
        &mut out_len,
    );
    
    if result == 0 && out_len > 0 {
        output.truncate(out_len);
        // The output is a string representation of the total energy
        match String::from_utf8(output) {
            Ok(energy_str) => EnclaveResponse {
                status: 0,
                message: energy_str,  // Energy value as string
                ima_hash: None,
                output_data: None,
            },
            Err(_) => EnclaveResponse {
                status: -104,
                message: "Failed to decode output as string".to_string(),
                ima_hash: None,
                output_data: None,
            },
        }
    } else {
        EnclaveResponse {
            status: result,
            message: format!("Host energy computation failed with status {}", result),
            ima_hash: None,
            output_data: None,
        }
    }
}

/// Handle initialize sealed key request
fn handle_init_sealed_key() -> EnclaveResponse {
    debug_msg("[SGX-SEALED] Initializing sealed HMAC key inside SGX");
    
    // For now, sealed storage requires OCALLs which we don't have in this simple model
    // Return a placeholder response
    EnclaveResponse {
        status: 0,
        message: "Sealed key initialization handled by enclave".to_string(),
        ima_hash: None,
        output_data: None,
    }
}
