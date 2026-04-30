
use std::io::{self, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::fs::{File, OpenOptions};
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

// Import functions from lib
use sgx_vm::{
    ecall_verify_energy_chain,
    ecall_compute_single_process_energy,
    ecall_verify_binary_hash,
    merkle,
    blockchain,
    redis_store,
};

#[cfg(feature = "use_mbedtls")]
use sgx_vm::{
    ecall_immudb_login,
    ecall_immudb_insert,
};

// Embedded TLS certificate and private key for the enclave server
#[cfg(feature = "use_mbedtls")]
const ENCLAVE_CERT_PEM: &str = include_str!("../enclave_cert.pem");
#[cfg(feature = "use_mbedtls")]
const ENCLAVE_KEY_PEM: &str = "<ENCLAVE_KEY_PEM>"; // Replace with your generated key: see README

/// Batch insertion control: accumulate data and insert every BATCH_SIZE iterations
static mut ITERATION_COUNT: u64 = 0;
static mut ACCUMULATED_RECORDS: Vec<merkle::EnergyRecord> = Vec::new();
static mut BLOCK_NUMBER: u64 = 0;
static mut LATEST_CHAINED_ROOT: [u8; 32] = [0u8; 32];
static mut STATE_INITIALIZED: bool = false;
const BATCH_SIZE: u64 = 100;

/// Timing log file path
const TIMING_LOG_FILE: &str = "/tmp/sgx_timing.csv";

fn debug_msg(msg: &str) {
    let _ = std::io::stderr().write_all(msg.as_bytes());
    let _ = std::io::stderr().write_all(b"\n");
    let _ = std::io::stderr().flush();
}

/// Log timing data to CSV file
fn log_timing(entry: &str) {
    if let Ok(mut file) = OpenOptions::new()
        .create(true)
        .append(true)
        .open(TIMING_LOG_FILE)
    {
        let _ = writeln!(file, "{}", entry);
    }
}

/// Initialize timing log with CSV header
fn init_timing_log() {
    if let Ok(mut file) = File::create(TIMING_LOG_FILE) {
        let _ = writeln!(file, "timestamp,event_type,iteration,block_num,parse_ms,chain_verify_ms,energy_calc_ms,iter_total_ms,clone_ms,merkle_ms,pg_connect_ms,pg_insert_ms,batch_total_ms,records,merkle_nodes,block_row_ms,records_ms,merkle_nodes_ms,commit_ms,pg_total_ms");
    }
    debug_msg(&format!("[TIMING] Initialized timing log: {}", TIMING_LOG_FILE));
}

/// Generic request wrapper with operation type
#[derive(Deserialize)]
struct EnclaveRequest {
    operation: String,
    #[serde(flatten)]
    data: Value,
}

/// Generic response
#[derive(Serialize)]
struct EnclaveResponse {
    status: i32,
    message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    output_data: Option<String>,  // Hex-encoded output or JSON
}

fn main() {
    // Use stderr for all debug output - stdout is reserved for port number
    debug_msg("[SGX-VM-ENCLAVE] STARTING...");
    debug_msg("[SGX-VM-ENCLAVE] ========================================");
    debug_msg("[SGX-VM-ENCLAVE] Running inside REAL SGX hardware enclave");
    debug_msg("[SGX-VM-ENCLAVE] Memory is encrypted by CPU");
    #[cfg(feature = "use_mbedtls")]
    debug_msg("[SGX-VM-ENCLAVE] Using TLS-encrypted TCP for communication");
    #[cfg(not(feature = "use_mbedtls"))]
    debug_msg("[SGX-VM-ENCLAVE] Using plain TCP (mbedtls not enabled)");
    debug_msg("[SGX-VM-ENCLAVE] PERSISTENT MODE - handles multiple requests");
    debug_msg("[SGX-VM-ENCLAVE] ========================================");
    
    let args: Vec<String> = std::env::args().collect();
    let bind_addr = if args.len() > 1 {
        let addr = &args[1];
        // If only IP is provided, append :0 for random port
        if !addr.contains(':') {
            format!("{}:0", addr)
        } else {
            addr.clone()
        }
    } else {
        "127.0.0.1:0".to_string()
    };
    
    debug_msg(&format!("[SGX-VM-ENCLAVE] Binding to {}", bind_addr));
    
    // Bind to specified address
    let listener = match TcpListener::bind(&bind_addr) {
        Ok(l) => l,
        Err(e) => {
            debug_msg(&format!("[SGX-VM-ENCLAVE] Failed to bind TCP to {}: {}", bind_addr, e));
            return;
        }
    };
    
    let local_addr = listener.local_addr().unwrap();
    let port = local_addr.port();
    debug_msg(&format!("[SGX-VM-ENCLAVE] TCP server listening on {}", local_addr));
    
    // Print port to stdout for the host to read (this is the only stdout output)
    println!("PORT:{}", port);
    let _ = io::stdout().flush();
    
    // Accept connection from client
    debug_msg("[SGX-VM-ENCLAVE] Waiting for connection...");
    let (tcp_stream, addr) = match listener.accept() {
        Ok((s, a)) => {
            let _ = s.set_nodelay(true); // Send immediately, no waiting
            debug_msg(&format!("[SGX-VM-ENCLAVE] TCP connection from {}", a));
            (s, a)
        }
        Err(e) => {
            debug_msg(&format!("[SGX-VM-ENCLAVE] Accept failed: {}", e));
            return;
        }
    };
    
    // Make tcp_stream mutable for both TLS and non-TLS paths
    let mut tcp_stream = tcp_stream;
    
    // With mbedtls: upgrade to TLS
    #[cfg(feature = "use_mbedtls")]
    {
        debug_msg("[SGX-VM-ENCLAVE] Setting up TLS server...");
        
        // Parse certificate and private key
        let cert_pem = format!("{}\0", ENCLAVE_CERT_PEM);
        let key_pem = format!("{}\0", ENCLAVE_KEY_PEM);
        
        let cert = match Certificate::from_pem(cert_pem.as_bytes()) {
            Ok(c) => c,
            Err(e) => {
                debug_msg(&format!("[SGX-VM-ENCLAVE] Failed to parse certificate: {:?}", e));
                return;
            }
        };
        
        let key = match Pk::from_private_key(key_pem.as_bytes(), None) {
            Ok(k) => k,
            Err(e) => {
                debug_msg(&format!("[SGX-VM-ENCLAVE] Failed to parse private key: {:?}", e));
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
            debug_msg(&format!("[SGX-VM-ENCLAVE] Failed to set certificate: {:?}", e));
            return;
        }
        
        let config = Arc::new(config);
        
        // Create TLS context and establish connection
        let mut tls_ctx = Context::new(config);
        
        if let Err(e) = tls_ctx.establish(&mut tcp_stream, None) {
            debug_msg(&format!("[SGX-VM-ENCLAVE] TLS handshake failed: {:?}", e));
            return;
        }
        
        debug_msg("[SGX-VM-ENCLAVE]  TLS connection established");
        debug_msg("[SGX-VM-ENCLAVE]  All communication is now encrypted");
        
        // Handle TLS requests - tcp_stream must stay in scope while tls_ctx is used
        // Note: tls_ctx holds a reference to tcp_stream internally
        let mut request_count = 0u64;
        loop {
            request_count += 1;
            debug_msg(&format!("[SGX-VM-ENCLAVE] Waiting for TLS request #{}...", request_count));
            
            match handle_single_tls_request(&mut tls_ctx) {
                Ok(should_continue) => {
                    if !should_continue {
                        debug_msg("[SGX-VM-ENCLAVE] Received shutdown signal");
                        break;
                    }
                }
                Err(e) => {
                    debug_msg(&format!("[SGX-VM-ENCLAVE] TLS connection error: {}", e));
                    break;
                }
            }
        }
        
        debug_msg(&format!("[SGX-VM-ENCLAVE] Handled {} TLS requests total", request_count - 1));
    }
    
    // Without mbedtls: plain TCP (insecure)
    #[cfg(not(feature = "use_mbedtls"))]
    {
        debug_msg("[SGX-VM-ENCLAVE] WARNING: Running without TLS encryption!");
        
        // Handle multiple requests on the same connection
        let mut request_count = 0u64;
        loop {
            request_count += 1;
            debug_msg(&format!("[SGX-VM-ENCLAVE] Waiting for request #{}...", request_count));
            
            match handle_single_request(&mut tcp_stream) {
                Ok(should_continue) => {
                    if !should_continue {
                        debug_msg("[SGX-VM-ENCLAVE] Received shutdown signal");
                        break;
                    }
                }
                Err(e) => {
                    debug_msg(&format!("[SGX-VM-ENCLAVE] Connection error: {}", e));
                    break;
                }
            }
        }
        
        debug_msg(&format!("[SGX-VM-ENCLAVE] Handled {} requests total", request_count - 1));
    }
    
    debug_msg("[SGX-VM-ENCLAVE] Enclave shutting down");
}

/// Handle a single TLS request using mbedTLS context
#[cfg(feature = "use_mbedtls")]
fn handle_single_tls_request<T: std::io::Read + std::io::Write>(ctx: &mut Context<T>) -> Result<bool, String> {
    // Read the request - first 4 bytes are length (big-endian u32)
    let mut len_buf = [0u8; 4];
    if let Err(e) = ctx.read_exact(&mut len_buf) {
        // Check for connection closed
        return Err(format!("TLS read failed: {:?}", e));
    }
    
    let request_len = u32::from_be_bytes(len_buf) as usize;
    
    // Special case: length 0 means shutdown
    if request_len == 0 {
        return Ok(false);
    }
    
    debug_msg(&format!("[SGX-VM-ENCLAVE] TLS: Expecting {} bytes of request data", request_len));
    
    // Sanity check - max 10MB
    if request_len > 10 * 1024 * 1024 {
        debug_msg("[SGX-VM-ENCLAVE] TLS: Request too large!");
        return Err("Request too large".to_string());
    }
    
    // Read the JSON request
    let mut request_data = vec![0u8; request_len];
    if let Err(e) = ctx.read_exact(&mut request_data) {
        return Err(format!("TLS: Failed to read request: {:?}", e));
    }
    
    debug_msg(&format!("[SGX-VM-ENCLAVE] TLS: Received {} bytes", request_data.len()));
    
    let line = match String::from_utf8(request_data) {
        Ok(s) => s,
        Err(e) => {
            debug_msg(&format!("[SGX-VM-ENCLAVE] TLS: Invalid UTF-8: {}", e));
            let err_response = EnclaveResponse {
                status: -50,
                message: "Invalid UTF-8 in request".to_string(),
                output_data: None,
            };
            send_tls_response(ctx, &err_response);
            return Ok(true);
        }
    };
    
    debug_msg(&format!("[SGX-VM-ENCLAVE] TLS Request: {}", &line.chars().take(200).collect::<String>()));
    
    // Parse generic request to get operation type
    let request: EnclaveRequest = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            debug_msg(&format!("[SGX-VM-ENCLAVE] TLS: JSON parse error: {}", e));
            let response = EnclaveResponse {
                status: -100,
                message: format!("Failed to parse request: {}", e),
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
            output_data: None,
        };
        send_tls_response(ctx, &response);
        return Ok(false);
    }
    
    debug_msg(&format!("[SGX-VM-ENCLAVE] TLS Operation: {}", request.operation));
    
    // Dispatch to appropriate handler
    let response = match request.operation.as_str() {
        "verify_boot" => handle_verify_boot(&line),
        "verify_chain" => handle_verify_chain(&line),
        "compute_process_energy" => handle_compute_process_energy(&line),
        "db_export" => handle_db_export(&line),
        "immudb_login" => handle_immudb_login(),
        "immudb_insert" => handle_immudb_insert(&line),
        _ => EnclaveResponse {
            status: -1000,
            message: format!("Unknown operation: {}", request.operation),
            output_data: None,
        },
    };
    
    // Send response over TLS
    send_tls_response(ctx, &response);
    debug_msg(&format!("[SGX-VM-ENCLAVE] TLS Operation complete, status: {}", response.status));
    
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
#[cfg(not(feature = "use_mbedtls"))]
fn handle_single_request(stream: &mut TcpStream) -> Result<bool, String> {
    // Read the request - first 4 bytes are length (big-endian u32)
    let mut len_buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_buf) {
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
    
    debug_msg(&format!("[SGX-VM-ENCLAVE] Expecting {} bytes of request data", request_len));
    
    // Sanity check - max 10MB
    if request_len > 10 * 1024 * 1024 {
        debug_msg("[SGX-VM-ENCLAVE] Request too large!");
        return Err("Request too large".to_string());
    }
    
    // Read the JSON request
    let mut request_data = vec![0u8; request_len];
    if let Err(e) = stream.read_exact(&mut request_data) {
        return Err(format!("Failed to read request: {}", e));
    }
    
    debug_msg(&format!("[SGX-VM-ENCLAVE] Received {} bytes", request_data.len()));
    
    let line = match String::from_utf8(request_data) {
        Ok(s) => s,
        Err(e) => {
            debug_msg(&format!("[SGX-VM-ENCLAVE] Invalid UTF-8: {}", e));
            let err_response = EnclaveResponse {
                status: -50,
                message: "Invalid UTF-8 in request".to_string(),
                output_data: None,
            };
            send_response(stream, &err_response);
            return Ok(true);
        }
    };
    
    debug_msg(&format!("[SGX-VM-ENCLAVE] Request: {}", &line.chars().take(200).collect::<String>()));
    
    // Parse generic request to get operation type
    let request: EnclaveRequest = match serde_json::from_str(&line) {
        Ok(r) => r,
        Err(e) => {
            debug_msg(&format!("[SGX-VM-ENCLAVE] JSON parse error: {}", e));
            let response = EnclaveResponse {
                status: -100,
                message: format!("Failed to parse request: {}", e),
                output_data: None,
            };
            send_response(stream, &response);
            return Ok(true);
        }
    };
    
    // Check for shutdown operation
    if request.operation == "shutdown" {
        let response = EnclaveResponse {
            status: 0,
            message: "Shutting down".to_string(),
            output_data: None,
        };
        send_response(stream, &response);
        return Ok(false);
    }
    
    debug_msg(&format!("[SGX-VM-ENCLAVE] Operation: {}", request.operation));
    
    // Dispatch to appropriate handler
    let response = match request.operation.as_str() {
        "verify_boot" => handle_verify_boot(&line),
        "verify_chain" => handle_verify_chain(&line),
        "compute_process_energy" => handle_compute_process_energy(&line),
        "db_export" => handle_db_export(&line),
        "immudb_login" => handle_immudb_login(),
        "immudb_insert" => handle_immudb_insert(&line),
        _ => EnclaveResponse {
            status: -1000,
            message: format!("Unknown operation: {}", request.operation),
            output_data: None,
        },
    };
    
    // Send response
    send_response(stream, &response);
    debug_msg(&format!("[SGX-VM-ENCLAVE] Operation complete, status: {}", response.status));
    
    Ok(true)
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

/// Handle boot verification request (TPM/IMA/ImmuDB inside SGX)
fn handle_verify_boot(json: &str) -> EnclaveResponse {
    #[derive(Deserialize)]
    struct VerifyBootReq {
        #[allow(dead_code)]
        operation: String,
        pcr_values: String,       // Hex-encoded 96 bytes (PCR0 + PCR7 + PCR10)
        ima_log: String,          // Full IMA log content
        hostname: String,
        deployment_type: String,  // "host" or "vm"
        immudb_addr: String,      // e.g., "<IMMUDB_HOST>:8443"
        ca_pem: String,           // CA certificate in PEM format
    }
    
    let request: VerifyBootReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse verify_boot request: {}", e),
                output_data: None,
            };
        }
    };
    
    debug_msg("[SGX-VM-BOOT] ========================================");
    debug_msg("[SGX-VM-BOOT] Boot integrity verification inside SGX");
    debug_msg("[SGX-VM-BOOT] ========================================");
    debug_msg(&format!("[SGX-VM-BOOT] Hostname: {}", request.hostname));
    debug_msg(&format!("[SGX-VM-BOOT] Deployment: {}", request.deployment_type));
    debug_msg(&format!("[SGX-VM-BOOT] IMA log size: {} bytes", request.ima_log.len()));
    
    // Decode PCR values
    let pcr_values = match hex::decode(&request.pcr_values) {
        Ok(v) if v.len() == 96 => v,
        Ok(v) => {
            return EnclaveResponse {
                status: -102,
                message: format!("Invalid PCR values length: {} (expected 96 bytes)", v.len()),
                output_data: None,
            };
        }
        Err(e) => {
            return EnclaveResponse {
                status: -102,
                message: format!("Invalid PCR hex: {}", e),
                output_data: None,
            };
        }
    };
    
    // Call the binary verification ECALL
    let result = unsafe {
        ecall_verify_binary_hash(
            pcr_values.as_ptr(),
            pcr_values.len(),
            request.ima_log.as_ptr(),
            request.ima_log.len(),
            request.hostname.as_ptr(),
            request.hostname.len(),
            request.deployment_type.as_ptr(),
            request.deployment_type.len(),
            request.immudb_addr.as_ptr(),
            request.immudb_addr.len(),
            request.ca_pem.as_ptr(),
            request.ca_pem.len(),
        )
    };
    
    match result {
        0 => {
            debug_msg("[SGX-VM-BOOT] ========================================");
            debug_msg("[SGX-VM-BOOT]    BOOT INTEGRITY VERIFIED ");
            debug_msg("[SGX-VM-BOOT] ========================================");
            EnclaveResponse {
                status: 0,
                message: "Boot integrity verified - binary hash and PCRs match".to_string(),
                output_data: None,
            }
        }
        -6 => EnclaveResponse {
            status: -6,
            message: "HASH MISMATCH - Binary has been tampered!".to_string(),
            output_data: None,
        },
        -7 => EnclaveResponse {
            status: -7,
            message: "PCR0 MISMATCH - Boot process tampered!".to_string(),
            output_data: None,
        },
        -8 => EnclaveResponse {
            status: -8,
            message: "PCR7 MISMATCH - Secure Boot tampered!".to_string(),
            output_data: None,
        },
        -9 => EnclaveResponse {
            status: -9,
            message: "PCR10 MISMATCH - IMA measurements tampered!".to_string(),
            output_data: None,
        },
        -4 => EnclaveResponse {
            status: -4,
            message: "Scaphandre binary not found in IMA log".to_string(),
            output_data: None,
        },
        -5 => EnclaveResponse {
            status: -5,
            message: "ImmuDB connection failed".to_string(),
            output_data: None,
        },
        _ => EnclaveResponse {
            status: result,
            message: format!("Boot verification failed with code {}", result),
            output_data: None,
        },
    }
}

/// Handle chain verification request
fn handle_verify_chain(json: &str) -> EnclaveResponse {
    #[derive(Deserialize)]
    struct VerifyChainReq {
        #[allow(dead_code)]
        operation: String,
        vm_name: String,
        energy_value: u64,
        #[serde(default)]
        energy_delta: u64,
        counter: u64,
        previous_hash: String,  // Hex-encoded 32 bytes
        signature: String,       // Hex-encoded 32 bytes
    }
    
    let request: VerifyChainReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse verify_chain request: {}", e),
                output_data: None,
            };
        }
    };
    
    debug_msg(&format!("[SGX-VM-VERIFY] Verifying chain for VM '{}', counter={}", 
                       request.vm_name, request.counter));
    
    // Decode hex values
    let previous_hash = match hex::decode(&request.previous_hash) {
        Ok(v) if v.len() == 32 => v,
        _ => {
            return EnclaveResponse {
                status: -102,
                message: "Invalid previous_hash (must be 64 hex chars)".to_string(),
                output_data: None,
            };
        }
    };
    
    let signature = match hex::decode(&request.signature) {
        Ok(v) if v.len() == 32 => v,
        _ => {
            return EnclaveResponse {
                status: -103,
                message: "Invalid signature (must be 64 hex chars)".to_string(),
                output_data: None,
            };
        }
    };
    
    // Call the verification function
    let result = unsafe {
        ecall_verify_energy_chain(
            request.vm_name.as_ptr(),
            request.vm_name.len(),
            request.energy_value,
            request.energy_delta,
            request.counter,
            previous_hash.as_ptr(),
            signature.as_ptr(),
        )
    };
    
    match result {
        0 => EnclaveResponse {
            status: 0,
            message: format!("Chain verified successfully (counter={})", request.counter),
            output_data: None,
        },
        1 => EnclaveResponse {
            status: 1,
            message: "Chain initialized (first verification)".to_string(),
            output_data: None,
        },
        2 => EnclaveResponse {
            status: 2,
            message: "Skipped (same counter, host not updated)".to_string(),
            output_data: None,
        },
        -2 => EnclaveResponse {
            status: -2,
            message: "TAMPERING DETECTED - signature mismatch!".to_string(),
            output_data: None,
        },
        -3 => EnclaveResponse {
            status: -3,
            message: "REPLAY/ROLLBACK ATTACK - counter discontinuity!".to_string(),
            output_data: None,
        },
        -4 => EnclaveResponse {
            status: -4,
            message: "FORK ATTACK - previous hash mismatch!".to_string(),
            output_data: None,
        },
        _ => EnclaveResponse {
            status: result,
            message: format!("Chain verification failed with code {}", result),
            output_data: None,
        },
    }
}

/// Handle per-process energy computation
fn handle_compute_process_energy(json: &str) -> EnclaveResponse {
    #[derive(Deserialize)]
    struct ComputeReq {
        #[allow(dead_code)]
        operation: String,
        vm_total_energy_uj: u64,
        cpu_percentage: f64,
    }
    
    let request: ComputeReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse compute request: {}", e),
                output_data: None,
            };
        }
    };
    
    debug_msg(&format!("[SGX-VM-COMPUTE] Computing energy: total={}uJ, cpu={:.2}%", 
                       request.vm_total_energy_uj, request.cpu_percentage));
    
    let mut out_energy: u64 = 0;
    
    let result = unsafe {
        ecall_compute_single_process_energy(
            request.vm_total_energy_uj,
            request.cpu_percentage,
            &mut out_energy as *mut u64,
        )
    };
    
    if result == 0 {
        debug_msg(&format!("[SGX-VM-COMPUTE]  Computed energy: {}uJ", out_energy));
        EnclaveResponse {
            status: 0,
            message: format!("Computed energy: {}uJ", out_energy),
            output_data: Some(out_energy.to_string()),
        }
    } else {
        EnclaveResponse {
            status: result,
            message: format!("Energy computation failed with code {}", result),
            output_data: None,
        }
    }
}

/// Get current timestamp in ISO-compatible format
fn get_timestamp() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    
    let secs = now.as_secs();
    
    // Convert to timestamp format: YYYY-MM-DD HH:MM:SS
    // Simple calculation (not accounting for leap years perfectly, but good enough)
    let days_since_epoch = secs / 86400;
    let time_of_day = secs % 86400;
    
    let hours = time_of_day / 3600;
    let minutes = (time_of_day % 3600) / 60;
    let seconds = time_of_day % 60;
    
    // Calculate year, month, day from days since epoch (1970-01-01)
    let mut year = 1970;
    let mut remaining_days = days_since_epoch as i64;
    
    loop {
        let days_in_year = if year % 4 == 0 && (year % 100 != 0 || year % 400 == 0) { 366 } else { 365 };
        if remaining_days < days_in_year {
            break;
        }
        remaining_days -= days_in_year;
        year += 1;
    }
    
    let is_leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days_in_months = if is_leap {
        [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    } else {
        [31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
    };
    
    let mut month = 1;
    for days in days_in_months.iter() {
        if remaining_days < *days as i64 {
            break;
        }
        remaining_days -= *days as i64;
        month += 1;
    }
    let day = remaining_days + 1;
    
    format!("{:04}-{:02}-{:02} {:02}:{:02}:{:02}", 
            year, month, day, hours, minutes, seconds)
}

/// Handle full DB export with verification and batch-wise Redis insertion
fn handle_db_export(json: &str) -> EnclaveResponse {
    let iter_start = std::time::Instant::now();
    
    #[derive(Deserialize)]
    struct DbExportReq {
        #[allow(dead_code)]
        operation: String,
        vm_name: String,
        energy_uj: u64,
        counter: u64,
        previous_hash: String,
        signature: String,
        energy_delta: u64,
        processes: Vec<(u32, u64)>,  // (pid, cpu_ticks)
        #[allow(dead_code)]
        session_id: Option<String>,  // Kept for compatibility, not used
    }
    
    let parse_start = std::time::Instant::now();
    let request: DbExportReq = match serde_json::from_str(json) {
        Ok(r) => r,
        Err(e) => {
            return EnclaveResponse {
                status: -101,
                message: format!("Failed to parse db_export request: {}", e),
                output_data: None,
            };
        }
    };
    let parse_time = parse_start.elapsed().as_secs_f64() * 1000.0;
    
    let current_iter = unsafe { ITERATION_COUNT + 1 };
    debug_msg(&format!("[SGX-VM-DB] Processing {} processes for VM '{}' (iteration {})", 
                       request.processes.len(), request.vm_name, current_iter));
    
    // Step 1: Verify chain
    let chain_verify_start = std::time::Instant::now();
    let previous_hash = match hex::decode(&request.previous_hash) {
        Ok(v) if v.len() == 32 => v,
        _ => {
            return EnclaveResponse {
                status: -102,
                message: "Invalid previous_hash".to_string(),
                output_data: None,
            };
        }
    };
    
    let signature = match hex::decode(&request.signature) {
        Ok(v) if v.len() == 32 => v,
        _ => {
            return EnclaveResponse {
                status: -103,
                message: "Invalid signature".to_string(),
                output_data: None,
            };
        }
    };
    
    let verify_result = unsafe {
        ecall_verify_energy_chain(
            request.vm_name.as_ptr(),
            request.vm_name.len(),
            request.energy_uj,
            request.energy_delta,
            request.counter,
            previous_hash.as_ptr(),
            signature.as_ptr(),
        )
    };
    
    if verify_result < 0 {
        return EnclaveResponse {
            status: verify_result,
            message: format!("Chain verification failed: {}", verify_result),
            output_data: None,
        };
    }

    if verify_result == 2 {
        return EnclaveResponse {
            status: 2,
            message: "Skipped (same counter, host not updated)".to_string(),
            output_data: None,
        };
    }

    let chain_verify_time = chain_verify_start.elapsed().as_secs_f64() * 1000.0;
    
    debug_msg(&format!("[SGX-VM-DB]  Chain verified (result={})", verify_result));
    
    // Step 2: Calculate total CPU ticks
    let energy_calc_start = std::time::Instant::now();
    let total_ticks: u64 = request.processes.iter().map(|(_, ticks)| ticks).sum();
    
    if total_ticks == 0 {
        return EnclaveResponse {
            status: 0,
            message: "No CPU activity, skipping".to_string(),
            output_data: None,
        };
    }
    
    // Step 3: Calculate per-process energy and accumulate records
    let mut results: Vec<(u32, u64)> = Vec::new();
    let timestamp = get_timestamp();
    
    for (pid, ticks) in &request.processes {
        let cpu_percentage = (*ticks as f64 / total_ticks as f64) * 100.0;
        let mut out_energy: u64 = 0;
        
        let result = unsafe {
            ecall_compute_single_process_energy(
                request.energy_delta,
                cpu_percentage,
                &mut out_energy as *mut u64,
            )
        };
        
        if result == 0 && out_energy > 0 {
            results.push((*pid, out_energy));
            
            // Accumulate record for batch insertion
            let cpu_time_seconds = *ticks as f64 / 100.0;
            let energy_joules = out_energy as f64 / 1_000_000.0;
            let power_watts = if cpu_time_seconds > 0.0 {
                energy_joules / cpu_time_seconds
            } else {
                0.0
            };
            
            unsafe {
                ACCUMULATED_RECORDS.push(merkle::EnergyRecord::new(
                    *pid,
                    cpu_time_seconds,
                    energy_joules,
                    power_watts,
                    request.vm_name.clone(),
                    timestamp.clone(),
                ));
            }
        }
    }
    let energy_calc_time = energy_calc_start.elapsed().as_secs_f64() * 1000.0;
    
    // Increment iteration count
    unsafe {
        ITERATION_COUNT += 1;
    }
    
    let current_iter = unsafe { ITERATION_COUNT };
    let accumulated_count = unsafe { ACCUMULATED_RECORDS.len() };
    
    // Print per-iteration timing breakdown
    let iter_elapsed = iter_start.elapsed().as_secs_f64() * 1000.0;
    debug_msg(&format!("[TIMING-VM] Iter {}: parse={:.2}ms, chain_verify={:.2}ms, energy_calc={:.2}ms, total={:.2}ms",
                       current_iter, parse_time, chain_verify_time, energy_calc_time, iter_elapsed));
    
    debug_msg(&format!("[SGX-VM-DB]  Calculated energy for {} processes (iteration {}/{})", 
                       results.len(), current_iter, BATCH_SIZE));
    debug_msg(&format!("[SGX-VM-DB] Total accumulated: {} records", accumulated_count));
    
    // Step 4: Check if batch size reached - insert to Redis
    if current_iter == BATCH_SIZE {
        debug_msg("[SGX-VM-DB] ================================================");
        debug_msg(&format!("[SGX-VM-DB]  Batch size reached! Creating block with {} records...", accumulated_count));
        
        // Redis server CA certificate for TLS verification (CN=<HOST_IP>)
        const REDIS_CA_CERT: &str = "<REDIS_CA_CERT_PEM>" // Replace with your Redis CA certificate;

        // Redis ACL credentials - only SGX enclave can write
        const REDIS_USER: &str = "sgx";
        const REDIS_PASS: &str = "<REDIS_PASSWORD>";
        
        // Initialize state from Redis on first batch (if not already done)
        let needs_init = unsafe { !STATE_INITIALIZED };
        if needs_init {
            debug_msg("[SGX-VM-DB] First batch - checking Redis for existing chain state...");
            let init_config = redis_store::RedisConfig::new_with_tls_auth(
                "<HOST_IP>", 6379, REDIS_CA_CERT, REDIS_USER, REDIS_PASS
            );
            match redis_store::RedisConnection::connect(init_config) {
                Ok(mut init_conn) => {
                    match init_conn.get_latest_block_state(&request.vm_name) {
                        Ok(Some((block_num, chained_root))) => {
                            debug_msg(&format!("[SGX-VM-DB]  Resuming from Redis state: block_number={}, chained_root={}...",
                                              block_num, hex::encode(&chained_root[..8])));
                            unsafe {
                                BLOCK_NUMBER = block_num + 1;  // Next block number
                                LATEST_CHAINED_ROOT = chained_root;
                                STATE_INITIALIZED = true;
                            }
                        }
                        Ok(None) => {
                            debug_msg("[SGX-VM-DB] No existing state found in Redis - starting fresh");
                            unsafe { STATE_INITIALIZED = true; }
                        }
                        Err(e) => {
                            debug_msg(&format!("[SGX-VM-DB]  Failed to retrieve state from Redis: {:?}", e));
                            // Continue anyway, will use default state
                            unsafe { STATE_INITIALIZED = true; }
                        }
                    }
                }
                Err(e) => {
                    debug_msg(&format!("[SGX-VM-DB]  Failed to connect to Redis for state init: {:?}", e));
                    // Continue anyway, will try to insert later
                }
            }
        }
        
        // Get accumulated records and create block
        let batch_start = std::time::Instant::now();
        let records: Vec<merkle::EnergyRecord> = unsafe { ACCUMULATED_RECORDS.clone() };
        let block_num = unsafe { BLOCK_NUMBER };
        let prev_root = unsafe { LATEST_CHAINED_ROOT };
        let clone_time = batch_start.elapsed().as_secs_f64() * 1000.0;
        
        // Create block with Merkle tree (inside SGX)
        let merkle_start = std::time::Instant::now();
        let block = blockchain::Block::new(
            block_num,
            request.vm_name.clone(),
            prev_root,
            records,
            timestamp,
        );
        let merkle_time = merkle_start.elapsed().as_secs_f64() * 1000.0;
        
        debug_msg(&format!("[TIMING-VM] Block creation: clone={:.2}ms, merkle_tree={:.2}ms", clone_time, merkle_time));
        debug_msg(&format!("[SGX-VM-DB] Block {} created:", block.block_number));
        debug_msg(&format!("[SGX-VM-DB]   Merkle root: {}...", &block.merkle_root_hex()[..16]));
        debug_msg(&format!("[SGX-VM-DB]   Chained root: {}...", &block.chained_root_hex()[..16]));
        debug_msg(&format!("[SGX-VM-DB]   Records: {}", block.record_count));
        
        // Connect to Redis with TLS
        let redis_connect_start = std::time::Instant::now();

        let redis_config = redis_store::RedisConfig::new_with_tls_auth(
            "<HOST_IP>",  // Host IP from VM
            6379,             // Redis default port
            REDIS_CA_CERT,
            REDIS_USER,
            REDIS_PASS
        );
        
        match redis_store::RedisConnection::connect(redis_config) {
            Ok(mut redis_conn) => {
                let redis_connect_time = redis_connect_start.elapsed().as_secs_f64() * 1000.0;
                let redis_insert_start = std::time::Instant::now();
                match redis_conn.insert_block(&block) {
                    Ok(block_id) => {
                        let redis_insert_time = redis_insert_start.elapsed().as_secs_f64() * 1000.0;
                        let batch_total = batch_start.elapsed().as_secs_f64() * 1000.0;
                        debug_msg(&format!("[TIMING-VM] Redis: connect={:.2}ms, insert={:.2}ms", redis_connect_time, redis_insert_time));
                        debug_msg(&format!("[TIMING-VM] BATCH TOTAL: {:.2}ms (clone={:.2}, merkle={:.2}, redis_connect={:.2}, redis_insert={:.2})",
                                          batch_total, clone_time, merkle_time, redis_connect_time, redis_insert_time));
                        debug_msg(&format!("[SGX-VM-DB]  Block inserted to Redis (id={})", block_id));
                        
                        // Update state for next block
                        unsafe {
                            BLOCK_NUMBER += 1;
                            LATEST_CHAINED_ROOT = block.chained_root;
                        }
                    }
                    Err(e) => {
                        debug_msg(&format!("[SGX-VM-DB]  Failed to insert block to Redis: {:?}", e));
                    }
                }
            }
            Err(e) => {
                debug_msg(&format!("[SGX-VM-DB]  Failed to connect to Redis: {:?}", e));
            }
        }
        
        // Reset counters and clear accumulated data
        unsafe {
            ITERATION_COUNT = 0;
            ACCUMULATED_RECORDS.clear();
        }
        debug_msg("[SGX-VM-DB] ================================================");
    }
    
    // Return results
    let output = serde_json::to_string(&results).unwrap_or_default();
    
    EnclaveResponse {
        status: 0,
        message: format!("Processed {} processes, {} with energy", 
                        request.processes.len(), results.len()),
        output_data: Some(output),
    }
}

/// Handle ImmuDB login (TLS inside SGX)
fn handle_immudb_login() -> EnclaveResponse {
    #[cfg(feature = "use_mbedtls")]
    {
        debug_msg("[SGX-VM-DB] Logging into ImmuDB via TLS (inside SGX)...");
        
        let mut response_buf = vec![0u8; 8192];
        let mut response_len: usize = 0;
        
        let result = unsafe {
            ecall_immudb_login(
                response_buf.as_mut_ptr(),
                response_buf.len(),
                &mut response_len as *mut usize,
            )
        };
        
        if result == 0 {
            response_buf.truncate(response_len);
            let response_str = String::from_utf8_lossy(&response_buf);
            
            // Extract session ID from response
            if let Some(start) = response_str.find("\"sessionID\":\"") {
                let start = start + 13;
                if let Some(end) = response_str[start..].find('"') {
                    let session_id = &response_str[start..start+end];
                    debug_msg(&format!("[SGX-VM-DB]  Got session ID: {}...", &session_id[..16.min(session_id.len())]));
                    return EnclaveResponse {
                        status: 0,
                        message: "Login successful".to_string(),
                        output_data: Some(session_id.to_string()),
                    };
                }
            }
            
            EnclaveResponse {
                status: -10,
                message: "Failed to extract session ID".to_string(),
                output_data: Some(response_str.to_string()),
            }
        } else {
            EnclaveResponse {
                status: result,
                message: format!("ImmuDB login failed: {}", result),
                output_data: None,
            }
        }
    }
    
    #[cfg(not(feature = "use_mbedtls"))]
    EnclaveResponse {
        status: -99,
        message: "mbedtls feature not enabled".to_string(),
        output_data: None,
    }
}

/// Handle ImmuDB insert (TLS inside SGX)
fn handle_immudb_insert(json: &str) -> EnclaveResponse {
    #[derive(Deserialize)]
    struct InsertReq {
        #[allow(dead_code)]
        operation: String,
        session_id: String,
        body: String,
    }
    
    #[cfg(feature = "use_mbedtls")]
    {
        let request: InsertReq = match serde_json::from_str(json) {
            Ok(r) => r,
            Err(e) => {
                return EnclaveResponse {
                    status: -101,
                    message: format!("Failed to parse insert request: {}", e),
                    output_data: None,
                };
            }
        };
        
        debug_msg("[SGX-VM-DB] Inserting into ImmuDB via TLS (inside SGX)...");
        
        let mut response_buf = vec![0u8; 4096];
        let mut response_len: usize = 0;
        
        let result = unsafe {
            ecall_immudb_insert(
                request.session_id.as_ptr(),
                request.session_id.len(),
                request.body.as_ptr(),
                request.body.len(),
                response_buf.as_mut_ptr(),
                response_buf.len(),
                &mut response_len as *mut usize,
            )
        };
        
        if result == 0 {
            response_buf.truncate(response_len);
            let response_str = String::from_utf8_lossy(&response_buf);
            debug_msg("[SGX-VM-DB]  Insert successful");
            EnclaveResponse {
                status: 0,
                message: "Insert successful".to_string(),
                output_data: Some(response_str.to_string()),
            }
        } else {
            EnclaveResponse {
                status: result,
                message: format!("ImmuDB insert failed: {}", result),
                output_data: None,
            }
        }
    }
    
    #[cfg(not(feature = "use_mbedtls"))]
    {
        let _ = json;
        EnclaveResponse {
            status: -99,
            message: "mbedtls feature not enabled".to_string(),
            output_data: None,
        }
    }
}
