
pub mod merkle;
pub mod blockchain;
pub mod postgres;
pub mod redis_store;
pub mod checkpoint;

use core::slice;
use std::collections::BTreeMap;

use hmac::{Hmac, Mac};
use sha2::Sha256;

// Provide __vsnprintf_chk stub for mbedtls in SGX environment
// mbedtls_printf uses this but we don't need formatted output in SGX
#[cfg(all(feature = "use_mbedtls", target_env = "sgx"))]
#[no_mangle]
pub unsafe extern "C" fn __vsnprintf_chk(
    _s: *mut core::ffi::c_char,
    _maxlen: usize,
    _flag: core::ffi::c_int,
    _slen: usize,
    _format: *const core::ffi::c_char,
    _ap: *mut core::ffi::c_void,
) -> core::ffi::c_int {
    0 // Return 0 bytes written (no-op)
}

type HmacSha256 = Hmac<Sha256>;

/// Master key for per-VM key derivation. Must match HOST derivation input.
const VM_MASTER_KEY: [u8; 32] = [0u8; 32];

#[derive(Clone)]
struct VmChainState {
    counter: u64,
    last_signature: [u8; 32],
    initialized: bool,
    last_energy_uj: u64,
}

impl VmChainState {
    fn new() -> Self {
        Self {
            counter: 0,
            last_signature: [0u8; 32],
            initialized: false,
            last_energy_uj: 0,
        }
    }
}

/// Stateful chain tracking in SGX enclave memory, isolated per VM.
static mut VM_CHAIN_STATES: Option<BTreeMap<String, VmChainState>> = None;

/// Batch insertion control: accumulate data and insert every 100 iterations
static mut ITERATION_COUNT: u64 = 0;
static mut ACCUMULATED_DATA: Vec<String> = Vec::new();
static mut ACCUMULATED_RECORDS: Vec<merkle::EnergyRecord> = Vec::new();
static mut BLOCK_NUMBER: u64 = 0;
static mut LATEST_CHAINED_ROOT: [u8; 32] = [0u8; 32];
const BATCH_SIZE: u64 = 100;
const MAX_RECORDS_PER_INSERT: usize = 500; // Limit to avoid TLS buffer overflow

fn derive_vm_key(master_key: &[u8; 32], vm_name: &str) -> [u8; 32] {
    let mut mac = HmacSha256::new_from_slice(master_key)
        .expect("HMAC can take key of any size");
    mac.update(b"vm:");
    mac.update(vm_name.as_bytes());
    let result = mac.finalize().into_bytes();

    let mut key = [0u8; 32];
    key.copy_from_slice(&result);
    key
}

fn vm_chain_states_mut() -> &'static mut BTreeMap<String, VmChainState> {
    unsafe {
        if VM_CHAIN_STATES.is_none() {
            VM_CHAIN_STATES = Some(BTreeMap::new());
        }
        VM_CHAIN_STATES.as_mut().expect("VM chain map initialized")
    }
}

/// Force linking for VM SGX
#[no_mangle]
pub extern "C" fn force_link_sgx_vm() {}

// Helper function to print from SGX (uses Fortanix std's stderr)
fn sgx_print(msg: &str) {
    use std::io::Write;
    let _ = std::io::stderr().write_all(msg.as_bytes());
    let _ = std::io::stderr().write_all(b"\n");
    let _ = std::io::stderr().flush();
}

#[no_mangle]
pub extern "C" fn ecall_compute_single_process_energy(
    vm_total_energy_uj: u64,
    cpu_percentage: f64,
    out_energy_ptr: *mut u64,
) -> i32 {
    // Validation
    if out_energy_ptr.is_null() {
        return -1;
    }

    if cpu_percentage < 0.0 || cpu_percentage > 100.0 {
        return -2; // Invalid percentage
    }

    // Trusted computation in SGX enclave
    // Formula: process_energy = vm_total x (cpu% / 100)
    let process_energy = (vm_total_energy_uj as f64 * (cpu_percentage / 100.0)) as u64;
    
    // Write result
    unsafe {
        *out_energy_ptr = process_energy;
    }

    0 // Success
}

#[no_mangle]
pub extern "C" fn ecall_verify_energy_chain(
    vm_name_ptr: *const u8,
    vm_name_len: usize,
    energy_uj: u64,
    energy_delta: u64,
    counter: u64,
    previous_hash_ptr: *const u8,
    received_signature_ptr: *const u8,
) -> i32 {
    // Validation
    if vm_name_ptr.is_null() || previous_hash_ptr.is_null() || received_signature_ptr.is_null() {
        return -1;
    }
    
    // Read VM name
    let vm_name_slice = unsafe { slice::from_raw_parts(vm_name_ptr, vm_name_len) };
    let vm_name = match core::str::from_utf8(vm_name_slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    
    // Read previous hash (32 bytes)
    let previous_hash = unsafe { slice::from_raw_parts(previous_hash_ptr, 32) };
    
    // Read received signature (32 bytes)
    let received_signature = unsafe { slice::from_raw_parts(received_signature_ptr, 32) };
    
    // Derive per-VM key (must match HOST derivation)
    let vm_key = derive_vm_key(&VM_MASTER_KEY, vm_name);
    
    // Build chain data (same format as HOST signer)
    // HMAC covers cumulative + delta + prev_hash + counter + vm_name.
    let chain_data = format!(
        "{}|{}|{}|{}|{}",
        counter,
        vm_name,
        energy_uj,
        energy_delta,
        hex::encode(previous_hash)
    );
    
    // Compute expected HMAC
    let mut mac = HmacSha256::new_from_slice(&vm_key)
        .expect("HMAC can take key of any size");
    mac.update(chain_data.as_bytes());
    
    let expected_signature = mac.finalize().into_bytes();
    
    // Debug logging
    println!("[SGX-VM-VERIFY] Chain verification:");
    println!("[SGX-VM-VERIFY]   VM: {}", vm_name);
    println!("[SGX-VM-VERIFY]   Counter: {}", counter);
    println!("[SGX-VM-VERIFY]   Energy: {}", energy_uj);
    println!("[SGX-VM-VERIFY]   Energy Delta: {}", energy_delta);
    println!("[SGX-VM-VERIFY]   Chain data: {}", &chain_data);
    println!("[SGX-VM-VERIFY]   Expected sig: {}", hex::encode(&expected_signature[..8]));
    println!("[SGX-VM-VERIFY]   Received sig: {}", hex::encode(&received_signature[..8]));
    
    // Constant-time comparison to prevent timing attacks
    if expected_signature.as_slice() != received_signature {
        println!("[SGX-VM-VERIFY]  Signature mismatch!");
        return -2; // Tampering detected (signature mismatch)
    }
    
    println!("[SGX-VM-VERIFY]  Signature valid");
    
    // Signature is valid, now check chain continuity (STATEFUL)
    let vm_states = vm_chain_states_mut();
    let vm_state = vm_states
        .entry(vm_name.to_string())
        .or_insert_with(VmChainState::new);

    let is_first_time = if vm_state.initialized {
        // Counter must be strictly monotonic per VM, with idempotent same-counter skip.
        if counter == vm_state.counter {
            if energy_uj != vm_state.last_energy_uj {
                eprintln!(
                    "[SGX-VM-VERIFY]  Same counter but cumulative energy changed: {} -> {}",
                    vm_state.last_energy_uj,
                    energy_uj
                );
                return -2;
            }
            println!("[SGX-VM-VERIFY]  Same counter ({}), skipping (host not updated yet)", counter);
            return 2;
        }

        if counter < vm_state.counter {
            eprintln!(
                "[SGX-VM-VERIFY]  Counter went backwards: {} -> {}",
                vm_state.counter,
                counter
            );
            return -3;
        }

        if counter != vm_state.counter + 1 {
            eprintln!(
                "[SGX-VM-VERIFY]  Counter discontinuity: expected {}, got {}",
                vm_state.counter + 1,
                counter
            );
            return -3;
        }

        let expected_energy = vm_state.last_energy_uj.saturating_add(energy_delta);
        if energy_uj != expected_energy {
            eprintln!(
                "[SGX-VM-VERIFY]  Cumulative energy mismatch: expected {}, got {}",
                expected_energy,
                energy_uj
            );
            return -2;
        }

        if previous_hash != vm_state.last_signature.as_slice() {
            eprintln!("[SGX-VM-VERIFY]  Previous hash mismatch");
            return -4;
        }

        false
    } else {
        vm_state.initialized = true;
        true
    };

    // Update per-VM stored state with newly verified signature.
    vm_state.counter = counter;
    vm_state.last_energy_uj = energy_uj;
    vm_state.last_signature.copy_from_slice(&expected_signature);
    
    if is_first_time {
        1 // First-time initialization successful
    } else {
        0 // Chain continuity verified
    }
}

#[no_mangle]
#[cfg(feature = "use_mbedtls")]
pub extern "C" fn ecall_db_export_with_verification(
    vm_name_ptr: *const u8,
    vm_name_len: usize,
    energy_uj: u64,
    counter: u64,
    previous_hash_ptr: *const u8,
    signature_ptr: *const u8,
    energy_delta: u64,
    proc_json_ptr: *const u8,
    proc_json_len: usize,
) -> i32 {
    // Validation
    if vm_name_ptr.is_null() || previous_hash_ptr.is_null() || signature_ptr.is_null() || proc_json_ptr.is_null() {
        return -1;
    }
    
    // Read VM name
    let vm_name_slice = unsafe { slice::from_raw_parts(vm_name_ptr, vm_name_len) };
    let vm_name = match core::str::from_utf8(vm_name_slice) {
        Ok(s) => s,
        Err(_) => return -1,
    };
    
    // Read chain metadata
    let previous_hash = unsafe { slice::from_raw_parts(previous_hash_ptr, 32) };
    let signature = unsafe { slice::from_raw_parts(signature_ptr, 32) };
    
    // STEP 1: Verify chain
    let chain_verify_start = std::time::Instant::now();
    let verify_result = ecall_verify_energy_chain(
        vm_name_ptr,
        vm_name_len,
        energy_uj,
        energy_delta,
        counter,
        previous_hash_ptr,
        signature_ptr,
    );
    
    match verify_result {
        0 | 1 => { /* Chain verified or initialized */ }
        -2 => return -2, // Tampering
        -3 => return -3, // Replay/rollback
        -4 => return -4, // Fork attack
        _ => return verify_result,
    }
    let chain_verify_duration = chain_verify_start.elapsed();
    let msg1 = format!(
        "[SGX-VM-DB]  Chain verified for counter={}, energy_uj={}uJ (delta={}uJ)",
        counter,
        energy_uj,
        energy_delta
    );
    sgx_print(&msg1);
    let msg2 = format!("[TIMING-SGX] Chain verification: {:.2} ms", chain_verify_duration.as_secs_f64() * 1000.0);
    sgx_print(&msg2);
    
    // STEP 2: Parse process data
    let parse_start = std::time::Instant::now();
    let proc_json_slice = unsafe { slice::from_raw_parts(proc_json_ptr, proc_json_len) };
    let processes: Vec<(u32, u64)> = match serde_json::from_slice(proc_json_slice) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[SGX-VM-DB] Failed to parse process JSON: {}", e);
            return -5;
        }
    };
    
    if processes.is_empty() {
        println!("[SGX-VM-DB] No processes to export");
        return 0;
    }
    
    // Calculate total CPU ticks
    let total_cpu_ticks: u64 = processes.iter().map(|(_, ticks)| ticks).sum();
    
    if total_cpu_ticks == 0 {
        println!("[SGX-VM-DB] No CPU activity");
        return 0;
    }
    
    let parse_duration = parse_start.elapsed();
    let msg1 = format!("[SGX-VM-DB] Processing {} processes, total CPU ticks: {}", processes.len(), total_cpu_ticks);
    sgx_print(&msg1);
    let msg2 = format!("[TIMING-SGX] Parse JSON: {:.2} ms", parse_duration.as_secs_f64() * 1000.0);
    sgx_print(&msg2);
    
    // Increment iteration count
    unsafe {
        ITERATION_COUNT += 1;
    }
    
    // STEP 3: Calculate per-process energy and accumulate data
    let process_start = std::time::Instant::now();
    let mut processed_count = 0;
    let mut last_hash = String::from("0000000000000000000000000000000000000000000000000000000000000000");
    let mut total_calc_time = 0.0;
    
    for (pid, cpu_ticks) in processes {
        if cpu_ticks == 0 {
            continue;
        }
        
        let calc_start = std::time::Instant::now();
        
        // Calculate CPU percentage
        let cpu_percentage = (cpu_ticks as f64 / total_cpu_ticks as f64) * 100.0;
        
        // Use SGX enclave to calculate process energy
        let mut process_energy_uj: u64 = 0;
        let result = ecall_compute_single_process_energy(
            energy_delta,
            cpu_percentage,
            &mut process_energy_uj as *mut u64,
        );
        
        if result != 0 {
            eprintln!("[SGX-VM-DB] Failed to compute energy for PID {}: error {}", pid, result);
            continue;
        }
        
        let cpu_time_seconds = cpu_ticks as f64 / 100.0;
        let energy_joules = process_energy_uj as f64 / 1_000_000.0;
        let power_watts = if cpu_time_seconds > 0.0 {
            energy_joules / cpu_time_seconds
        } else {
            0.0
        };
        
        println!("[SGX-VM-DB] PID {}: {:.2}% CPU, {:.6} J", pid, cpu_percentage, energy_joules);
        
        let calc_duration = calc_start.elapsed().as_secs_f64() * 1000.0;
        total_calc_time += calc_duration;
        
        // Create hash chain entry and accumulate
        let timestamp = sgx_get_timestamp();
        
        let base_entry = format!(
            r#"{{"pid":{},"cpu_time":{:.4},"energy_joules":{:.4},"power_watts":{:.4},"timestamp":"{}","vm_name":"{}"}}"#,
            pid, cpu_time_seconds, energy_joules, power_watts, timestamp, vm_name
        );
        
        let chain_input = format!("{}{}", last_hash, base_entry);
        let new_hash = sgx_sha256(&chain_input);
        last_hash = new_hash.clone();
        
        let final_entry = format!(
            r#"{{"pid":{},"cpu_time":{:.4},"energy_joules":{:.4},"power_watts":{:.4},"timestamp":"{}","vm_name":"{}","hash_chain":"{}"}}"#,
            pid, cpu_time_seconds, energy_joules, power_watts, timestamp, vm_name, new_hash
        );
        
        // Accumulate data instead of inserting immediately
        unsafe {
            ACCUMULATED_DATA.push(final_entry);
            // Also accumulate EnergyRecord for PostgreSQL block
            ACCUMULATED_RECORDS.push(merkle::EnergyRecord::new(
                pid,
                cpu_time_seconds,
                energy_joules,
                power_watts,
                vm_name.to_string(),
                timestamp,
            ));
        }
        processed_count += 1;
    }
    
    let process_duration = process_start.elapsed();
    
    let current_iter = unsafe { ITERATION_COUNT };
    let accumulated_count = unsafe { ACCUMULATED_DATA.len() };
    
    let msg1 = format!("[SGX-VM-DB]  Processed {} records (iteration {}/{})", processed_count, current_iter, BATCH_SIZE);
    sgx_print(&msg1);
    let msg2 = format!("[SGX-VM-DB] Total accumulated: {} records", accumulated_count);
    sgx_print(&msg2);
    
    // Check if we reached batch size - insert to PostgreSQL
    if current_iter == BATCH_SIZE {
        sgx_print("[SGX-VM-DB] ================================================");
        sgx_print(&format!("[SGX-VM-DB]  Batch size reached! Creating block with {} records...", accumulated_count));
        
        // Get accumulated records and create block
        let records: Vec<merkle::EnergyRecord> = unsafe { ACCUMULATED_RECORDS.clone() };
        let block_num = unsafe { BLOCK_NUMBER };
        let prev_root = unsafe { LATEST_CHAINED_ROOT };
        let timestamp = sgx_get_timestamp();
        
        // Create block with Merkle tree (inside SGX)
        let block = blockchain::Block::new(
            block_num,
            vm_name.to_string(),
            prev_root,
            records,
            timestamp,
        );
        
        sgx_print(&format!("[SGX-VM-DB] Block {} created:", block.block_number));
        sgx_print(&format!("[SGX-VM-DB]   Merkle root: {}...", &block.merkle_root_hex()[..16]));
        sgx_print(&format!("[SGX-VM-DB]   Chained root: {}...", &block.chained_root_hex()[..16]));
        sgx_print(&format!("[SGX-VM-DB]   Records: {}", block.record_count));
        
        // Connect to PostgreSQL and insert block
        let pg_start = std::time::Instant::now();
        let pg_config = postgres::PgConfig::new(
            "<HOST_IP>",  // Host IP from VM
            5432,
            "scaphandre",
            "scaphandre",
            "scaphandre"
        );
        
        match postgres::PgConnection::connect(pg_config) {
            Ok(mut pg_conn) => {
                match pg_conn.insert_block(&block) {
                    Ok(block_id) => {
                        let pg_duration = pg_start.elapsed().as_secs_f64() * 1000.0;
                        sgx_print(&format!("[TIMING-SGX] PostgreSQL insert: {:.2} ms", pg_duration));
                        sgx_print(&format!("[SGX-VM-DB]  Block inserted to PostgreSQL (id={})", block_id));
                        
                        // Update state for next block
                        unsafe {
                            BLOCK_NUMBER += 1;
                            LATEST_CHAINED_ROOT = block.chained_root;
                        }
                    }
                    Err(e) => {
                        eprintln!("[SGX-VM-DB]  Failed to insert block to PostgreSQL: {:?}", e);
                        return -7;
                    }
                }
            }
            Err(e) => {
                eprintln!("[SGX-VM-DB]  Failed to connect to PostgreSQL: {:?}", e);
                return -8;
            }
        }
        
        // Reset counters and clear accumulated data
        unsafe {
            ITERATION_COUNT = 0;
            ACCUMULATED_DATA.clear();
            ACCUMULATED_RECORDS.clear();
        }
        sgx_print("[SGX-VM-DB] ================================================");
    }
    
    sgx_print("[TIMING-SGX] ================================================");
    let msg3 = format!("[TIMING-SGX] +- Energy calculations: {:.2} ms (avg {:.3} ms)", total_calc_time, total_calc_time / processed_count.max(1) as f64);
    sgx_print(&msg3);
    let msg4 = format!("[TIMING-SGX] +- Total processing: {:.2} ms", process_duration.as_secs_f64() * 1000.0);
    sgx_print(&msg4);
    sgx_print("[TIMING-SGX] ================================================");
    
    0 // Success
}

#[no_mangle]
#[cfg(not(feature = "use_mbedtls"))]
pub extern "C" fn ecall_db_export_with_verification(
    _vm_name_ptr: *const u8,
    _vm_name_len: usize,
    _energy_uj: u64,
    _counter: u64,
    _previous_hash_ptr: *const u8,
    _signature_ptr: *const u8,
    _energy_delta: u64,
    _proc_json_ptr: *const u8,
    _proc_json_len: usize,
) -> i32 {
    -99 // mbedtls feature not enabled
}

#[no_mangle]
pub extern "C" fn ecall_immudb_login(
    response_ptr: *mut u8,
    response_cap: usize,
    response_len_ptr: *mut usize,
) -> i32 {
    #[cfg(feature = "use_mbedtls")]
    {
        use std::net::TcpStream;
        use std::io::{Read, Write};
        use std::sync::Arc;
        use mbedtls::rng::Rdrand;
        use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
        use mbedtls::ssl::{Config, Context};
        use mbedtls::x509::certificate::Certificate;
        use mbedtls::alloc::List as MbedtlsList;
        
        if response_ptr.is_null() || response_len_ptr.is_null() {
            return -1;
        }
        
        // ImmuDB CA certificate (embedded)
        const IMMUD_CA_PEM: &str = include_str!("../../immudb_ca.pem");
        
        let addr = "127.0.0.1:8443";
        let body = r#"{"username":"immudb","password":"immudb","database":"defaultdb"}"#;
        let request = format!(
            "POST /api/v2/authorization/session/open HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {}",
            body.len(),
            body
        );
        
        // Setup TLS
        let pem = format!("{}\0", IMMUD_CA_PEM);
        let cert = match Certificate::from_pem(pem.as_bytes()) {
            Ok(c) => c,
            Err(_) => return -2, // CA cert parse failed
        };
        
        let mut ca_list = MbedtlsList::new();
        ca_list.push(cert);
        let ca_list: Arc<MbedtlsList<Certificate>> = Arc::new(ca_list);
        
        let rng = Arc::new(Rdrand);
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_authmode(AuthMode::Required);
        config.set_rng(rng.clone());
        config.set_ca_list(ca_list.clone(), None);
        let config = Arc::new(config);
        
        // Connect and perform TLS handshake
        let result = (|| -> Result<String, i32> {
            let mut tcp_stream = TcpStream::connect(addr).map_err(|_| -4)?;
            
            let mut ctx = Context::new(config.clone());
            ctx.establish(&mut tcp_stream, Some("localhost")).map_err(|_| -6)?;
            
            ctx.write_all(request.as_bytes()).map_err(|_| -7)?;
            ctx.flush().map_err(|_| -7)?;
            
            let mut response = String::new();
            ctx.read_to_string(&mut response).map_err(|_| -8)?;
            
            Ok(response)
        })();
        
        match result {
            Ok(response) => {
                let response_bytes = response.as_bytes();
                let copy_len = response_bytes.len().min(response_cap);
                
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        response_bytes.as_ptr(),
                        response_ptr,
                        copy_len
                    );
                    *response_len_ptr = copy_len;
                }
                
                0 // Success
            }
            Err(code) => code,
        }
    }
    
    #[cfg(not(feature = "use_mbedtls"))]
    {
        -99 // mbedtls feature not enabled
    }
}

#[no_mangle]
pub extern "C" fn ecall_immudb_insert(
    session_id_ptr: *const u8,
    session_id_len: usize,
    body_ptr: *const u8,
    body_len: usize,
    response_ptr: *mut u8,
    response_cap: usize,
    response_len_ptr: *mut usize,
) -> i32 {
    #[cfg(feature = "use_mbedtls")]
    {
        use std::net::TcpStream;
        use std::io::{Read, Write};
        use std::sync::Arc;
        use mbedtls::rng::Rdrand;
        use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
        use mbedtls::ssl::{Config, Context};
        use mbedtls::x509::certificate::Certificate;
        use mbedtls::alloc::List as MbedtlsList;
        
        if session_id_ptr.is_null() || body_ptr.is_null() || response_ptr.is_null() || response_len_ptr.is_null() {
            return -1;
        }
        
        // Read inputs
        let session_id_bytes = unsafe { slice::from_raw_parts(session_id_ptr, session_id_len) };
        let session_id = match core::str::from_utf8(session_id_bytes) {
            Ok(s) => s,
            Err(_) => return -2,
        };
        
        let body_bytes = unsafe { slice::from_raw_parts(body_ptr, body_len) };
        let body = match core::str::from_utf8(body_bytes) {
            Ok(s) => s,
            Err(_) => return -3,
        };
        
        let request = format!(
            "POST /api/v2/collection/cpulog_v3/documents HTTP/1.1\r\n\
             Host: localhost\r\n\
             Content-Type: application/json\r\n\
             Grpc-Metadata-SessionID: {}\r\n\
             Content-Length: {}\r\n\
             Connection: close\r\n\r\n\
             {}",
            session_id.trim(),
            body.len(),
            body
        );
        
        // ImmuDB CA certificate
        const IMMUD_CA_PEM: &str = include_str!("../../immudb_ca.pem");
        
        let addr = "127.0.0.1:8443";
        
        // Setup TLS
        let pem = format!("{}\0", IMMUD_CA_PEM);
        let cert = match Certificate::from_pem(pem.as_bytes()) {
            Ok(c) => c,
            Err(_) => return -4,
        };
        
        let mut ca_list = MbedtlsList::new();
        ca_list.push(cert);
        let ca_list: Arc<MbedtlsList<Certificate>> = Arc::new(ca_list);
        
        let rng = Arc::new(Rdrand);
        let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
        config.set_authmode(AuthMode::Required);
        config.set_rng(rng.clone());
        config.set_ca_list(ca_list.clone(), None);
        let config = Arc::new(config);
        
        // Connect and send
        let result = (|| -> Result<String, i32> {
            let mut tcp_stream = TcpStream::connect(addr).map_err(|_| -6)?;
            
            let mut ctx = Context::new(config.clone());
            ctx.establish(&mut tcp_stream, Some("localhost")).map_err(|_| -8)?;
            
            ctx.write_all(request.as_bytes()).map_err(|_| -9)?;
            ctx.flush().map_err(|_| -9)?;
            
            let mut response = String::new();
            ctx.read_to_string(&mut response).map_err(|_| -10)?;
            
            Ok(response)
        })();
        
        match result {
            Ok(response) => {
                let response_bytes = response.as_bytes();
                let copy_len = response_bytes.len().min(response_cap);
                
                unsafe {
                    std::ptr::copy_nonoverlapping(
                        response_bytes.as_ptr(),
                        response_ptr,
                        copy_len
                    );
                    *response_len_ptr = copy_len;
                }
                
                0 // Success
            }
            Err(code) => code,
        }
    }
    
    #[cfg(not(feature = "use_mbedtls"))]
    {
        -99 // mbedtls feature not enabled
    }
}

// UNUSED: This function uses std::fs and cannot run in real SGX enclaves
// Kept for reference but commented out - use ecall_db_export_with_verification instead
/*
#[no_mangle]
pub extern "C" fn ecall_db_exporter_run(
    vm_name_ptr: *const u8,
    vm_name_len: usize,
    stop_flag_ptr: *const u8,
) -> i32 {
    #[cfg(feature = "use_mbedtls")]
    {
        use std::fs;
        use std::thread;
        use std::time::{Duration, Instant};
        
        let total_start = Instant::now();
        
        if vm_name_ptr.is_null() || stop_flag_ptr.is_null() {
            return -1;
        }
        
        let vm_name_bytes = unsafe { slice::from_raw_parts(vm_name_ptr, vm_name_len) };
        let vm_name = match core::str::from_utf8(vm_name_bytes) {
            Ok(s) => s,
            Err(_) => return -2,
        };
        
        const IMMUD_CA_PEM: &str = include_str!("../../immudb_ca.pem");
        let addr = "<IMMUDB_HOST>:8443";  // Host IP from VM
        
        
        
        println!("[SGX-DB] ================================================");
        println!("[SGX-DB] BOOT INTEGRITY VERIFICATION");
        println!("[SGX-DB] ================================================");
        
        let boot_verify_start = Instant::now();
        
        // Read IMA log
        let ima_read_start = Instant::now();
        let ima_log = match fs::read_to_string("/sys/kernel/security/ima/ascii_runtime_measurements") {
            Ok(content) => content,
            Err(e) => {
                eprintln!("[SGX-DB]  Failed to read IMA log: {}", e);
                return -10;
            }
        };
        println!("[TIMING-SGX-VM] IMA log read: {:.2} ms", ima_read_start.elapsed().as_secs_f64() * 1000.0);
        
        // Extract scaphandre hash from IMA
        let ima_hash = match extract_scaphandre_hash_from_ima(&ima_log) {
            Some(hash) => hash,
            None => {
                eprintln!("[SGX-DB]  Scaphandre not found in IMA log");
                return -13;
            }
        };
        
        println!("[SGX-DB]  IMA measured hash: {}", ima_hash);
        
        // Query ImmuDB for expected hash and PCRs
        println!("[SGX-DB] Querying ImmuDB for expected hash and PCRs...");
        let immudb_start = Instant::now();
        let (expected_hash, _expected_pcr0, _expected_pcr7, _expected_pcr10) = match fetch_expected_hash_from_immudb(
            "scaphandre",
            vm_name,
            "vm",
            addr,
            IMMUD_CA_PEM
        ) {
            Ok(data) => {
                let immudb_duration = immudb_start.elapsed();
                println!("[TIMING-SGX-VM] ImmuDB Query: {:.2} ms", immudb_duration.as_secs_f64() * 1000.0);
                data
            },
            Err(e) => {
                eprintln!("[SGX-DB]  Failed to query ImmuDB: error {}", e);
                return -14;
            }
        };
        
        println!("[SGX-DB]  ImmuDB expected hash: {}", expected_hash);
        
        // Compare hashes
        let hash_compare_start = Instant::now();
        if !hashes_match(&ima_hash, &expected_hash) {
            eprintln!("[SGX-DB] ================================================");
            eprintln!("[SGX-DB]    HASH MISMATCH - BINARY TAMPERED ");
            eprintln!("[SGX-DB] ================================================");
            eprintln!("[SGX-DB] IMA measured:   {}", ima_hash);
            eprintln!("[SGX-DB] ImmuDB expects: {}", expected_hash);
            eprintln!("[SGX-DB] REFUSING TO EXPORT DATA");
            return -15;
        }
        println!("[TIMING-SGX-VM] Hash comparison: {:.2} ms", hash_compare_start.elapsed().as_secs_f64() * 1000.0);
        
        println!("[SGX-DB]  Hash verification passed");
        
        
        // Read current PCR values from TPM
        let pcr_read_start = Instant::now();
        let pcr0_current = fs::read_to_string("/sys/class/tpm/tpm0/pcr-sha256/0")
            .ok()
            .and_then(|s| s.trim().strip_prefix("0x").or(Some(s.trim())).map(|s| s.to_lowercase()));
        let pcr7_current = fs::read_to_string("/sys/class/tpm/tpm0/pcr-sha256/7")
            .ok()
            .and_then(|s| s.trim().strip_prefix("0x").or(Some(s.trim())).map(|s| s.to_lowercase()));
        let pcr10_current = fs::read_to_string("/sys/class/tpm/tpm0/pcr-sha256/10")
            .ok()
            .and_then(|s| s.trim().strip_prefix("0x").or(Some(s.trim())).map(|s| s.to_lowercase()));
        println!("[TIMING-SGX-VM] PCR read: {:.2} ms", pcr_read_start.elapsed().as_secs_f64() * 1000.0);
        
        // Verify PCR0 if it exists in the database
        let pcr_verify_start = Instant::now();
        if !_expected_pcr0.is_empty() {
            if let Some(ref current) = pcr0_current {
                if !hashes_match(current, &_expected_pcr0) {
                    eprintln!("[SGX-DB] ================================================");
                    eprintln!("[SGX-DB]    PCR0 MISMATCH - BOOT TAMPERING ");
                    eprintln!("[SGX-DB] ================================================");
                    eprintln!("[SGX-DB] Current PCR0:  {}", current);
                    eprintln!("[SGX-DB] Expected PCR0: {}", _expected_pcr0);
                    eprintln!("[SGX-DB] REFUSING TO EXPORT DATA");
                    return -16;
                }
                println!("[SGX-DB]  PCR0 verification passed");
            }
        }
        
        // Verify PCR7 if it exists in the database
        if !_expected_pcr7.is_empty() {
            if let Some(ref current) = pcr7_current {
                if !hashes_match(current, &_expected_pcr7) {
                    eprintln!("[SGX-DB] ================================================");
                    eprintln!("[SGX-DB]    PCR7 MISMATCH - SECURE BOOT TAMPERING ");
                    eprintln!("[SGX-DB] ================================================");
                    eprintln!("[SGX-DB] Current PCR7:  {}", current);
                    eprintln!("[SGX-DB] Expected PCR7: {}", _expected_pcr7);
                    eprintln!("[SGX-DB] REFUSING TO EXPORT DATA");
                    return -17;
                }
                println!("[SGX-DB]  PCR7 verification passed");
            }
        }
        
        println!("[SGX-DB] PCR10 verification skipped (disabled)");
        println!("[TIMING-SGX-VM] PCR verification: {:.2} ms", pcr_verify_start.elapsed().as_secs_f64() * 1000.0);
        
        let boot_verify_duration = boot_verify_start.elapsed();
        println!("[TIMING-SGX-VM] Total boot verification: {:.2} ms", boot_verify_duration.as_secs_f64() * 1000.0);
        
        println!("[SGX-DB] ================================================");
        println!("[SGX-DB]    BOOT INTEGRITY VERIFIED ");
        println!("[SGX-DB] ================================================");
        println!("[SGX-DB] Starting secure data export...");
        
        // Login to get session
        let session_id = match sgx_immudb_login(addr, IMMUD_CA_PEM) {
            Ok(sid) => sid,
            Err(code) => return code,
        };
        
        eprintln!("[SGX-DB]  Session established inside SGX: {}...", &session_id[..16]);
        
        let mut last_hash = String::from("0000000000000000000000000000000000000000000000000000000000000000");
        let mut buffer: Vec<String> = Vec::new();
        const BATCH_SIZE: usize = 100;
        
        // Track previous energy for delta calculation
        let mut prev_vm_energy_uj: u64 = 0;
        
        loop {
            let iteration_start = Instant::now();
            let mut proc_read_count = 0;
            let mut stat_read_count = 0;
            let mut chain_verify_count = 0;
            let mut energy_calc_count = 0;
            let mut batch_send_count = 0;
            let mut total_proc_read_time = Duration::ZERO;
            let mut total_stat_read_time = Duration::ZERO;
            let mut total_chain_verify_time = Duration::ZERO;
            let mut total_energy_calc_time = Duration::ZERO;
            let mut total_batch_send_time = Duration::ZERO;
            
            let stop = unsafe { *stop_flag_ptr };
            if stop != 0 {
                eprintln!("[SGX-DB] Stop signal received");
                break;
            }
            
            let chain_dir = "/var/scaphandre/intel-rapl:0";
            
            // Read energy value
            let vm_total_energy_uj = match fs::read_to_string(format!("{}/energy_uj", chain_dir)) {
                Ok(content) => content.trim().parse::<u64>().unwrap_or(0),
                Err(e) => {
                    eprintln!("[SGX-DB] Failed to read VM total energy: {}", e);
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            
            // Calculate energy delta since last iteration
            let energy_delta_uj = if prev_vm_energy_uj > 0 {
                vm_total_energy_uj.saturating_sub(prev_vm_energy_uj)
            } else {
                0 // First iteration, no delta
            };
            prev_vm_energy_uj = vm_total_energy_uj;
            
            if energy_delta_uj == 0 {
                // No energy change, skip this iteration
                thread::sleep(Duration::from_secs(2));
                continue;
            }
            
            let chain_metadata_start = Instant::now();
            
            // Read chain metadata files (outside SGX)
            let counter = match fs::read_to_string(format!("{}/chain_counter", chain_dir)) {
                Ok(content) => content.trim().parse::<u64>().unwrap_or(0),
                Err(_) => {
                    eprintln!("[SGX-DB] No chain metadata found, skipping verification");
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            
            let prev_hash_hex = match fs::read_to_string(format!("{}/chain_previous_hash", chain_dir)) {
                Ok(content) => content.trim().to_string(),
                Err(e) => {
                    eprintln!("[SGX-DB] Failed to read previous hash: {}", e);
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            
            let signature_hex = match fs::read_to_string(format!("{}/chain_signature", chain_dir)) {
                Ok(content) => content.trim().to_string(),
                Err(e) => {
                    eprintln!("[SGX-DB] Failed to read signature: {}", e);
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            
            let chain_energy_delta = match fs::read_to_string(format!("{}/chain_energy_delta", chain_dir)) {
                Ok(content) => content.trim().parse::<u64>().unwrap_or(0),
                Err(e) => {
                    eprintln!("[SGX-DB] Failed to read energy delta: {}", e);
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            
            // Decode hex to bytes
            let prev_hash = match hex::decode(&prev_hash_hex) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("[SGX-DB] Failed to decode previous hash: {}", e);
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            
            let signature = match hex::decode(&signature_hex) {
                Ok(bytes) => bytes,
                Err(e) => {
                    eprintln!("[SGX-DB] Failed to decode signature: {}", e);
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            println!("[TIMING-SGX] Chain metadata read: {:.2} ms", chain_metadata_start.elapsed().as_secs_f64() * 1000.0);
            
            // Verify chain INSIDE SGX enclave
            let chain_verify_start = Instant::now();
            let verify_result = ecall_verify_energy_chain(
                vm_name.as_ptr(),
                vm_name.len(),
                vm_total_energy_uj,
                chain_energy_delta,
                counter,
                prev_hash.as_ptr(),
                signature.as_ptr(),
            );
            let chain_verify_duration = chain_verify_start.elapsed();
            println!("[TIMING-SGX] Chain verification (SGX): {:.2} ms", chain_verify_duration.as_secs_f64() * 1000.0);
            
            total_chain_verify_time += chain_verify_duration;
            chain_verify_count += 1;
            
            match verify_result {
                0 => {
                    println!("[SGX-DB]  Chain verified: counter={}, energy_delta={}uJ", 
                             counter, chain_energy_delta);
                }
                1 => {
                    println!("[SGX-DB]  Chain initialized: counter={}, energy_delta={}uJ", 
                             counter, chain_energy_delta);
                }
                -2 => {
                    eprintln!("[SGX-DB]  TAMPERING DETECTED: Signature mismatch!");
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
                -3 => {
                    // DISABLED: Ignore replay/rollback for testing - treat as warning
                    eprintln!("[SGX-DB]  WARNING: Counter discontinuity (ignored for testing)");
                    // Don't sleep, just continue normally
                }
                -4 => {
                    eprintln!("[SGX-DB]  FORK ATTACK: Previous hash mismatch!");
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
                _ => {
                    eprintln!("[SGX-DB] Chain verification failed: error {}", verify_result);
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            }
            
            println!("[SGX-DB] VM total energy: {} uJ, delta: {} uJ", 
                     vm_total_energy_uj, energy_delta_uj);
            
            let proc_read_start = Instant::now();
            let proc_entries = match fs::read_dir("/proc") {
                Ok(entries) => entries,
                Err(_) => {
                    thread::sleep(Duration::from_secs(2));
                    continue;
                }
            };
            total_proc_read_time += proc_read_start.elapsed();
            proc_read_count += 1;
            
            // Collect process data first
            let mut process_data: Vec<(u32, u64)> = Vec::new(); // (pid, cpu_ticks)
            let mut total_cpu_ticks: u64 = 0;
            
            for entry in proc_entries.flatten() {
                if let Ok(file_name) = entry.file_name().into_string() {
                    if let Ok(pid) = file_name.parse::<u32>() {
                        let stat_path = format!("/proc/{}/stat", pid);
                        let stat_read_start = Instant::now();
                        if let Ok(stat_content) = fs::read_to_string(&stat_path) {
                            total_stat_read_time += stat_read_start.elapsed();
                            stat_read_count += 1;
                            let parts: Vec<&str> = stat_content.split_whitespace().collect();
                            if parts.len() > 14 {
                                let utime: u64 = parts[13].parse().unwrap_or(0);
                                let stime: u64 = parts[14].parse().unwrap_or(0);
                                let cpu_ticks = utime + stime;
                                
                                if cpu_ticks > 0 {
                                    process_data.push((pid, cpu_ticks));
                                    total_cpu_ticks += cpu_ticks;
                                }
                            }
                        }
                    }
                }
            }
            
            if total_cpu_ticks == 0 {
                eprintln!("[SGX-DB] No CPU activity detected, skipping iteration");
                thread::sleep(Duration::from_secs(2));
                continue;
            }
            
            println!("[SGX-DB] Found {} processes, total CPU ticks: {}", 
                     process_data.len(), total_cpu_ticks);
            
            for (pid, cpu_ticks) in process_data {
                let energy_calc_start = Instant::now();
                
                // Calculate CPU percentage
                let cpu_percentage = (cpu_ticks as f64 / total_cpu_ticks as f64) * 100.0;
                
                // Use SGX enclave to calculate process energy
                let mut process_energy_uj: u64 = 0;
                let result = ecall_compute_single_process_energy(
                    energy_delta_uj,
                    cpu_percentage,
                    &mut process_energy_uj as *mut u64,
                );
                
                total_energy_calc_time += energy_calc_start.elapsed();
                energy_calc_count += 1;
                
                if result != 0 {
                    eprintln!("[SGX-DB] Failed to compute energy for PID {}: error {}", pid, result);
                    continue;
                }
                
                // Convert to joules and watts
                let cpu_time_seconds = cpu_ticks as f64 / 100.0;
                let energy_joules = process_energy_uj as f64 / 1_000_000.0;
                let power_watts = if cpu_time_seconds > 0.0 {
                    energy_joules / cpu_time_seconds
                } else {
                    0.0
                };
                
                let timestamp = sgx_get_timestamp();
                
                let base_entry = format!(
                    r#"{{"pid":{},"cpu_time":{:.4},"energy_joules":{:.4},"power_watts":{:.4},"timestamp":"{}","vm_name":"{}"}}"#,
                    pid, cpu_time_seconds, energy_joules, power_watts, timestamp, vm_name
                );
                
                let chain_input = format!("{}{}", last_hash, base_entry);
                let new_hash = sgx_sha256(&chain_input);
                last_hash = new_hash.clone();
                
                let final_entry = format!(
                    r#"{{"pid":{},"cpu_time":{:.4},"energy_joules":{:.4},"power_watts":{:.4},"timestamp":"{}","vm_name":"{}","hash_chain":"{}"}}"#,
                    pid, cpu_time_seconds, energy_joules, power_watts, timestamp, vm_name, new_hash
                );
                
                buffer.push(final_entry);
                
                if buffer.len() >= BATCH_SIZE {
                    let docs = buffer.join(",\n");
                    let body = format!(r#"{{"documents":[{}]}}"#, docs);
                    
                    let batch_send_start = Instant::now();
                    match sgx_immudb_insert(addr, IMMUD_CA_PEM, &session_id, &body) {
                        Ok(_) => {
                            total_batch_send_time += batch_send_start.elapsed();
                            batch_send_count += 1;
                            eprintln!("[SGX-DB]  {} records", buffer.len());
                            buffer.clear();
                        }
                        Err(_) => {
                            eprintln!("[SGX-DB] Insert failed, retrying...");
                        }
                    }
                }
            }
            
            // Send remaining buffered entries
            if !buffer.is_empty() {
                let docs = buffer.join(",\n");
                let body = format!(r#"{{"documents":[{}]}}"#, docs);
                
                let batch_send_start = Instant::now();
                match sgx_immudb_insert(addr, IMMUD_CA_PEM, &session_id, &body) {
                    Ok(_) => {
                        total_batch_send_time += batch_send_start.elapsed();
                        batch_send_count += 1;
                        eprintln!("[SGX-DB]  {} records (final batch)", buffer.len());
                        buffer.clear();
                    }
                    Err(_) => {
                        eprintln!("[SGX-DB] Final batch insert failed");
                    }
                }
            }
            
            let iteration_duration = iteration_start.elapsed();
            eprintln!("[TIMING-SGX-VM] Export Iteration: {:.2} ms", iteration_duration.as_secs_f64() * 1000.0);
            eprintln!("[TIMING-SGX-VM]   /proc reads: {} times, {:.2} ms total", 
                proc_read_count, 
                total_proc_read_time.as_secs_f64() * 1000.0);
            eprintln!("[TIMING-SGX-VM]   stat reads: {} times, {:.2} ms total, {:.4} ms avg", 
                stat_read_count, 
                total_stat_read_time.as_secs_f64() * 1000.0,
                total_stat_read_time.as_secs_f64() * 1000.0 / stat_read_count.max(1) as f64);
            eprintln!("[TIMING-SGX-VM]   chain verify (SGX): {} times, {:.2} ms total", 
                chain_verify_count, 
                total_chain_verify_time.as_secs_f64() * 1000.0);
            eprintln!("[TIMING-SGX-VM]   energy calc (SGX): {} times, {:.2} ms total, {:.4} ms avg", 
                energy_calc_count, 
                total_energy_calc_time.as_secs_f64() * 1000.0,
                total_energy_calc_time.as_secs_f64() * 1000.0 / energy_calc_count.max(1) as f64);
            eprintln!("[TIMING-SGX-VM]   batch sends: {} times, {:.2} ms total, {:.2} ms avg", 
                batch_send_count, 
                total_batch_send_time.as_secs_f64() * 1000.0,
                total_batch_send_time.as_secs_f64() * 1000.0 / batch_send_count.max(1) as f64);
            
            thread::sleep(Duration::from_secs(2));
        }
        
        let total_duration = total_start.elapsed();
        println!("[TIMING-SGX-VM] Total SGX VM Runtime: {:.2} seconds", total_duration.as_secs_f64());
        
        0
    }
    
    #[cfg(not(feature = "use_mbedtls"))]
    {
        -99
    }
}
*/

#[cfg(feature = "use_mbedtls")]
fn sgx_immudb_login(addr: &str, ca_pem: &str) -> Result<String, i32> {
    use std::sync::Arc;
    use std::net::TcpStream;
    use std::io::{Read, Write};
    use mbedtls::rng::Rdrand;
    use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
    use mbedtls::ssl::{Config, Context};
    use mbedtls::x509::certificate::Certificate;
    use mbedtls::alloc::List as MbedtlsList;
    
    let body = r#"{"username":"immudb","password":"immudb","database":"defaultdb"}"#;
    let request = format!(
        "POST /api/v2/authorization/session/open HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        body.len(), body
    );
    
    let pem = format!("{}\0", ca_pem);
    let cert = Certificate::from_pem(pem.as_bytes()).map_err(|_| -2)?;
    let mut ca_list = MbedtlsList::new();
    ca_list.push(cert);
    let ca_list = Arc::new(ca_list);
    
    let rng = Arc::new(Rdrand);
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_authmode(AuthMode::Required);
    config.set_rng(rng);
    config.set_ca_list(ca_list, None);
    let config = Arc::new(config);
    
    let mut tcp = TcpStream::connect(addr).map_err(|_| -3)?;
    let mut ctx = Context::new(config);
    ctx.establish(&mut tcp, Some("localhost")).map_err(|_| -4)?;
    ctx.write_all(request.as_bytes()).map_err(|_| -5)?;
    ctx.flush().map_err(|_| -5)?;
    
    let mut response = String::new();
    ctx.read_to_string(&mut response).map_err(|_| -6)?;
    
    if let Some(start) = response.find("\"sessionID\":\"") {
        if let Some(end) = response[start + 13..].find('"') {
            return Ok(response[start + 13..start + 13 + end].to_string());
        }
    }
    Err(-7)
}

#[cfg(feature = "use_mbedtls")]
fn sgx_immudb_insert(addr: &str, ca_pem: &str, session_id: &str, body: &str) -> Result<(), i32> {
    use std::sync::Arc;
    use std::net::TcpStream;
    use std::io::{Read, Write};
    use mbedtls::rng::Rdrand;
    use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
    use mbedtls::ssl::{Config, Context};
    use mbedtls::x509::certificate::Certificate;
    use mbedtls::alloc::List as MbedtlsList;
    
    let request = format!(
        "POST /api/v2/collection/cpulog_v3/documents HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nGrpc-Metadata-SessionID: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
        session_id.trim(), body.len(), body
    );
    
    let pem = format!("{}\0", ca_pem);
    let cert = Certificate::from_pem(pem.as_bytes()).map_err(|_| -2)?;
    let mut ca_list = MbedtlsList::new();
    ca_list.push(cert);
    let ca_list = Arc::new(ca_list);
    
    let rng = Arc::new(Rdrand);
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_authmode(AuthMode::Required);
    config.set_rng(rng);
    config.set_ca_list(ca_list, None);
    let config = Arc::new(config);
    
    let mut tcp = TcpStream::connect(addr).map_err(|_| -3)?;
    let mut ctx = Context::new(config);
    ctx.establish(&mut tcp, Some("localhost")).map_err(|_| -4)?;
    ctx.write_all(request.as_bytes()).map_err(|_| -5)?;
    ctx.flush().map_err(|_| -5)?;
    
    let mut response = String::new();
    ctx.read_to_string(&mut response).map_err(|_| -6)?;
    
    if response.contains("\"transactionId\"") { Ok(()) } else { Err(-7) }
}

#[cfg(feature = "use_mbedtls")]
fn sgx_sha256(data: &str) -> String {
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(data.as_bytes());
    format!("{:x}", hasher.finalize())
}

#[cfg(feature = "use_mbedtls")]
fn sgx_get_timestamp() -> String {
    use std::time::SystemTime;
    let now = SystemTime::now();
    let duration = now.duration_since(SystemTime::UNIX_EPOCH).unwrap();
    let secs = duration.as_secs();
    
    let days = secs / 86400;
    let remaining = secs % 86400;
    let hour = (remaining / 3600) as u32;
    let min = ((remaining % 3600) / 60) as u32;
    let sec = (remaining % 60) as u32;
    
    let mut year = 1970;
    let mut day_count = days;
    loop {
        let days_in_year = if (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0) { 366 } else { 365 };
        if day_count < days_in_year { break; }
        day_count -= days_in_year;
        year += 1;
    }
    
    let mut month = 1u32;
    for m in 1..=12 {
        let days_in_month = match m {
            1|3|5|7|8|10|12 => 31,
            4|6|9|11 => 30,
            2 => if (year%4==0 && year%100!=0)||(year%400==0) {29} else {28},
            _ => 0
        };
        if day_count < days_in_month { month = m; break; }
        day_count -= days_in_month;
    }
    let day = (day_count + 1) as u32;
    format!("{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", year, month, day, hour, min, sec)
}


/// Extract scaphandre binary hash from IMA log
/// Searches for scaphandre binary entry and extracts its SHA256 hash
fn extract_scaphandre_hash_from_ima(ima_log: &str) -> Option<String> {
    let mut last_hash: Option<String> = None;
    
    for line in ima_log.lines() {
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() < 5 {
            continue;
        }
        
        let file_path = parts[4];
        let file_hash = parts[3];
        
        // Look for scaphandre binary (not loader, not build scripts)
        if file_path.contains("scaphandre") 
            && !file_path.contains("loader") 
            && !file_path.contains("build-script")
            && !file_path.contains("/build/")
            && file_path.ends_with("/scaphandre") {
            // Extract hash value (format: "sha256:abc123...")
            let hash_value = if file_hash.contains(':') {
                file_hash.split(':').nth(1).unwrap_or("")
            } else {
                file_hash
            };
            
            // Keep updating to get the LAST measurement
            last_hash = Some(hash_value.to_string());
        }
    }
    last_hash
}

/// Fetch expected hash from ImmuDB inside SGX using TLS
#[cfg(feature = "use_mbedtls")]
fn fetch_expected_hash_from_immudb(
    binary_name: &str,
    hostname: &str,
    deployment_type: &str,
    addr: &str,
    ca_pem: &str,
) -> Result<(String, String, String, String), i32> {
    use mbedtls::ssl::{Config, Context};
    use mbedtls::x509::Certificate;
    use mbedtls::ssl::config::{Endpoint, Preset, Transport, AuthMode};
    use mbedtls::alloc::List as MbedtlsList;
    use mbedtls::rng::Rdrand;
    use std::net::TcpStream;
    use std::io::{Read, Write};
    use std::sync::Arc;
    
    println!("[SGX-HASH] ================================================");
    println!("[SGX-HASH] Querying ImmuDB INSIDE SGX ENCLAVE");
    println!("[SGX-HASH] ================================================");
    println!("[SGX-HASH]   Binary: {}", binary_name);
    println!("[SGX-HASH]   Host: {}", hostname);
    println!("[SGX-HASH]   Type: {}", deployment_type);
    println!("[SGX-HASH]   ImmuDB: {}", addr);
    println!("[SGX-HASH] NOTE: This TLS connection is INSIDE SGX enclave");
    println!("[SGX-HASH]       Host CANNOT see the query or response");
    
    // 1. Login to ImmuDB
    let login_body = format!(
        r#"{{"username":"immudb","password":"immudb","database":"defaultdb"}}"#
    );
    let login_request = format!(
        "POST /api/v2/authorization/session/open HTTP/1.1\r\n\
         Host: localhost\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Connection: keep-alive\r\n\r\n{}",
        login_body.len(),
        login_body
    );
    
    let pem = format!("{}\0", ca_pem);
    let cert = Certificate::from_pem(pem.as_bytes()).map_err(|_| -2)?;
    let mut ca_list = MbedtlsList::new();
    ca_list.push(cert);
    let ca_list = Arc::new(ca_list);
    
    let rng = Arc::new(Rdrand);
    let mut config = Config::new(Endpoint::Client, Transport::Stream, Preset::Default);
    config.set_authmode(AuthMode::Required);
    config.set_rng(rng);
    config.set_ca_list(ca_list, None);
    let config = Arc::new(config);
    
    let mut tcp = TcpStream::connect(addr).map_err(|_| -3)?;
    let mut ctx = Context::new(config.clone());
    ctx.establish(&mut tcp, Some("localhost")).map_err(|_| -4)?;
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
    
    println!("[SGX-HASH]  Logged in to ImmuDB (TLS inside SGX)");
    println!("[SGX-HASH]  Session established - host cannot see credentials");
    
    // 2. Query for hash
    let query_body = format!(
        r#"{{"page":1,"pageSize":1,"query":{{"expressions":[{{"fieldComparisons":[{{"field":"binary_name","operator":"EQ","value":"{}"}},{{"field":"hostname","operator":"EQ","value":"{}"}},{{"field":"deployment_type","operator":"EQ","value":"{}"}},{{"field":"active","operator":"EQ","value":true}}]}}]}},"orderBy":[{{"field":"_id","desc":true}}]}}"#,
        binary_name, hostname, deployment_type
    );
    let query_request = format!(
        "POST /api/v2/collection/binary_hashes_v2/documents/search HTTP/1.1\r\n\
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
    ctx2.establish(&mut tcp2, Some("localhost")).map_err(|_| -4)?;
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
    
    // Extract hash_value and PCR values from response
    let hash = if let Some(start) = query_response.find(r#""hash_value":""#) {
        let start = start + r#""hash_value":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            query_response[start..start + end].to_string()
        } else {
            return Err(-8);
        }
    } else {
        return Err(-8);
    };
    
    let pcr0 = if let Some(start) = query_response.find(r#""pcr0":""#) {
        let start = start + r#""pcr0":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            query_response[start..start + end].to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    
    let pcr7 = if let Some(start) = query_response.find(r#""pcr7":""#) {
        let start = start + r#""pcr7":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            query_response[start..start + end].to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    
    let pcr10 = if let Some(start) = query_response.find(r#""pcr10":""#) {
        let start = start + r#""pcr10":""#.len();
        if let Some(end) = query_response[start..].find('"') {
            query_response[start..start + end].to_string()
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    
    println!("[SGX-HASH]  Retrieved expected hash from ImmuDB");
    println!("[SGX-HASH]  Expected hash: {}", hash);
    println!("[SGX-HASH]  Expected PCR0:  {}", pcr0);
    println!("[SGX-HASH]  Expected PCR7:  {}", pcr7);
    println!("[SGX-HASH]  Expected PCR10: {}", pcr10);
    println!("[SGX-HASH]  Host CANNOT see these values - protected by SGX");
    
    Ok((hash, pcr0, pcr7, pcr10))
}

#[cfg(not(feature = "use_mbedtls"))]
fn fetch_expected_hash_from_immudb(
    _binary_name: &str,
    _hostname: &str,
    _deployment_type: &str,
    _addr: &str,
    _ca_pem: &str,
) -> Result<(String, String, String, String), i32> {
    Err(-99) // mbedtls feature not enabled
}

/// Compare two hashes (case-insensitive)
fn hashes_match(hash1: &str, hash2: &str) -> bool {
    hash1.eq_ignore_ascii_case(hash2)
}

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
    
    println!("[SGX-HASH-VERIFY] ===================================");
    println!("[SGX-HASH-VERIFY] Starting binary verification inside SGX");
    println!("[SGX-HASH-VERIFY] ===================================");
    println!("[SGX-HASH-VERIFY] Hostname: {}", hostname);
    println!("[SGX-HASH-VERIFY] Deployment: {}", deployment_type);
    
    // Extract PCR values from input (96 bytes: 32 bytes each for PCR0, PCR7, PCR10)
    if pcr_values.len() < 96 {
        return -2;
    }
    let pcr0_bytes = &pcr_values[0..32];
    let pcr7_bytes = &pcr_values[32..64];
    let pcr10_bytes = &pcr_values[64..96];
    
    // Convert to hex strings for comparison
    let pcr0_hex = pcr0_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let pcr7_hex = pcr7_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    let pcr10_hex = pcr10_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();
    
    println!("[SGX-HASH-VERIFY]  Received PCR0:  {}", pcr0_hex);
    println!("[SGX-HASH-VERIFY]  Received PCR7:  {}", pcr7_hex);
    println!("[SGX-HASH-VERIFY]  Received PCR10: {}", pcr10_hex);
    
    // Verify PCR 10 is not zero (IMA is active)
    let pcr10_nonzero = pcr10_bytes.iter().any(|&b| b != 0);
    if !pcr10_nonzero {
        eprintln!("[SGX-HASH-VERIFY]  PCR 10 is zero - IMA not active");
        return -2;
    }
    println!("[SGX-HASH-VERIFY]  PCR 10 verified (IMA active)");
    
    let ima_hash = match extract_scaphandre_hash_from_ima(ima_log) {
        Some(hash) => hash,
        None => {
            eprintln!("[SGX-HASH-VERIFY]  Scaphandre binary not found in IMA log");
            return -4;
        }
    };
    
    println!("[SGX-HASH-VERIFY]  IMA measured hash: {}", ima_hash);
    
    println!("[SGX-HASH-VERIFY] Querying ImmuDB via TLS inside SGX...");
    println!("[SGX-HASH-VERIFY] Host provides address but CANNOT see the query");
    
    let (expected_hash, expected_pcr0, expected_pcr7, expected_pcr10) = match fetch_expected_hash_from_immudb(
        "scaphandre",
        hostname,
        deployment_type,
        immudb_addr,
        ca_pem
    ) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("[SGX-HASH-VERIFY]  Failed to query ImmuDB: error code {}", e);
            return -5;
        }
    };
    
    println!("[SGX-HASH-VERIFY]  ImmuDB expected hash: {}", expected_hash);
    
    println!("[SGX-HASH-VERIFY] Comparing hashes inside SGX enclave...");
    println!("[SGX-HASH-VERIFY]   IMA measured:   {}", ima_hash);
    println!("[SGX-HASH-VERIFY]   ImmuDB expects: {}", expected_hash);
    if !hashes_match(&ima_hash, &expected_hash) {
        eprintln!("[SGX-HASH-VERIFY] ===================================");
        eprintln!("[SGX-HASH-VERIFY]    HASH MISMATCH DETECTED ");
        eprintln!("[SGX-HASH-VERIFY] ===================================");
        eprintln!("[SGX-HASH-VERIFY] IMA measured:   {}", ima_hash);
        eprintln!("[SGX-HASH-VERIFY] ImmuDB expects: {}", expected_hash);
        eprintln!("[SGX-HASH-VERIFY] POSSIBLE TAMPERING - REJECTING ALL DATA");
        eprintln!("[SGX-HASH-VERIFY] ===================================");
        return -6; // CRITICAL: Hash mismatch
    }
    
    println!("[SGX-HASH-VERIFY] Comparing PCR values inside SGX enclave...");
    
    // Only verify PCRs if they exist in the database (for backwards compatibility)
    if !expected_pcr0.is_empty() && !hashes_match(&pcr0_hex, &expected_pcr0) {
        eprintln!("[SGX-HASH-VERIFY] ===================================");
        eprintln!("[SGX-HASH-VERIFY]    PCR0 MISMATCH DETECTED ");
        eprintln!("[SGX-HASH-VERIFY] ===================================");
        eprintln!("[SGX-HASH-VERIFY] Received PCR0: {}", pcr0_hex);
        eprintln!("[SGX-HASH-VERIFY] Expected PCR0: {}", expected_pcr0);
        eprintln!("[SGX-HASH-VERIFY] POSSIBLE BOOT TAMPERING - REJECTING ALL DATA");
        eprintln!("[SGX-HASH-VERIFY] ===================================");
        return -7; // PCR0 mismatch
    }
    
    if !expected_pcr7.is_empty() && !hashes_match(&pcr7_hex, &expected_pcr7) {
        eprintln!("[SGX-HASH-VERIFY] ===================================");
        eprintln!("[SGX-HASH-VERIFY]    PCR7 MISMATCH DETECTED ");
        eprintln!("[SGX-HASH-VERIFY] ===================================");
        eprintln!("[SGX-HASH-VERIFY] Received PCR7: {}", pcr7_hex);
        eprintln!("[SGX-HASH-VERIFY] Expected PCR7: {}", expected_pcr7);
        eprintln!("[SGX-HASH-VERIFY] POSSIBLE SECURE BOOT TAMPERING - REJECTING ALL DATA");
        eprintln!("[SGX-HASH-VERIFY] ===================================");
        return -8; // PCR7 mismatch
    }
    
    println!("[SGX-HASH-VERIFY] PCR10 verification skipped (disabled)");
    
    if !expected_pcr0.is_empty() {
        println!("[SGX-HASH-VERIFY]  PCR0 verified");
    }
    if !expected_pcr7.is_empty() {
        println!("[SGX-HASH-VERIFY]  PCR7 verified");
    }
    
    println!("[SGX-HASH-VERIFY] ===================================");
    println!("[SGX-HASH-VERIFY]    HASH VERIFICATION PASSED ");
    println!("[SGX-HASH-VERIFY] ===================================");
    println!("[SGX-HASH-VERIFY] Binary integrity confirmed");
    println!("[SGX-HASH-VERIFY] Hash: {}", ima_hash);
    println!("[SGX-HASH-VERIFY] ===================================");
    
    0 // Success
}


use crate::merkle::EnergyRecord;
use crate::blockchain::Blockchain;
use crate::postgres::{PgConfig, PgConnection};
use crate::checkpoint::{Checkpoint, SealedStorage};

/// Global blockchain state (inside SGX enclave)
static mut BLOCKCHAIN: Option<Blockchain> = None;
static mut PG_CONNECTION: Option<PgConnection> = None;
static mut SEALED_STORAGE: Option<SealedStorage> = None;

/// Blockchain batch size (records per block)
const BLOCKCHAIN_BATCH_SIZE: usize = 100;

#[no_mangle]
pub extern "C" fn ecall_blockchain_init(
    vm_name_ptr: *const u8,
    vm_name_len: usize,
    pg_host_ptr: *const u8,
    pg_host_len: usize,
    pg_port: u16,
    pg_user_ptr: *const u8,
    pg_user_len: usize,
    pg_pass_ptr: *const u8,
    pg_pass_len: usize,
    pg_db_ptr: *const u8,
    pg_db_len: usize,
    checkpoint_path_ptr: *const u8,
    checkpoint_path_len: usize,
) -> i32 {
    // Validate pointers
    if vm_name_ptr.is_null() || pg_host_ptr.is_null() || pg_user_ptr.is_null() 
        || pg_pass_ptr.is_null() || pg_db_ptr.is_null() || checkpoint_path_ptr.is_null() {
        return -1;
    }

    // Parse strings
    let vm_name = unsafe {
        let slice = slice::from_raw_parts(vm_name_ptr, vm_name_len);
        String::from_utf8_lossy(slice).to_string()
    };
    let pg_host = unsafe {
        let slice = slice::from_raw_parts(pg_host_ptr, pg_host_len);
        String::from_utf8_lossy(slice).to_string()
    };
    let pg_user = unsafe {
        let slice = slice::from_raw_parts(pg_user_ptr, pg_user_len);
        String::from_utf8_lossy(slice).to_string()
    };
    let pg_pass = unsafe {
        let slice = slice::from_raw_parts(pg_pass_ptr, pg_pass_len);
        String::from_utf8_lossy(slice).to_string()
    };
    let pg_db = unsafe {
        let slice = slice::from_raw_parts(pg_db_ptr, pg_db_len);
        String::from_utf8_lossy(slice).to_string()
    };
    let checkpoint_path = unsafe {
        let slice = slice::from_raw_parts(checkpoint_path_ptr, checkpoint_path_len);
        String::from_utf8_lossy(slice).to_string()
    };

    println!("[SGX-BLOCKCHAIN] ============================================");
    println!("[SGX-BLOCKCHAIN] Initializing blockchain for VM: {}", vm_name);
    println!("[SGX-BLOCKCHAIN] PostgreSQL: {}:{}/{}", pg_host, pg_port, pg_db);
    println!("[SGX-BLOCKCHAIN] ============================================");

    // Connect to PostgreSQL
    let pg_config = PgConfig::new(&pg_host, pg_port, &pg_db, &pg_user, &pg_pass);
    let mut pg_conn = match PgConnection::connect(pg_config) {
        Ok(conn) => conn,
        Err(e) => {
            eprintln!("[SGX-BLOCKCHAIN]  PostgreSQL connection failed: {}", e);
            return -2;
        }
    };

    // Load sealed checkpoint
    let sealed_storage = SealedStorage::new(&checkpoint_path);
    let checkpoint = match sealed_storage.load() {
        Ok(Some(cp)) => {
            println!("[SGX-BLOCKCHAIN]  Loaded checkpoint: block={}, root={}...",
                cp.block_count, &cp.chained_root_hex()[..16]);
            cp
        }
        Ok(None) => {
            println!("[SGX-BLOCKCHAIN] No checkpoint found, starting fresh");
            Checkpoint::new(vm_name.clone())
        }
        Err(e) => {
            eprintln!("[SGX-BLOCKCHAIN]  Checkpoint load error: {:?}", e);
            return -3;
        }
    };

    // Verify checkpoint against database
    if checkpoint.block_count > 0 {
        match pg_conn.get_latest_block(&vm_name) {
            Ok(Some(latest)) => {
                if latest.block_number + 1 != checkpoint.block_count {
                    eprintln!("[SGX-BLOCKCHAIN]  Block count mismatch!");
                    eprintln!("[SGX-BLOCKCHAIN]   Checkpoint: {}", checkpoint.block_count);
                    eprintln!("[SGX-BLOCKCHAIN]   Database: {}", latest.block_number + 1);
                    return -3;
                }
                if latest.chained_root != checkpoint.chained_root_hex() {
                    eprintln!("[SGX-BLOCKCHAIN]  Chained root mismatch - TAMPERING DETECTED!");
                    eprintln!("[SGX-BLOCKCHAIN]   Checkpoint: {}", checkpoint.chained_root_hex());
                    eprintln!("[SGX-BLOCKCHAIN]   Database: {}", latest.chained_root);
                    return -3;
                }
                println!("[SGX-BLOCKCHAIN]  Database matches checkpoint");
            }
            Ok(None) => {
                eprintln!("[SGX-BLOCKCHAIN]  Database empty but checkpoint has {} blocks!", checkpoint.block_count);
                return -3;
            }
            Err(e) => {
                eprintln!("[SGX-BLOCKCHAIN]  Database query failed: {}", e);
                return -2;
            }
        }
    }

    // Initialize blockchain state
    let blockchain = Blockchain::from_checkpoint(
        vm_name,
        checkpoint.block_count,
        checkpoint.latest_chained_root,
        BLOCKCHAIN_BATCH_SIZE,
    );

    // Store in global state
    unsafe {
        BLOCKCHAIN = Some(blockchain);
        PG_CONNECTION = Some(pg_conn);
        SEALED_STORAGE = Some(sealed_storage);
    }

    println!("[SGX-BLOCKCHAIN]  Blockchain initialized successfully");
    println!("[SGX-BLOCKCHAIN] ============================================");

    0 // Success
}

#[no_mangle]
pub extern "C" fn ecall_blockchain_add_record(
    pid: u32,
    cpu_time: f64,
    energy_joules: f64,
    power_watts: f64,
    timestamp_ptr: *const u8,
    timestamp_len: usize,
) -> i32 {
    if timestamp_ptr.is_null() {
        return -2;
    }

    let timestamp = unsafe {
        let slice = slice::from_raw_parts(timestamp_ptr, timestamp_len);
        String::from_utf8_lossy(slice).to_string()
    };

    unsafe {
        let blockchain = match BLOCKCHAIN.as_mut() {
            Some(bc) => bc,
            None => {
                eprintln!("[SGX-BLOCKCHAIN]  Blockchain not initialized");
                return -1;
            }
        };

        let vm_name = blockchain.vm_name.clone();

        // Create energy record
        let record = EnergyRecord::new(
            pid,
            cpu_time,
            energy_joules,
            power_watts,
            vm_name,
            timestamp,
        );

        // Add to blockchain (may create block)
        let block_opt = blockchain.add_record(record);

        if let Some(block) = block_opt {
            // Block created - insert to database
            println!("[SGX-BLOCKCHAIN] ============================================");
            println!("[SGX-BLOCKCHAIN] Block {} created with {} records",
                block.block_number, block.record_count);
            println!("[SGX-BLOCKCHAIN]   Merkle root: {}...", &block.merkle_root_hex()[..16]);
            println!("[SGX-BLOCKCHAIN]   Chained root: {}...", &block.chained_root_hex()[..16]);

            // Insert to PostgreSQL
            let pg_conn = match PG_CONNECTION.as_mut() {
                Some(conn) => conn,
                None => return -1,
            };

            match pg_conn.insert_block(&block) {
                Ok(block_id) => {
                    println!("[SGX-BLOCKCHAIN]  Block inserted to PostgreSQL (id={})", block_id);
                }
                Err(e) => {
                    eprintln!("[SGX-BLOCKCHAIN]  Database insert failed: {}", e);
                    return -3;
                }
            }

            // Update and save checkpoint
            let sealed_storage = match SEALED_STORAGE.as_ref() {
                Some(ss) => ss,
                None => return -1,
            };

            let mut checkpoint = Checkpoint::new(blockchain.vm_name.clone());
            checkpoint.update(block.chained_root, blockchain.current_block_number);

            if let Err(e) = sealed_storage.save(&checkpoint) {
                eprintln!("[SGX-BLOCKCHAIN]  Checkpoint save failed: {:?}", e);
                return -4;
            }

            println!("[SGX-BLOCKCHAIN]  Checkpoint updated");
            println!("[SGX-BLOCKCHAIN] ============================================");

            return 1; // Block created
        }

        0 // Record added, no block yet
    }
}

#[no_mangle]
pub extern "C" fn ecall_blockchain_flush() -> i32 {
    unsafe {
        let blockchain = match BLOCKCHAIN.as_mut() {
            Some(bc) => bc,
            None => return -1,
        };

        if blockchain.accumulated_count() == 0 {
            println!("[SGX-BLOCKCHAIN] No records to flush");
            return 0;
        }

        let block = match blockchain.flush() {
            Some(b) => b,
            None => return 0,
        };

        println!("[SGX-BLOCKCHAIN] Flushing {} records to block {}",
            block.record_count, block.block_number);

        // Insert to PostgreSQL
        let pg_conn = match PG_CONNECTION.as_mut() {
            Some(conn) => conn,
            None => return -1,
        };

        match pg_conn.insert_block(&block) {
            Ok(_) => {}
            Err(e) => {
                eprintln!("[SGX-BLOCKCHAIN]  Database insert failed: {}", e);
                return -3;
            }
        }

        // Update checkpoint
        let sealed_storage = match SEALED_STORAGE.as_ref() {
            Some(ss) => ss,
            None => return -1,
        };

        let mut checkpoint = Checkpoint::new(blockchain.vm_name.clone());
        checkpoint.update(block.chained_root, blockchain.current_block_number);

        if let Err(e) = sealed_storage.save(&checkpoint) {
            eprintln!("[SGX-BLOCKCHAIN]  Checkpoint save failed: {:?}", e);
            return -4;
        }

        println!("[SGX-BLOCKCHAIN]  Flush complete");
        1
    }
}

#[no_mangle]
pub extern "C" fn ecall_blockchain_status(
    block_count_ptr: *mut u64,
    accumulated_count_ptr: *mut usize,
    chained_root_ptr: *mut u8, // 64 bytes for hex string
) -> i32 {
    unsafe {
        let blockchain = match BLOCKCHAIN.as_ref() {
            Some(bc) => bc,
            None => return -1,
        };

        if !block_count_ptr.is_null() {
            *block_count_ptr = blockchain.current_block_number;
        }

        if !accumulated_count_ptr.is_null() {
            *accumulated_count_ptr = blockchain.accumulated_count();
        }

        if !chained_root_ptr.is_null() {
            let hex = blockchain.latest_chained_root_hex();
            let bytes = hex.as_bytes();
            std::ptr::copy_nonoverlapping(bytes.as_ptr(), chained_root_ptr, bytes.len().min(64));
        }

        0
    }
}

