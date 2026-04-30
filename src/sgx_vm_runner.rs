
use std::path::Path;
use std::io::{Write, Read, BufRead, BufReader};
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::net::TcpStream;
use serde::{Deserialize, Serialize};

#[cfg(feature = "use_sgx_vm")]
use std::sync::Arc;
#[cfg(feature = "use_sgx_vm")]
use rustls::ClientConfig;
#[cfg(feature = "use_sgx_vm")]
use rustls::pki_types::{ServerName, CertificateDer};

/// Enclave CA certificate (embedded) - must match the enclave's certificate
#[cfg(feature = "use_sgx_vm")]
const ENCLAVE_CA_PEM: &str = include_str!("../enclave_ca.pem");

/// Default path to the SGX VM enclave binary
pub const DEFAULT_VM_ENCLAVE_PATH: &str = "/usr/lib/scaphandre/sgx_vm.sgxs";

/// Check if we should use remote SGX mode (connect to host's enclave)
fn get_remote_sgx_host() -> Option<String> {
    std::env::var("SGX_REMOTE_HOST").ok()
}

/// TLS stream wrapper for the enclave connection
#[cfg(feature = "use_sgx_vm")]
enum TlsStream {
    Rustls(rustls::StreamOwned<rustls::ClientConnection, TcpStream>),
    Plain(TcpStream),  // Fallback for debugging
}

#[cfg(feature = "use_sgx_vm")]
impl Read for TlsStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            TlsStream::Rustls(s) => s.read(buf),
            TlsStream::Plain(s) => s.read(buf),
        }
    }
}

#[cfg(feature = "use_sgx_vm")]
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

/// Persistent SGX enclave connection (local or remote) with TLS
#[cfg(feature = "use_sgx_vm")]
struct VmEnclaveConnection {
    stream: TlsStream,
    child: Option<std::process::Child>,  // None for remote connections
    is_remote: bool,
}

#[cfg(not(feature = "use_sgx_vm"))]
struct VmEnclaveConnection {
    stream: TcpStream,
    child: Option<std::process::Child>,
    is_remote: bool,
}

/// Global persistent enclave connection (created once, reused for all requests)
lazy_static::lazy_static! {
    static ref VM_ENCLAVE_CONNECTION: Mutex<Option<VmEnclaveConnection>> = Mutex::new(None);
}

#[derive(Serialize)]
struct VerifyChainRequest {
    operation: String,
    vm_name: String,
    energy_value: u64,
    counter: u64,
    previous_hash: String,  // Hex
    signature: String,       // Hex
}

#[derive(Serialize)]
struct ComputeEnergyRequest {
    operation: String,
    vm_total_energy_uj: u64,
    cpu_percentage: f64,
}

#[derive(Serialize)]
struct DbExportRequest {
    operation: String,
    vm_name: String,
    energy_uj: u64,
    counter: u64,
    previous_hash: String,
    signature: String,
    energy_delta: u64,
    processes: Vec<(u32, u64)>,
    session_id: Option<String>,
}

#[derive(Serialize)]
struct ImmudbInsertRequest {
    operation: String,
    session_id: String,
    body: String,
}

#[derive(Serialize)]
struct VerifyBootRequest {
    operation: String,
    pcr_values: String,       // Hex-encoded 96 bytes (PCR0 + PCR7 + PCR10)
    ima_log: String,          // Full IMA log content
    hostname: String,
    deployment_type: String,  // "host" or "vm"
    immudb_addr: String,      // e.g., "<IMMUDB_HOST>:8443"
    ca_pem: String,           // CA certificate in PEM format
}

#[derive(Deserialize, Debug)]
pub struct VmEnclaveResponse {
    pub status: i32,
    pub message: String,
    #[serde(default)]
    pub output_data: Option<String>,
}

/// Check if SGX hardware is available (local or remote)
#[cfg(feature = "use_sgx_vm")]
pub fn check_sgx_hardware() -> Result<(), String> {
    // If remote host is specified, we don't need local SGX hardware
    if get_remote_sgx_host().is_some() {
        println!("[SGX-VM] Using REMOTE SGX enclave (no local hardware needed)");
        return Ok(());
    }
    
    // Check for /dev/isgx or /dev/sgx_enclave
    if Path::new("/dev/isgx").exists() || Path::new("/dev/sgx_enclave").exists() {
        println!("[SGX-VM]  SGX hardware detected and available");
        return Ok(());
    }
    
    Err("SGX hardware not available - /dev/isgx or /dev/sgx_enclave not found. Set SGX_REMOTE_HOST=ip:port to use remote enclave.".to_string())
}

#[cfg(not(feature = "use_sgx_vm"))]
pub fn check_sgx_hardware() -> Result<(), String> {
    Err("SGX VM feature not compiled".to_string())
}

/// Get path to the SGX VM enclave binary
#[cfg(feature = "use_sgx_vm")]
fn get_vm_enclave_path() -> Result<String, String> {
    // Check environment variable first
    if let Ok(path) = std::env::var("SGX_VM_ENCLAVE_PATH") {
        if Path::new(&path).exists() {
            return Ok(path);
        }
    }
    
    // Check workspace/target paths
    let paths = [
        "target/x86_64-fortanix-unknown-sgx/release/sgx_vm.sgxs",
        "../target/x86_64-fortanix-unknown-sgx/release/sgx_vm.sgxs",
        "<SCAPHANDRE_DIR>/target/x86_64-fortanix-unknown-sgx/release/sgx_vm.sgxs",
        DEFAULT_VM_ENCLAVE_PATH,
    ];
    
    for path in &paths {
        if Path::new(path).exists() {
            return Ok(path.to_string());
        }
    }
    
    Err(format!(
        "SGX VM enclave binary not found. Tried:\n\
         - $SGX_VM_ENCLAVE_PATH environment variable\n\
         - {}\n\
         Build the enclave with: cargo build --release --target x86_64-fortanix-unknown-sgx -p sgx_vm",
        paths.join("\n- ")
    ))
}

/// Find the ftxsgx-runner executable
fn which_ftxsgx_runner() -> String {
    let paths = [
        "ftxsgx-runner",
        "/usr/bin/ftxsgx-runner",
        "/usr/local/bin/ftxsgx-runner",
        &format!("{}/.cargo/bin/ftxsgx-runner", std::env::var("HOME").unwrap_or_default()),
    ];
    
    for path in &paths {
        if Command::new(path)
            .arg("--version")
            .output()
            .is_ok()
        {
            return path.to_string();
        }
    }
    
    "ftxsgx-runner".to_string()
}

/// Spawn VM enclave and connect via TCP
#[cfg(feature = "use_sgx_vm")]
fn spawn_vm_enclave_with_tcp(enclave_path: &str) -> Result<(TcpStream, std::process::Child), i32> {
    let runner_path = which_ftxsgx_runner();
    println!("[SGX-VM-RUNNER] Using runner: {}", runner_path);
    println!("[SGX-VM-RUNNER] Starting VM enclave process...");
    
    let mut child = match Command::new(&runner_path)
        .arg(enclave_path)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            eprintln!("[SGX-VM-RUNNER] Failed to spawn enclave: {}", e);
            return Err(-202);
        }
    };
    
    println!("[SGX-VM-RUNNER] Enclave process started (PID: {})", child.id());
    
    // Read the port from stdout
    let stdout = child.stdout.take().expect("Failed to get stdout");
    let mut reader = BufReader::new(stdout);
    let mut port_line = String::new();
    
    match reader.read_line(&mut port_line) {
        Ok(0) => {
            eprintln!("[SGX-VM-RUNNER] Enclave closed without sending port");
            let _ = child.wait();
            return Err(-210);
        }
        Ok(_) => {}
        Err(e) => {
            eprintln!("[SGX-VM-RUNNER] Failed to read port from enclave: {}", e);
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
                eprintln!("[SGX-VM-RUNNER] Invalid port number '{}': {}", p, e);
                let _ = child.wait();
                return Err(-212);
            }
        }
    } else {
        eprintln!("[SGX-VM-RUNNER] Unexpected enclave output: {}", port_str);
        let _ = child.wait();
        return Err(-213);
    };
    
    println!("[SGX-VM-RUNNER] Enclave listening on port {}", port);
    
    // Connect to the enclave via TCP
    let stream = match TcpStream::connect(format!("127.0.0.1:{}", port)) {
        Ok(s) => {
            let _ = s.set_nodelay(true); // Send immediately, no waiting
            s
        }
        Err(e) => {
            eprintln!("[SGX-VM-RUNNER] Failed to connect to enclave: {}", e);
            let _ = child.wait();
            return Err(-214);
        }
    };
    
    println!("[SGX-VM-RUNNER]  Connected to enclave via TCP");
    Ok((stream, child))
}

/// Create TLS client configuration with embedded CA certificate
#[cfg(feature = "use_sgx_vm")]
fn create_tls_config() -> Result<Arc<ClientConfig>, i32> {
    use rustls::RootCertStore;
    
    // Parse the embedded CA certificate
    let mut root_store = RootCertStore::empty();
    
    let certs = rustls_pemfile::certs(&mut ENCLAVE_CA_PEM.as_bytes())
        .filter_map(|r| r.ok())
        .collect::<Vec<_>>();
    
    if certs.is_empty() {
        eprintln!("[SGX-VM-RUNNER] Failed to parse enclave CA certificate");
        return Err(-240);
    }
    
    for cert in certs {
        if let Err(e) = root_store.add(cert) {
            eprintln!("[SGX-VM-RUNNER] Failed to add CA cert: {:?}", e);
            return Err(-241);
        }
    }
    
    println!("[SGX-VM-RUNNER] Loaded enclave CA certificate");
    
    // Build TLS config
    let config = ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    
    Ok(Arc::new(config))
}

/// Connect to remote SGX enclave on host with TLS
#[cfg(feature = "use_sgx_vm")]
fn connect_to_remote_enclave(host_addr: &str) -> Result<TlsStream, i32> {
    println!("[SGX-VM-RUNNER] Connecting to REMOTE SGX enclave at {} with TLS...", host_addr);
    
    // Create TLS configuration
    let tls_config = create_tls_config()?;
    
    // Parse server name (use "sgx-enclave" to match the certificate CN)
    let server_name = ServerName::try_from("sgx-enclave".to_string())
        .map_err(|e| {
            eprintln!("[SGX-VM-RUNNER] Invalid server name: {:?}", e);
            -242
        })?;
    
    // Connect TCP
    let tcp_stream = TcpStream::connect(host_addr).map_err(|e| {
        eprintln!("[SGX-VM-RUNNER] Failed to connect to {}: {}", host_addr, e);
        -230
    })?;
    
    let _ = tcp_stream.set_nodelay(true); // Send immediately, no waiting
    
    println!("[SGX-VM-RUNNER] TCP connected, starting TLS handshake...");
    
    // Create TLS connection
    let tls_conn = rustls::ClientConnection::new(tls_config, server_name)
        .map_err(|e| {
            eprintln!("[SGX-VM-RUNNER] TLS connection failed: {:?}", e);
            -243
        })?;
    
    // Wrap in StreamOwned
    let tls_stream = rustls::StreamOwned::new(tls_conn, tcp_stream);
    
    println!("[SGX-VM-RUNNER] TLS connection established to remote SGX enclave");
    println!("[SGX-VM-RUNNER] All communication is now encrypted");
    
    Ok(TlsStream::Rustls(tls_stream))
}

/// Get or create a persistent VM enclave connection (local or remote)
#[cfg(feature = "use_sgx_vm")]
fn get_vm_enclave_connection() -> Result<std::sync::MutexGuard<'static, Option<VmEnclaveConnection>>, i32> {
    let mut conn_guard = VM_ENCLAVE_CONNECTION.lock().unwrap();
    
    if conn_guard.is_some() {
        return Ok(conn_guard);
    }
    
    // Check if we should use remote mode
    if let Some(remote_host) = get_remote_sgx_host() {
        println!("[SGX-VM-RUNNER] Creating REMOTE SGX enclave TLS connection...");
        println!("[SGX-VM-RUNNER] Remote host: {}", remote_host);
        
        let stream = connect_to_remote_enclave(&remote_host)?;
        
        *conn_guard = Some(VmEnclaveConnection { 
            stream, 
            child: None,
            is_remote: true,
        });
        println!("[SGX-VM-RUNNER] OK Remote TLS enclave connection established");
        
        return Ok(conn_guard);
    }
    
    // Local mode - spawn enclave and connect with TLS
    println!("[SGX-VM-RUNNER] Creating persistent LOCAL VM enclave TLS connection...");
    
    let enclave_path = match get_vm_enclave_path() {
        Ok(p) => p,
        Err(e) => {
            eprintln!("[SGX-VM-RUNNER] FATAL: {}", e);
            return Err(-201);
        }
    };
    
    let (tcp_stream, child) = spawn_vm_enclave_with_tcp(&enclave_path)?;
    
    // Upgrade to TLS
    let tls_config = create_tls_config()?;
    let server_name = ServerName::try_from("sgx-enclave".to_string())
        .map_err(|_| -242)?;
    let tls_conn = rustls::ClientConnection::new(tls_config, server_name)
        .map_err(|e| {
            eprintln!("[SGX-VM-RUNNER] Local TLS connection failed: {:?}", e);
            -243
        })?;
    let tls_stream = rustls::StreamOwned::new(tls_conn, tcp_stream);
    
    *conn_guard = Some(VmEnclaveConnection { 
        stream: TlsStream::Rustls(tls_stream), 
        child: Some(child),
        is_remote: false,
    });
    println!("[SGX-VM-RUNNER] Persistent LOCAL TLS enclave connection established");
    
    Ok(conn_guard)
}

/// Send request over TLS and receive response
#[cfg(feature = "use_sgx_vm")]
fn send_tls_request(stream: &mut TlsStream, request_json: &str) -> Result<VmEnclaveResponse, i32> {
    let request_bytes = request_json.as_bytes();
    let len_bytes = (request_bytes.len() as u32).to_be_bytes();
    
    // Send length prefix + data
    if let Err(e) = stream.write_all(&len_bytes) {
        eprintln!("[SGX-VM-RUNNER] TLS: Failed to send length: {}", e);
        return Err(-220);
    }
    if let Err(e) = stream.write_all(request_bytes) {
        eprintln!("[SGX-VM-RUNNER] TLS: Failed to send request: {}", e);
        return Err(-221);
    }
    if let Err(e) = stream.flush() {
        eprintln!("[SGX-VM-RUNNER] TLS: Failed to flush: {}", e);
        return Err(-222);
    }
    
    println!("[SGX-VM-RUNNER] TLS: Sent {} encrypted bytes to enclave", request_bytes.len());
    
    // Read response length
    let mut len_buf = [0u8; 4];
    if let Err(e) = stream.read_exact(&mut len_buf) {
        eprintln!("[SGX-VM-RUNNER] TLS: Failed to read response length: {}", e);
        return Err(-223);
    }
    
    let response_len = u32::from_be_bytes(len_buf) as usize;
    
    // Read response data
    let mut response_data = vec![0u8; response_len];
    if let Err(e) = stream.read_exact(&mut response_data) {
        eprintln!("[SGX-VM-RUNNER] TLS: Failed to read response: {}", e);
        return Err(-224);
    }
    
    // Parse response JSON
    let response_str = match String::from_utf8(response_data) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("[SGX-VM-RUNNER] TLS: Invalid UTF-8 in response: {}", e);
            return Err(-225);
        }
    };
    
    match serde_json::from_str(&response_str) {
        Ok(r) => Ok(r),
        Err(e) => {
            eprintln!("[SGX-VM-RUNNER] TLS: Failed to parse response JSON: {}", e);
            Err(-226)
        }
    }
}

/// Send request using the persistent VM enclave TLS connection
#[cfg(feature = "use_sgx_vm")]
fn send_request_to_vm_enclave(request_json: &str) -> Result<VmEnclaveResponse, i32> {
    let mut conn_guard = get_vm_enclave_connection()?;
    let conn = conn_guard.as_mut().ok_or(-250)?;
    send_tls_request(&mut conn.stream, request_json)
}



/// Verify boot integrity (TPM/IMA/ImmuDB) inside VM SGX enclave
#[cfg(feature = "use_sgx_vm")]
pub fn verify_boot_in_sgx(
    pcr_values: &[u8],       // 96 bytes: PCR0 + PCR7 + PCR10
    ima_log: &str,
    hostname: &str,
    deployment_type: &str,
    immudb_addr: &str,
    ca_pem: &str,
) -> Result<i32, i32> {
    println!("[SGX-VM-RUNNER] ================================================");
    println!("[SGX-VM-RUNNER] BOOT INTEGRITY VERIFICATION (inside SGX)");
    println!("[SGX-VM-RUNNER] ================================================");
    println!("[SGX-VM-RUNNER] Hostname: {}", hostname);
    println!("[SGX-VM-RUNNER] Deployment: {}", deployment_type);
    println!("[SGX-VM-RUNNER] IMA log size: {} bytes", ima_log.len());
    
    check_sgx_hardware().map_err(|_| -200)?;
    
    let request = VerifyBootRequest {
        operation: "verify_boot".to_string(),
        pcr_values: hex::encode(pcr_values),
        ima_log: ima_log.to_string(),
        hostname: hostname.to_string(),
        deployment_type: deployment_type.to_string(),
        immudb_addr: immudb_addr.to_string(),
        ca_pem: ca_pem.to_string(),
    };
    
    let request_json = serde_json::to_string(&request).unwrap();
    println!("[SGX-VM-RUNNER] Sending {} bytes to enclave...", request_json.len());
    
    let response = send_request_to_vm_enclave(&request_json)?;
    
    match response.status {
        0 => {
            println!("[SGX-VM-RUNNER] ================================================");
            println!("[SGX-VM-RUNNER]    BOOT INTEGRITY VERIFIED ");
            println!("[SGX-VM-RUNNER] ================================================");
        }
        -6 => {
            eprintln!("[SGX-VM-RUNNER] ================================================");
            eprintln!("[SGX-VM-RUNNER]    HASH MISMATCH - BINARY TAMPERED ");
            eprintln!("[SGX-VM-RUNNER] ================================================");
        }
        -7 => {
            eprintln!("[SGX-VM-RUNNER]    PCR0 MISMATCH - BOOT TAMPERED");
        }
        -8 => {
            eprintln!("[SGX-VM-RUNNER]    PCR7 MISMATCH - SECURE BOOT TAMPERED");
        }
        -9 => {
            eprintln!("[SGX-VM-RUNNER]    PCR10 MISMATCH - IMA TAMPERED");
        }
        _ => {
            eprintln!("[SGX-VM-RUNNER] Boot verification failed: {} - {}", response.status, response.message);
        }
    }
    
    Ok(response.status)
}

/// Verify HMAC chain from host SGX (inside VM SGX enclave)
#[cfg(feature = "use_sgx_vm")]
pub fn verify_chain_in_sgx(
    vm_name: &str,
    energy_value: u64,
    counter: u64,
    previous_hash: &[u8; 32],
    signature: &[u8; 32],
) -> Result<i32, i32> {
    println!("[SGX-VM-RUNNER] Verifying chain inside SGX enclave...");
    
    check_sgx_hardware().map_err(|_| -200)?;
    
    let request = VerifyChainRequest {
        operation: "verify_chain".to_string(),
        vm_name: vm_name.to_string(),
        energy_value,
        counter,
        previous_hash: hex::encode(previous_hash),
        signature: hex::encode(signature),
    };
    
    let request_json = serde_json::to_string(&request).unwrap();
    let response = send_request_to_vm_enclave(&request_json)?;
    
    println!("[SGX-VM-RUNNER] Chain verification result: {} - {}", response.status, response.message);
    
    Ok(response.status)
}

/// Compute per-process energy inside VM SGX enclave
#[cfg(feature = "use_sgx_vm")]
pub fn compute_process_energy_in_sgx(
    vm_total_energy_uj: u64,
    cpu_percentage: f64,
) -> Result<u64, i32> {
    check_sgx_hardware().map_err(|_| -200)?;
    
    let request = ComputeEnergyRequest {
        operation: "compute_process_energy".to_string(),
        vm_total_energy_uj,
        cpu_percentage,
    };
    
    let request_json = serde_json::to_string(&request).unwrap();
    let response = send_request_to_vm_enclave(&request_json)?;
    
    if response.status != 0 {
        return Err(response.status);
    }
    
    // Parse output_data as u64
    let energy = response.output_data
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or(-300)?;
    
    Ok(energy)
}

/// Full DB export with verification inside VM SGX enclave
#[cfg(feature = "use_sgx_vm")]
pub fn db_export_in_sgx(
    vm_name: &str,
    energy_uj: u64,
    counter: u64,
    previous_hash: &[u8; 32],
    signature: &[u8; 32],
    energy_delta: u64,
    processes: &[(u32, u64)],
    session_id: Option<&str>,
) -> Result<Vec<(u32, u64)>, i32> {
    println!("[SGX-VM-RUNNER] ========================================");
    println!("[SGX-VM-RUNNER] Running DB export inside REAL SGX enclave");
    println!("[SGX-VM-RUNNER] ========================================");
    
    check_sgx_hardware().map_err(|_| -200)?;
    
    let request = DbExportRequest {
        operation: "db_export".to_string(),
        vm_name: vm_name.to_string(),
        energy_uj,
        counter,
        previous_hash: hex::encode(previous_hash),
        signature: hex::encode(signature),
        energy_delta,
        processes: processes.to_vec(),
        session_id: session_id.map(|s| s.to_string()),
    };
    
    let request_json = serde_json::to_string(&request).unwrap();
    println!("[SGX-VM-RUNNER] Request size: {} bytes", request_json.len());
    
    let response = send_request_to_vm_enclave(&request_json)?;
    
    println!("[SGX-VM-RUNNER] ========================================");
    println!("[SGX-VM-RUNNER] Enclave response:");
    println!("[SGX-VM-RUNNER]   Status: {}", response.status);
    println!("[SGX-VM-RUNNER]   Message: {}", response.message);
    println!("[SGX-VM-RUNNER] ========================================");
    
    if response.status != 0 {
        return Err(response.status);
    }
    
    // Parse output_data as Vec<(u32, u64)>
    let results: Vec<(u32, u64)> = response.output_data
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default();
    
    println!("[SGX-VM-RUNNER] DB export completed inside REAL SGX enclave");
    println!("[SGX-VM-RUNNER]   {} processes computed", results.len());
    
    Ok(results)
}

/// Login to ImmuDB via TLS inside VM SGX enclave
#[cfg(feature = "use_sgx_vm")]
pub fn immudb_login_in_sgx() -> Result<String, i32> {
    println!("[SGX-VM-RUNNER] Logging into ImmuDB inside SGX enclave...");
    
    check_sgx_hardware().map_err(|_| -200)?;
    
    let request = serde_json::json!({
        "operation": "immudb_login"
    });
    
    let request_json = request.to_string();
    let response = send_request_to_vm_enclave(&request_json)?;
    
    if response.status != 0 {
        eprintln!("[SGX-VM-RUNNER] ImmuDB login failed: {}", response.message);
        return Err(response.status);
    }
    
    response.output_data.ok_or(-301)
}

/// Insert into ImmuDB via TLS inside VM SGX enclave
#[cfg(feature = "use_sgx_vm")]
pub fn immudb_insert_in_sgx(session_id: &str, body: &str) -> Result<String, i32> {
    check_sgx_hardware().map_err(|_| -200)?;
    
    let request = ImmudbInsertRequest {
        operation: "immudb_insert".to_string(),
        session_id: session_id.to_string(),
        body: body.to_string(),
    };
    
    let request_json = serde_json::to_string(&request).unwrap();
    let response = send_request_to_vm_enclave(&request_json)?;
    
    if response.status != 0 {
        return Err(response.status);
    }
    
    Ok(response.output_data.unwrap_or_default())
}

/// Shutdown the VM enclave
#[cfg(feature = "use_sgx_vm")]
pub fn shutdown_vm_enclave() {
    let mut conn_guard = match VM_ENCLAVE_CONNECTION.lock() {
        Ok(g) => g,
        Err(_) => return,
    };
    
    if let Some(ref mut conn) = *conn_guard {
        if conn.is_remote {
            // For remote connections, just close the TCP connection
            // Don't send shutdown signal - let the host manage the enclave
            println!("[SGX-VM-RUNNER] Closing remote enclave connection");
        } else {
            // Send shutdown signal (length 0) for local enclave
            let _ = conn.stream.write_all(&[0u8; 4]);
            let _ = conn.stream.flush();
            
            // Wait for process to exit
            if let Some(ref mut child) = conn.child {
                let _ = child.wait();
            }
        }
    }
    
    *conn_guard = None;
    println!("[SGX-VM-RUNNER] VM enclave connection closed");
}


#[cfg(not(feature = "use_sgx_vm"))]
pub fn verify_boot_in_sgx(
    _pcr_values: &[u8],
    _ima_log: &str,
    _hostname: &str,
    _deployment_type: &str,
    _immudb_addr: &str,
    _ca_pem: &str,
) -> Result<i32, i32> {
    eprintln!("[SGX-VM-RUNNER] SGX VM feature not enabled");
    Err(-999)
}

#[cfg(not(feature = "use_sgx_vm"))]
pub fn verify_chain_in_sgx(
    _vm_name: &str,
    _energy_value: u64,
    _counter: u64,
    _previous_hash: &[u8; 32],
    _signature: &[u8; 32],
) -> Result<i32, i32> {
    eprintln!("[SGX-VM-RUNNER] SGX VM feature not enabled");
    Err(-999)
}

#[cfg(not(feature = "use_sgx_vm"))]
pub fn compute_process_energy_in_sgx(
    _vm_total_energy_uj: u64,
    _cpu_percentage: f64,
) -> Result<u64, i32> {
    eprintln!("[SGX-VM-RUNNER] SGX VM feature not enabled");
    Err(-999)
}

#[cfg(not(feature = "use_sgx_vm"))]
pub fn db_export_in_sgx(
    _vm_name: &str,
    _energy_uj: u64,
    _counter: u64,
    _previous_hash: &[u8; 32],
    _signature: &[u8; 32],
    _energy_delta: u64,
    _processes: &[(u32, u64)],
    _session_id: Option<&str>,
) -> Result<Vec<(u32, u64)>, i32> {
    eprintln!("[SGX-VM-RUNNER] SGX VM feature not enabled");
    Err(-999)
}

#[cfg(not(feature = "use_sgx_vm"))]
pub fn immudb_login_in_sgx() -> Result<String, i32> {
    eprintln!("[SGX-VM-RUNNER] SGX VM feature not enabled");
    Err(-999)
}

#[cfg(not(feature = "use_sgx_vm"))]
pub fn immudb_insert_in_sgx(_session_id: &str, _body: &str) -> Result<String, i32> {
    eprintln!("[SGX-VM-RUNNER] SGX VM feature not enabled");
    Err(-999)
}

#[cfg(not(feature = "use_sgx_vm"))]
pub fn shutdown_vm_enclave() {
    // No-op when feature not enabled
}

/// Print SGX VM mode information
pub fn print_sgx_vm_info() {
    println!("\n[SGX-VM-INFO] ========================================");
    
    #[cfg(feature = "use_sgx_vm")]
    {
        // Check if remote mode
        if let Some(remote_host) = get_remote_sgx_host() {
            println!("[SGX-VM-INFO] Mode: REMOTE SGX (connecting to host)");
            println!("[SGX-VM-INFO] Remote host: {}", remote_host);
            println!("[SGX-VM-INFO] No local SGX hardware required");
        } else {
            println!("[SGX-VM-INFO] Mode: LOCAL SGX HARDWARE");
            println!("[SGX-VM-INFO] No simulation fallback - hardware required");
            
            match check_sgx_hardware() {
                Ok(_) => println!("[SGX-VM-INFO]  SGX hardware available"),
                Err(e) => {
                    println!("[SGX-VM-INFO]  SGX hardware NOT available");
                    println!("[SGX-VM-INFO]   Error: {}", e);
                    println!("[SGX-VM-INFO]   Tip: Set SGX_REMOTE_HOST=host:port to use remote enclave");
                }
            }
            
            match get_vm_enclave_path() {
                Ok(p) => println!("[SGX-VM-INFO] Enclave binary: {}", p),
                Err(_) => println!("[SGX-VM-INFO] Enclave binary not found"),
            }
        }
    }
    
    #[cfg(not(feature = "use_sgx_vm"))]
    {
        println!("[SGX-VM-INFO]  SGX VM feature not compiled");
        println!("[SGX-VM-INFO]   Build with: cargo build --features use_sgx_vm");
    }
    
    println!("[SGX-VM-INFO] ========================================\n");
}
