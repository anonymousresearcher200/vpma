use crate::exporters::*;
use crate::sensors::{Sensor, Topology};
use std::sync::atomic::{AtomicU8, Ordering};
use std::sync::Arc;

#[cfg(feature = "use_sgx_vm")]
use crate::sgx_vm_runner;

pub struct DBExporter {
    vm_name: String,
    topology: Topology,
    stop_flag: Arc<AtomicU8>,
}

impl DBExporter {
    pub fn new(sensor: &dyn Sensor) -> DBExporter {
        // IMPORTANT: VM name must match the libvirt domain name used by HOST qemu exporter
        // The HOST derives HMAC key using this name: HMAC(master_key, "vm:<vm_name>")
        // Priority: VM_NAME env var > chain metadata file > hostname
        let vm_name = std::env::var("VM_NAME").unwrap_or_else(|_| {
            // Try reading from chain metadata file written by host
            std::fs::read_to_string("/var/scaphandre/intel-rapl:0/chain_vm_name")
                .map(|s| s.trim().to_string())
                .unwrap_or_else(|_| {
                    // Fall back to hostname
                    hostname::get()
                        .map(|h| h.to_string_lossy().to_string())
                        .unwrap_or_else(|_| "unknown".to_string())
                })
        });
        let hostname = utils::get_hostname();
        
        println!("[DB-EXPORTER] Initializing VM DB exporter");
        println!("[DB-EXPORTER]   Hostname: {}", hostname);
        println!("[DB-EXPORTER]   VM Name for chain: {}", vm_name);
        println!("[DB-EXPORTER] Architecture: topology.refresh() -> reads VM energy files (from HOST SGX)");
        println!("[DB-EXPORTER]               sends to REAL SGX enclave (via TCP) -> verifies chain -> calculates per-process -> exports to ImmuDB");
        
        // Get topology from sensor (same pattern as QemuHostExporter)
        let topology = sensor.get_topology()
            .expect("[DB-EXPORTER] Failed to get topology from sensor");
        
        println!("[DB-EXPORTER] Topology initialized (will read from /var/scaphandre)");
        
        DBExporter {
            vm_name,
            topology,
            stop_flag: Arc::new(AtomicU8::new(0)),
        }
    }
}

impl Exporter for DBExporter {
    fn run(&mut self) {
        use std::thread;
        use std::time::Duration;
        
        println!("[DB-EXPORTER] Starting VM DB exporter for '{}'", self.vm_name);
        println!("[DB-EXPORTER] Architecture: topology.refresh() -> REAL SGX enclave (TCP) -> ImmuDB");
        
        #[cfg(feature = "use_sgx_vm")]
        {
            // Print SGX info
            sgx_vm_runner::print_sgx_vm_info();
            
            // =====================================================================
            // STEP 0: VERIFY BINARY INTEGRITY INSIDE REAL SGX (before any data export)
            // =====================================================================
            println!("[DB-EXPORTER] ================================================");
            println!("[DB-EXPORTER] BOOT INTEGRITY VERIFICATION (SGX)");
            println!("[DB-EXPORTER] ================================================");
            
            // Read PCR values from TPM
            let mut pcr_values = Vec::new();
            
            let pcr0_hex = match std::fs::read_to_string("/sys/class/tpm/tpm0/pcr-sha256/0") {
                Ok(content) => content.trim().strip_prefix("0x").unwrap_or(content.trim()).to_string(),
                Err(e) => {
                    eprintln!("[DB-EXPORTER] Failed to read PCR0: {}", e);
                    return;
                }
            };
            
            let pcr7_hex = match std::fs::read_to_string("/sys/class/tpm/tpm0/pcr-sha256/7") {
                Ok(content) => content.trim().strip_prefix("0x").unwrap_or(content.trim()).to_string(),
                Err(e) => {
                    eprintln!("[DB-EXPORTER] Failed to read PCR7: {}", e);
                    return;
                }
            };
            
            let pcr10_hex = match std::fs::read_to_string("/sys/class/tpm/tpm0/pcr-sha256/10") {
                Ok(content) => content.trim().strip_prefix("0x").unwrap_or(content.trim()).to_string(),
                Err(e) => {
                    eprintln!("[DB-EXPORTER] Failed to read PCR10: {}", e);
                    return;
                }
            };
            
            // Decode PCR hex to bytes and concatenate (96 bytes total)
            pcr_values.extend_from_slice(&hex::decode(&pcr0_hex).expect("Invalid PCR0 hex"));
            pcr_values.extend_from_slice(&hex::decode(&pcr7_hex).expect("Invalid PCR7 hex"));
            pcr_values.extend_from_slice(&hex::decode(&pcr10_hex).expect("Invalid PCR10 hex"));
            
            println!("[DB-EXPORTER] Read PCR values from TPM");
            
            // Read IMA log
            let ima_log = match std::fs::read_to_string("/sys/kernel/security/ima/ascii_runtime_measurements") {
                Ok(content) => content,
                Err(e) => {
                    eprintln!("[DB-EXPORTER] Failed to read IMA log: {}", e);
                    return;
                }
            };
            
            println!("[DB-EXPORTER] Read IMA log ({} bytes)", ima_log.len());
            
            // Prepare verification parameters
            let hostname = utils::get_hostname();
            let deployment_type = "vm";
            
            // ImmuDB address depends on where the enclave runs:
            // - Remote SGX (enclave on host): use 127.0.0.1:8443 (enclave connects to localhost)
            // - Local SGX (enclave in VM): use <IMMUDB_HOST>:8443 (connect to host from VM)
            let immudb_addr = if std::env::var("SGX_REMOTE_HOST").is_ok() {
                "127.0.0.1:8443"  // Remote enclave runs on host, so use localhost
            } else {
                "<IMMUDB_HOST>:8443"  // Local enclave runs in VM, needs host IP
            };
            println!("[DB-EXPORTER] ImmuDB address (for enclave): {}", immudb_addr);
            
            const CA_PEM: &str = include_str!("../../immudb_ca.pem");
            
            // Call REAL SGX enclave to verify binary integrity (via sgx_vm_runner)
            println!("[DB-EXPORTER] Sending to REAL SGX enclave for verification...");
            
            let sgx_verify_start = std::time::Instant::now();
            let verify_result = match sgx_vm_runner::verify_boot_in_sgx(
                &pcr_values,
                &ima_log,
                &hostname,
                deployment_type,
                immudb_addr,
                CA_PEM,
            ) {
                Ok(status) => status,
                Err(e) => {
                    eprintln!("[DB-EXPORTER] SGX enclave error: {}", e);
                    return;
                }
            };
            let sgx_verify_duration = sgx_verify_start.elapsed();
            println!("[TIMING-VM] SGX Boot Verification: {:.2} ms", sgx_verify_duration.as_secs_f64() * 1000.0);
            
            match verify_result {
                0 => {
                    println!("[DB-EXPORTER] ================================================");
                    println!("[DB-EXPORTER]   BINARY INTEGRITY VERIFIED ");
                    println!("[DB-EXPORTER] ================================================");
                }
                -6 => {
                    eprintln!("[DB-EXPORTER] ================================================");
                    eprintln!("[DB-EXPORTER]   HASH MISMATCH - BINARY TAMPERED ");
                    eprintln!("[DB-EXPORTER] ================================================");
                    eprintln!("[DB-EXPORTER] REFUSING TO EXPORT DATA");
                    return;
                }
                -7 => {
                    eprintln!("[DB-EXPORTER] ================================================");
                    eprintln!("[DB-EXPORTER]   PCR0 MISMATCH - BOOT TAMPERED ");
                    eprintln!("[DB-EXPORTER] ================================================");
                    eprintln!("[DB-EXPORTER] REFUSING TO EXPORT DATA");
                    return;
                }
                -8 => {
                    eprintln!("[DB-EXPORTER] ================================================");
                    eprintln!("[DB-EXPORTER]   PCR7 MISMATCH - SECURE BOOT TAMPERED ");
                    eprintln!("[DB-EXPORTER] ================================================");
                    eprintln!("[DB-EXPORTER] REFUSING TO EXPORT DATA");
                    return;
                }
                -9 => {
                    eprintln!("[DB-EXPORTER] ================================================");
                    eprintln!("[DB-EXPORTER]   PCR10 MISMATCH - IMA TAMPERED ");
                    eprintln!("[DB-EXPORTER] ================================================");
                    eprintln!("[DB-EXPORTER] REFUSING TO EXPORT DATA");
                    return;
                }
                code => {
                    eprintln!("[DB-EXPORTER] Verification failed: error {}", code);
                    return;
                }
            }
            
            println!("[DB-EXPORTER] Starting secure data export...");
            
            use std::time::Instant;
            
            loop {
                let iteration_start = Instant::now();
                
                let stop = self.stop_flag.load(Ordering::Relaxed);
                if stop != 0 {
                    println!("[DB-EXPORTER] Stop signal received");
                    break;
                }
                
                println!("\n[DB-EXPORTER] === Iteration start ===");
                
                // Refresh topology to read energy files (same as QemuHostExporter)
                let topo_start = Instant::now();
                println!("[DB-EXPORTER] Calling topology.refresh()...");
                self.topology.refresh();
                let topo_duration = topo_start.elapsed();
                println!("[DB-EXPORTER] Topology refreshed (energy files read)");
                println!("[TIMING-VM] Topology refresh: {:.2} ms", topo_duration.as_secs_f64() * 1000.0);
                
                // Read chain metadata files
                let metadata_start = Instant::now();
                let chain_dir = "/var/scaphandre/intel-rapl:0";
                
                // Read energy value from topology's refreshed data
                let energy_uj = match std::fs::read_to_string(format!("{}/energy_uj", chain_dir)) {
                    Ok(content) => content.trim().parse::<u64>().unwrap_or(0),
                    Err(e) => {
                        eprintln!("[DB-EXPORTER] Failed to read energy file: {}", e);
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };
                
                let counter = match std::fs::read_to_string(format!("{}/chain_counter", chain_dir)) {
                    Ok(content) => content.trim().parse::<u64>().unwrap_or(0),
                    Err(_) => {
                        eprintln!("[DB-EXPORTER] No chain metadata found");
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };
                
                let prev_hash_hex = match std::fs::read_to_string(format!("{}/chain_previous_hash", chain_dir)) {
                    Ok(content) => content.trim().to_string(),
                    Err(_) => {
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };
                
                let signature_hex = match std::fs::read_to_string(format!("{}/chain_signature", chain_dir)) {
                    Ok(content) => content.trim().to_string(),
                    Err(_) => {
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };
                
                let energy_delta = match std::fs::read_to_string(format!("{}/chain_energy_delta", chain_dir)) {
                    Ok(content) => content.trim().parse::<u64>().unwrap_or(0),
                    Err(_) => {
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };
                
                // Decode hex to bytes
                let prev_hash = match hex::decode(&prev_hash_hex) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };
                
                let signature = match hex::decode(&signature_hex) {
                    Ok(bytes) => bytes,
                    Err(_) => {
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };
                
                let metadata_duration = metadata_start.elapsed();
                println!("[TIMING-VM] Chain metadata read: {:.2} ms", metadata_duration.as_secs_f64() * 1000.0);
                
                // Collect process data (read /proc)
                let proc_start = Instant::now();
                use std::fs;
                let mut processes = Vec::new();
                
                if let Ok(entries) = fs::read_dir("/proc") {
                    for entry in entries.flatten() {
                        if let Ok(file_name) = entry.file_name().into_string() {
                            if let Ok(pid) = file_name.parse::<u32>() {
                                let stat_path = format!("/proc/{}/stat", pid);
                                if let Ok(stat_content) = fs::read_to_string(&stat_path) {
                                    let parts: Vec<&str> = stat_content.split_whitespace().collect();
                                    if parts.len() > 14 {
                                        let utime: u64 = parts[13].parse().unwrap_or(0);
                                        let stime: u64 = parts[14].parse().unwrap_or(0);
                                        processes.push((pid, utime + stime));
                                    }
                                }
                            }
                        }
                    }
                }
                
                let proc_duration = proc_start.elapsed();
                println!("[TIMING-VM] Process data collection: {:.2} ms ({} processes)", 
                         proc_duration.as_secs_f64() * 1000.0, processes.len());
                
                // Debug: Log what we're sending to SGX
                println!("[DB-EXPORTER] Calling REAL SGX enclave:");
                println!("[DB-EXPORTER]   VM: {}", self.vm_name);
                println!("[DB-EXPORTER]   Counter: {}", counter);
                println!("[DB-EXPORTER]   Energy: {} uJ", energy_uj);
                println!("[DB-EXPORTER]   Energy Delta: {} uJ", energy_delta);
                println!("[DB-EXPORTER]   Prev Hash: {}", &prev_hash_hex[..16.min(prev_hash_hex.len())]);
                println!("[DB-EXPORTER]   Signature: {}", &signature_hex[..16.min(signature_hex.len())]);
                println!("[DB-EXPORTER]   Processes: {}", processes.len());
                
                // Convert hash/signature to fixed size arrays
                let prev_hash_arr: [u8; 32] = match prev_hash.try_into() {
                    Ok(arr) => arr,
                    Err(_) => {
                        eprintln!("[DB-EXPORTER] Invalid previous hash length");
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };
                
                let signature_arr: [u8; 32] = match signature.try_into() {
                    Ok(arr) => arr,
                    Err(_) => {
                        eprintln!("[DB-EXPORTER] Invalid signature length");
                        thread::sleep(Duration::from_secs(2));
                        continue;
                    }
                };
                
                // Call REAL SGX enclave via TCP (sgx_vm_runner)
                let sgx_start = Instant::now();
                let result = sgx_vm_runner::db_export_in_sgx(
                    &self.vm_name,
                    energy_uj,
                    counter,
                    &prev_hash_arr,
                    &signature_arr,
                    energy_delta,
                    &processes,
                    None,  // session_id - enclave handles login internally
                );
                let sgx_duration = sgx_start.elapsed();
                
                match result {
                    Ok(energy_results) => {
                        println!("[DB-EXPORTER]  Iteration completed inside REAL SGX");
                        println!("[DB-EXPORTER]   {} processes with energy calculated", energy_results.len());
                        println!("[TIMING-VM] SGX verification + calculation + export: {:.2} ms", sgx_duration.as_secs_f64() * 1000.0);
                    }
                    Err(status) => {
                        match status {
                            2 => println!("[DB-EXPORTER] Skipped (same counter, waiting for host)"),
                            -2 => eprintln!("[DB-EXPORTER] Chain verification failed (tampering - signature mismatch)"),
                            -3 => eprintln!("[DB-EXPORTER] Replay/rollback attack (counter mismatch)"),
                            -4 => eprintln!("[DB-EXPORTER] Fork attack (previous hash mismatch)"),
                            -200 => eprintln!("[DB-EXPORTER] SGX hardware not available"),
                            -201 => eprintln!("[DB-EXPORTER] SGX enclave binary not found"),
                            code => eprintln!("[DB-EXPORTER] Error: {}", code),
                        }
                    }
                }
                
                let iteration_duration = iteration_start.elapsed();
                println!("[TIMING-VM] ========================================");
                println!("[TIMING-VM] Total iteration time: {:.2} ms", iteration_duration.as_secs_f64() * 1000.0);
                println!("[TIMING-VM] ========================================");
                
                thread::sleep(Duration::from_secs(2));
            }
        }
        
        #[cfg(not(feature = "use_sgx_vm"))]
        {
            eprintln!("[DB-EXPORTER] Error: SGX feature not enabled");
        }
    }
    
    fn kind(&self) -> &str {
        "db-sgx"
    }
}

impl Drop for DBExporter {
    fn drop(&mut self) {
        // Signal SGX to stop
        self.stop_flag.store(1, Ordering::Relaxed);
        #[cfg(feature = "use_sgx_vm")]
        {
            sgx_vm_runner::shutdown_vm_enclave();
        }
        println!("[DB-EXPORTER] Stopping SGX exporter");
    }
}
