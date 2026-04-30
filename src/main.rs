//! Generic sensor and transmission agent for energy consumption related metrics.

use clap::{command, ArgAction, Parser, Subcommand};
use colored::Colorize;
use scaphandre::{exporters, sensors::Sensor};

#[cfg(target_os = "linux")]
use scaphandre::sensors::powercap_rapl;

#[cfg(target_os = "windows")]
use scaphandre::sensors::msr_rapl;

#[cfg(feature = "qemu")]
use scaphandre::sensors::powercap_rapl::QemuHostExporter;

#[cfg(all(feature = "use_sgx", feature = "qemu"))]
use scaphandre::exporters::export_vm;

#[cfg(target_os = "windows")]
use windows_service::{
    service::ServiceControl,
    service::ServiceControlAccept,
    service::ServiceExitCode,
    service::ServiceState,
    service::ServiceStatus,
    service::ServiceType,
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

#[cfg(target_os = "windows")]
define_windows_service!(ffi_service_main, my_service_main);

#[cfg(target_os = "windows")]
#[macro_use]
extern crate windows_service;

#[cfg(target_os = "windows")]
use std::time::Duration;

#[cfg(target_os = "windows")]
use std::ffi::OsString;

// Arguments for QEMU/SGX-QEMU exporters
#[cfg(feature = "qemu")]
#[derive(Parser, Clone)]
pub struct QemuExporterArgs {
    /// URL of remote attestation server to fetch expected hash
    /// Example: https://attestation.example.com/api/hash
    #[arg(long)]
    pub verifier_url: Option<String>,
}

// the struct below defines the main Scaphandre command-line interface
/// Extensible metrology agent for electricity consumption related metrics.
#[derive(Parser)]
#[command(author, version)]
struct Cli {
    /// The exporter module to use to output the energy consumption metrics
    #[command(subcommand)]
    exporter: ExporterChoice,

    /// Increase the verbosity level
    #[arg(short, action = ArgAction::Count, default_value_t = 0)]
    verbose: u8,

    /// Don't print the header to the standard output
    #[arg(long, default_value_t = false)]
    no_header: bool,

    /// Tell Scaphandre that it's running in a virtual machine.
    /// You should have another instance of Scaphandre running on the hypervisor (see docs).
    #[arg(long, default_value_t = false)]
    vm: bool,

    /// The sensor module to use to gather the energy consumption metrics
    #[arg(short, long)]
    sensor: Option<String>,

    /// Maximum memory size allowed, in KiloBytes, for storing energy consumption of each **domain**.
    /// Only available for the RAPL sensor (on Linux).
    #[cfg(target_os = "linux")]
    #[arg(long, default_value_t = powercap_rapl::DEFAULT_BUFFER_PER_DOMAIN_MAX_KBYTES)]
    sensor_buffer_per_domain_max_kb: u16,

    /// Maximum memory size allowed, in KiloBytes, for storing energy consumption of each **socket**.
    /// Only available for the RAPL sensor (on Linux).
    #[cfg(target_os = "linux")]
    #[arg(long, default_value_t = powercap_rapl::DEFAULT_BUFFER_PER_SOCKET_MAX_KBYTES)]
    sensor_buffer_per_socket_max_kb: u16,
}

/// Defines the possible subcommands, one per exporter.
///
/// ### Description style
/// Per the clap documentation, the description of commands and arguments should be written in the style applied here,
/// *not* in the third-person. That is, use "Do xyz" instead of "Does xyz".
#[derive(Subcommand)]
enum ExporterChoice {
    /// Write the metrics to the terminal
    Stdout(exporters::stdout::ExporterArgs),

    /// Write the metrics in the JSON format to a file or to stdout
    #[cfg(feature = "json")]
    Json(exporters::json::ExporterArgs),

    /// Expose the metrics to a Prometheus HTTP endpoint
    #[cfg(feature = "prometheus")]
    Prometheus(exporters::prometheus::ExporterArgs),

    /// Watch all Qemu-KVM virtual machines running on the host and expose the metrics
    /// of each of them in a dedicated folder (now backed by QemuHostExporter)
    #[cfg(feature = "qemu")]
    Qemu(QemuExporterArgs),

    /// SGX-enabled QEMU energy computation (same backend as QemuHostExporter, but explicit name)
    #[cfg(feature = "qemu")]
    SgxQemu(QemuExporterArgs),

    /// Expose the metrics to a Riemann server
    #[cfg(feature = "riemann")]
    Riemann(exporters::riemann::ExporterArgs),

    /// Expose the metrics to a Warp10 host, through HTTP
    #[cfg(feature = "warpten")]
    Warpten(exporters::warpten::ExporterArgs),

    /// Push metrics to Prometheus Push Gateway
    #[cfg(feature = "prometheuspush")]
    PrometheusPush(exporters::prometheuspush::ExporterArgs),
    
    /// Store VM per-process energy data to immudb via SGX TLS
    #[cfg(feature = "use_sgx_vm")]
    Db,
}

#[cfg(target_os = "windows")]
fn my_service_main(_arguments: Vec<OsString>) {
    use std::thread::JoinHandle;
    let graceful_period = 3;

    let start_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS, // Should match the one from system service registry
        current_state: ServiceState::Running,   // The new state
        controls_accepted: ServiceControlAccept::STOP, // Accept stop events when running
        exit_code: ServiceExitCode::Win32(0), // Used to report an error when starting or stopping only, otherwise must be zero
        checkpoint: 0, // Only used for pending states, otherwise must be zero
        wait_hint: Duration::default(), // Only used for pending states, otherwise must be zero
        process_id: None, // Unused for setting status
    };
    let stop_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    };
    let stoppending_status = ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::StopPending,
        controls_accepted: ServiceControlAccept::STOP,
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::from_secs(graceful_period),
        process_id: None,
    };

    let thread_handle: Option<JoinHandle<()>>;
    let mut _stop = false;
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        println!("Got service control event: {:?}", control_event);
        match control_event {
            ServiceControl::Stop => {
                // Handle stop event and return control back to the system.
                _stop = true;
                ServiceControlHandlerResult::NoError
            }
            // All services must accept Interrogate even if it's a no-op.
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    if let Ok(system_handler) = service_control_handler::register("scaphandre", event_handler) {
        // Tell the system that the service is running now and run it
        match system_handler.set_service_status(start_status.clone()) {
            Ok(status_set) => {
                println!(
                    "Starting main thread, service status has been set: {:?}",
                    status_set
                );
                thread_handle = Some(std::thread::spawn(move || {
                    parse_cli_and_run_exporter();
                }));
            }
            Err(e) => {
                panic!("Couldn't set Windows service status. Error: {:?}", e);
            }
        }
        loop {
            if _stop {
                // Wait for the thread to finnish, then end the current function
                match system_handler.set_service_status(stoppending_status.clone()) {
                    Ok(status_set) => {
                        println!("Stop status has been set for service: {:?}", status_set);
                        if let Some(thr) = thread_handle {
                            if thr.join().is_ok() {
                                match system_handler.set_service_status(stop_status.clone()) {
                                    Ok(laststatus_set) => {
                                        println!(
                                            "Scaphandre gracefully stopped: {:?}",
                                            laststatus_set
                                        );
                                    }
                                    Err(e) => {
                                        panic!(
                                            "Could'nt set Stop status on scaphandre service: {:?}",
                                            e
                                        );
                                    }
                                }
                            } else {
                                panic!("Joining the thread failed.");
                            }
                            break;
                        } else {
                            panic!("Thread handle was not initialized.");
                        }
                    }
                    Err(e) => {
                        panic!("Couldn't set Windows service status. Error: {:?}", e);
                    }
                }
            }
        }
    } else {
        panic!("Failed getting system_handle.");
    }
}

fn main() {
    #[cfg(target_os = "windows")]
    match service_dispatcher::start("Scaphandre", ffi_service_main) {
        Ok(_) => {}
        Err(e) => {
            println!("Couldn't start Windows service dispatcher. Got : {}", e);
        }
    }

    parse_cli_and_run_exporter();
}

fn parse_cli_and_run_exporter() {
    let cli = Cli::parse();
    loggerv::init_with_verbosity(cli.verbose.into()).expect("unable to initialize the logger");

    // Print SGX mode information
    #[cfg(any(feature = "use_sgx", feature = "use_sgx_real"))]
    scaphandre::sgx_runner::print_sgx_info();

    // Extract verifier URL if using SGX-QEMU exporter
    #[cfg(all(feature = "qemu", any(feature = "tpm_attestation", feature = "tpm_attestation_vm")))]
    let verifier_url = match &cli.exporter {
        ExporterChoice::Qemu(args) => args.verifier_url.as_deref(),
        ExporterChoice::SgxQemu(args) => args.verifier_url.as_deref(),
        _ => None,
    };
    
    #[cfg(not(all(feature = "qemu", any(feature = "tpm_attestation", feature = "tpm_attestation_vm"))))]
    let verifier_url: Option<&str> = None;

    // Register OCALL with SGX enclave BEFORE TPM attestation
    // (attestation needs OCALL to fetch hash from server)
    #[cfg(all(feature = "use_sgx", feature = "qemu"))]
    export_vm::register_sgx_ocall();

    // TPM attestation and HMAC key unsealing (HOST MODE - strict)
    #[cfg(feature = "tpm_attestation")]
    let tpm_key = {
        use scaphandre::tpm_attestation::TpmAttestation;
        
        println!("[MAIN] Starting TPM attestation (HOST MODE - strict)...");
        match TpmAttestation::new(verifier_url) {
            Ok(tpm) => {
                if tpm.is_attested() {
                    println!("[MAIN] TPM attestation successful - boot chain verified");
                    tpm.get_hmac_key().map(|k| k.to_vec())
                } else {
                    eprintln!("[MAIN] TPM attestation failed - no HMAC key available");
                    eprintln!("[MAIN] Continuing without TPM protection (degraded security)");
                    None
                }
            }
            Err(e) => {
                eprintln!("[MAIN] TPM initialization failed: {}", e);
                eprintln!("[MAIN] This may indicate:");
                eprintln!("  - System has been tampered with");
                eprintln!("  - PCR values don't match expected measurements");
                eprintln!("  - TPM sealed key is missing or corrupted");
                eprintln!("[MAIN] ABORTING - refusing to run on untrusted system");
                std::process::exit(1);
            }
        }
    };
    
    // TPM attestation for VM mode (graceful vTPM handling)
    #[cfg(all(feature = "tpm_attestation_vm", not(feature = "tpm_attestation")))]
    let tpm_key = {
        use scaphandre::tpm_attestation::TpmAttestation;
        
        println!("[MAIN] Starting vTPM attestation (VM MODE - graceful)...");
        match TpmAttestation::new_vm_mode(verifier_url) {
            Ok(tpm) => {
                if tpm.is_attested() {
                    println!("[MAIN] vTPM attestation successful - VM boot chain verified");
                    tpm.get_hmac_key().map(|k| k.to_vec())
                } else {
                    println!("[MAIN] Continuing without vTPM protection (relying on host TPM)");
                    None
                }
            }
            Err(e) => {
                eprintln!("[MAIN] vTPM initialization failed: {}", e);
                eprintln!("[MAIN] Continuing without vTPM protection (relying on host TPM)");
                None
            }
        }
    };
    
    #[cfg(not(any(feature = "tpm_attestation", feature = "tpm_attestation_vm")))]
    let tpm_key: Option<Vec<u8>> = None;

    // REMOVED: Duplicate OCALL registration (now done before TPM attestation)
    
    
    // Set HMAC key for signing sensor readings (both host and VM modes)
    #[cfg(all(target_os = "linux", any(feature = "tpm_attestation", feature = "tpm_attestation_vm")))]
    if let Some(ref key) = tpm_key {
        println!("[MAIN] Setting HMAC key for sensor data signing");
        powercap_rapl::set_sensor_hmac_key(key);
    }

    
    #[cfg(all(feature = "use_sgx", target_os = "linux"))]
    verify_hash_inside_sgx();

    
    #[cfg(target_os = "linux")]
    let _runtime_protectors = init_runtime_protection();

    let sensor = build_sensor(&cli);
    let mut exporter = build_exporter(cli.exporter, &sensor);
    if !cli.no_header {
        print_scaphandre_header(exporter.kind());
    }

    exporter.run();
}

#[cfg(all(feature = "use_sgx", target_os = "linux"))]
fn verify_hash_inside_sgx() {
    use std::fs;
    use std::path::Path;
    
    println!("\n[HASH-VERIFY] ================================================");
    println!("[HASH-VERIFY] Starting binary hash verification");
    println!("[HASH-VERIFY] ================================================\n");
    
    // 1. Read TPM PCRs (0, 7, 10)
    let pcr_values = read_pcr_values();
    if pcr_values.len() != 96 {
        eprintln!("[HASH-VERIFY] Failed to read PCR values (expected 96 bytes, got {})", pcr_values.len());
        std::process::exit(1);
    }
    
    // 2. Read IMA log
    let ima_log_path = "/sys/kernel/security/ima/ascii_runtime_measurements";
    let ima_log = match fs::read_to_string(ima_log_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("[HASH-VERIFY] Failed to read IMA log: {}", e);
            eprintln!("[HASH-VERIFY]   Path: {}", ima_log_path);
            eprintln!("[HASH-VERIFY]   Note: Requires IMA enabled and root access");
            std::process::exit(1);
        }
    };
    
    // 3. Get hostname (for ImmuDB query)
    let hostname = scaphandre::exporters::utils::get_hostname();
    println!("[HASH-VERIFY] Hostname: {}", hostname);
    
    // 4. Detect deployment type (host vs vm)
    let deployment_type = detect_deployment_type();
    println!("[HASH-VERIFY] Deployment type: {}", deployment_type);
    
    // 5. ImmuDB connection details
    let immudb_addr = std::env::var("IMMUDB_ADDR")
        .unwrap_or_else(|_| "<IMMUDB_HOST>:8443".to_string());
    
    let ca_pem_path = std::env::var("IMMUDB_CA_CERT")
        .unwrap_or_else(|_| "<IMMUDB_CERTS_PATH>/ca.pem".to_string());
    
    let ca_pem = match fs::read_to_string(&ca_pem_path) {
        Ok(content) => content,
        Err(e) => {
            eprintln!("[HASH-VERIFY]  Failed to read CA certificate: {}", e);
            eprintln!("[HASH-VERIFY]   Path: {}", ca_pem_path);
            std::process::exit(1);
        }
    };
    
    println!("[HASH-VERIFY] ImmuDB address: {}", immudb_addr);
    println!("[HASH-VERIFY] CA cert: {}", ca_pem_path);
    
    // 6. Call SGX enclave to verify hash (REAL HARDWARE - no simulation)
    #[cfg(feature = "use_sgx")]
    {
        use scaphandre::sgx_runner;
        
        // Print SGX status first
        sgx_runner::print_sgx_info();
        
        match sgx_runner::verify_in_sgx_enclave(
            &pcr_values,
            &ima_log,
            &hostname,
            &deployment_type,
            &immudb_addr,
            &ca_pem,
        ) {
            Ok(_) => {
                println!("\n[HASH-VERIFY] ================================================");
                println!("[HASH-VERIFY] Binary hash verification PASSED");
                println!("[HASH-VERIFY] Verified INSIDE REAL SGX ENCLAVE");
                println!("[HASH-VERIFY] ================================================\n");
            }
            Err(-200) => {
                eprintln!("[HASH-VERIFY] SGX hardware not available");
                eprintln!("[HASH-VERIFY]   This system REQUIRES real SGX hardware");
                std::process::exit(1);
            }
            Err(-201) => {
                eprintln!("[HASH-VERIFY] SGX enclave binary not found");
                std::process::exit(1);
            }
            Err(-202) => {
                eprintln!("[HASH-VERIFY] Failed to start SGX enclave");
                eprintln!("[HASH-VERIFY] Install: cargo install fortanix-sgx-tools");
                std::process::exit(1);
            }
            Err(-1) => {
                eprintln!("[HASH-VERIFY] Null pointer error");
                std::process::exit(1);
            }
            Err(-2) => {
                eprintln!("[HASH-VERIFY] Invalid PCR data (IMA not active)");
                std::process::exit(1);
            }
            Err(-3) => {
                eprintln!("[HASH-VERIFY] IMA log parse error");
                std::process::exit(1);
            }
            Err(-4) => {
                eprintln!("[HASH-VERIFY] Scaphandre binary not found in IMA log");
                std::process::exit(1);
            }
            Err(-5) => {
                eprintln!("[HASH-VERIFY] ImmuDB connection failed");
                std::process::exit(1);
            }
            Err(-6) => {
                eprintln!("[HASH-VERIFY] HASH MISMATCH DETECTED FAILFAILFAIL");
                eprintln!("[HASH-VERIFY] Binary has been TAMPERED - REFUSING TO RUN");
                std::process::exit(1);
            }
            Err(-99) => {
                eprintln!("[HASH-VERIFY]  mbedtls feature not enabled");
                std::process::exit(1);
            }
            Err(code) => {
                eprintln!("[HASH-VERIFY] Unknown error code: {}", code);
                std::process::exit(1);
            }
        }
    }
}

#[cfg(all(feature = "use_sgx", target_os = "linux"))]
fn read_pcr_values() -> Vec<u8> {
    use std::fs;
    
    let mut pcr_values = Vec::with_capacity(96); // 3 PCRs * 32 bytes each
    
    for pcr in &[0, 7, 10] {
        let path = format!("/sys/class/tpm/tpm0/pcr-sha256/{}", pcr);
        match fs::read_to_string(&path) {
            Ok(hex_str) => {
                let hex_clean = hex_str.trim();
                if hex_clean.len() == 64 {
                    for i in (0..64).step_by(2) {
                        if let Ok(byte) = u8::from_str_radix(&hex_clean[i..i+2], 16) {
                            pcr_values.push(byte);
                        } else {
                            eprintln!("[HASH-VERIFY] Failed to parse PCR {} hex", pcr);
                            return vec![0u8; 96]; // Return zeros on error
                        }
                    }
                } else {
                    eprintln!("[HASH-VERIFY] Invalid PCR {} length: {} (expected 64)", pcr, hex_clean.len());
                    return vec![0u8; 96];
                }
            }
            Err(e) => {
                eprintln!("[HASH-VERIFY] Failed to read PCR {}: {}", pcr, e);
                return vec![0u8; 96];
            }
        }
    }
    
    pcr_values
}

#[cfg(all(feature = "use_sgx", target_os = "linux"))]
fn detect_deployment_type() -> String {
    use std::fs;
    
    // Check /sys/class/dmi/id/product_name for VM indicators
    let product_name_path = "/sys/class/dmi/id/product_name";
    if let Ok(product_name) = fs::read_to_string(product_name_path) {
        let product_lower = product_name.to_lowercase();
        if product_lower.contains("kvm") || product_lower.contains("qemu") 
            || product_lower.contains("virtualbox") || product_lower.contains("vmware") {
            return "vm".to_string();
        }
    }
    
    // Check for hypervisor flag in /proc/cpuinfo
    if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
        if cpuinfo.contains("hypervisor") {
            return "vm".to_string();
        }
    }
    
    "host".to_string()
}

#[cfg(target_os = "linux")]
fn init_runtime_protection() -> RuntimeProtectors {
    use scaphandre::sensors::memory_protection;
    use scaphandre::sensors::hash_verifier;

    println!("\n[RUNTIME-PROTECTION] ========================================");
    println!("[RUNTIME-PROTECTION] Initializing runtime integrity defenses");
    println!("[RUNTIME-PROTECTION] ========================================\n");

    // 1. Initialize eBPF memory protection
    let mem_protector = match memory_protection::protect_current_process() {
        Ok(protector) => {
            println!("[RUNTIME-PROTECTION] Memory protection active");
            println!("[RUNTIME-PROTECTION]   - Blocks ptrace (anti-debugging)");
            println!("[RUNTIME-PROTECTION]   - Blocks /proc/PID/mem writes");
            println!("[RUNTIME-PROTECTION]   - Blocks RWX mprotect/mmap");
            Some(protector)
        }
        Err(e) => {
            eprintln!("[RUNTIME-PROTECTION]  Failed to initialize memory protection: {}", e);
            eprintln!("[RUNTIME-PROTECTION]   Continuing without eBPF protection");
            eprintln!("[RUNTIME-PROTECTION]   Note: Requires root/CAP_BPF and kernel eBPF support");
            None
        }
    };

    let hash_verifier: Option<hash_verifier::HashVerifier> = None;

    println!("\n[RUNTIME-PROTECTION] ========================================");
    println!("[RUNTIME-PROTECTION] Runtime integrity protection initialized");
    println!("[RUNTIME-PROTECTION] ========================================\n");

    RuntimeProtectors {
        _memory_protector: mem_protector,
        _hash_verifier: hash_verifier,
    }
}

#[cfg(target_os = "linux")]
struct RuntimeProtectors {
    _memory_protector: Option<scaphandre::sensors::memory_protection::MemoryProtector>,
    _hash_verifier: Option<scaphandre::sensors::hash_verifier::HashVerifier>,
}

fn build_exporter(choice: ExporterChoice, sensor: &dyn Sensor) -> Box<dyn exporters::Exporter> {
    match choice {
        ExporterChoice::Stdout(args) => {
            Box::new(exporters::stdout::StdoutExporter::new(sensor, args))
        }
        #[cfg(feature = "json")]
        ExporterChoice::Json(args) => {
            Box::new(exporters::json::JsonExporter::new(sensor, args)) // keep this in braces
        }
        #[cfg(feature = "prometheus")]
        ExporterChoice::Prometheus(args) => {
            Box::new(exporters::prometheus::PrometheusExporter::new(sensor, args))
        }

        // We map the legacy "qemu" subcommand to your SGX-capable QemuHostExporter
        #[cfg(feature = "qemu")]
        ExporterChoice::Qemu(args) => {
            println!("Running SGX-QEMU exporter (qemu)...");
            let mut exporter = QemuHostExporter::new(sensor);
            
            // Set verifier URL if provided
            if let Some(ref url) = args.verifier_url {
                exporter.set_verifier_url(url.clone());
            }
            
            Box::new(exporter)
        }

        // Explicit SGX-QEMU subcommand (same implementation, but separate name)
        #[cfg(feature = "qemu")]
        ExporterChoice::SgxQemu(args) => {
            println!("Running SGX-QEMU exporter (sgx-qemu)...");
            let mut exporter = QemuHostExporter::new(sensor);
            
            // Set verifier URL if provided
            if let Some(ref url) = args.verifier_url {
                exporter.set_verifier_url(url.clone());
            }
            
            Box::new(exporter)
        }

        #[cfg(feature = "riemann")]
        ExporterChoice::Riemann(args) => {
            Box::new(exporters::riemann::RiemannExporter::new(sensor, args))
        }
        #[cfg(feature = "warpten")]
        ExporterChoice::Warpten(args) => {
            Box::new(exporters::warpten::Warp10Exporter::new(sensor, args))
        }
        #[cfg(feature = "prometheuspush")]
        ExporterChoice::PrometheusPush(args) => Box::new(
            exporters::prometheuspush::PrometheusPushExporter::new(sensor, args),
        ),
        
        #[cfg(feature = "use_sgx_vm")]
        ExporterChoice::Db => {
            Box::new(exporters::db::DBExporter::new(sensor))
        }
    }
    // Note that invalid choices are automatically turned into errors by `parse()` before the Cli is populated,
    // that's why they don't appear in this function.
}

fn build_sensor(cli: &Cli) -> impl Sensor {
    #[cfg(target_os = "linux")]
    let rapl_sensor = || {
        powercap_rapl::PowercapRAPLSensor::new(
            cli.sensor_buffer_per_socket_max_kb,
            cli.sensor_buffer_per_domain_max_kb,
            cli.vm,
        )
    };

    #[cfg(target_os = "windows")]
    let msr_sensor_win = msr_rapl::MsrRAPLSensor::new;

    match cli.sensor.as_deref() {
        Some("powercap_rapl") => {
            #[cfg(target_os = "linux")]
            {
                rapl_sensor()
            }
            #[cfg(not(target_os = "linux"))]
            panic!("Invalid sensor: Scaphandre's powercap_rapl only works on Linux")
        }
        Some("msr") => {
            #[cfg(target_os = "windows")]
            {
                msr_sensor_win()
            }
            #[cfg(not(target_os = "windows"))]
            panic!("Invalid sensor: Scaphandre's msr only works on Windows")
        }
        Some(s) => panic!("Unknown sensor type {}", s),
        None => {
            #[cfg(target_os = "linux")]
            return rapl_sensor();

            #[cfg(target_os = "windows")]
            return msr_sensor_win();

            #[cfg(not(any(target_os = "linux", target_os = "windows")))]
            compile_error!("Unsupported target OS")
        }
    }
}

fn print_scaphandre_header(exporter_name: &str) {
    let title = format!("Scaphandre {exporter_name} exporter");
    println!("{}", title.red().bold());
    println!("Sending metrics");
}

#[cfg(test)]
mod test {
    use super::*;

    const SUBCOMMANDS: &[&str] = &[
        "stdout",
        #[cfg(feature = "prometheus")]
        "prometheus",
        #[cfg(feature = "riemann")]
        "riemann",
        #[cfg(feature = "json")]
        "json",
        #[cfg(feature = "warpten")]
        "warpten",
        #[cfg(feature = "qemu")]
        "qemu",
        #[cfg(feature = "qemu")]
        "sgx-qemu",
    ];

    /// Test that `--help` works for Scaphandre _and_ for each subcommand.
    /// This also ensures that all the subcommands are properly defined, as Clap will check some constraints
    /// when trying to parse a subcommand (for instance, it will check that no two short options have the same name).
    #[test]
    fn test_help() {
        fn assert_shows_help(args: &[&str]) {
            match Cli::try_parse_from(args) {
                Ok(_) => panic!(
                    "The CLI didn't generate a help message for {args:?}, are the inputs correct?"
                ),
                Err(e) => assert_eq!(
                    e.kind(),
                    clap::error::ErrorKind::DisplayHelp,
                    "The CLI emitted an error for {args:?}:\n{e}"
                ),
            };
        }
        assert_shows_help(&["scaphandre", "--help"]);
        for cmd in SUBCOMMANDS {
            assert_shows_help(&["scaphandre", cmd, "--help"]);
        }
    }
}

