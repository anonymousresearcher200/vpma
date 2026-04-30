#[macro_use]
extern crate log;
pub mod exporters;
pub mod sensors;
pub mod tpm_attestation;

// SGX enclave runner for REAL HARDWARE ONLY (no simulation)
#[cfg(feature = "use_sgx")]
pub mod sgx_runner;

// SGX VM enclave runner for per-process energy calculation inside VM
#[cfg(feature = "use_sgx_vm")]
pub mod sgx_vm_runner;

#[cfg(target_os = "windows")]
use sensors::msr_rapl;

#[cfg(target_os = "linux")]
use sensors::powercap_rapl;

/// Create a new [`Sensor`] instance with the default sensor available,
/// with its default options.
pub fn get_default_sensor() -> impl sensors::Sensor {
    #[cfg(target_os = "linux")]
    return powercap_rapl::PowercapRAPLSensor::new(
        powercap_rapl::DEFAULT_BUFFER_PER_SOCKET_MAX_KBYTES,
        powercap_rapl::DEFAULT_BUFFER_PER_DOMAIN_MAX_KBYTES,
        false,
    );

    #[cfg(target_os = "windows")]
    return msr_rapl::MsrRAPLSensor::new();
}

