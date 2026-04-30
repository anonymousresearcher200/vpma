
use serde::{Serialize, Deserialize};


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RawEnergyValue {
    pub value: String,
    /// HMAC-SHA256 signature of the value (TPM-based attestation)
    #[serde(default)]
    pub hmac_signature: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessSample {
    pub pid: u32,
    pub cmdline: Vec<String>,
    pub cpu_usage_percentage: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmEnergyUpdate {
    pub vm_name: String,
    pub uj_to_add: u64,
    #[serde(default)]
    pub hmac_signature: Vec<u8>,
}


pub fn compute_total_host_energy(
    pkg_values: &[RawEnergyValue],
    dram_values: &[RawEnergyValue],
) -> String {
    let mut total: i128 = 0;

    for r in pkg_values {
        if let Ok(v) = r.value.trim().parse::<i128>() {
            total += v;
        }
    }

    for r in dram_values {
        if let Ok(v) = r.value.trim().parse::<i128>() {
            total += v;
        }
    }

    total.to_string()
}



pub struct QemuExporter {}

impl QemuExporter {
    pub fn new() -> QemuExporter {
        QemuExporter {}
    }

    pub fn iterate(
        &mut self,
        _path: String,
        topo_energy_value: String,
        processes: Vec<Vec<ProcessSample>>,
    ) -> Vec<VmEnergyUpdate> {
        let topo_energy = topo_energy_value.parse::<f64>().unwrap_or(0.0);

        let qemu_proc_groups = Self::filter_qemu_vm_processes(&processes);

        let mut updates = vec![];

        for proc_group in qemu_proc_groups {
            if let Some(first_proc) = proc_group.first() {
                let vm_name = Self::get_vm_name_from_cmdline(&first_proc.cmdline);
                if vm_name.is_empty() {
                    continue;
                }

                let cpu_percent =
                    first_proc.cpu_usage_percentage.parse::<f64>().unwrap_or(0.0);

                let uj_to_add = cpu_percent * topo_energy / 100.0;

                updates.push(VmEnergyUpdate {
                    vm_name,
                    uj_to_add: uj_to_add.max(0.0) as u64,
                    hmac_signature: Vec::new(), // Signature added in SGX
                });
            }
        }

        updates
    }

    pub fn get_vm_name_from_cmdline(cmdline: &[String]) -> String {
        for e in cmdline {
            if e.starts_with("guest=") {
                let mut parts = e.split('=');
                parts.next();
                return parts.next().unwrap().split(',').next().unwrap().to_string();
            }
        }
        String::new()
    }

    pub fn filter_qemu_vm_processes(
        processes: &[Vec<ProcessSample>],
    ) -> Vec<Vec<ProcessSample>> {
        let mut out = vec![];

        for g in processes {
            if let Some(f) = g.first() {
                if f.cmdline.iter().any(|a| a.contains("qemu-system")) {
                    out.push(g.clone());
                }
            }
        }

        out
    }

    pub fn kind(&self) -> &str {
        "qemu"
    }
}

