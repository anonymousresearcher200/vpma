
use bcc::BPF;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;
use std::fs;

pub struct MemoryProtector {
    bpf: Arc<Mutex<BPF>>,
    running: Arc<Mutex<bool>>,
}

impl MemoryProtector {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        // Read eBPF program source
        let ebpf_code = include_str!("../../memory_protection.c");

        // Compile and load eBPF program
        let bpf = BPF::new(ebpf_code)?;

        Ok(MemoryProtector {
            bpf: Arc::new(Mutex::new(bpf)),
            running: Arc::new(Mutex::new(false)),
        })
    }

    fn attach_hooks(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut bpf = self.bpf.lock().unwrap();
        
        // Attach ptrace hook
        bcc::Kprobe::new()
            .handler("syscall__trace_ptrace")
            .function("__x64_sys_ptrace")
            .attach(&mut *bpf)?;

        // Attach /proc/mem write hook
        bcc::Kprobe::new()
            .handler("kprobe__mem_write")
            .function("mem_write")
            .attach(&mut *bpf)?;

        // Attach mprotect hook
        bcc::Kprobe::new()
            .handler("syscall__trace_mprotect")
            .function("__x64_sys_mprotect")
            .attach(&mut *bpf)?;

        // Attach mmap hook
        bcc::Kprobe::new()
            .handler("syscall__trace_mmap")
            .function("__x64_sys_mmap")
            .attach(&mut *bpf)?;

        Ok(())
    }

    /// Add a PID to the protected list
    pub fn add_protected_pid(&self, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        let bpf = self.bpf.lock().unwrap();
        let mut table = bpf.table("protected_pids")?;
        
        let mut key = pid.to_ne_bytes();
        let mut value = 1u64.to_ne_bytes();
        
        table.set(&mut key, &mut value)?;
        
        println!("[MEMORY-PROTECTION] Added PID {} to protected list", pid);
        Ok(())
    }

    /// Remove a PID from the protected list
    pub fn remove_protected_pid(&self, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        let bpf = self.bpf.lock().unwrap();
        let mut table = bpf.table("protected_pids")?;
        
        let mut key = pid.to_ne_bytes();
        table.delete(&mut key)?;
        
        println!("[MEMORY-PROTECTION] Removed PID {} from protected list", pid);
        Ok(())
    }

    /// Add an authorized debugger PID (optional, for controlled debugging)
    pub fn add_authorized_debugger(&self, pid: u32) -> Result<(), Box<dyn std::error::Error>> {
        let bpf = self.bpf.lock().unwrap();
        let mut table = bpf.table("authorized_debuggers")?;
        
        let mut key = pid.to_ne_bytes();
        let mut value = 1u64.to_ne_bytes();
        
        table.set(&mut key, &mut value)?;
        
        println!("[MEMORY-PROTECTION]  Authorized debugger PID {}", pid);
        Ok(())
    }

    /// Register .text section address range for a PID
    /// This enables detection of attempts to modify code section permissions
    pub fn add_text_section_protection(&self, pid: u32, start: u64, end: u64) -> Result<(), Box<dyn std::error::Error>> {
        let bpf = self.bpf.lock().unwrap();
        
        // Set start address
        let mut start_table = bpf.table("text_section_start")?;
        let mut key = pid.to_ne_bytes();
        let mut start_val = start.to_ne_bytes();
        start_table.set(&mut key, &mut start_val)?;
        
        // Set end address
        let mut end_table = bpf.table("text_section_end")?;
        let mut end_val = end.to_ne_bytes();
        end_table.set(&mut key, &mut end_val)?;
        
        println!("[MEMORY-PROTECTION] Monitoring .text section: 0x{:x}-0x{:x} for PID {}", start, end, pid);
        Ok(())
    }

    /// Automatically detect and protect .text section for current process
    /// Parses /proc/self/maps to find executable code region
    pub fn protect_text_section(&self) -> Result<(), Box<dyn std::error::Error>> {
        let pid = std::process::id();
        
        if let Some((start, end)) = get_text_section_range()? {
            self.add_text_section_protection(pid, start, end)?;
            println!("[MEMORY-PROTECTION]  .text section protected: {} KB of code monitored", 
                     (end - start) / 1024);
        } else {
            println!("[MEMORY-PROTECTION] Warning: Could not find .text section in /proc/self/maps");
        }
        
        Ok(())
    }

    /// Start monitoring for security events
    pub fn start_monitoring(&self) -> Result<(), Box<dyn std::error::Error>> {
        let mut running = self.running.lock().unwrap();
        if *running {
            return Ok(()); // Already running
        }
        *running = true;
        drop(running);

        // Attach hooks after setting running flag
        self.attach_hooks()?;

        let running_flag = Arc::clone(&self.running);

        thread::spawn(move || {
            // Keep BPF loaded while running
            loop {
                {
                    let running_guard = running_flag.lock().unwrap();
                    if !*running_guard {
                        break;
                    }
                }
                thread::sleep(Duration::from_secs(1));
            }
        });

        println!("[MEMORY-PROTECTION]  Started monitoring for security events");
        Ok(())
    }

    /// Stop monitoring
    pub fn stop(&self) {
        let mut running = self.running.lock().unwrap();
        *running = false;
        println!("[MEMORY-PROTECTION] Stopped monitoring");
    }
}

impl Drop for MemoryProtector {
    fn drop(&mut self) {
        self.stop();
    }
}

/// Parse /proc/self/maps to find the .text section (r-xp) of the current executable
/// Returns (start_address, end_address) of the executable code section
fn get_text_section_range() -> Result<Option<(u64, u64)>, Box<dyn std::error::Error>> {
    let maps = fs::read_to_string("/proc/self/maps")?;
    
    // Get current executable path
    let exe_path = fs::read_link("/proc/self/exe")?;
    let exe_str = exe_path.to_string_lossy();
    
    // Find all r-xp (read + execute, private) mappings for our executable
    // These contain executable code
    let mut text_start: Option<u64> = None;
    let mut text_end: Option<u64> = None;
    
    for line in maps.lines() {
        // Format: address perms offset dev inode pathname
        // Example: 00400000-00452000 r-xp 00000000 08:01 123456 /path/to/scaphandre
        
        // Check if this line is for our executable with execute permission
        if line.contains(&*exe_str) && line.contains("r-xp") {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if let Some(addr_range) = parts.first() {
                let addrs: Vec<&str> = addr_range.split('-').collect();
                if addrs.len() == 2 {
                    let start = u64::from_str_radix(addrs[0], 16)?;
                    let end = u64::from_str_radix(addrs[1], 16)?;
                    
                    // Track the full range (there may be multiple r-xp segments)
                    text_start = Some(text_start.map_or(start, |s| s.min(start)));
                    text_end = Some(text_end.map_or(end, |e| e.max(end)));
                }
            }
        }
    }
    
    match (text_start, text_end) {
        (Some(start), Some(end)) => Ok(Some((start, end))),
        _ => Ok(None),
    }
}

/// Get all executable memory regions (not just main binary)
/// Useful for monitoring JIT/dynamic code regions
#[allow(dead_code)]
fn get_all_executable_regions() -> Result<Vec<(u64, u64, String)>, Box<dyn std::error::Error>> {
    let maps = fs::read_to_string("/proc/self/maps")?;
    let mut regions = Vec::new();
    
    for line in maps.lines() {
        // Check for any execute permission (--x-)
        let parts: Vec<&str> = line.split_whitespace().collect();
        if parts.len() >= 2 && parts[1].contains('x') {
            if let Some(addr_range) = parts.first() {
                let addrs: Vec<&str> = addr_range.split('-').collect();
                if addrs.len() == 2 {
                    if let (Ok(start), Ok(end)) = (
                        u64::from_str_radix(addrs[0], 16),
                        u64::from_str_radix(addrs[1], 16)
                    ) {
                        let name = parts.get(5).unwrap_or(&"[anonymous]").to_string();
                        regions.push((start, end, name));
                    }
                }
            }
        }
    }
    
    Ok(regions)
}

/// Initialize memory protection for the current process
pub fn protect_current_process() -> Result<MemoryProtector, Box<dyn std::error::Error>> {
    let protector = MemoryProtector::new()?;
    
    // Add current process to protected list
    let current_pid = std::process::id();
    protector.add_protected_pid(current_pid)?;
    
    // Start monitoring
    protector.start_monitoring()?;
    
    // Protect .text section (executable code)
    // This enables detection of attempts to make code writable
    if let Err(e) = protector.protect_text_section() {
        println!("[MEMORY-PROTECTION] Warning: Could not set .text protection: {}", e);
    }
    
    println!(
        "[MEMORY-PROTECTION]  Runtime memory protection active for PID {}",
        current_pid
    );
    println!("[MEMORY-PROTECTION]  Monitoring: ptrace, /proc/mem, mprotect(W on .text), RWX pages");
    
    Ok(protector)
}
