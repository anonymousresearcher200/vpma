use std::process::Command;

fn main() {
    // Build host SGX enclave if feature enabled
 
    
    {
        let workspace_dir = std::env::var("CARGO_MANIFEST_DIR").unwrap();
        let sgx_vm_lib_path = format!("{}/target/release", workspace_dir);
        
        println!("cargo:rerun-if-changed=sgx_vm/src/");
        println!("cargo:rustc-link-search=native={}", sgx_vm_lib_path);
        println!("cargo:rustc-link-lib=static=scaphandre_sgx_vm");
    }
}

