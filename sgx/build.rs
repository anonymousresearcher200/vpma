use std::env;

fn main() {
    let target = env::var("TARGET").unwrap_or_default();
    
    // Only compile the shim for SGX target
    if target.contains("fortanix") || target.contains("sgx") {
        // Compile the vsnprintf shim for SGX
        cc::Build::new()
            .file("src/vsnprintf_shim.c")
            .flag("-fno-stack-protector")
            .flag("-fPIC")
            .compile("vsnprintf_shim");
        
        println!("cargo:rerun-if-changed=src/vsnprintf_shim.c");
    }
}
