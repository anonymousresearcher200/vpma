# Verifiable Power Metrics Architecture (VPMA)

This artifact contains the VPMA energy monitoring stack with SGX-based attestation, eBPF kernel-side integrity guards, TPM boot verification, and evaluation scripts.

---

## Requirements

- **OS:** Ubuntu 20.04 / 22.04 (Linux kernel 5.15+)
- **CPU:** Intel x86-64 with SGX support
- **Rust:** 1.74+
- **Databases:** ImmuDB and Redis must be running before starting scaphandre
- **Tools:**
  ```bash
  sudo apt-get install -y \
    clang llvm libclang-dev \
    linux-headers-$(uname -r) \
    libbpf-dev bpfcc-tools python3-bpfcc \
    libssl-dev pkg-config \
    tpm2-tools
  ```

---

## Build

### 1. Install Fortanix SGX toolchain

```bash
rustup target add x86_64-fortanix-unknown-sgx
cargo install fortanix-sgx-tools sgxs-tools
```

### 2. Configure IMA

Enable IMA measurement in the kernel boot parameters (`/etc/default/grub`):

```
GRUB_CMDLINE_LINUX="ima_policy=tcb ima_hash=sha256"
```

Then update grub and reboot:

```bash
sudo update-grub && sudo reboot
```

Verify IMA is active:

```bash
cat /sys/kernel/security/ima/policy
```

### 3. Configure TPM

Verify TPM is available:

```bash
tpm2_getcap properties-fixed
ls /dev/tpm*
```

Read PCR values (PCR0, PCR7, PCR10 are used for boot attestation):

```bash
tpm2_pcrread sha256:0,7,10
```

If using a vTPM inside the VM, ensure the VM is configured with a TPM device (e.g., via libvirt `<tpm>` element).

### 4. Deploy eBPF guard source

```bash
sudo mkdir -p /usr/local/etc/filemonitor
sudo cp filemonitor_scaphandre.c filemonitor_vm.c /usr/local/etc/filemonitor/
```

### 5. Configure secrets

Replace placeholders in source before building:

| Placeholder | File | Description |
|---|---|---|
| `<REDIS_CA_CERT_PEM>` | `sgx_vm/src/main.rs` | Redis TLS CA certificate |
| `<REDIS_PASSWORD>` | `sgx_vm/src/main.rs` | Redis password |
| `<ENCLAVE_KEY_PEM>` | `sgx/src/main.rs`, `sgx_vm/src/main.rs` | SGX enclave signing key |
| `<HOST_IP>`, `<VM_IP>` | `attack_demo.sh` | Network addresses |

Generate keys:
```bash
openssl genrsa -out sgx/enclave_key.pem 3072
openssl genrsa -out sgx_vm/enclave_key.pem 3072
```

### 6. Build

```bash
# Host binary
cargo build --release --no-default-features \
  --features use_sgx,with_ebpf_guard,tpm_attestation,qemu,json

# Host SGX enclave
cd sgx && cargo build --release --target x86_64-fortanix-unknown-sgx
ftxsgx-elf2sgxs target/x86_64-fortanix-unknown-sgx/release/sgx \
  --heap-size 0x2000000 --stack-size 0x20000 --threads 8 --ssaframesize 1 \
  --output target/x86_64-fortanix-unknown-sgx/release/sgx.sgxs && cd ..

# VM SGX enclave
cd sgx_vm && cargo build --release --target x86_64-fortanix-unknown-sgx
ftxsgx-elf2sgxs target/x86_64-fortanix-unknown-sgx/release/sgx_vm \
  --heap-size 0x8000000 --stack-size 0x100000 \
  --output sgx_vm_enclave.sgxs && cd ..

# VM binary 
cargo build --release --no-default-features \
  --features use_sgx_vm,with_ebpf_guard,tpm_attestation_vm,json
```

---

## Register Binary Hash

After building, register the binary hash and TPM PCR values in ImmuDB before running:

```bash
# Host
sudo bash scripts/register_binary_hash.sh

# VM
sudo VM_HOSTNAME=<VM_NAME> bash scripts/register_binary_hash.sh
```

---

## Run

```bash

# Host binary
sudo IMMUDB_ADDR="127.0.0.1:8443" \
     IMMUDB_CA_CERT="<IMMUDB_CERTS_PATH>/ca.pem" \
     ./target/release/scaphandre qemu

# SGX enclave 
ftxsgx-runner sgx_vm_enclave.sgxs 0.0.0.0:9999 &

# VM binary
sudo VM_NAME=<VM_NAME> \
     SGX_REMOTE_HOST=<HOST_IP>:9999 \
     ./target/release/scaphandre --vm db
```

---

## Performance Evaluation

Install Phoronix Test Suite:

```bash
sudo apt-get install phoronix-test-suite
```

Run benchmarks:

```bash
phoronix-test-suite batch-benchmark compress-7zip
phoronix-test-suite batch-benchmark fio
phoronix-test-suite batch-benchmark iperf
phoronix-test-suite batch-benchmark c-ray
phoronix-test-suite batch-benchmark stress-ng
phoronix-test-suite batch-benchmark sysbench
```

Run the same benchmarks with scaphandre running on the host to measure overhead.

To measure power overhead using `turbostat`:

```bash
sudo bash scripts/power_overhead_test.sh
```

---

## Security Evaluation

```bash
sudo ./scripts/attack_demo.sh all
sudo ./scripts/attack_demo.sh 1
```
---

## Offline Verification

To verify energy records stored in Redis (Merkle tree reconstruction):

```bash
python3 scripts/verify_redis_data.py --block 1
python3 scripts/verify_redis_data.py --date "YYYY-MM-DD"
python3 scripts/verify_redis_data.py --all
```


