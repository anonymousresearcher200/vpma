#!/bin/bash

set -e

SCAPHANDRE_DIR="<SCAPHANDRE_DIR>"
VM_DIR="/var/lib/scaphandre/<VM_NAME>/intel-rapl:0"
VM_IP="<VM_IP>"
VM_USER="${VM_USER:-<VM_USER>}"
LOG_DIR="/tmp/attack_demo_$(date +%Y%m%d_%H%M%S)"
BINARY="$SCAPHANDRE_DIR/target/release/scaphandre"
VM_SCAPHANDRE_DIR=""
SSH_OPTS="-o BatchMode=yes -o ConnectTimeout=5"

SSH_AS_USER=""
if [ -n "$SUDO_USER" ] && [ "$EUID" -eq 0 ]; then
    SSH_AS_USER="sudo -u $SUDO_USER"
fi
vm_ssh() {
    $SSH_AS_USER ssh $SSH_OPTS "$@"
}

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

mkdir -p "$LOG_DIR"

print_header() {
    echo ""
    echo -e "${BLUE}=============================================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}=============================================================================${NC}"
    echo ""
}

print_attack() {
    echo -e "${RED}[ATTACK]${NC} $1"
}

print_detected() {
    echo -e "${GREEN}[DETECTED]${NC} $1"
}

print_info() {
    echo -e "${YELLOW}[INFO]${NC} $1"
}

HAMMER_PID=""

start_hammer() {
    local file="$1"
    local value="$2"
    bash -c "while true; do echo '$value' > '$file' 2>/dev/null; done" &
    HAMMER_PID=$!
    disown $HAMMER_PID 2>/dev/null || true
    print_info "Hammer started (PID=$HAMMER_PID)  '$value'  $file"
}

stop_hammer() {
    if [ -n "$HAMMER_PID" ]; then
        kill -9 "$HAMMER_PID" 2>/dev/null || true
        wait "$HAMMER_PID" 2>/dev/null || true
        print_info "Hammer stopped (PID=$HAMMER_PID)"
        HAMMER_PID=""
    fi
}

trap 'stop_hammer' EXIT

detect_vm_scaphandre_dir() {
    if [ -n "$VM_SCAPHANDRE_DIR" ]; then
        return 0
    fi

    local candidate
    local tried=""
    for candidate in "secure-scaphandre-full" "scaphandre" "Desktop/scaphandre" "desktop/scaphandre"; do
        tried="$tried ~/$candidate"
        if vm_ssh "$VM_USER@$VM_IP" "test -d ~/$candidate" >/dev/null 2>&1; then
            VM_SCAPHANDRE_DIR="~/$candidate"
            print_info "Detected VM scaphandre path: $VM_SCAPHANDRE_DIR"
            return 0
        fi
    done

    print_info "Could not detect scaphandre directory on VM (tried:$tried)"
    return 1
}

run_vm_scaphandre_check() {
    if ! detect_vm_scaphandre_dir; then
        echo "VM scaphandre directory not found"
        return 1
    fi

    vm_ssh "$VM_USER@$VM_IP" "cd $VM_SCAPHANDRE_DIR && timeout 8 sudo ./target/release/scaphandre --vm stdout 2>&1"
}

save_state() {
    print_info "Saving original chain state..."
    cp "$VM_DIR/chain_counter" "$LOG_DIR/orig_counter" 2>/dev/null || echo "0" > "$LOG_DIR/orig_counter"
    cp "$VM_DIR/chain_signature" "$LOG_DIR/orig_signature" 2>/dev/null || true
    cp "$VM_DIR/chain_previous_hash" "$LOG_DIR/orig_prev_hash" 2>/dev/null || true
    cp "$VM_DIR/energy_uj" "$LOG_DIR/orig_energy" 2>/dev/null || echo "0" > "$LOG_DIR/orig_energy"
    cp "$VM_DIR/chain_energy_delta" "$LOG_DIR/orig_delta" 2>/dev/null || echo "0" > "$LOG_DIR/orig_delta"
}

restore_state() {
    print_info "Restoring original chain state..."
    cp "$LOG_DIR/orig_counter" "$VM_DIR/chain_counter" 2>/dev/null || true
    cp "$LOG_DIR/orig_signature" "$VM_DIR/chain_signature" 2>/dev/null || true
    cp "$LOG_DIR/orig_prev_hash" "$VM_DIR/chain_previous_hash" 2>/dev/null || true
    cp "$LOG_DIR/orig_energy" "$VM_DIR/energy_uj" 2>/dev/null || true
    cp "$LOG_DIR/orig_delta" "$VM_DIR/chain_energy_delta" 2>/dev/null || true
}

attack_rapl_injection() {
    print_header "ATTACK 1: RAPL Value Injection"

    print_info "Scenario: Attacker with root access modifies RAPL energy reading"
    print_info "Goal: Make VM believe it consumed less energy than actual"
    echo ""

    local orig_energy=$(cat "$VM_DIR/energy_uj" 2>/dev/null || echo "100000000")
    local orig_sig=$(cat "$VM_DIR/chain_signature" 2>/dev/null)

    print_info "Original energy: ${orig_energy} uJ"
    print_info "Original signature: ${orig_sig:0:16}..."
    echo ""

    local fake_energy=$((orig_energy / 2))
    print_attack "Injecting fake energy value: ${fake_energy} uJ (50% of actual)"
    start_hammer "$VM_DIR/energy_uj" "$fake_energy"

    print_attack "Signature NOT updated (attacker doesn't have HMAC key)"
    echo ""

    print_info "Attempting verification from VM SGX enclave..."

    local result
    if run_vm_scaphandre_check > "$LOG_DIR/attack1_output.txt" 2>&1; then
        result=$(cat "$LOG_DIR/attack1_output.txt")
    else
        result=$(cat "$LOG_DIR/attack1_output.txt" 2>/dev/null || echo "Connection failed")
    fi

    echo ""
    if echo "$result" | grep -q "TAMPERING DETECTED\|signature mismatch\|Signature mismatch"; then
        print_detected "VM SGX detected signature mismatch!"
        echo ""
        echo "  Detection mechanism: HMAC-SHA256 chain verification"
        echo "  Chain data: counter|vm_name|energy|prev_hash"
        echo "  Expected signature != received signature"
        echo ""
        echo -e "  ${GREEN} Attack BLOCKED - fake energy rejected${NC}"
    else
        print_info "Verification output:"
        echo "$result" | head -20
        echo ""
        echo -e "  ${YELLOW}Note: VM may need active scaphandre host to detect${NC}"
    fi

    stop_hammer
    echo "$orig_energy" > "$VM_DIR/energy_uj"
    print_info "Original energy restored"
}

attack_replay() {
    print_header "ATTACK 2: Replay Attack"

    print_info "Scenario: Attacker records valid signed energy reading"
    print_info "Goal: Replay old reading to hide current high consumption"
    echo ""

    local curr_counter=$(cat "$VM_DIR/chain_counter" 2>/dev/null || echo "100")
    local curr_sig=$(cat "$VM_DIR/chain_signature" 2>/dev/null)
    local curr_energy=$(cat "$VM_DIR/energy_uj" 2>/dev/null)

    print_info "Captured valid state:"
    echo "  Counter: $curr_counter"
    echo "  Signature: ${curr_sig:0:16}..."
    echo "  Energy: $curr_energy uJ"
    echo ""

    print_info "Simulating normal operation (counter increments)..."
    local new_counter=$((curr_counter + 10))
    echo "$new_counter" > "$VM_DIR/chain_counter"
    print_info "Counter advanced to: $new_counter"
    echo ""

    print_attack "Replaying captured state (counter: $curr_counter)"
    start_hammer "$VM_DIR/chain_counter" "$curr_counter"

    print_info "Attempting verification with replayed counter..."

    local result
    run_vm_scaphandre_check > "$LOG_DIR/attack2_output.txt" 2>&1 || true
    result=$(cat "$LOG_DIR/attack2_output.txt" 2>/dev/null)

    echo ""
    if echo "$result" | grep -qi "REPLAY\|ROLLBACK\|counter discontinuity\|Same counter"; then
        print_detected "VM SGX detected replay attack!"
        echo ""
        echo "  Detection mechanism: Stateful counter tracking in SGX enclave"
        echo "  SGX stores: last_verified_counter in protected memory"
        echo "  Attack counter ($curr_counter) <= stored counter"
        echo ""
        echo -e "  ${GREEN} Attack BLOCKED - replayed data rejected${NC}"
    else
        if echo "$result" | grep -qi "Chain initialized\|first verification"; then
            print_info "VM SGX initialized chain (first verification)"
            echo ""
            echo "  To fully test replay, run verification twice:"
            echo "  1. First run: SGX accepts and stores counter"
            echo "  2. Replay: SGX rejects same/lower counter"
        else
            print_info "Output:"
            echo "$result" | head -15
        fi
    fi

    stop_hammer
    echo "$new_counter" > "$VM_DIR/chain_counter"
    print_info "Counter restored to: $new_counter"
}

attack_rollback() {
    print_header "ATTACK 3: Rollback Attack"

    print_info "Scenario: Attacker restores VM snapshot from earlier time"
    print_info "Goal: Hide energy consumption that occurred after snapshot"
    echo ""

    local curr_counter=$(cat "$VM_DIR/chain_counter" 2>/dev/null || echo "100")
    local curr_sig=$(cat "$VM_DIR/chain_signature" 2>/dev/null)

    print_info "Current state:"
    echo "  Counter: $curr_counter"
    echo "  Signature: ${curr_sig:0:16}..."
    echo ""

    local rolled_back_counter=$((curr_counter - 50))
    print_attack "Rolling back counter: $curr_counter  $rolled_back_counter"
    print_attack "(Simulating restore from snapshot 50 iterations ago)"
    start_hammer "$VM_DIR/chain_counter" "$rolled_back_counter"

    print_attack "Using signature from rolled-back state"
    echo ""

    print_info "Attempting verification with rolled-back state..."

    local result
    run_vm_scaphandre_check > "$LOG_DIR/attack3_output.txt" 2>&1 || true
    result=$(cat "$LOG_DIR/attack3_output.txt" 2>/dev/null)

    echo ""
    if echo "$result" | grep -qi "ROLLBACK\|counter discontinuity\|counter went backwards"; then
        print_detected "VM SGX detected rollback attack!"
        echo ""
        echo "  Detection mechanism: Monotonic counter enforcement"
        echo "  SGX enclave stores highest seen counter"
        echo "  Rolled-back counter ($rolled_back_counter) < stored ($curr_counter)"
        echo ""
        echo -e "  ${GREEN} Attack BLOCKED - rollback detected${NC}"
    else
        if echo "$result" | grep -qi "REPLAY"; then
            print_detected "Rollback detected as REPLAY attack (same mechanism)"
        else
            print_info "Output:"
            echo "$result" | head -15
        fi
    fi

    stop_hammer
    echo "$curr_counter" > "$VM_DIR/chain_counter"
    print_info "Counter restored to: $curr_counter"
}

attack_fork() {
    print_header "ATTACK 4: Fork/Equivocation Attack"

    print_info "Scenario: Host maintains two divergent chains"
    print_info "Goal: Show different energy data to different VMs"
    echo ""

    local curr_counter=$(cat "$VM_DIR/chain_counter" 2>/dev/null || echo "100")
    local curr_sig=$(cat "$VM_DIR/chain_signature" 2>/dev/null)
    local curr_prev=$(cat "$VM_DIR/chain_previous_hash" 2>/dev/null)

    print_info "Current chain state:"
    echo "  Counter: $curr_counter"
    echo "  Current sig: ${curr_sig:0:16}..."
    echo "  Previous hash: ${curr_prev:0:16}..."
    echo ""

    local fake_prev="0000000000000000000000000000000000000000000000000000000000000000"
    print_attack "Creating forked chain with different previous_hash"
    print_attack "Fake previous hash: ${fake_prev:0:16}..."
    start_hammer "$VM_DIR/chain_previous_hash" "$fake_prev"

    local fork_counter=$((curr_counter + 1))
    echo "$fork_counter" > "$VM_DIR/chain_counter"
    print_attack "Fork counter: $fork_counter"
    echo ""

    print_info "Attempting verification with forked chain..."

    local result
    run_vm_scaphandre_check > "$LOG_DIR/attack4_output.txt" 2>&1 || true
    result=$(cat "$LOG_DIR/attack4_output.txt" 2>/dev/null)

    echo ""
    if echo "$result" | grep -qi "FORK\|previous hash mismatch\|equivocation"; then
        print_detected "VM SGX detected fork/equivocation attack!"
        echo ""
        echo "  Detection mechanism: Previous signature chaining"
        echo "  SGX stores: signature from last verified reading"
        echo "  Received previous_hash != stored signature"
        echo ""
        echo -e "  ${GREEN} Attack BLOCKED - fork detected${NC}"
    else
        if echo "$result" | grep -qi "TAMPERING\|signature mismatch"; then
            print_detected "Fork caused TAMPERING detection (signature invalid)"
        else
            print_info "Output:"
            echo "$result" | head -15
        fi
    fi

    stop_hammer
    echo "$curr_counter" > "$VM_DIR/chain_counter"
    echo "$curr_prev" > "$VM_DIR/chain_previous_hash" 2>/dev/null || true
    print_info "Chain state restored"
}

attack_binary_tampering() {
    print_header "ATTACK 5: Binary Tampering"

    print_info "Scenario: Attacker adds backdoor to scaphandre binary"
    print_info "Goal: Exfiltrate data or manipulate measurements"
    echo ""

    if [ ! -f "$BINARY" ]; then
        print_info "Building scaphandre first..."
        cd "$SCAPHANDRE_DIR"
        cargo build --release --features "use_sgx qemu" 2>/dev/null
    fi

    local orig_hash=$(sha256sum "$BINARY" | awk '{print $1}')
    print_info "Original binary hash: ${orig_hash:0:16}..."

    cp "$BINARY" "$LOG_DIR/scaphandre_backup"

    print_attack "Injecting 'backdoor' into binary..."
    local tamper_target="$BINARY"
    if ! echo "BACKDOOR_PAYLOAD_SIMULATED" >> "$tamper_target" 2>/dev/null; then
        print_info "Binary is busy; using tampered copy for hash-verification demo"
        tamper_target="$LOG_DIR/scaphandre_tampered"
        cp "$BINARY" "$tamper_target"
        echo "BACKDOOR_PAYLOAD_SIMULATED" >> "$tamper_target"
    fi

    local tampered_hash=$(sha256sum "$tamper_target" | awk '{print $1}')
    print_attack "Tampered binary hash: ${tampered_hash:0:16}..."
    echo ""

    print_info "Checking IMA measurement log..."

    if [ -f /sys/kernel/security/ima/ascii_runtime_measurements ]; then
        local ima_entry=$(grep scaphandre /sys/kernel/security/ima/ascii_runtime_measurements 2>/dev/null | tail -1)
        if [ -n "$ima_entry" ]; then
            echo "  IMA entry: $(echo "$ima_entry" | cut -d' ' -f4-)"
        fi
    fi

    print_info "Simulating attestation server verification..."

    local expected_hash
    if curl -s http://localhost:8080/api/hash > /dev/null 2>&1; then
        expected_hash=$(curl -s http://localhost:8080/api/hash)
        print_info "Attestation server expected hash: ${expected_hash:0:16}..."
    else
        expected_hash="$orig_hash"
        print_info "Using original hash as expected: ${expected_hash:0:16}..."
    fi

    echo ""
    if [ "$tampered_hash" != "$expected_hash" ]; then
        print_detected "Binary tampering detected!"
        echo ""
        echo "  Detection mechanism: Hash verification"
        echo "  Expected: ${expected_hash:0:32}..."
        echo "  Actual:   ${tampered_hash:0:32}..."
        echo ""
        echo "  Additional protections:"
        echo "    - IMA logs all binary executions to TPM PCR 10"
        echo "    - SGX enclave verifies hash via OCALL"
        echo "    - eBPF guard monitors binary file modifications"
        echo ""
        echo -e "  ${GREEN} Attack DETECTED - backdoored binary identified${NC}"
    fi

    if [ "$tamper_target" = "$BINARY" ]; then
        cp "$LOG_DIR/scaphandre_backup" "$BINARY"
        print_info "Original binary restored"
    else
        rm -f "$tamper_target"
        print_info "Original binary unchanged (tampered copy removed)"
    fi
}

attack_msr_spoof() {
    print_header "ATTACK 6: RAPL MSR Spoofing (Kernel Level)"

    print_info "Scenario: Attacker with kernel module tries to spoof MSR reads"
    print_info "Goal: Return fake values from /sys/class/powercap"
    echo ""

    print_info "Checking eBPF guard status..."

    if bpftool prog list 2>/dev/null | grep -q "scaphandre\|rapl"; then
        print_info "eBPF guard is ACTIVE"
        echo ""
        print_info "eBPF guard provides:"
        echo "  1. SipHash-2-4 computed in kernel space"
        echo "  2. Hash verified against SGX computation"
        echo "  3. File access monitoring on /var/lib/scaphandre/*"
        echo ""

        print_attack "Simulating fake powercap write..."

        local test_file="/var/lib/scaphandre/<VM_NAME>/intel-rapl:0/test_write"
        if echo "fake_data" > "$test_file" 2>/dev/null; then
            rm -f "$test_file"
            print_info "Write succeeded (eBPF may be in audit mode)"
        else
            print_detected "eBPF blocked unauthorized write!"
        fi
    else
        print_info "eBPF guard not loaded (run with --features with_ebpf_guard)"
        echo ""
        echo "  Without eBPF guard:"
        echo "  - RAPL values can be spoofed by root"
        echo "  - No kernel-level integrity protection"
        echo ""
        echo "  With eBPF guard:"
        echo "  - SipHash computed atomically with RAPL read"
        echo "  - SGX verifies hash matches expected"
        echo "  - Spoofed values will have wrong hash  rejected"
    fi
}

attack_host_rapl_tamper() {
    print_header "ATTACK 7: Host RAPL File Tampering (eBPF guard)"

    print_info "Scenario: Root attacker tampers with host's exported RAPL chain dir"
    print_info "Target:   $VM_DIR (monitored by eBPF guard)"
    echo ""

    print_attack "Attempting write to sysfs RAPL: /sys/class/powercap/intel-rapl:0/energy_uj"
    if echo 0 > /sys/class/powercap/intel-rapl:0/energy_uj 2>/dev/null; then
        print_info "  Unexpected: write succeeded (kernel should have refused)"
    else
        print_detected "Kernel refused sysfs write (read-only file)"
    fi
    echo ""

    if [ -f "$VM_DIR/chain_signature" ]; then
        print_attack "Renaming $VM_DIR/chain_signature  chain_signature.tampered"
        mv "$VM_DIR/chain_signature" "$VM_DIR/chain_signature.tampered" 2>/dev/null || true
        sleep 1
        mv "$VM_DIR/chain_signature.tampered" "$VM_DIR/chain_signature" 2>/dev/null || true
        print_info "   expect [EBPF-GUARD] vfs_rename event"
    fi
    echo ""

    print_attack "Creating fake file: $VM_DIR/attacker_dropped.bin"
    echo "MALICIOUS_PAYLOAD" > "$VM_DIR/attacker_dropped.bin" 2>/dev/null || true
    sleep 1
    rm -f "$VM_DIR/attacker_dropped.bin"
    print_info "   expect [EBPF-GUARD] security_inode_create event"
    echo ""

    if [ -f "$VM_DIR/chain_energy_delta" ]; then
        cp "$VM_DIR/chain_energy_delta" "$LOG_DIR/chain_energy_delta.bak"
        print_attack "Deleting $VM_DIR/chain_energy_delta (will restore)"
        rm -f "$VM_DIR/chain_energy_delta"
        sleep 1
        cp "$LOG_DIR/chain_energy_delta.bak" "$VM_DIR/chain_energy_delta"
        print_info "   expect [EBPF-GUARD] vfs_unlink event"
        print_info "  Original chain_energy_delta restored"
    fi
    echo ""

    print_info "Looking for [EBPF-GUARD] alerts (scaphandre stdout / journalctl / dmesg)..."
    local hits=""
    for src in /var/log/scaphandre.log /var/log/syslog; do
        if [ -r "$src" ]; then
            hits+="$(tail -200 $src 2>/dev/null | grep -E 'EBPF-GUARD.*unauthorized')"$'\n'
        fi
    done
    hits+="$(journalctl -u scaphandre --since '1 minute ago' --no-pager 2>/dev/null | grep -E 'EBPF-GUARD.*unauthorized')"$'\n'
    hits+="$(dmesg 2>/dev/null | tail -200 | grep -iE 'ebpf|scaphandre.*guard')"

    if echo "$hits" | grep -qE 'EBPF-GUARD|unauthorized'; then
        print_detected "eBPF guard logged unauthorized RAPL file activity:"
        echo "$hits" | grep -E 'EBPF-GUARD|unauthorized' | head -10
        echo -e "  ${GREEN} Attack DETECTED by eBPF guard${NC}"
    else
        print_info "No [EBPF-GUARD] hits found in standard log paths."
        echo "  Verify: is scaphandre running with --features with_ebpf_guard?"
        echo "  If running in foreground, check that terminal for [EBPF-GUARD] lines."
        echo "  Probes attached: vfs_rename, security_inode_create, vfs_unlink"
    fi
}

attack_rapl_unauth_read() {
    print_header "ATTACK 8: Unauthorized RAPL sysfs Read"

    local target="/sys/class/powercap/intel-rapl:0/energy_uj"
    print_info "Scenario: rogue process reads $target without going through scaphandre"
    print_info "Goal:     bypass attestation by sampling energy directly from the kernel"
    echo ""

    if [ ! -r "$target" ]; then
        print_info "$target not readable on this host; skipping"
        return 0
    fi

    print_attack "Reading $target via /usr/bin/dd (not allowlisted)"
    local raw
    raw=$(/usr/bin/dd if="$target" bs=64 count=1 2>/dev/null | tr -d '\n')
    print_info "  Raw value harvested: ${raw} uJ"
    echo ""

    print_attack "Reading $target via /usr/bin/cat (not allowlisted)"
    /usr/bin/cat "$target" >/dev/null 2>&1
    echo ""

    print_info "Looking for [EBPF-GUARD] open/read alerts on powercap..."
    local hits=""
    for src in /var/log/scaphandre.log /var/log/syslog; do
        if [ -r "$src" ]; then
            hits+="$(tail -200 "$src" 2>/dev/null | grep -E 'EBPF-GUARD.*(open|read).*powercap')"$'\n'
        fi
    done
    hits+="$(journalctl -u scaphandre --since '1 minute ago' --no-pager 2>/dev/null | grep -E 'EBPF-GUARD.*(open|read).*powercap')"$'\n'
    hits+="$(dmesg 2>/dev/null | tail -200 | grep -iE 'ebpf.*powercap|unauthorized.*energy_uj')"

    if echo "$hits" | grep -qE 'EBPF-GUARD|unauthorized'; then
        print_detected "eBPF guard logged unauthorized sysfs read:"
        echo "$hits" | grep -E 'EBPF-GUARD|unauthorized' | head -10
        echo -e "  ${GREEN} Attack DETECTED - non-allowlisted reader caught${NC}"
    else
        print_info "No [EBPF-GUARD] open/read hits found."
        echo "  Verify: scaphandre running with --features with_ebpf_guard?"
        echo "  Verify: powercap probe (security_file_open / vfs_read) attached?"
        echo "  Without it, sysfs is world-readable and the read silently succeeds."
    fi
}

attack_ptrace_inject() {
    print_header "ATTACK 9: ptrace Runtime Interference"

    print_info "Scenario: attacker attaches a debugger to a live scaphandre process"
    print_info "Goal:     inspect/modify in-memory state (keys, RAPL buffers, control flow)"
    echo ""

    if ! command -v python3 >/dev/null 2>&1; then
        print_info "python3 not available; skipping ptrace demo"
        return 0
    fi

    local target_pid
    target_pid=$(pidof scaphandre 2>/dev/null | awk '{print $1}')
    local launched_target=0

    if [ -z "$target_pid" ] && [ -x "$BINARY" ]; then
        print_info "No running scaphandre; launching one for the demo..."
        "$BINARY" stdout >/dev/null 2>&1 &
        target_pid=$!
        launched_target=1
        sleep 2
    fi

    if [ -z "$target_pid" ] || ! kill -0 "$target_pid" 2>/dev/null; then
        print_info "Could not obtain a running scaphandre PID; skipping"
        return 0
    fi

    print_info "Target scaphandre PID: $target_pid"
    print_info "YAMA ptrace_scope:    $(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo unknown)"
    echo ""

    print_attack "Calling ptrace(PTRACE_ATTACH, $target_pid) from a foreign process"
    local ptrace_out
    ptrace_out=$(python3 - "$target_pid" <<'PY' 2>&1
import ctypes, os, sys, time
libc = ctypes.CDLL("libc.so.6", use_errno=True)
PTRACE_ATTACH = 16
PTRACE_DETACH = 17
pid = int(sys.argv[1])
r = libc.ptrace(PTRACE_ATTACH, pid, 0, 0)
if r == -1:
    err = ctypes.get_errno()
    print(f"ATTACH_FAIL errno={err} ({os.strerror(err)})")
    sys.exit(0)
print("ATTACH_OK")
time.sleep(1)
libc.ptrace(PTRACE_DETACH, pid, 0, 0)
print("DETACHED")
PY
)
    echo "  $ptrace_out"
    echo ""

    print_info "Inspecting /proc/$target_pid/status for TracerPid..."
    local tracer
    tracer=$(grep -E '^TracerPid:' /proc/$target_pid/status 2>/dev/null | awk '{print $2}')
    print_info "  TracerPid (post-detach) = ${tracer:-unknown}"
    echo ""

    print_info "Looking for [EBPF-GUARD] ptrace alerts..."
    local hits=""
    for src in /var/log/scaphandre.log /var/log/syslog; do
        if [ -r "$src" ]; then
            hits+="$(tail -200 "$src" 2>/dev/null | grep -E 'EBPF-GUARD.*ptrace')"$'\n'
        fi
    done
    hits+="$(journalctl -u scaphandre --since '1 minute ago' --no-pager 2>/dev/null | grep -E 'EBPF-GUARD.*ptrace')"$'\n'
    hits+="$(dmesg 2>/dev/null | tail -200 | grep -iE 'ptrace.*scaphandre|ebpf.*ptrace')"

    if echo "$ptrace_out" | grep -q 'ATTACH_FAIL'; then
        print_detected "Kernel/YAMA refused ptrace attach (EPERM)"
        echo -e "  ${GREEN} Attack BLOCKED at the kernel boundary${NC}"
    elif echo "$hits" | grep -qE 'EBPF-GUARD|ptrace'; then
        print_detected "eBPF guard logged unauthorized ptrace attach:"
        echo "$hits" | grep -E 'EBPF-GUARD|ptrace' | head -10
        echo -e "  ${GREEN} Attack DETECTED - tracer caught by guard${NC}"
    else
        print_info "ptrace attach succeeded and no guard hit was found."
        echo "  Hardening checklist:"
        echo "    - kernel.yama.ptrace_scope >= 2 (admin only)"
        echo "    - eBPF probe on sys_enter_ptrace / __arm64_sys_ptrace attached"
        echo "    - scaphandre self-check on /proc/self/status TracerPid each loop"
    fi

    if [ "$launched_target" = "1" ]; then
        kill "$target_pid" 2>/dev/null || true
        wait "$target_pid" 2>/dev/null || true
    fi
}

attack_ldpreload_hook() {
    print_header "ATTACK 10: LD_PRELOAD Control-Flow Hook"

    print_info "Scenario: attacker preloads a shared library that lies about RAPL reads"
    print_info "Goal:     return falsified energy bytes from libc fopen()"
    echo ""

    if ! command -v gcc >/dev/null 2>&1; then
        print_info "gcc not available; skipping LD_PRELOAD compile step"
        return 0
    fi

    local hook_src="$LOG_DIR/rapl_hook.c"
    local hook_so="$LOG_DIR/rapl_hook.so"
    local fake_data="$LOG_DIR/fake_energy_uj"

    cat > "$hook_src" <<'HOOK_EOF'
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dlfcn.h>

static FILE* (*real_fopen)(const char*, const char*) = NULL;

__attribute__((constructor))
static void hook_init(void) {
    real_fopen = dlsym(RTLD_NEXT, "fopen");
    fprintf(stderr, "[HOOK] rapl_hook.so loaded\n");
}

FILE* fopen(const char *path, const char *mode) {
    if (!real_fopen) real_fopen = dlsym(RTLD_NEXT, "fopen");
    if (path && strstr(path, "/sys/class/powercap") && strstr(path, "energy_uj")) {
        const char *fake = getenv("FAKE_ENERGY_FILE");
        if (fake && *fake) {
            fprintf(stderr, "[HOOK] redirecting %s -> %s\n", path, fake);
            return real_fopen(fake, mode);
        }
    }
    return real_fopen(path, mode);
}
HOOK_EOF

    print_attack "Compiling malicious shared library: $hook_so"
    if ! gcc -shared -fPIC -o "$hook_so" "$hook_src" -ldl 2>"$LOG_DIR/hook_build.log"; then
        print_info "Hook build failed; see $LOG_DIR/hook_build.log"
        return 0
    fi

    echo "1" > "$fake_data"
    print_attack "Fake energy bytes prepared at $fake_data (value=1 uJ)"
    echo ""

    if [ ! -x "$BINARY" ]; then
        print_info "scaphandre binary missing at $BINARY; demonstrating hook in isolation"
        print_attack "Running cat /sys/class/powercap/intel-rapl:0/energy_uj under hook..."
        local hooked_out
        hooked_out=$(LD_PRELOAD="$hook_so" FAKE_ENERGY_FILE="$fake_data" \
                     cat /sys/class/powercap/intel-rapl:0/energy_uj 2>&1 | head -5)
        echo "  $hooked_out"
    else
        print_attack "Launching scaphandre with LD_PRELOAD=$hook_so"
        local hooked_log="$LOG_DIR/attack10_scaphandre.log"
        LD_PRELOAD="$hook_so" FAKE_ENERGY_FILE="$fake_data" \
            timeout 5 "$BINARY" stdout > "$hooked_log" 2>&1 || true
        print_info "Hooked scaphandre output (first 20 lines):"
        head -20 "$hooked_log" | sed 's/^/    /'

        local sca_pid
        sca_pid=$(pidof scaphandre 2>/dev/null | awk '{print $1}')
        if [ -n "$sca_pid" ] && [ -r "/proc/$sca_pid/maps" ]; then
            print_info "Scanning /proc/$sca_pid/maps for hook library..."
            grep rapl_hook "/proc/$sca_pid/maps" | head -3 | sed 's/^/    /'
        fi
    fi
    echo ""

    print_info "Detection (a): IMA measurement of loaded library"
    if [ -r /sys/kernel/security/ima/ascii_runtime_measurements ]; then
        local ima_hit
        ima_hit=$(grep rapl_hook /sys/kernel/security/ima/ascii_runtime_measurements 2>/dev/null | tail -1)
        if [ -n "$ima_hit" ]; then
            print_detected "IMA recorded hook library:"
            echo "    $ima_hit"
            echo -e "  ${GREEN} Attack DETECTED - unattested .so flagged by IMA${NC}"
        else
            print_info "  No IMA entry yet (kernel may not measure this path; need ima-policy)."
        fi
    else
        print_info "  IMA runtime_measurements unreadable; need root + IMA enabled."
    fi
    echo ""

    print_info "Detection (b): chain hash mismatch at SGX verifier"
    echo "  Kernel-side eBPF SipHash is computed on the RAW sysfs bytes;"
    echo "  the hooked user-space value will not match the signed chain entry."
    echo "  Expect: VM-side verifier reports 'TAMPERING DETECTED' / signature mismatch."
    echo ""

    rm -f "$hook_so" "$hook_src" "$fake_data"
    print_info "Hook artifacts removed from $LOG_DIR"
}

attack_runtime_cfi() {
    print_header "ATTACK 11: Runtime CFI Hijack on Live scaphandre"

    local target_pid
    target_pid=$(pidof scaphandre 2>/dev/null | awk '{print $1}')

    if [ -z "$target_pid" ]; then
        print_info "No running scaphandre found. Start it first, e.g.:"
        echo "    sudo $BINARY stdout &"
        return 0
    fi

    if ! command -v gdb >/dev/null 2>&1; then
        print_info "gdb not installed; install with: sudo apt-get install -y gdb"
        return 0
    fi

    print_info "Target scaphandre PID: $target_pid"
    print_info "Pre-attack TracerPid:  $(grep ^TracerPid /proc/$target_pid/status | awk '{print $2}')"
    print_info "YAMA ptrace_scope:     $(cat /proc/sys/kernel/yama/ptrace_scope 2>/dev/null || echo unknown)"
    echo ""

    local pre_sig pre_counter
    pre_sig=$(cat "$VM_DIR/chain_signature" 2>/dev/null)
    pre_counter=$(cat "$VM_DIR/chain_counter" 2>/dev/null)
    print_info "Pre-attack chain: counter=$pre_counter sig=${pre_sig:0:16}..."
    echo ""

    print_attack "Attaching gdb to PID $target_pid and forcing inferior code execution"
    local gdb_log="$LOG_DIR/attack11_gdb.log"
    local watcher_log="$LOG_DIR/attack11_tracerpid.log"

    (
        for _ in $(seq 1 25); do
            grep ^TracerPid /proc/$target_pid/status 2>/dev/null
            sleep 0.2
        done
    ) > "$watcher_log" &
    local watcher_pid=$!

    gdb -p "$target_pid" --batch \
        -ex 'set confirm off' \
        -ex 'set pagination off' \
        -ex 'call (int)write(2, "[CFI-INJECT] runtime hijack via gdb\n", 36)' \
        -ex 'call (int)getpid()' \
        -ex 'detach' \
        -ex 'quit' \
        > "$gdb_log" 2>&1 || true

    wait "$watcher_pid" 2>/dev/null || true

    print_info "gdb output (first 15 lines):"
    head -15 "$gdb_log" | sed 's/^/    /'
    echo ""

    print_info "TracerPid samples while gdb was attached:"
    sort -u "$watcher_log" | sed 's/^/    /'
    echo ""

    print_info "Post-attack TracerPid: $(grep ^TracerPid /proc/$target_pid/status 2>/dev/null | awk '{print $2}')"
    echo ""

    print_info "Detection (a): TracerPid signal"
    if grep -qE '^TracerPid:\s+[1-9]' "$watcher_log"; then
        print_detected "TracerPid was non-zero during attack window"
        echo "    Scaphandre self-check on /proc/self/status TracerPid would refuse to sign"
        echo "    new chain entries while a tracer is attached."
        echo -e "  ${GREEN} Runtime hijack DETECTED via TracerPid${NC}"
    else
        print_info "  No non-zero TracerPid captured (sampling may have missed window)."
    fi
    echo ""

    print_info "Detection (b): eBPF ptrace alerts"
    local hits=""
    set +e
    for src in /var/log/scaphandre.log /var/log/syslog; do
        if [ -r "$src" ]; then
            hits+="$(tail -200 "$src" 2>/dev/null | grep -E 'EBPF-GUARD.*ptrace' || true)"$'\n'
        fi
    done
    hits+="$(journalctl -u scaphandre --since '1 minute ago' --no-pager 2>/dev/null | grep -E 'EBPF-GUARD.*ptrace' || true)"$'\n'
    hits+="$(dmesg 2>/dev/null | tail -200 | grep -iE 'ptrace.*scaphandre|ebpf.*ptrace' || true)"
    set -e
    if echo "$hits" | grep -qE 'EBPF-GUARD|ptrace'; then
        print_detected "eBPF guard logged ptrace attach against scaphandre:"
        echo "$hits" | grep -E 'EBPF-GUARD|ptrace' | head -10
    else
        print_info "  No [EBPF-GUARD] ptrace hits found (probe may not be attached)."
    fi
    echo ""

    print_info "Detection (c): chain hash divergence at VM verifier"
    echo "    An attacker patching user-space memory cannot forge the kernel-side"
    echo "    eBPF SipHash on raw /sys/class/powercap bytes. The next chain entry"
    echo "    signed by scaphandre will mismatch the VM-side verifier's expected"
    echo "    hash and be reported as TAMPERING DETECTED."
    echo "    Confirm on the VM: cd ~/<scaphandre-dir> && sudo ./target/release/scaphandre --vm stdout"
}

attack_control_flow_hijack() {
    print_header "ATTACK 15: Saved-RIP / RSP Hijack via ptrace"

    local target_pid
    target_pid=$(pidof scaphandre 2>/dev/null | awk '{print $1}')
    if [ -z "$target_pid" ]; then
        print_info "No running scaphandre; skipping"
        return 0
    fi
    if ! command -v gdb >/dev/null 2>&1; then
        print_info "gdb required; skipping"
        return 0
    fi

    print_info "Target scaphandre PID: $target_pid"
    print_info "Mitigation under test: control-flow integrity (shadow stack / CET / self-check)"
    echo ""

    local cpu_flags shstk_cpu="" ibt_cpu=""
    cpu_flags=$(grep -m1 ^flags /proc/cpuinfo | tr ' ' '\n')
    echo "$cpu_flags" | grep -qx 'shstk'      && shstk_cpu=yes
    echo "$cpu_flags" | grep -qx 'user_shstk' && shstk_cpu=yes
    echo "$cpu_flags" | grep -qx 'ibt'        && ibt_cpu=yes
    echo "$cpu_flags" | grep -qx 'user_ibt'   && ibt_cpu=yes
    print_info "CPU shadow stack (shstk):    ${shstk_cpu:-no}"
    print_info "CPU indirect branch tracking (ibt): ${ibt_cpu:-no}"

    local proc_cet="no"
    if grep -qiE 'shstk|x86_thread_features.*shstk' /proc/$target_pid/status 2>/dev/null; then
        proc_cet="yes"
    fi
    print_info "scaphandre opted into shadow stack: $proc_cet"
    echo ""

    print_attack "Reading and tampering with RIP / RSP / *(RSP) on main thread"
    local gdb_log="$LOG_DIR/attack15_gdb.log"
    gdb -p "$target_pid" --batch \
        -ex 'set confirm off' -ex 'set pagination off' \
        -ex 'printf "rip=0x%lx rsp=0x%lx rbp=0x%lx\n", $rip, $rsp, $rbp' \
        -ex 'set $orig_word = *(unsigned long*)$rsp' \
        -ex 'printf "*(rsp) before    = 0x%lx\n", $orig_word' \
        -ex 'set {unsigned long}$rsp = 0xdeadbeefcafebabe' \
        -ex 'printf "*(rsp) tampered  = 0x%lx\n", *(unsigned long*)$rsp' \
        -ex 'set {unsigned long}$rsp = $orig_word' \
        -ex 'printf "*(rsp) restored  = 0x%lx\n", *(unsigned long*)$rsp' \
        -ex 'set $orig_rsp = $rsp' \
        -ex 'set $rsp = $rsp - 0x40' \
        -ex 'printf "rsp shifted to   = 0x%lx (pivot)\n", $rsp' \
        -ex 'set $rsp = $orig_rsp' \
        -ex 'printf "rsp restored to  = 0x%lx\n", $rsp' \
        -ex 'detach' -ex 'quit' \
        > "$gdb_log" 2>&1 || true

    grep -E 'rip=|rsp |rsp=|\*\(rsp\)|rsp shifted|rsp restored' "$gdb_log" | sed 's/^/    /'
    echo ""

    local hijack_ok=0
    grep -q 'tampered  = 0xdeadbeefcafebabe' "$gdb_log" && hijack_ok=1

    if [ "$hijack_ok" = "1" ]; then
        print_info "Saved RIP and RSP were both modifiable via ptrace."
        echo "    A real attacker would now wait for the next RET - control flow"
        echo "    would jump to 0xdeadbeefcafebabe (or any attacker-chosen ROP gadget)."
        echo ""
    fi

    print_info "Detection status on this host:"
    if [ -n "$shstk_cpu" ]; then
        echo "    (a) CET shadow stack: CPU supports it."
        if [ "$proc_cet" = "yes" ]; then
            echo "        scaphandre opted in  RET would raise #CP and kill the process."
            echo -e "      ${GREEN} Hardware CFI would catch the saved-RIP overwrite${NC}"
        else
            echo "        scaphandre did NOT opt in  no enforcement."
            echo -e "      ${YELLOW} Detection available but not enabled${NC}"
        fi
    else
        echo "    (a) CET shadow stack: CPU/kernel does not advertise shstk."
        echo -e "      ${RED} No hardware CFI on this host${NC}"
    fi
    echo "    (b) CET IBT: ${ibt_cpu:+CPU advertises ibt; needs}-fcf-protection=branch + opt-in."
    echo "    (c) Software self-check (stack-walk vs .text range): not implemented."
    echo "    (d) eBPF sched_switch RSP/RIP sampling: not implemented."
    echo ""

    if [ "$hijack_ok" = "1" ] && [ "$proc_cet" != "yes" ]; then
        echo -e "  ${YELLOW} Control-flow hijack succeeded; no detector fired${NC}"
        echo "    Closest implementable mitigation without hardware CET:"
        echo "      software stack-walk inside scaphandre's signing loop. For each"
        echo "      saved RIP found via DWARF unwinding, verify it falls inside the"
        echo "      attested text range; refuse to sign on mismatch."
    fi
}

main() {
    if [ "$EUID" -ne 0 ]; then
        echo "This script requires root privileges for attack simulation"
        echo "Usage: sudo $0 [1-15|all]"
        exit 1
    fi

    print_header "SCAPHANDRE SECURITY ATTACK DEMONSTRATIONS"
    echo "Date: $(date)"
    echo "Host: $(hostname)"
    echo "Log directory: $LOG_DIR"

    save_state

    case "${1:-all}" in
        1) attack_rapl_injection ;;
        2) attack_replay ;;
        3) attack_rollback ;;
        4) attack_fork ;;
        5) attack_binary_tampering ;;
        6) attack_msr_spoof ;;
        7) attack_host_rapl_tamper ;;
        8) attack_rapl_unauth_read ;;
        9) attack_ptrace_inject ;;
        10) attack_ldpreload_hook ;;
        11) attack_runtime_cfi ;;
        15) attack_control_flow_hijack ;;
        all)
            attack_rapl_injection
            attack_replay
            attack_rollback
            attack_fork
            attack_binary_tampering
            attack_msr_spoof
            attack_host_rapl_tamper
            attack_rapl_unauth_read
            attack_ptrace_inject
            attack_ldpreload_hook
            attack_runtime_cfi
            attack_control_flow_hijack
            ;;
        *)
            echo "Usage: $0 [1-15|all]"
            echo ""
            echo "Attacks:"
            echo "   1 - RAPL value injection (VM chain)"
            echo "   2 - Replay attack"
            echo "   3 - Rollback attack"
            echo "   4 - Fork/equivocation attack"
            echo "   5 - Binary tampering"
            echo "   6 - MSR spoofing"
            echo "   7 - Host RAPL file tampering (eBPF guard)"
            echo "   8 - Unauthorized RAPL sysfs read (non-allowlisted process)"
            echo "   9 - ptrace runtime interference"
            echo "  10 - LD_PRELOAD / control-flow hook (start-time)"
            echo "  11 - Runtime CFI hijack on a LIVE scaphandre (gdb in-memory)"
            echo "  12 - ASLR / PIE bypass via /proc/<pid>/maps"
            echo "  13 - Full RELRO test (ptrace GOT overwrite)"
            echo "  14 - NX stack test (page perm + PT_GNU_STACK)"
            echo "  all - Run all attacks"
            exit 1
            ;;
    esac

    restore_state
    echo ""
    print_info "Attack demonstration complete!"
}

main "$@"
