#!/bin/bash

DURATION=180
ITERATIONS=5
OUTPUT_DIR="./power_results"
VANILLA_BIN="<NONSECURE_SCAPHANDRE_BIN>"
SECURE_BIN="./target/release/scaphandre"

mkdir -p "$OUTPUT_DIR"

echo "=== Power Overhead Test (QEMU Mode) ==="
echo "Duration per test: ${DURATION}s"
echo "Iterations: $ITERATIONS"
echo ""

if ! pgrep -f "qemu.*guest=" > /dev/null; then
    echo "WARNING: No QEMU VM with 'guest=' name detected!"
    echo "Please start a VM first, e.g.:"
    echo "  qemu-system-x86_64 -name guest=<VM_NAME> ..."
    exit 1
fi

echo "Found QEMU VMs:"
pgrep -af "qemu.*guest="
echo ""

measure_power() {
    local label=$1
    local iteration=$2
    local outfile="$OUTPUT_DIR/${label}_iter${iteration}.txt"
    echo "Measuring: $label (iteration $iteration)..."
    sudo turbostat --quiet --interval 1 --num_iterations $DURATION \
        --show PkgWatt,CorWatt,RAMWatt 2>&1 | tee "$outfile"
}

calc_average() {
    local file=$1
    awk 'NR>1 && $1 ~ /^[0-9]/ {sum+=$1; count++} END {if(count>0) printf "%.2f", sum/count}' "$file"
}

echo "=== Test 1: Secure Scaphandre QEMU ==="
for i in $(seq 1 $ITERATIONS); do
    sudo pkill -f "scaphandre qemu" 2>/dev/null
    sleep 2
    echo "Starting secure scaphandre qemu..."
    gnome-terminal --title="Secure Scaphandre" -- bash -c "sudo IMMUDB_ADDR='127.0.0.1:8443' $SECURE_BIN qemu; read -p 'Press enter to close'" &
    sleep 10
    measure_power "secure" $i
    sudo pkill -f "$SECURE_BIN qemu" 2>/dev/null
    sleep 2
done

echo ""
echo "=== Test 2: Baseline (VM running, no scaphandre) ==="
sudo pkill -f "scaphandre qemu" 2>/dev/null
sleep 2
for i in $(seq 1 $ITERATIONS); do
    measure_power "baseline" $i
done

echo ""
echo "=== Test 3: Vanilla Scaphandre QEMU ==="
for i in $(seq 1 $ITERATIONS); do
    sudo pkill -f "scaphandre qemu" 2>/dev/null
    sleep 2
    echo "Starting vanilla scaphandre qemu..."
    gnome-terminal --title="Vanilla Scaphandre" -- bash -c "sudo $VANILLA_BIN qemu; read -p 'Press enter to close'" &
    sleep 10
    measure_power "vanilla" $i
    sudo pkill -f "$VANILLA_BIN qemu" 2>/dev/null
    sleep 2
done

echo ""
echo "=== Results Summary ==="
echo ""

baseline_total=0
vanilla_total=0
secure_total=0

for i in $(seq 1 $ITERATIONS); do
    b=$(calc_average "$OUTPUT_DIR/baseline_iter${i}.txt")
    v=$(calc_average "$OUTPUT_DIR/vanilla_iter${i}.txt")
    s=$(calc_average "$OUTPUT_DIR/secure_iter${i}.txt")
    echo "Iteration $i: Baseline=${b}W, Vanilla=${v}W, Secure=${s}W"
    baseline_total=$(echo "$baseline_total + $b" | bc)
    vanilla_total=$(echo "$vanilla_total + $v" | bc)
    secure_total=$(echo "$secure_total + $s" | bc)
done

baseline_avg=$(echo "scale=2; $baseline_total / $ITERATIONS" | bc)
vanilla_avg=$(echo "scale=2; $vanilla_total / $ITERATIONS" | bc)
secure_avg=$(echo "scale=2; $secure_total / $ITERATIONS" | bc)

vanilla_overhead=$(echo "scale=2; $vanilla_avg - $baseline_avg" | bc)
secure_overhead=$(echo "scale=2; $secure_avg - $baseline_avg" | bc)
security_cost=$(echo "scale=2; $secure_avg - $vanilla_avg" | bc)

echo ""
echo "=== Averages ==="
echo "Baseline:       ${baseline_avg}W"
echo "Vanilla:        ${vanilla_avg}W (overhead: ${vanilla_overhead}W)"
echo "Secure:         ${secure_avg}W (overhead: ${secure_overhead}W)"
echo ""
echo "Security features cost: ${security_cost}W extra"

cat > "$OUTPUT_DIR/summary.txt" << EOF
Power Overhead Test Results (QEMU Mode)
=======================================
Date: $(date)
Duration per test: ${DURATION}s
Iterations: $ITERATIONS

Averages:
- Baseline (VM only): ${baseline_avg}W
- Vanilla Scaphandre QEMU: ${vanilla_avg}W
- Secure Scaphandre QEMU: ${secure_avg}W

Overhead Analysis:
- Vanilla overhead vs baseline: ${vanilla_overhead}W
- Secure overhead vs baseline: ${secure_overhead}W
- Security features extra cost: ${security_cost}W
EOF

echo "Results saved to: $OUTPUT_DIR/summary.txt"
